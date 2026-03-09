//! API client for AirVPN's encrypted manifest endpoint.
//!
//! Implements Eddie's FetchUrl/FetchUrls protocol:
//! 1. Build RSA+AES envelope (s + d params) via crypto module
//! 2. POST to bootstrap IPs with fallback
//! 3. Decrypt AES-CBC response to get XML manifest
//!
//! Provider configuration (bootstrap URLs, RSA key) is loaded from
//! `resources/provider.json` at runtime, matching Eddie's approach of loading
//! from `resources/providers/AirVPN.json`.
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs

use anyhow::{bail, Context, Result};
use log::{debug, error};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::blocking::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::time::Duration;
use zeroize::Zeroizing;

use crate::crypto;
use crate::manifest::{attr_opt, sanitize_server_message};

// ---------------------------------------------------------------------------
// Provider configuration (loaded from JSON, matching Eddie's AirVPN.json)
// ---------------------------------------------------------------------------

/// Provider configuration loaded from `resources/provider.json`.
///
/// Matches the structure of Eddie's `resources/providers/AirVPN.json`:
/// bootstrap URLs, RSA modulus, and RSA exponent are loaded from JSON
/// rather than being hardcoded in source.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Bootstrap URLs tried in order until one succeeds.
    ///
    /// SECURITY: IP-address entries are preferred over hostnames. Hostname
    /// entries require plaintext DNS resolution before netlock is active,
    /// allowing a router-level attacker to poison the DNS response and inject
    /// their IP into the netlock allowlist.
    ///
    /// NOTE: These use HTTP (not HTTPS) because AirVPN's API servers serve TLS
    /// certificates for *.airvpn.org which don't include IP SANs. This matches
    /// Eddie's design ("We don't use SSL. Useless layer in our case" —
    /// Service.cs:906). The RSA+AES application-layer envelope provides the
    /// actual security.
    pub bootstrap_urls: Vec<String>,
    /// AirVPN's RSA-4096 public key modulus (base64).
    pub rsa_modulus: String,
    /// AirVPN's RSA public key exponent (base64).
    pub rsa_exponent: String,
}

/// Intermediate serde structs for deserializing the provider JSON.
#[derive(Deserialize)]
struct ProviderJson {
    manifest: ManifestJson,
}

#[derive(Deserialize)]
struct ManifestJson {
    auth_rsa_exponent: String,
    auth_rsa_modulus: String,
    urls: Vec<UrlEntry>,
}

#[derive(Deserialize)]
struct UrlEntry {
    address: String,
}

/// SHA-256 hash of "{rsa_modulus}:{rsa_exponent}" for integrity verification.
/// Detects tampering of the provider JSON file or embedded fallback.
const RSA_KEY_SHA256: &str = "d86e44a1b74da304ae9fc646b471a6ffa648ce1639304e44c5c67b6cc2440b56";


fn parse_provider_json(json_str: &str) -> Result<ProviderConfig> {
    let provider: ProviderJson = serde_json::from_str(json_str)
        .context("failed to parse provider JSON")?;
    let bootstrap_urls: Vec<String> = provider.manifest.urls
        .into_iter()
        .map(|u| u.address)
        .collect();
    if bootstrap_urls.is_empty() {
        anyhow::bail!("provider JSON contains no bootstrap URLs");
    }
    if provider.manifest.auth_rsa_modulus.is_empty() {
        anyhow::bail!("provider JSON contains empty RSA modulus");
    }
    if provider.manifest.auth_rsa_exponent.is_empty() {
        anyhow::bail!("provider JSON contains empty RSA exponent");
    }
    Ok(ProviderConfig {
        bootstrap_urls,
        rsa_modulus: provider.manifest.auth_rsa_modulus,
        rsa_exponent: provider.manifest.auth_rsa_exponent,
    })
}

/// Load the provider configuration from JSON.
///
/// Search order (first match wins):
/// 1. `/etc/airvpn-rs/provider.json` (system-wide install)
/// 2. `<exe_dir>/../../resources/provider.json` (cargo build: exe is in target/{debug,release}/)
///
/// Never searches relative to CWD — a stray provider.json in the working
/// directory should not silently override the real config.
pub fn load_provider_config() -> Result<ProviderConfig> {
    let mut search_paths: Vec<std::path::PathBuf> = vec![
        "/etc/airvpn-rs/provider.json".into(),
    ];

    // Look relative to the executable for cargo/dev builds
    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // exe is in target/release/ or target/debug/, repo root is ../../
            search_paths.push(exe_dir.join("../../resources/provider.json"));
            // exe is in target/debug/deps/ for tests, repo root is ../../../
            search_paths.push(exe_dir.join("../../../resources/provider.json"));
        }
    }

    for path in &search_paths {
        if path.is_file() {
            debug!("Loading provider config from {}", path.display());
            let json_str = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            return parse_provider_json(&json_str);
        }
    }

    let searched: Vec<String> = search_paths.iter().map(|p| format!("  {}", p.display())).collect();
    bail!(
        "provider.json not found. Searched:\n{}\n\
         Copy resources/provider.json to one of these locations.",
        searched.join("\n")
    )
}

/// Verify the integrity of the provider.json RSA public key.
///
/// This detects tampering of the provider JSON file (binary integrity check).
/// Only applies to the initial bootstrap key from provider.json. The manifest's
/// RSA key (if provided) does not need this check because it was authenticated
/// by the RSA+AES envelope of the manifest response.
///
/// Panics on mismatch (unrecoverable -- config may have been tampered with).
pub fn verify_rsa_key_integrity(config: &ProviderConfig) {
    let material = format!("{}:{}", config.rsa_modulus, config.rsa_exponent);
    let hash = hex::encode(Sha256::digest(material.as_bytes()));
    if hash != RSA_KEY_SHA256 {
        error!(
            "CRITICAL: RSA key integrity check FAILED. Expected hash {}, got {}. \
             The provider config may have been tampered with. Aborting.",
            RSA_KEY_SHA256, hash
        );
        panic!("RSA key integrity verification failed");
    }
    debug!("RSA key integrity check passed (SHA-256: {}...)", &hash[..16]);
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SOFTWARE_ID: &str = "EddieDesktop_2.24.6";

// ---------------------------------------------------------------------------
// Connect directive
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum ConnectDirective {
    Ok,
    Stop(String),
    Next(String),
    Retry(String),
}

fn parse_connect_response(xml: &str) -> Result<ConnectDirective> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if let Some(err) = attr_opt(e, b"error") {
                    if !err.is_empty() {
                        return Ok(ConnectDirective::Stop(sanitize_server_message(&err)));
                    }
                }
                if let Some(msg) = attr_opt(e, b"message") {
                    if !msg.is_empty() {
                        let sanitized = sanitize_server_message(&msg);
                        let action = attr_opt(e, b"message_action").unwrap_or_default();
                        return match action.as_str() {
                            "stop" => Ok(ConnectDirective::Stop(sanitized)),
                            "next" => Ok(ConnectDirective::Next(sanitized)),
                            _ => Ok(ConnectDirective::Retry(sanitized)),
                        };
                    }
                }
                return Ok(ConnectDirective::Ok);
            }
            Ok(Event::Eof) => return Ok(ConnectDirective::Ok),
            Err(e) => anyhow::bail!("XML parse error in connect response: {e}"),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// API calls
// ---------------------------------------------------------------------------

pub fn fetch_manifest(config: &ProviderConfig, username: &str, password: &str) -> Result<Zeroizing<String>> {
    fetch_manifest_with_timeout(config, username, password, 10)
}

pub fn fetch_manifest_with_timeout(config: &ProviderConfig, username: &str, password: &str, http_timeout_secs: u64) -> Result<Zeroizing<String>> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "manifest".into()));
    params.insert(1, ("ts".into(), "0".into()));
    fetch_encrypted(config, &params, &[], http_timeout_secs)
}

pub fn fetch_user(config: &ProviderConfig, username: &str, password: &str) -> Result<Zeroizing<String>> {
    fetch_user_with_urls(config, username, password, &[])
}

pub fn fetch_user_with_urls(
    config: &ProviderConfig,
    username: &str,
    password: &str,
    extra_urls: &[String],
) -> Result<Zeroizing<String>> {
    fetch_user_with_urls_timeout(config, username, password, extra_urls, 10)
}

pub fn fetch_user_with_urls_timeout(
    config: &ProviderConfig,
    username: &str,
    password: &str,
    extra_urls: &[String],
    http_timeout_secs: u64,
) -> Result<Zeroizing<String>> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "user".into()));
    fetch_encrypted(config, &params, extra_urls, http_timeout_secs)
}

pub fn fetch_connect(
    config: &ProviderConfig,
    username: &str,
    password: &str,
    server_name: &str,
) -> Result<ConnectDirective> {
    fetch_connect_with_urls(config, username, password, server_name, &[])
}

pub fn fetch_connect_with_urls(
    config: &ProviderConfig,
    username: &str,
    password: &str,
    server_name: &str,
    extra_urls: &[String],
) -> Result<ConnectDirective> {
    fetch_connect_with_urls_timeout(config, username, password, server_name, extra_urls, 10)
}

pub fn fetch_connect_with_urls_timeout(
    config: &ProviderConfig,
    username: &str,
    password: &str,
    server_name: &str,
    extra_urls: &[String],
    http_timeout_secs: u64,
) -> Result<ConnectDirective> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "connect".into()));
    params.insert(1, ("server".into(), server_name.into()));
    let xml = fetch_encrypted(config, &params, extra_urls, http_timeout_secs)?;
    parse_connect_response(&xml)
}

fn normalize_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "arm" => "armv7l",
        other => other,
    }
}

fn base_params(username: &str, password: &str) -> Vec<(String, String)> {
    let arch = normalize_arch();
    vec![
        ("login".into(), username.into()),
        ("password".into(), password.into()),
        ("software".into(), SOFTWARE_ID.into()),
        ("arch".into(), arch.into()),
        ("system".into(), format!("linux_{}", arch)),
        ("version".into(), "296".into()),
    ]
}

/// Performs an encrypted API call using the RSA+AES envelope protocol.
///
/// The RSA key comes from `config` which is either:
/// - The provider.json key (for the initial manifest fetch, integrity-verified)
/// - The manifest-provided key (for subsequent calls, authenticated by the
///   RSA+AES envelope of the manifest response)
///
/// This matches Eddie (Service.cs:920-938) which reads the RSA key from the
/// current Manifest node, updated after each manifest fetch.
fn fetch_encrypted(
    config: &ProviderConfig,
    params: &[(String, String)],
    extra_urls: &[String],
    http_timeout_secs: u64,
) -> Result<Zeroizing<String>> {
    let safe_params: Vec<(&str, &str)> = params.iter()
        .map(|(k, v)| {
            let v_safe: &str = match k.as_str() {
                "login" | "password" => "[REDACTED]",
                _ => v.as_str(),
            };
            (k.as_str(), v_safe)
        })
        .collect();
    debug!("API request params: {:?}", safe_params);
    debug!("Using {} bootstrap URLs + {} extra URLs", config.bootstrap_urls.len(), extra_urls.len());

    let public_key = crypto::build_rsa_public_key(&config.rsa_modulus, &config.rsa_exponent)
        .context("failed to build AirVPN RSA public key")?;

    let (s_b64, d_b64, session_key) = crypto::build_envelope(&public_key, params)
        .context("failed to build API envelope")?;

    // NOTE: no https_only(true) here because bootstrap IPs use HTTP
    // (AirVPN's servers don't have IP-matching TLS certificates).
    // The RSA+AES application-layer envelope is the security layer.
    let client = Client::builder()
        .timeout(Duration::from_secs(http_timeout_secs))
        .user_agent("Eddie/2.24.6")
        .build()
        .context("failed to build HTTP client")?;

    let mut last_error: Option<anyhow::Error> = None;
    let all_urls: Vec<&str> = config.bootstrap_urls.iter().map(|s| s.as_str())
        .chain(extra_urls.iter().map(|s| s.as_str()))
        .collect();

    for base_url in &all_urls {
        let url = format!("{}/", base_url);
        debug!("Trying bootstrap URL: {}", base_url);
        let req_start = std::time::Instant::now();
        match client.post(&url).form(&[("s", &s_b64), ("d", &d_b64)]).send() {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    last_error = Some(anyhow::anyhow!("{}: HTTP {}", base_url, status));
                    continue;
                }
                let body = match response.bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        last_error = Some(anyhow::Error::new(e).context(format!("{}: failed to read response body", base_url)));
                        continue;
                    }
                };
                let xml = match crypto::decrypt_response(&body, &session_key.key, &session_key.iv) {
                    Ok(xml) => xml,
                    Err(e) => {
                        last_error = Some(e.context(format!("{}: failed to decrypt response", base_url)));
                        continue;
                    }
                };
                debug!("API response from {}: {} bytes encrypted, {} bytes decrypted, {:.1}ms",
                    base_url, body.len(), xml.len(), req_start.elapsed().as_secs_f64() * 1000.0);
                return Ok(xml);
            }
            Err(e) => {
                last_error = Some(anyhow::Error::new(e).context(format!("{}: request failed", base_url)));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no bootstrap URLs configured")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_provider_config() {
        let config = load_provider_config().expect("failed to load provider config");
        assert!(!config.bootstrap_urls.is_empty());
        assert!(!config.rsa_modulus.is_empty());
        assert!(!config.rsa_exponent.is_empty());
    }

    #[test]
    fn test_rsa_key_integrity_passes() {
        let config = load_provider_config().expect("failed to load provider config");
        verify_rsa_key_integrity(&config);
    }

    #[test]
    fn test_parse_provider_json_rejects_empty_urls() {
        let json = r#"{"manifest":{"auth_rsa_exponent":"AQAB","auth_rsa_modulus":"abc","urls":[]}}"#;
        assert!(parse_provider_json(json).is_err());
    }

    #[test]
    fn test_parse_provider_json_rejects_empty_modulus() {
        let json = r#"{"manifest":{"auth_rsa_exponent":"AQAB","auth_rsa_modulus":"","urls":[{"address":"http://1.2.3.4"}]}}"#;
        assert!(parse_provider_json(json).is_err());
    }

    #[test]
    fn test_connect_response_ok() {
        assert!(matches!(parse_connect_response(r#"<connect />"#).unwrap(), ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_stop() {
        match parse_connect_response(r#"<connect error="expired" />"#).unwrap() {
            ConnectDirective::Stop(msg) => assert_eq!(msg, "expired"),
            other => panic!("expected Stop, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_next() {
        match parse_connect_response(r#"<connect message="full" message_action="next" />"#).unwrap() {
            ConnectDirective::Next(msg) => assert_eq!(msg, "full"),
            other => panic!("expected Next, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_html_stripped() {
        // Note: quick_xml attr_opt returns raw bytes without XML entity decoding,
        // so &lt;b&gt; stays as literal "&lt;b&gt;", not "<b>". The sanitizer
        // still provides defense-in-depth against actual < > in attribute values.
        // Test with actual angle brackets in the message (not entity-encoded):
        let sanitized = sanitize_server_message("<b>Alert</b>: check <a>here</a>");
        assert_eq!(sanitized, "Alert: check here");
    }
}
