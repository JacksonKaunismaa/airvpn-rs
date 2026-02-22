//! API client for AirVPN's encrypted manifest endpoint.
//!
//! Implements Eddie's FetchUrl/FetchUrls protocol:
//! 1. Build RSA+AES envelope (s + d params) via crypto module
//! 2. POST to bootstrap IPs with fallback
//! 3. Decrypt AES-CBC response to get XML manifest
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs

use anyhow::{Context, Result};
use log::{debug, error};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::time::Duration;

use crate::crypto;
use crate::manifest::{attr_opt, sanitize_server_message};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Bootstrap IPs tried in order until one succeeds.
///
/// SECURITY: All entries MUST be IP addresses (not hostnames). Hostname entries
/// would require plaintext DNS resolution before netlock is active, allowing a
/// router-level attacker to poison the DNS response and inject their IP into
/// the netlock allowlist.
///
/// SECURITY: HTTPS is required for transport security. The application-layer
/// RSA+AES envelope only protects against passive eavesdroppers -- an active
/// MITM can tamper with the ciphertext or inject their own envelope if the
/// transport is plaintext HTTP.
pub const BOOTSTRAP_IPS: &[&str] = &[
    "https://63.33.78.166",
    "https://54.93.175.114",
    "https://82.196.3.205",
    "https://63.33.116.50",
    "https://[2a03:b0c0:0:1010::9b:c001]",
];

/// AirVPN's RSA-4096 public key modulus (base64).
pub const RSA_MODULUS_B64: &str = "wuQXz7eZeEBwaaRsVK8iEHpueXoKyQzW8sr8qMUkZIcKtKv5iseXMrTbcGYGpRXdiqXp7FqrSjPSMDuRGaHfjWgjbnW4PwecmgJSfhkWt4xY8OnIwKkuI2Eo0MAa9lduPOQRKSfa9I1PBogIyEUrf7kSjcoJQgeY66D429m1BDWY3f65c+8HrCQ8qPg1GY+pSxuwp6+2dV7fd1tiKLQEoJg9NeWGW0he/DDkNSe4c8gFfHj3ANYwDhTQijb+VaVZqPmxVJIzLoE1JOom0/P8fKsvpx3cFOtDS4apiI+N7MyVAMcx5Jjk2AQ/tyDiybwwZ32fOqYJVGxs13guOlgI6h77QxqNIq2bGEjzSRZ4tem1uN7F8AoVKPls6yAUQK1cWM5AVu4apoNIFG+svS/2kmn0Nx8DRVDvKD+nOByXgqg01Y6r0Se8Tz9EEBTiEopdlKjmO1wlrmW3iWKeFIwZnHt2PMceJMqziV8rRGh9gUMLLJC9qdXCAS4vf5VVnZ+Pq3SK9pP87hOislIu4/Kcn06cotQChpVnALA83hFW5LXJvc85iloWJkuLGAV3CcAwoSA5CG1Uo2S76MM+GLLkVIqUk1PiJMTTlSw1SlMEflU4bZiZP8di5e2OJI6vOHjdM2oonpPi/Ul5KKmfp+jci+kGMs9+zOyjKFLVIKDE+Vc=";

/// AirVPN's RSA public key exponent (base64).
pub const RSA_EXPONENT_B64: &str = "AQAB";

/// SHA-256 hash of "{RSA_MODULUS_B64}:{RSA_EXPONENT_B64}" for binary integrity verification.
const RSA_KEY_SHA256: &str = "d86e44a1b74da304ae9fc646b471a6ffa648ce1639304e44c5c67b6cc2440b56";

/// Verify the integrity of the embedded RSA public key at startup.
/// Panics on mismatch (unrecoverable -- binary is compromised).
pub fn verify_rsa_key_integrity() {
    let material = format!("{}:{}", RSA_MODULUS_B64, RSA_EXPONENT_B64);
    let hash = hex::encode(Sha256::digest(material.as_bytes()));
    if hash != RSA_KEY_SHA256 {
        error!(
            "CRITICAL: RSA key integrity check FAILED. Expected hash {}, got {}. \
             The binary may have been tampered with. Aborting.",
            RSA_KEY_SHA256, hash
        );
        panic!("RSA key integrity verification failed");
    }
    debug!("RSA key integrity check passed (SHA-256: {}...)", &hash[..16]);
}

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

pub fn fetch_manifest(username: &str, password: &str) -> Result<String> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "manifest".into()));
    params.insert(1, ("ts".into(), "0".into()));
    fetch_encrypted(&params, &[])
}

pub fn fetch_user(username: &str, password: &str) -> Result<String> {
    fetch_user_with_urls(username, password, &[])
}

pub fn fetch_user_with_urls(
    username: &str,
    password: &str,
    extra_urls: &[String],
) -> Result<String> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "user".into()));
    fetch_encrypted(&params, extra_urls)
}

pub fn fetch_connect(username: &str, password: &str, server_name: &str) -> Result<ConnectDirective> {
    fetch_connect_with_urls(username, password, server_name, &[])
}

pub fn fetch_connect_with_urls(
    username: &str,
    password: &str,
    server_name: &str,
    extra_urls: &[String],
) -> Result<ConnectDirective> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "connect".into()));
    params.insert(1, ("server".into(), server_name.into()));
    let xml = fetch_encrypted(&params, extra_urls)?;
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

/// SECURITY: Always uses the hardcoded RSA key. RSA key rotation from
/// untrusted manifest responses is intentionally rejected (C2).
fn fetch_encrypted(
    params: &[(String, String)],
    extra_urls: &[String],
) -> Result<String> {
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
    debug!("Using {} bootstrap URLs + {} extra URLs", BOOTSTRAP_IPS.len(), extra_urls.len());

    let public_key = crypto::build_rsa_public_key(RSA_MODULUS_B64, RSA_EXPONENT_B64)
        .context("failed to build AirVPN RSA public key")?;

    let (s_b64, d_b64, session_key) = crypto::build_envelope(&public_key, params)
        .context("failed to build API envelope")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Eddie/2.24.6")
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .context("failed to build HTTP client")?;

    let mut last_error: Option<anyhow::Error> = None;
    let all_urls: Vec<&str> = BOOTSTRAP_IPS.iter().copied()
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
    fn test_normalize_arch() {
        let arch = normalize_arch();
        assert!(!arch.is_empty());
    }

    #[test]
    fn test_base_params_count() {
        assert_eq!(base_params("u", "p").len(), 6);
    }

    #[test]
    fn test_rsa_key_integrity_passes() {
        verify_rsa_key_integrity();
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
