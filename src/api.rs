//! API client for AirVPN's encrypted manifest endpoint.
//!
//! Implements Eddie's FetchUrl/FetchUrls protocol:
//! 1. Build RSA+AES envelope (s + d params) via crypto module
//! 2. POST to bootstrap IPs with fallback
//! 3. Decrypt AES-CBC response to get XML manifest
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs

use anyhow::{Context, Result};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use reqwest::blocking::Client;
use std::time::Duration;

use crate::crypto;
use crate::manifest::attr_opt;

// ---------------------------------------------------------------------------
// Constants — exported for netlock whitelisting and other modules
// ---------------------------------------------------------------------------

/// Bootstrap IPs tried in order until one succeeds.
/// From Eddie's hardcoded server list (IPv4 only for now).
pub const BOOTSTRAP_IPS: &[&str] = &[
    "http://63.33.78.166",
    "http://54.93.175.114",
    "http://82.196.3.205",
    "http://63.33.116.50",
    "http://[2a03:b0c0:0:1010::9b:c001]",
    "http://bootme.org",
];

/// AirVPN's RSA-4096 public key modulus (base64).
/// From resources/providers/AirVPN.json `auth_rsa_modulus`.
pub const RSA_MODULUS_B64: &str = "wuQXz7eZeEBwaaRsVK8iEHpueXoKyQzW8sr8qMUkZIcKtKv5iseXMrTbcGYGpRXdiqXp7FqrSjPSMDuRGaHfjWgjbnW4PwecmgJSfhkWt4xY8OnIwKkuI2Eo0MAa9lduPOQRKSfa9I1PBogIyEUrf7kSjcoJQgeY66D429m1BDWY3f65c+8HrCQ8qPg1GY+pSxuwp6+2dV7fd1tiKLQEoJg9NeWGW0he/DDkNSe4c8gFfHj3ANYwDhTQijb+VaVZqPmxVJIzLoE1JOom0/P8fKsvpx3cFOtDS4apiI+N7MyVAMcx5Jjk2AQ/tyDiybwwZ32fOqYJVGxs13guOlgI6h77QxqNIq2bGEjzSRZ4tem1uN7F8AoVKPls6yAUQK1cWM5AVu4apoNIFG+svS/2kmn0Nx8DRVDvKD+nOByXgqg01Y6r0Se8Tz9EEBTiEopdlKjmO1wlrmW3iWKeFIwZnHt2PMceJMqziV8rRGh9gUMLLJC9qdXCAS4vf5VVnZ+Pq3SK9pP87hOislIu4/Kcn06cotQChpVnALA83hFW5LXJvc85iloWJkuLGAV3CcAwoSA5CG1Uo2S76MM+GLLkVIqUk1PiJMTTlSw1SlMEflU4bZiZP8di5e2OJI6vOHjdM2oonpPi/Ul5KKmfp+jci+kGMs9+zOyjKFLVIKDE+Vc=";

/// AirVPN's RSA public key exponent (base64).
/// From resources/providers/AirVPN.json `auth_rsa_exponent`.
pub const RSA_EXPONENT_B64: &str = "AQAB";

/// Software identifier sent in API requests.
const SOFTWARE_ID: &str = "EddieDesktop_2.24.6";

// ---------------------------------------------------------------------------
// Connect directive — parsed from act=connect response
// ---------------------------------------------------------------------------

/// Server directive returned by `act=connect` pre-authorization.
///
/// Eddie checks `message` and `message_action` attributes on the response:
/// - No message → proceed normally
/// - `message_action="stop"` → abort connection
/// - `message_action="next"` → skip this server, try next (5s delay in Eddie)
/// - Any other message → retry with delay (10s in Eddie)
///
/// Reference: Eddie src/Lib.Core/Session.cs:195-217
#[derive(Debug)]
pub enum ConnectDirective {
    /// No message — proceed with connection.
    Ok,
    /// Server says stop — abort connection entirely.
    Stop(String),
    /// Server says try a different server.
    Next(String),
    /// Server sent a message but no hard stop/next — retry with delay.
    Retry(String),
}

/// Parse the `act=connect` XML response into a [`ConnectDirective`].
///
/// Checks `error`, `message`, and `message_action` attributes on the root element,
/// matching Eddie's Session.cs logic.
fn parse_connect_response(xml: &str) -> Result<ConnectDirective> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                // Check for error attribute first (same as check_api_error)
                if let Some(err) = attr_opt(e, b"error") {
                    if !err.is_empty() {
                        return Ok(ConnectDirective::Stop(err));
                    }
                }
                // Check for message + message_action (Eddie Session.cs:195-217)
                if let Some(msg) = attr_opt(e, b"message") {
                    if !msg.is_empty() {
                        let action = attr_opt(e, b"message_action").unwrap_or_default();
                        return match action.as_str() {
                            "stop" => Ok(ConnectDirective::Stop(msg)),
                            "next" => Ok(ConnectDirective::Next(msg)),
                            _ => Ok(ConnectDirective::Retry(msg)),
                        };
                    }
                }
                // Root element has no error/message — all clear
                return Ok(ConnectDirective::Ok);
            }
            Ok(Event::Eof) => return Ok(ConnectDirective::Ok),
            Err(e) => anyhow::bail!("XML parse error in connect response: {e}"),
            _ => {} // skip declarations, comments, etc.
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest fetch
// ---------------------------------------------------------------------------

/// Fetch the server manifest (act=manifest).
///
/// Returns XML with servers, modes, RSA key, bootstrap URLs.
/// Does NOT contain user/WireGuard data — use fetch_user() for that.
///
/// Reference: Eddie Service.cs OnRefresh() -> FetchUrls({act=manifest})
pub fn fetch_manifest(username: &str, password: &str) -> Result<String> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "manifest".into()));
    params.insert(1, ("ts".into(), "0".into()));
    // Bootstrap: always use hardcoded key (no rotation available yet).
    // No extra URLs — manifest is the first call before we have bootstrap URLs.
    fetch_encrypted(&params, None, None, &[])
}

/// Fetch user data (act=user).
///
/// Returns XML with WireGuard keys, certificates, per-device keys.
/// The root element is <user> with <keys><key .../></keys> children.
///
/// Reference: Eddie Engine.cs Auth() -> FetchUrls({act=user})
pub fn fetch_user(username: &str, password: &str) -> Result<String> {
    fetch_user_with_key(username, password, None, None, &[])
}

/// Fetch user data with optional RSA key override (for key rotation).
pub fn fetch_user_with_key(
    username: &str,
    password: &str,
    rsa_mod: Option<&str>,
    rsa_exp: Option<&str>,
    extra_urls: &[String],
) -> Result<String> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "user".into()));
    fetch_encrypted(&params, rsa_mod, rsa_exp, extra_urls)
}

/// Pre-connection authorization (act=connect).
///
/// Eddie sends this before launching the WireGuard tunnel.
/// The server may use it to allocate resources or verify authorization.
/// Returns a [`ConnectDirective`] indicating whether to proceed, stop, or retry.
///
/// Reference: Eddie src/Lib.Core/Session.cs:174
pub fn fetch_connect(username: &str, password: &str, server_name: &str) -> Result<ConnectDirective> {
    fetch_connect_with_key(username, password, server_name, None, None, &[])
}

/// Pre-connection authorization with optional RSA key override (for key rotation).
/// Returns a [`ConnectDirective`] parsed from the server's response.
pub fn fetch_connect_with_key(
    username: &str,
    password: &str,
    server_name: &str,
    rsa_mod: Option<&str>,
    rsa_exp: Option<&str>,
    extra_urls: &[String],
) -> Result<ConnectDirective> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "connect".into()));
    params.insert(1, ("server".into(), server_name.into()));
    let xml = fetch_encrypted(&params, rsa_mod, rsa_exp, extra_urls)?;
    parse_connect_response(&xml)
}

/// Normalize CPU architecture to match Eddie's naming convention.
///
/// Eddie sends "x64" (not "x86_64") and "arm64" (not "aarch64").
/// The AirVPN server may reject requests with raw `std::env::consts::ARCH`.
fn normalize_arch() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "arm" => "armv7l",
        other => other,
    }
}

/// Common parameters sent with every API call (matching Eddie's FetchUrls).
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

/// Encrypt params and POST to bootstrap IPs with fallback.
///
/// If `rsa_modulus` / `rsa_exponent` are provided, they override the
/// hardcoded constants. This supports RSA key rotation via the manifest.
///
/// `extra_urls` are tried after the hardcoded `BOOTSTRAP_IPS` — these come
/// from the manifest's `<urls>` section (Eddie merges them into the URL list
/// for subsequent API calls).
fn fetch_encrypted(
    params: &[(String, String)],
    rsa_modulus: Option<&str>,
    rsa_exponent: Option<&str>,
    extra_urls: &[String],
) -> Result<String> {
    let modulus = rsa_modulus.unwrap_or(RSA_MODULUS_B64);
    let exponent = rsa_exponent.unwrap_or(RSA_EXPONENT_B64);
    let public_key = crypto::build_rsa_public_key(modulus, exponent)
        .context("failed to build AirVPN RSA public key")?;

    let (s_b64, d_b64, session_key) = crypto::build_envelope(&public_key, params)
        .context("failed to build API envelope")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("Eddie/2.24.6")
        .build()
        .context("failed to build HTTP client")?;

    let mut last_error: Option<anyhow::Error> = None;

    let all_urls: Vec<&str> = BOOTSTRAP_IPS.iter().copied()
        .chain(extra_urls.iter().map(|s| s.as_str()))
        .collect();

    for base_url in &all_urls {
        let url = format!("{}/", base_url);

        match client
            .post(&url)
            .form(&[("s", &s_b64), ("d", &d_b64)])
            .send()
        {
            Ok(response) => {
                let status = response.status();
                if !status.is_success() {
                    last_error = Some(anyhow::anyhow!(
                        "{}: HTTP {}",
                        base_url,
                        status
                    ));
                    continue;
                }

                let body = match response.bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        last_error = Some(
                            anyhow::Error::new(e)
                                .context(format!("{}: failed to read response body", base_url)),
                        );
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

                return Ok(xml);
            }
            Err(e) => {
                last_error = Some(
                    anyhow::Error::new(e).context(format!("{}: request failed", base_url)),
                );
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no bootstrap URLs configured")))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_arch_current_platform() {
        let arch = normalize_arch();
        // On x86_64 linux (CI / dev), this should return "x64"
        #[cfg(target_arch = "x86_64")]
        assert_eq!(arch, "x64");
        #[cfg(target_arch = "aarch64")]
        assert_eq!(arch, "arm64");
        // On any platform, it should be non-empty
        assert!(!arch.is_empty());
    }

    #[test]
    fn test_base_params_uses_normalized_arch() {
        let params = base_params("u", "p");
        let arch_val = params.iter().find(|(k, _)| k == "arch").unwrap();
        let system_val = params.iter().find(|(k, _)| k == "system").unwrap();
        // arch should NOT be raw "x86_64" on x86_64
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(arch_val.1, "x64");
            assert_eq!(system_val.1, "linux_x64");
        }
    }

    #[test]
    #[ignore] // Requires real AirVPN credentials
    fn test_fetch_manifest_real() {
        let xml = super::fetch_manifest("testuser", "testpass").unwrap();
        assert!(xml.contains("<manifest"));
    }

    // -----------------------------------------------------------------------
    // parse_connect_response tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_connect_response_ok() {
        let xml = r#"<connect />"#;
        let d = parse_connect_response(xml).unwrap();
        assert!(matches!(d, ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_ok_with_empty_message() {
        let xml = r#"<connect message="" />"#;
        let d = parse_connect_response(xml).unwrap();
        assert!(matches!(d, ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_stop_from_error() {
        let xml = r#"<connect error="Account expired" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Stop(msg) => assert_eq!(msg, "Account expired"),
            other => panic!("expected Stop, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_stop_from_message_action() {
        let xml = r#"<connect message="Banned" message_action="stop" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Stop(msg) => assert_eq!(msg, "Banned"),
            other => panic!("expected Stop, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_next() {
        let xml = r#"<connect message="Server full" message_action="next" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Next(msg) => assert_eq!(msg, "Server full"),
            other => panic!("expected Next, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_retry_unknown_action() {
        let xml = r#"<connect message="Temporary issue" message_action="wait" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Retry(msg) => assert_eq!(msg, "Temporary issue"),
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_retry_no_action() {
        // message present but no message_action → Retry (Eddie default branch)
        let xml = r#"<connect message="Please wait" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Retry(msg) => assert_eq!(msg, "Please wait"),
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_error_takes_priority() {
        // When both error and message are present, error wins (checked first)
        let xml = r#"<connect error="Fatal" message="Try again" message_action="next" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Stop(msg) => assert_eq!(msg, "Fatal"),
            other => panic!("expected Stop from error attr, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_empty_xml() {
        // Empty document → Ok (EOF before any element)
        let xml = "";
        let d = parse_connect_response(xml).unwrap();
        assert!(matches!(d, ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_start_element() {
        // Non-empty element (not self-closing) — should still parse root attrs
        let xml = r#"<response message="Maintenance" message_action="stop"></response>"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Stop(msg) => assert_eq!(msg, "Maintenance"),
            other => panic!("expected Stop, got {:?}", other),
        }
    }

    // -----------------------------------------------------------------------
    // Additional normalize_arch tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_normalize_arch_returns_non_empty() {
        // Regardless of platform, normalize_arch should never be empty
        let arch = normalize_arch();
        assert!(!arch.is_empty());
        // On known platforms, verify the mapping
        let raw = std::env::consts::ARCH;
        match raw {
            "x86_64" => assert_eq!(arch, "x64"),
            "aarch64" => assert_eq!(arch, "arm64"),
            "arm" => assert_eq!(arch, "armv7l"),
            other => assert_eq!(arch, other, "unknown arch should pass through unchanged"),
        }
    }

    // -----------------------------------------------------------------------
    // Additional base_params tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_base_params_has_all_six_keys() {
        let params = base_params("testuser", "testpass");
        assert_eq!(params.len(), 6, "base_params should return exactly 6 params");

        let keys: Vec<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
        assert!(keys.contains(&"login"), "missing 'login' param");
        assert!(keys.contains(&"password"), "missing 'password' param");
        assert!(keys.contains(&"software"), "missing 'software' param");
        assert!(keys.contains(&"arch"), "missing 'arch' param");
        assert!(keys.contains(&"system"), "missing 'system' param");
        assert!(keys.contains(&"version"), "missing 'version' param");
    }

    #[test]
    fn test_base_params_credential_values() {
        let params = base_params("alice", "hunter2");
        let login = params.iter().find(|(k, _)| k == "login").unwrap();
        let password = params.iter().find(|(k, _)| k == "password").unwrap();
        assert_eq!(login.1, "alice");
        assert_eq!(password.1, "hunter2");
    }

    #[test]
    fn test_base_params_software_version() {
        let params = base_params("u", "p");
        let software = params.iter().find(|(k, _)| k == "software").unwrap();
        assert_eq!(software.1, SOFTWARE_ID);
        let version = params.iter().find(|(k, _)| k == "version").unwrap();
        assert_eq!(version.1, "296");
    }

    #[test]
    fn test_base_params_system_includes_arch() {
        let params = base_params("u", "p");
        let arch_val = params.iter().find(|(k, _)| k == "arch").unwrap();
        let system_val = params.iter().find(|(k, _)| k == "system").unwrap();
        // system should be "linux_{arch}"
        assert_eq!(system_val.1, format!("linux_{}", arch_val.1));
    }

    // -----------------------------------------------------------------------
    // Additional parse_connect_response edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_connect_response_whitespace_only() {
        // Only whitespace — should hit EOF → Ok
        let xml = "   \n\t  ";
        let d = parse_connect_response(xml).unwrap();
        assert!(matches!(d, ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_xml_declaration_only() {
        // Just an XML declaration, no elements
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>"#;
        let d = parse_connect_response(xml).unwrap();
        assert!(matches!(d, ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_nested_elements_ignored() {
        // Nested elements after root should not affect result
        let xml = r#"<connect><inner message="ignored" error="ignored" /></connect>"#;
        let d = parse_connect_response(xml).unwrap();
        // Root <connect> has no error/message, so Ok
        assert!(matches!(d, ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_multiple_attributes() {
        // Root element with many attributes
        let xml = r#"<connect status="ok" version="2" region="eu" error="" message="" />"#;
        let d = parse_connect_response(xml).unwrap();
        // error="" and message="" are both empty → Ok
        assert!(matches!(d, ConnectDirective::Ok));
    }

    #[test]
    fn test_connect_response_comment_before_element() {
        // XML comment before root element
        let xml = r#"<!-- comment --><connect error="Auth failed" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Stop(msg) => assert_eq!(msg, "Auth failed"),
            other => panic!("expected Stop, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_empty_error_attribute() {
        // Empty error attribute should NOT trigger Stop — proceed to check message
        let xml = r#"<connect error="" message="Please wait" />"#;
        let d = parse_connect_response(xml).unwrap();
        match d {
            ConnectDirective::Retry(msg) => assert_eq!(msg, "Please wait"),
            other => panic!("expected Retry, got {:?}", other),
        }
    }

    #[test]
    fn test_connect_response_invalid_xml() {
        let xml = r#"<not closed"#;
        let result = parse_connect_response(xml);
        assert!(result.is_err(), "malformed XML should return error");
    }
}
