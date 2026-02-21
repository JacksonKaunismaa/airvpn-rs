//! API client for AirVPN's encrypted manifest endpoint.
//!
//! Implements Eddie's FetchUrl/FetchUrls protocol:
//! 1. Build RSA+AES envelope (s + d params) via crypto module
//! 2. POST to bootstrap IPs with fallback
//! 3. Decrypt AES-CBC response to get XML manifest
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::time::Duration;

use crate::crypto;

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
    params.insert(1, ("ts".into(), std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())));
    fetch_encrypted(&params)
}

/// Fetch user data (act=user).
///
/// Returns XML with WireGuard keys, certificates, per-device keys.
/// The root element is <user> with <keys><key .../></keys> children.
///
/// Reference: Eddie Engine.cs Auth() -> FetchUrls({act=user})
pub fn fetch_user(username: &str, password: &str) -> Result<String> {
    let mut params = base_params(username, password);
    params.insert(0, ("act".into(), "user".into()));
    fetch_encrypted(&params)
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
fn fetch_encrypted(params: &[(String, String)]) -> Result<String> {
    let public_key = crypto::build_rsa_public_key(RSA_MODULUS_B64, RSA_EXPONENT_B64)
        .context("failed to build AirVPN RSA public key")?;

    let (s_b64, d_b64, session_key) = crypto::build_envelope(&public_key, params)
        .context("failed to build API envelope")?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client")?;

    let mut last_error: Option<anyhow::Error> = None;

    for base_url in BOOTSTRAP_IPS {
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

                let xml = crypto::decrypt_response(&body, &session_key.key, &session_key.iv)
                    .with_context(|| format!("{}: failed to decrypt response", base_url))?;

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
}
