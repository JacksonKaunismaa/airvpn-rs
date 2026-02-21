//! Post-connection verification (tunnel + DNS checks).
//!
//! Eddie verifies the tunnel actually works after handshake by:
//! 1. HTTP GET to check endpoint, verifying exit IP matches VPN pool
//! 2. DNS resolution challenge to verify DNS goes through VPN
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs:296-556

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::time::Duration;

const MAX_RETRIES: u32 = 5;

/// Verify the tunnel is working by checking exit IP.
///
/// Makes an HTTPS request through the tunnel to the provider's check endpoint
/// and verifies the returned IP is our assigned VPN IP.
///
/// Eddie: `checkUrl = checkProtocol + "://" + serverName + "_exit." + checkDomain + "/check/tun/"`
/// then asserts the returned `"ip"` is in the VPN IP pool.
///
/// `check_domain` comes from the provider manifest (e.g. "airvpn.org").
pub fn check_tunnel(server_name: &str, expected_ipv4: &str, check_domain: &str) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client for tunnel check")?;

    let url = format!(
        "https://{}_exit.{}/check/tun/",
        server_name.to_lowercase(),
        check_domain
    );

    for attempt in 1..=MAX_RETRIES {
        // Eddie: Thread.Sleep(t * 1000) — increasing delay, 0 on first attempt
        if attempt > 1 {
            std::thread::sleep(Duration::from_secs((attempt - 1) as u64));
        }

        match client.get(&url).send() {
            Ok(response) => {
                let body = match response.text() {
                    Ok(b) => b,
                    Err(e) => {
                        if attempt == MAX_RETRIES {
                            anyhow::bail!("tunnel check: failed to read response body: {}", e);
                        }
                        continue;
                    }
                };

                let json: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        if attempt == MAX_RETRIES {
                            anyhow::bail!("tunnel check: invalid JSON response: {}", e);
                        }
                        continue;
                    }
                };

                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
                    if ip == expected_ipv4 {
                        return Ok(());
                    }
                    // IP doesn't match -- tunnel may be misconfigured
                    if attempt == MAX_RETRIES {
                        anyhow::bail!(
                            "tunnel check failed: exit IP {} does not match expected {}",
                            ip,
                            expected_ipv4
                        );
                    }
                } else if attempt == MAX_RETRIES {
                    anyhow::bail!(
                        "tunnel check failed: response missing 'ip' field: {}",
                        body
                    );
                }
            }
            Err(e) => {
                if attempt == MAX_RETRIES {
                    anyhow::bail!("tunnel check failed after {} attempts: {}", MAX_RETRIES, e);
                }
            }
        }
    }

    anyhow::bail!("tunnel check failed after {} attempts", MAX_RETRIES)
}

/// Verify DNS is routed through the VPN tunnel.
///
/// Eddie's protocol:
/// 1. Generate a random token (hash)
/// 2. Resolve `<hash>.{check_domain}` via system DNS (which should go through VPN)
/// 3. GET `https://<server>_exit.<domain>/check/dns/` and verify the server saw that hash
///
/// `check_domain` comes from the provider manifest (e.g. "airvpn.org").
pub fn check_dns(server_name: &str, check_domain: &str) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .context("failed to build HTTP client for DNS check")?;

    let check_url = format!(
        "https://{}_exit.{}/check/dns/",
        server_name.to_lowercase(),
        check_domain
    );

    for attempt in 1..=MAX_RETRIES {
        if attempt > 1 {
            std::thread::sleep(Duration::from_secs((attempt - 1) as u64));
        }

        // Generate random token (Eddie: RandomGenerator.GetRandomToken())
        let hash = generate_random_token();

        // Resolve <hash>.<check_domain> via system DNS (goes through VPN tunnel)
        let dns_host = format!("{}.{}", hash, check_domain);
        // We only need to trigger the DNS query -- the result doesn't matter.
        // The VPN server logs the hash from the query it receives.
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&mut (dns_host.as_str(), 80));

        // Small delay to let the server process the DNS query
        std::thread::sleep(Duration::from_millis(500));

        // Now ask the check endpoint if it saw our hash
        match client.get(&check_url).send() {
            Ok(response) => {
                let body = match response.text() {
                    Ok(b) => b,
                    Err(e) => {
                        if attempt == MAX_RETRIES {
                            anyhow::bail!("DNS check: failed to read response body: {}", e);
                        }
                        continue;
                    }
                };

                let json: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        if attempt == MAX_RETRIES {
                            anyhow::bail!("DNS check: invalid JSON response: {}", e);
                        }
                        continue;
                    }
                };

                if let Some(dns_answer) = json.get("dns").and_then(|v| v.as_str()) {
                    if dns_answer == hash {
                        return Ok(());
                    }
                    // Hash mismatch -- DNS may not be going through VPN
                    if attempt == MAX_RETRIES {
                        anyhow::bail!(
                            "DNS check failed: server returned hash '{}', expected '{}'",
                            dns_answer,
                            hash
                        );
                    }
                } else if attempt == MAX_RETRIES {
                    anyhow::bail!(
                        "DNS check failed: response missing 'dns' field: {}",
                        body
                    );
                }
            }
            Err(e) => {
                if attempt == MAX_RETRIES {
                    anyhow::bail!("DNS check failed after {} attempts: {}", MAX_RETRIES, e);
                }
            }
        }
    }

    anyhow::bail!("DNS check failed after {} attempts", MAX_RETRIES)
}

/// Generate a short random hex token for DNS verification.
///
/// Eddie uses `RandomGenerator.GetRandomToken()` which produces a short alphanumeric string.
/// We use 16 random bytes encoded as 32 hex chars.
fn generate_random_token() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_token_length() {
        let token = generate_random_token();
        assert_eq!(token.len(), 32); // 16 bytes * 2 hex chars
    }

    #[test]
    fn test_generate_random_token_uniqueness() {
        let a = generate_random_token();
        let b = generate_random_token();
        assert_ne!(a, b);
    }

    #[test]
    fn test_generate_random_token_is_hex() {
        let token = generate_random_token();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
