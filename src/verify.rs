//! Post-connection verification (tunnel + DNS checks).
//!
//! Eddie verifies the tunnel actually works after handshake by:
//! 1. HTTP GET to check endpoint, verifying exit IP matches VPN pool
//! 2. DNS resolution challenge to verify DNS goes through VPN
//!
//! Both checks are best-effort with a hard 10-second overall timeout.
//! If they fail or time out, the caller should log a warning and continue.
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs:296-556

use anyhow::{Context, Result};
use reqwest::blocking::Client;
use std::sync::mpsc;
use std::time::Duration;

/// Hard ceiling for each verification step (tunnel check, DNS check).
/// If the check hasn't succeeded within this window, we give up.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-request timeout for HTTP calls. Must be shorter than VERIFY_TIMEOUT
/// so we have time for at least one retry.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Verify the tunnel is working by checking exit IP.
///
/// Makes an HTTPS request through the tunnel to the provider's check endpoint
/// and verifies the returned IP is our assigned VPN IP.
///
/// Returns `Ok(())` on success, `Err` on timeout or verification failure.
/// The caller should treat errors as non-fatal warnings.
///
/// `check_domain` comes from the provider manifest (e.g. "airvpn.org").
pub fn check_tunnel(server_name: &str, expected_ipv4: &str, check_domain: &str, exit_ip: &str) -> Result<()> {
    let server_name = server_name.to_string();
    let expected_ipv4 = expected_ipv4.to_string();
    let check_domain = check_domain.to_string();
    let exit_ip = exit_ip.to_string();

    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = check_tunnel_inner(&server_name, &expected_ipv4, &check_domain, &exit_ip);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(VERIFY_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            anyhow::bail!("tunnel check timed out after {}s", VERIFY_TIMEOUT.as_secs())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            anyhow::bail!("tunnel check thread panicked")
        }
    }
}

/// Inner tunnel check logic, run inside a thread with a hard timeout.
fn check_tunnel_inner(server_name: &str, expected_ipv4: &str, check_domain: &str, exit_ip: &str) -> Result<()> {
    let check_host = format!("{}_exit.{}", server_name.to_lowercase(), check_domain);

    // Eddie: ForceResolve = checkDomain + ":" + IpsExit.OnlyIPv4.First.Address
    // Bypass DNS for the check domain by resolving directly to the exit IP.
    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .resolve(
            &check_host,
            format!("{}:443", exit_ip).parse().map_err(|e| anyhow::anyhow!("invalid exit IP '{}': {}", exit_ip, e))?,
        )
        .build()
        .context("failed to build HTTP client for tunnel check")?;

    let url = format!("https://{}/check/tun/", check_host);

    // Try up to 3 times (with the outer timeout as the real deadline).
    for attempt in 1..=3 {
        if attempt > 1 {
            std::thread::sleep(Duration::from_secs(1));
        }

        match client.get(&url).send() {
            Ok(response) => {
                let body = match response.text() {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let json: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(_) => continue,
                };

                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
                    if ip == expected_ipv4 {
                        return Ok(());
                    }
                    anyhow::bail!(
                        "tunnel check failed: exit IP {} does not match expected {}",
                        ip,
                        expected_ipv4
                    );
                }
            }
            Err(_) => continue,
        }
    }

    anyhow::bail!("tunnel check failed after 3 attempts")
}

/// Verify DNS is routed through the VPN tunnel.
///
/// Eddie's protocol:
/// 1. Generate a random token (hash)
/// 2. Resolve `<hash>.{check_domain}` via system DNS (which should go through VPN)
/// 3. GET `https://<server>_exit.<domain>/check/dns/` and verify the server saw that hash
///
/// Returns `Ok(())` on success, `Err` on timeout or verification failure.
/// The caller should treat errors as non-fatal warnings.
///
/// `check_domain` comes from the provider manifest (e.g. "airvpn.org").
pub fn check_dns(server_name: &str, check_domain: &str, exit_ip: &str) -> Result<()> {
    let server_name = server_name.to_string();
    let check_domain = check_domain.to_string();
    let exit_ip = exit_ip.to_string();

    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = check_dns_inner(&server_name, &check_domain, &exit_ip);
        let _ = tx.send(result);
    });

    match rx.recv_timeout(VERIFY_TIMEOUT) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            anyhow::bail!("DNS check timed out after {}s", VERIFY_TIMEOUT.as_secs())
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            anyhow::bail!("DNS check thread panicked")
        }
    }
}

/// Inner DNS check logic, run inside a thread with a hard timeout.
fn check_dns_inner(server_name: &str, check_domain: &str, exit_ip: &str) -> Result<()> {
    let check_host = format!("{}_exit.{}", server_name.to_lowercase(), check_domain);

    // Eddie: ForceResolve = checkDomain + ":" + IpsExit.OnlyIPv4.First
    // Bypass DNS for the check endpoint by resolving directly to the exit IP.
    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .resolve(
            &check_host,
            format!("{}:443", exit_ip).parse().map_err(|e| anyhow::anyhow!("invalid exit IP '{}': {}", exit_ip, e))?,
        )
        .build()
        .context("failed to build HTTP client for DNS check")?;

    let check_url = format!("https://{}/check/dns/", check_host);

    // Try up to 3 times (with the outer timeout as the real deadline).
    for attempt in 1..=3 {
        if attempt > 1 {
            std::thread::sleep(Duration::from_secs(1));
        }

        // Generate random token (Eddie: RandomGenerator.GetRandomToken())
        let hash = generate_random_token();

        // Resolve <hash>.<check_domain> via system DNS (goes through VPN tunnel).
        // We only need to trigger the DNS query -- the result doesn't matter.
        // The VPN server logs the hash from the query it receives.
        let dns_host = format!("{}.{}", hash, check_domain);
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&mut (dns_host.as_str(), 80));

        // Small delay to let the server process the DNS query
        std::thread::sleep(Duration::from_millis(500));

        // Now ask the check endpoint if it saw our hash
        match client.get(&check_url).send() {
            Ok(response) => {
                let body = match response.text() {
                    Ok(b) => b,
                    Err(_) => continue,
                };

                let json: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(_) => continue,
                };

                if let Some(dns_answer) = json.get("dns").and_then(|v| v.as_str()) {
                    if dns_answer == hash {
                        return Ok(());
                    }
                    // Hash mismatch -- DNS may not be going through VPN, try again
                }
            }
            Err(_) => continue,
        }
    }

    anyhow::bail!("DNS check failed after 3 attempts")
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

    #[test]
    fn test_generate_random_token_is_lowercase_hex() {
        let token = generate_random_token();
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
        // hex::encode produces lowercase
        assert_eq!(token, token.to_lowercase());
    }

    #[test]
    fn test_check_tunnel_timeout_on_bad_ip() {
        // With a non-routable exit IP, the check should time out (not hang).
        let start = std::time::Instant::now();
        let result = check_tunnel("TestServer", "10.0.0.1", "example.invalid", "192.0.2.1");
        let elapsed = start.elapsed();
        assert!(result.is_err());
        // Must complete within VERIFY_TIMEOUT + small margin (not hang forever)
        assert!(elapsed < VERIFY_TIMEOUT + Duration::from_secs(2),
            "tunnel check took {:?}, expected < {:?}", elapsed, VERIFY_TIMEOUT + Duration::from_secs(2));
    }

    #[test]
    fn test_check_dns_timeout_on_bad_ip() {
        // With a non-routable exit IP, the check should time out (not hang).
        let start = std::time::Instant::now();
        let result = check_dns("TestServer", "example.invalid", "192.0.2.1");
        let elapsed = start.elapsed();
        assert!(result.is_err());
        // Must complete within VERIFY_TIMEOUT + small margin (not hang forever)
        assert!(elapsed < VERIFY_TIMEOUT + Duration::from_secs(2),
            "DNS check took {:?}, expected < {:?}", elapsed, VERIFY_TIMEOUT + Duration::from_secs(2));
    }
}
