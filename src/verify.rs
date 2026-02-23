//! Post-connection verification (tunnel + DNS checks).
//!
//! Eddie verifies the tunnel actually works after handshake by:
//! 1. HTTP GET to check endpoint, verifying exit IP matches VPN pool
//! 2. DNS resolution challenge to verify DNS goes through VPN:
//!    - Generate random hash token
//!    - Substitute into `check_dns_query` template from manifest (e.g. `{hash}.airvpn.org`)
//!    - Resolve via system DNS (goes through VPN's DNS post-connection)
//!    - GET `/check/dns/` endpoint and verify server saw the hash
//!
//! Both checks are best-effort with a hard 10-second overall timeout.
//! If they fail or time out, the caller should log a warning and continue.
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs:296-556

use anyhow::{Context, Result};
use log::{debug, warn};
use reqwest::blocking::Client;
use std::sync::mpsc;
use std::time::Duration;

/// Hard ceiling for each verification step (tunnel check, DNS check).
/// If the check hasn't succeeded within this window, we give up.
const VERIFY_TIMEOUT: Duration = Duration::from_secs(10);

/// Per-request timeout for HTTP calls. Must be shorter than VERIFY_TIMEOUT
/// so we have time for at least one retry.
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// Strip CIDR suffix (e.g. "/32") from an IP address string.
///
/// The manifest returns `wg_ipv4="10.167.32.97/32"` but the check server
/// returns `{"ip": "10.167.32.97"}` without the prefix length.
fn strip_cidr(ip: &str) -> &str {
    ip.split('/').next().unwrap_or(ip)
}

/// Split a check_domain that may contain a port (e.g. "airservers.org:89")
/// into (domain, port). Returns (domain, 443) if no port is specified.
fn split_domain_port(check_domain: &str) -> (&str, u16) {
    if let Some((domain, port_str)) = check_domain.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (domain, port);
        }
    }
    (check_domain, 443)
}

/// Verify the tunnel is working by checking exit IP.
///
/// Makes an HTTPS request through the tunnel to the provider's check endpoint
/// and verifies the returned IP is our assigned VPN IP.
///
/// Returns `Ok(())` on success, `Err` on timeout or verification failure.
/// The caller should treat errors as non-fatal warnings.
///
/// `check_domain` comes from the provider manifest (e.g. "airservers.org:89").
pub fn check_tunnel(server_name: &str, expected_ipv4: &str, check_domain: &str, exit_ip: &str, check_protocol: &str) -> Result<()> {
    let server_name = server_name.to_string();
    let expected_ipv4 = expected_ipv4.to_string();
    let check_domain = check_domain.to_string();
    let exit_ip = exit_ip.to_string();
    let check_protocol = check_protocol.to_string();

    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = check_tunnel_inner(&server_name, &expected_ipv4, &check_domain, &exit_ip, &check_protocol);
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
fn check_tunnel_inner(server_name: &str, expected_ipv4: &str, check_domain: &str, exit_ip: &str, check_protocol: &str) -> Result<()> {
    // Strip CIDR suffix: "10.167.32.97/32" -> "10.167.32.97"
    let expected_ip = strip_cidr(expected_ipv4);

    // Split "airservers.org:89" into ("airservers.org", 89)
    let (domain, port) = split_domain_port(check_domain);

    // Hostname for the check endpoint: "achernar_exit.airservers.org"
    let check_hostname = format!("{}_exit.{}", server_name.to_lowercase(), domain);

    // Eddie: ForceResolve = checkDomain + ":" + IpsExit.OnlyIPv4.First.Address
    // Bypass DNS for the check domain by resolving directly to the exit IP.
    // SECURITY (H4): Use system CA bundle for TLS verification.
    let resolve_addr = format!("{}:{}", exit_ip, port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid exit IP '{}' or port {}: {}", exit_ip, port, e))?;

    // Eddie uses check_protocol from the manifest (default "https").
    // We use HTTPS when available but don't force it — the check server
    // may only serve HTTP on its custom port.
    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .resolve(&check_hostname, resolve_addr)
        .build()
        .context("failed to build HTTP client for tunnel check")?;

    let url = format!("{}://{}:{}/check/tun/", check_protocol, check_hostname, port);
    debug!("Tunnel check URL: {}, expected_ip={} (raw={})", url, expected_ip, expected_ipv4);

    // Track last error for the final bail message.
    let mut last_error: Option<String> = None;

    // Try up to 3 times (with the outer timeout as the real deadline).
    for attempt in 1..=3 {
        if attempt > 1 {
            std::thread::sleep(Duration::from_secs(1));
        }

        match client.get(&url).send() {
            Ok(response) => {
                let status = response.status();
                let body = match response.text() {
                    Ok(b) => b,
                    Err(e) => {
                        last_error = Some(format!("attempt {}: failed to read response body: {}", attempt, e));
                        warn!("{}", last_error.as_ref().unwrap());
                        continue;
                    }
                };

                debug!("Tunnel check attempt {}: status={}, body={}", attempt, status, body);

                let json: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        last_error = Some(format!("attempt {}: invalid JSON: {} (body: {})", attempt, e, body));
                        warn!("{}", last_error.as_ref().unwrap());
                        continue;
                    }
                };

                if let Some(ip) = json.get("ip").and_then(|v| v.as_str()) {
                    if ip == expected_ip {
                        return Ok(());
                    }
                    anyhow::bail!(
                        "tunnel check failed: exit IP {} does not match expected {}",
                        ip,
                        expected_ip
                    );
                }

                last_error = Some(format!("attempt {}: response missing 'ip' field: {}", attempt, body));
                warn!("{}", last_error.as_ref().unwrap());
            }
            Err(e) => {
                last_error = Some(format!("attempt {}: request failed: {}", attempt, e));
                warn!("{}", last_error.as_ref().unwrap());
                continue;
            }
        }
    }

    anyhow::bail!("tunnel check failed after 3 attempts (last: {})",
        last_error.unwrap_or_else(|| "unknown".to_string()))
}

/// Verify DNS is routed through the VPN tunnel.
///
/// Eddie's protocol (Service.cs lines 497-536):
/// 1. Generate a random token (hash)
/// 2. Substitute the hash into the `check_dns_query` template from the manifest
///    (e.g. `{hash}.airvpn.org` becomes `a1b2c3d4.airvpn.org`)
/// 3. Resolve that domain via system DNS — which, post-connection, goes through
///    the VPN's DNS server. The server logs the hash from the query.
/// 4. GET `https://<server>_exit.<check_domain>/check/dns/` and verify the
///    server's `dns` field matches our hash.
///
/// Returns `Ok(())` on success, `Err` on timeout or verification failure.
/// The caller should treat errors as non-fatal warnings.
///
/// `check_domain` comes from the provider manifest (e.g. "airservers.org:89").
/// `check_dns_query` is the DNS query template (e.g. "{hash}.airvpn.org").
pub fn check_dns(server_name: &str, check_domain: &str, exit_ip: &str, check_dns_query: &str, check_protocol: &str) -> Result<()> {
    if check_dns_query.is_empty() {
        anyhow::bail!("DNS check skipped: manifest has no check_dns_query template");
    }

    let server_name = server_name.to_string();
    let check_domain = check_domain.to_string();
    let exit_ip = exit_ip.to_string();
    let check_dns_query = check_dns_query.to_string();
    let check_protocol = check_protocol.to_string();

    let (tx, rx) = mpsc::channel();

    std::thread::spawn(move || {
        let result = check_dns_inner(&server_name, &check_domain, &exit_ip, &check_dns_query, &check_protocol);
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
fn check_dns_inner(server_name: &str, check_domain: &str, exit_ip: &str, check_dns_query: &str, check_protocol: &str) -> Result<()> {
    // Split "airservers.org:89" into ("airservers.org", 89)
    let (domain, port) = split_domain_port(check_domain);

    // Hostname for the check endpoint: "achernar_exit.airservers.org"
    let check_hostname = format!("{}_exit.{}", server_name.to_lowercase(), domain);

    // Eddie: ForceResolve = checkDomain + ":" + IpsExit.OnlyIPv4.First
    // Bypass DNS for the check endpoint by resolving directly to the exit IP.
    // SECURITY (H4): Use system CA bundle for TLS verification.
    let resolve_addr = format!("{}:{}", exit_ip, port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid exit IP '{}' or port {}: {}", exit_ip, port, e))?;

    let client = Client::builder()
        .timeout(HTTP_TIMEOUT)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .resolve(&check_hostname, resolve_addr)
        .build()
        .context("failed to build HTTP client for DNS check")?;

    let check_url = format!("{}://{}:{}/check/dns/", check_protocol, check_hostname, port);
    debug!("DNS check URL: {}, query_template={}", check_url, check_dns_query);

    // Track last error for the final bail message.
    let mut last_error: Option<String> = None;

    // Try up to 3 times (with the outer timeout as the real deadline).
    for attempt in 1..=3 {
        if attempt > 1 {
            std::thread::sleep(Duration::from_secs(1));
        }

        // Generate random token (Eddie: RandomGenerator.GetRandomToken())
        let hash = generate_random_token();

        // Eddie: Service.cs line 501-503
        //   string dnsQuery = GetKeyValue("check_dns_query", "");
        //   string dnsHost = dnsQuery.Replace("{hash}", hash);
        //   IpAddresses result = DnsManager.ResolveDNS(dnsHost, true);
        //
        // Substitute hash into the template (e.g. "{hash}.airvpn.org" -> "a1b2c3.airvpn.org")
        // then resolve via system DNS. Post-connection, system DNS points at the VPN's DNS
        // server, which logs the hash from the query it receives.
        let dns_host = check_dns_query.replace("{hash}", &hash);
        debug!("DNS check attempt {}: resolving {} (hash={})", attempt, dns_host, hash);
        let _ = std::net::ToSocketAddrs::to_socket_addrs(&mut (dns_host.as_str(), 80));

        // Small delay to let the server process the DNS query
        std::thread::sleep(Duration::from_millis(500));

        // Now ask the check endpoint if it saw our hash
        match client.get(&check_url).send() {
            Ok(response) => {
                let status = response.status();
                let body = match response.text() {
                    Ok(b) => b,
                    Err(e) => {
                        last_error = Some(format!("attempt {}: failed to read response body: {}", attempt, e));
                        warn!("{}", last_error.as_ref().unwrap());
                        continue;
                    }
                };

                debug!("DNS check attempt {}: status={}, body={}", attempt, status, body);

                let json: serde_json::Value = match serde_json::from_str(&body) {
                    Ok(j) => j,
                    Err(e) => {
                        last_error = Some(format!("attempt {}: invalid JSON: {} (body: {})", attempt, e, body));
                        warn!("{}", last_error.as_ref().unwrap());
                        continue;
                    }
                };

                if let Some(dns_answer) = json.get("dns").and_then(|v| v.as_str()) {
                    if dns_answer == hash {
                        return Ok(());
                    }
                    // Hash mismatch -- DNS may not be going through VPN, try again
                    last_error = Some(format!("attempt {}: DNS hash mismatch: got {}, expected {}", attempt, dns_answer, hash));
                    warn!("{}", last_error.as_ref().unwrap());
                } else {
                    last_error = Some(format!("attempt {}: response missing 'dns' field: {}", attempt, body));
                    warn!("{}", last_error.as_ref().unwrap());
                }
            }
            Err(e) => {
                last_error = Some(format!("attempt {}: request failed: {}", attempt, e));
                warn!("{}", last_error.as_ref().unwrap());
                continue;
            }
        }
    }

    anyhow::bail!("DNS check failed after 3 attempts (last: {})",
        last_error.unwrap_or_else(|| "unknown".to_string()))
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
    fn test_strip_cidr_with_prefix() {
        assert_eq!(strip_cidr("10.167.32.97/32"), "10.167.32.97");
    }

    #[test]
    fn test_strip_cidr_without_prefix() {
        assert_eq!(strip_cidr("10.167.32.97"), "10.167.32.97");
    }

    #[test]
    fn test_strip_cidr_ipv6() {
        assert_eq!(strip_cidr("fd7d:76ee:e68f:a993::1196/128"), "fd7d:76ee:e68f:a993::1196");
    }

    #[test]
    fn test_split_domain_port_with_port() {
        assert_eq!(split_domain_port("airservers.org:89"), ("airservers.org", 89));
    }

    #[test]
    fn test_split_domain_port_without_port() {
        assert_eq!(split_domain_port("airvpn.org"), ("airvpn.org", 443));
    }

    #[test]
    fn test_split_domain_port_standard_https() {
        assert_eq!(split_domain_port("example.com:443"), ("example.com", 443));
    }

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
    fn test_check_tunnel_timeout_on_bad_ip_with_port() {
        // Same as above but with a port in check_domain.
        let start = std::time::Instant::now();
        let result = check_tunnel("TestServer", "10.0.0.1/32", "example.invalid:89", "192.0.2.1");
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(elapsed < VERIFY_TIMEOUT + Duration::from_secs(2),
            "tunnel check took {:?}, expected < {:?}", elapsed, VERIFY_TIMEOUT + Duration::from_secs(2));
    }

    #[test]
    fn test_check_dns_timeout_on_bad_ip() {
        // With a non-routable exit IP, the check should time out (not hang).
        let start = std::time::Instant::now();
        let result = check_dns("TestServer", "example.invalid", "192.0.2.1", "{hash}.example.invalid");
        let elapsed = start.elapsed();
        assert!(result.is_err());
        // Must complete within VERIFY_TIMEOUT + small margin (not hang forever)
        assert!(elapsed < VERIFY_TIMEOUT + Duration::from_secs(2),
            "DNS check took {:?}, expected < {:?}", elapsed, VERIFY_TIMEOUT + Duration::from_secs(2));
    }

    #[test]
    fn test_check_dns_timeout_on_bad_ip_with_port() {
        // Same as above but with a port in check_domain.
        let start = std::time::Instant::now();
        let result = check_dns("TestServer", "example.invalid:89", "192.0.2.1", "{hash}.example.invalid");
        let elapsed = start.elapsed();
        assert!(result.is_err());
        assert!(elapsed < VERIFY_TIMEOUT + Duration::from_secs(2),
            "DNS check took {:?}, expected < {:?}", elapsed, VERIFY_TIMEOUT + Duration::from_secs(2));
    }

    #[test]
    fn test_check_dns_empty_query_template() {
        // Empty check_dns_query should bail immediately, not hang.
        let result = check_dns("TestServer", "example.invalid", "192.0.2.1", "");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no check_dns_query"));
    }
}
