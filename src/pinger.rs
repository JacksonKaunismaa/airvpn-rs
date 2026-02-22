//! ICMP ping measurement for server latency scoring.
//!
//! Eddie measures per-server latency via ICMP ping and uses it in the
//! scoring formula. We use the `ping` command since raw ICMP requires
//! root (which we have) or CAP_NET_RAW.
//!
//! Reference: Eddie src/Lib.Core/Jobs/Latency.cs

use std::collections::HashMap;
use std::process::Command;

use log::warn;

/// Ping results for all servers.
pub struct PingResults {
    /// Server name -> latency in ms (-1 = not measured/failed)
    pub latencies: HashMap<String, i64>,
}

impl PingResults {
    pub fn new() -> Self {
        Self {
            latencies: HashMap::new(),
        }
    }

    /// Get latency for a server (-1 if not measured).
    pub fn get(&self, server_name: &str) -> i64 {
        *self.latencies.get(server_name).unwrap_or(&-1)
    }
}

/// Ping a single IP address, return latency in ms or None on failure.
///
/// Uses the system `ping` command with 1 packet, 3s timeout (Eddie default:
/// `pinger.timeout = 3000` i.e. 3000ms).
fn ping_ip(ip: &str) -> Option<u64> {
    let output = Command::new("ping")
        .args(["-c", "1", "-W", "3", "-q", ip])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Parse "rtt min/avg/max/mdev = 12.345/12.345/12.345/0.000 ms"
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("rtt") || line.contains("round-trip") {
            // Extract avg from "min/avg/max/mdev = X/Y/Z/W"
            if let Some(eq_pos) = line.find('=') {
                let values = line[eq_pos + 1..].trim();
                let parts: Vec<&str> = values.split('/').collect();
                if parts.len() >= 2 {
                    if let Ok(avg) = parts[1].trim().parse::<f64>() {
                        return Some(avg as u64);
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_results_new() {
        let pr = PingResults::new();
        assert_eq!(pr.get("any_server"), -1);
    }

    #[test]
    fn test_ping_results_get_existing() {
        let mut pr = PingResults::new();
        pr.latencies.insert("TestServer".to_string(), 42);
        assert_eq!(pr.get("TestServer"), 42);
    }

    #[test]
    fn test_ping_results_get_missing() {
        let pr = PingResults::new();
        assert_eq!(pr.get("NoSuchServer"), -1);
    }

    #[test]
    fn test_ping_results_negative_one_sentinel() {
        let mut pr = PingResults::new();
        pr.latencies.insert("FailedServer".to_string(), -1);
        assert_eq!(pr.get("FailedServer"), -1);
    }
}

/// Measure latency for all servers (pings first IPv4 entry IP of each).
///
/// This is a simplified version of Eddie's Latency job -- single ping per server,
/// no concurrency, no rolling average (since we only measure once before connecting).
///
/// Eddie pings `IpsEntry.FirstPreferIPv4` (Latency.cs line 75).
pub fn measure_all(servers: &[crate::manifest::Server]) -> PingResults {
    let mut results = PingResults::new();

    for server in servers {
        // Use first IPv4 entry IP (matching Eddie: IpsEntry.FirstPreferIPv4)
        let ip = server
            .ips_entry
            .iter()
            .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
            .or_else(|| server.ips_entry.first());

        if let Some(ip) = ip {
            // Validate IP address before passing to ping command to prevent
            // command injection via malicious manifest data.
            if ip.parse::<std::net::IpAddr>().is_err() {
                warn!("skipping invalid IP for server {}: {:?}", server.name, ip);
                results.latencies.insert(server.name.clone(), -1);
                continue;
            }
            match ping_ip(ip) {
                Some(ms) => {
                    results.latencies.insert(server.name.clone(), ms as i64);
                }
                None => {
                    results.latencies.insert(server.name.clone(), -1);
                }
            }
        } else {
            results.latencies.insert(server.name.clone(), -1);
        }
    }

    results
}
