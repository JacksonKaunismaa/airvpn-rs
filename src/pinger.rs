//! ICMP ping measurement for server latency scoring.
//!
//! Eddie measures per-server latency via ICMP ping and uses it in the
//! scoring formula. We use the `ping` command since raw ICMP requires
//! root (which we have) or CAP_NET_RAW.
//!
//! Reference: Eddie src/Lib.Core/Jobs/Latency.cs

use std::collections::HashMap;
use std::process::Command;

use log::info;

/// Ping results for all servers.
#[derive(Default)]
pub struct PingResults {
    /// Server name -> latency in ms (-1 = not measured/failed)
    pub latencies: HashMap<String, i64>,
}

impl PingResults {
    pub fn new() -> Self {
        Self::default()
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

    #[test]
    fn test_median_ping_all_success() {
        // Three successful pings: 10, 20, 15 → sorted: 10, 15, 20 → median = 15
        let rounds = vec![Some(10), Some(20), Some(15)];
        assert_eq!(median_ping(&rounds), Some(15));
    }

    #[test]
    fn test_median_ping_one_failure() {
        // Two successes + one failure → use median of successes
        let rounds = vec![Some(10), None, Some(30)];
        assert_eq!(median_ping(&rounds), Some(30));
    }

    #[test]
    fn test_median_ping_two_failures() {
        // Two failures → too unreliable, return None
        let rounds = vec![None, Some(10), None];
        assert_eq!(median_ping(&rounds), None);
    }

    #[test]
    fn test_median_ping_all_failures() {
        let rounds = vec![None, None, None];
        assert_eq!(median_ping(&rounds), None);
    }

    #[test]
    fn test_median_ping_identical_values() {
        let rounds = vec![Some(42), Some(42), Some(42)];
        assert_eq!(median_ping(&rounds), Some(42));
    }

    #[test]
    fn test_median_ping_sorted_already() {
        let rounds = vec![Some(1), Some(2), Some(3)];
        assert_eq!(median_ping(&rounds), Some(2));
    }

    #[test]
    fn test_median_ping_reverse_sorted() {
        let rounds = vec![Some(100), Some(50), Some(10)];
        assert_eq!(median_ping(&rounds), Some(50));
    }
}

/// Number of ping rounds per server for median calculation.
/// Multiple rounds resist ICMP spoofing — a single spoofed reply can't
/// dominate the median.
const PING_ROUNDS: usize = 3;

/// Compute the median of successful pings. If the majority failed, returns None.
///
/// Rules:
/// - If 2 or more pings failed (out of 3), return None (too unreliable).
/// - Otherwise sort the successful values and return the middle one.
fn median_ping(results: &[Option<u64>]) -> Option<u64> {
    let mut successes: Vec<u64> = results.iter().filter_map(|r| *r).collect();
    let fail_count = results.len() - successes.len();
    if fail_count >= 2 {
        return None;
    }
    successes.sort_unstable();
    if successes.is_empty() {
        return None;
    }
    Some(successes[successes.len() / 2])
}

/// Measure latency for all servers (pings first IPv4 entry IP of each).
///
/// Each server is pinged [PING_ROUNDS] times and the median is used to resist
/// ICMP spoofing. If the majority of pings fail, the server is marked as -1.
///
/// Eddie pings `IpsEntry.FirstPreferIPv4` (Latency.cs line 75).
pub fn measure_all(servers: &[crate::manifest::Server]) -> PingResults {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    let total = servers.len();
    let completed = Arc::new(AtomicUsize::new(0));

    // Spawn a thread per server. Each thread does PING_ROUNDS sequential pings
    // and returns (server_name, latency_ms). All servers ping in parallel.
    let handles: Vec<_> = servers
        .iter()
        .map(|server| {
            let name = server.name.clone();
            let ip = server
                .ips_entry
                .iter()
                .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                .or_else(|| server.ips_entry.first())
                .cloned();
            let completed = Arc::clone(&completed);

            thread::spawn(move || {
                let latency = match ip {
                    Some(ref ip) if ip.parse::<std::net::IpAddr>().is_ok() => {
                        let rounds: Vec<Option<u64>> =
                            (0..PING_ROUNDS).map(|_| ping_ip(ip)).collect();
                        match median_ping(&rounds) {
                            Some(ms) => ms as i64,
                            None => -1,
                        }
                    }
                    _ => -1,
                };

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if done % 50 == 0 || done == total {
                    info!("Ping progress: {}/{}", done, total);
                }

                (name, latency)
            })
        })
        .collect();

    let mut results = PingResults::new();
    for handle in handles {
        if let Ok((name, latency)) = handle.join() {
            results.latencies.insert(name, latency);
        }
    }

    results
}
