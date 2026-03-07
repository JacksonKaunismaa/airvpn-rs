//! ICMP ping measurement for server latency scoring.
//!
//! Eddie measures per-server latency via ICMP ping and uses it in the
//! scoring formula. We use the `ping` command since raw ICMP requires
//! root (which we have) or CAP_NET_RAW.
//!
//! Latency values are smoothed with EWMA (α=0.3) so that transient
//! spikes don't dominate server selection. The cache is persisted to
//! disk so latency data survives daemon restarts.
//!
//! Reference: Eddie src/Lib.Core/Jobs/Latency.cs

use std::collections::HashMap;
use std::process::Command;

use log::{info, warn};
use serde::{Deserialize, Serialize};

/// EWMA smoothing factor. Higher values weight new samples more heavily.
const ALPHA: f64 = 0.3;

/// Default filesystem path for the persisted latency cache.
pub const LATENCY_CACHE_PATH: &str = "/var/lib/airvpn-rs/latency.json";

/// EWMA-smoothed latency cache for all servers.
///
/// Each server's latency is tracked as an exponentially weighted moving
/// average. The cache also stores the entry IP for each server so the
/// background pinger knows which IPs to allowlist.
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct LatencyCache {
    ewma: HashMap<String, f64>,
    server_ips: HashMap<String, String>,
}

impl LatencyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a new latency sample for `name`. First sample seeds directly;
    /// subsequent samples are blended: `α * new + (1-α) * old`.
    pub fn update(&mut self, name: &str, sample_ms: i64) {
        let sample = sample_ms as f64;
        let smoothed = match self.ewma.get(name) {
            Some(&old) => ALPHA * sample + (1.0 - ALPHA) * old,
            None => sample,
        };
        self.ewma.insert(name.to_string(), smoothed);
    }

    /// Record a failed ping. Keeps stale EWMA if one exists (better than
    /// nothing); no-op if the server was never measured.
    pub fn update_failed(&mut self, _name: &str) {
        // Intentionally a no-op: stale data > no data.
    }

    /// Get the smoothed latency for a server, rounded to the nearest
    /// millisecond. Returns -1 if the server has never been measured.
    pub fn get(&self, server_name: &str) -> i64 {
        match self.ewma.get(server_name) {
            Some(&v) => v.round() as i64,
            None => -1,
        }
    }

    /// Number of servers with measured latency.
    pub fn len(&self) -> usize {
        self.ewma.len()
    }

    /// True if the cache contains at least one measured server.
    pub fn has_data(&self) -> bool {
        !self.ewma.is_empty()
    }

    /// Store the name→entry-IP mapping for all servers.
    pub fn set_server_ips(&mut self, pairs: Vec<(String, String)>) {
        self.server_ips = pairs.into_iter().collect();
    }

    /// Get the entry IP for a specific server.
    pub fn server_ip(&self, name: &str) -> Option<&str> {
        self.server_ips.get(name).map(|s| s.as_str())
    }

    /// All unique entry IPs (for firewall allowlisting).
    pub fn all_entry_ips(&self) -> Vec<&str> {
        self.server_ips.values().map(|s| s.as_str()).collect()
    }

    /// All (name, entry_ip) pairs for the background pinger.
    pub fn server_ips(&self) -> &HashMap<String, String> {
        &self.server_ips
    }

    /// Persist the cache to a JSON file.
    pub fn save(&self, path: &str) -> anyhow::Result<()> {
        let parent = std::path::Path::new(path).parent();
        if let Some(dir) = parent {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load the cache from a JSON file. Returns `Default` on any error
    /// (missing file, corrupt JSON) — stale cache is optional, not critical.
    pub fn load(path: &str) -> Self {
        match std::fs::read_to_string(path) {
            Ok(json) => match serde_json::from_str(&json) {
                Ok(cache) => cache,
                Err(e) => {
                    warn!("Corrupt latency cache at {path}: {e}");
                    Self::default()
                }
            },
            Err(_) => Self::default(),
        }
    }
}

/// Ping an IP via the default route (host routes send it through physical NIC).
fn ping_ip(ip: &str) -> Option<u64> {
    let mut cmd = Command::new("ping");
    cmd.args(["-c", "1", "-W", "3", "-q"]);
    cmd.arg(ip);
    let output = cmd.output().ok()?;

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

    // ---------------------------------------------------------------
    // LatencyCache EWMA tests
    // ---------------------------------------------------------------

    #[test]
    fn test_ewma_first_sample_seeds_directly() {
        let mut cache = LatencyCache::new();
        cache.update("Alpha", 100);
        assert_eq!(cache.get("Alpha"), 100);
    }

    #[test]
    fn test_ewma_blends_subsequent_samples() {
        let mut cache = LatencyCache::new();
        cache.update("Alpha", 100);
        cache.update("Alpha", 200);
        // Expected: 0.3 * 200 + 0.7 * 100 = 60 + 70 = 130
        assert_eq!(cache.get("Alpha"), 130);
    }

    #[test]
    fn test_ewma_three_samples() {
        let mut cache = LatencyCache::new();
        cache.update("A", 100);
        cache.update("A", 200); // 0.3*200 + 0.7*100 = 130
        cache.update("A", 50);  // 0.3*50 + 0.7*130 = 15 + 91 = 106
        assert_eq!(cache.get("A"), 106);
    }

    #[test]
    fn test_get_unmeasured_returns_negative_one() {
        let cache = LatencyCache::new();
        assert_eq!(cache.get("NoSuchServer"), -1);
    }

    #[test]
    fn test_update_failed_preserves_stale_data() {
        let mut cache = LatencyCache::new();
        cache.update("Alpha", 50);
        cache.update_failed("Alpha");
        assert_eq!(cache.get("Alpha"), 50);
    }

    #[test]
    fn test_update_failed_noop_for_unknown() {
        let mut cache = LatencyCache::new();
        cache.update_failed("Unknown");
        assert_eq!(cache.get("Unknown"), -1);
    }

    #[test]
    fn test_has_data() {
        let mut cache = LatencyCache::new();
        assert!(!cache.has_data());
        cache.update("A", 10);
        assert!(cache.has_data());
    }

    #[test]
    fn test_server_ips() {
        let mut cache = LatencyCache::new();
        cache.set_server_ips(vec![
            ("A".into(), "1.2.3.4".into()),
            ("B".into(), "5.6.7.8".into()),
        ]);
        assert_eq!(cache.server_ip("A"), Some("1.2.3.4"));
        assert_eq!(cache.server_ip("C"), None);
        let ips = cache.all_entry_ips();
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn test_persistence_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("latency.json");
        let path_str = path.to_str().unwrap();

        let mut cache = LatencyCache::new();
        cache.update("Alpha", 42);
        cache.update("Beta", 100);
        cache.update("Beta", 200); // blended
        cache.set_server_ips(vec![("Alpha".into(), "1.2.3.4".into())]);
        cache.save(path_str).unwrap();

        let loaded = LatencyCache::load(path_str);
        assert_eq!(loaded.get("Alpha"), 42);
        assert_eq!(loaded.get("Beta"), cache.get("Beta"));
        assert_eq!(loaded.server_ip("Alpha"), Some("1.2.3.4"));
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let cache = LatencyCache::load("/tmp/nonexistent_latency_cache_test.json");
        assert!(!cache.has_data());
    }

    #[test]
    fn test_load_corrupt_json_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.json");
        std::fs::write(&path, "not json at all").unwrap();
        let cache = LatencyCache::load(path.to_str().unwrap());
        assert!(!cache.has_data());
    }
}

/// Measure latency for a list of (name, ip) pairs.
///
/// Used by the background pinger which already has extracted IPs from the
/// LatencyCache. Returns `Vec<(name, latency_ms)>` where latency is -1 on
/// failure. All servers are pinged in parallel via host routes (physical NIC).
/// EWMA smoothing handles outliers across cycles.
pub fn measure_all_from_ips(
    pairs: &[(String, String)],
) -> Vec<(String, i64)> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    let total = pairs.len();
    if total == 0 {
        return Vec::new();
    }

    let completed = Arc::new(AtomicUsize::new(0));

    let handles: Vec<_> = pairs
        .iter()
        .map(|(name, ip)| {
            let name = name.clone();
            let ip = ip.clone();
            let completed = Arc::clone(&completed);

            thread::spawn(move || {
                let latency = match ping_ip(&ip) {
                    Some(ms) => ms as i64,
                    None => -1,
                };

                let done = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if done % 50 == 0 || done == total {
                    info!("Ping cycle progress: {}/{}", done, total);
                }

                (name, latency)
            })
        })
        .collect();

    let mut results = Vec::with_capacity(total);
    for handle in handles {
        if let Ok(pair) = handle.join() {
            results.push(pair);
        }
    }
    results
}

/// Measure latency for all servers (pings first IPv4 entry IP of each).
///
/// One-shot fallback for `/servers` when background pinger has no data yet.
/// Eddie pings `IpsEntry.FirstPreferIPv4` (Latency.cs line 75).
pub fn measure_all(servers: &[crate::manifest::Server]) -> LatencyCache {
    // Extract (name, ip) pairs — prefer first IPv4, fall back to first entry IP.
    let pairs: Vec<(String, String)> = servers
        .iter()
        .filter_map(|server| {
            let ip = server
                .ips_entry
                .iter()
                .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                .or_else(|| server.ips_entry.first())
                .cloned()?;
            if ip.parse::<std::net::IpAddr>().is_ok() {
                Some((server.name.clone(), ip))
            } else {
                None
            }
        })
        .collect();

    let results = measure_all_from_ips(&pairs);

    let mut cache = LatencyCache::new();
    for (name, latency) in &results {
        if *latency >= 0 {
            cache.update(name, *latency);
        } else {
            cache.update_failed(name);
        }
    }

    cache
}
