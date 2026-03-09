//! Unified option registry with defaults and layered resolution.
//!
//! Options flow through three layers (lowest to highest priority):
//!   1. Registry defaults (compiled-in)
//!   2. Profile values (persisted in user's profile)
//!   3. Overrides (CLI flags, ConnectRequest fields)
//!
//! The `resolve()` function merges all three layers into a single HashMap.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Option name constants
// ---------------------------------------------------------------------------

// Connection
pub const NETLOCK: &str = "netlock";
pub const NETLOCK_ALLOW_PRIVATE: &str = "netlock.allow_private";
pub const RECONNECT: &str = "reconnect";
pub const VERIFY: &str = "verify";
pub const CONNECTIONS_ALLOW_ANYWAY: &str = "connections.allow_anyway";

// Server selection
pub const SERVER: &str = "server";
pub const SERVERS_ALLOWLIST: &str = "servers.allowlist";
pub const SERVERS_DENYLIST: &str = "servers.denylist";
pub const AREAS_ALLOWLIST: &str = "areas.allowlist";
pub const AREAS_DENYLIST: &str = "areas.denylist";
pub const SERVERS_LOCKLAST: &str = "servers.locklast";
pub const SERVERS_STARTLAST: &str = "servers.startlast";
pub const SERVERS_LAST: &str = "servers.last";
pub const SERVERS_SCORETYPE: &str = "servers.scoretype";

// WireGuard
pub const KEY: &str = "key";
pub const WG_MTU: &str = "wireguard.interface.mtu";
pub const WG_KEEPALIVE: &str = "wireguard.peer.persistentkeepalive";
pub const WG_HANDSHAKE_FIRST: &str = "wireguard.handshake.timeout.first";
pub const WG_HANDSHAKE_CONNECTED: &str = "wireguard.handshake.timeout.connected";

// Network Lock
pub const NETLOCK_INCOMING: &str = "netlock.incoming";
pub const NETLOCK_ALLOW_PING: &str = "netlock.allow_ping";

// Network
pub const NETWORK_IFACE_NAME: &str = "network.iface.name";
pub const NETWORK_ENTRY_IPLAYER: &str = "network.entry.iplayer";
pub const NETWORK_IPV6_MODE: &str = "network.ipv6.mode";
pub const DNS_SERVERS: &str = "dns.servers";

// Scoring
pub const SCORING_PENALITY_FACTOR: &str = "scoring.penality_factor";
pub const SERVERS_CAPACITY_FACTOR: &str = "servers.capacity_factor";

// Advanced / Pinger
pub const PINGER_TIMEOUT: &str = "pinger.timeout";
pub const PINGER_ENABLED: &str = "pinger.enabled";
pub const PINGER_JOBS: &str = "pinger.jobs";
pub const MANIFEST_REFRESH: &str = "advanced.manifest.refresh";
pub const PENALITY_ON_ERROR: &str = "advanced.penality_on_error";
pub const HTTP_TIMEOUT: &str = "http.timeout";
pub const CHECKING_NTRY: &str = "checking.ntry";

// ---------------------------------------------------------------------------
// Option registry
// ---------------------------------------------------------------------------

pub struct OptionDef {
    pub name: &'static str,
    pub default: &'static str,
    pub description: &'static str,
}

pub static REGISTRY: &[OptionDef] = &[
    // Connection
    OptionDef { name: NETLOCK, default: "true", description: "Enable network lock (kill switch)" },
    OptionDef { name: NETLOCK_ALLOW_PRIVATE, default: "true", description: "Allow LAN traffic through lock" },
    OptionDef { name: RECONNECT, default: "true", description: "Auto-reconnect on disconnect" },
    OptionDef { name: VERIFY, default: "true", description: "Verify tunnel and DNS after connect" },
    OptionDef { name: CONNECTIONS_ALLOW_ANYWAY, default: "false", description: "Allow connection even when account has warnings (e.g. expired)" },
    // Server selection
    OptionDef { name: SERVER, default: "", description: "Server name (auto-select if empty)" },
    OptionDef { name: SERVERS_ALLOWLIST, default: "", description: "Only connect to these servers (comma-separated)" },
    OptionDef { name: SERVERS_DENYLIST, default: "", description: "Never connect to these servers (comma-separated)" },
    OptionDef { name: AREAS_ALLOWLIST, default: "", description: "Only connect to servers in these countries (comma-separated 2-letter codes)" },
    OptionDef { name: AREAS_DENYLIST, default: "", description: "Never connect to these countries (comma-separated)" },
    OptionDef { name: SERVERS_LOCKLAST, default: "false", description: "Lock to same server during session" },
    OptionDef { name: SERVERS_STARTLAST, default: "false", description: "Resume last-used server on startup" },
    OptionDef { name: SERVERS_LAST, default: "", description: "SHA256 hash of last-used server name" },
    OptionDef { name: SERVERS_SCORETYPE, default: "Speed", description: "Server scoring mode: Speed or Latency" },
    // WireGuard
    OptionDef { name: KEY, default: "Default", description: "WireGuard device/key name (Eddie: key)" },
    OptionDef { name: WG_MTU, default: "1320", description: "MTU for the WireGuard interface" },
    OptionDef { name: WG_KEEPALIVE, default: "15", description: "WireGuard PersistentKeepalive interval (seconds)" },
    OptionDef { name: WG_HANDSHAKE_FIRST, default: "50", description: "Timeout for initial WireGuard handshake (seconds)" },
    OptionDef { name: WG_HANDSHAKE_CONNECTED, default: "200", description: "Max age of handshake before treating tunnel as dead (seconds)" },
    // Network Lock
    OptionDef { name: NETLOCK_INCOMING, default: "block", description: "Incoming policy: block or allow" },
    OptionDef { name: NETLOCK_ALLOW_PING, default: "true", description: "Allow ICMP ping through the lock" },
    // Network
    OptionDef { name: NETWORK_IFACE_NAME, default: "avpn0", description: "WireGuard interface name" },
    OptionDef { name: NETWORK_ENTRY_IPLAYER, default: "ipv4", description: "Preferred entry IP layer: ipv4 or ipv6" },
    OptionDef { name: NETWORK_IPV6_MODE, default: "in-block", description: "IPv6 mode: in, in-block, or block" },
    OptionDef { name: DNS_SERVERS, default: "", description: "Custom DNS servers (comma-separated IPs)" },
    // Scoring
    OptionDef { name: SCORING_PENALITY_FACTOR, default: "1000", description: "Multiplier for server penalties in scoring" },
    OptionDef { name: SERVERS_CAPACITY_FACTOR, default: "0", description: "Capacity weighting factor (0 = disabled). Higher values prefer high-bandwidth servers" },
    // Advanced / Pinger
    OptionDef { name: PINGER_TIMEOUT, default: "3", description: "ICMP ping timeout per server (seconds)" },
    OptionDef { name: PINGER_ENABLED, default: "true", description: "Enable background latency pinger" },
    OptionDef { name: PINGER_JOBS, default: "25", description: "Max concurrent ping jobs" },
    OptionDef { name: MANIFEST_REFRESH, default: "1800", description: "Manifest refresh interval (seconds)" },
    OptionDef { name: PENALITY_ON_ERROR, default: "30", description: "Penalty added to server score on connection error" },
    OptionDef { name: HTTP_TIMEOUT, default: "10", description: "HTTP request timeout for API calls (seconds)" },
    OptionDef { name: CHECKING_NTRY, default: "3", description: "Number of retries for tunnel/DNS verification" },
];

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// Build defaults from the registry.
pub fn defaults() -> HashMap<String, String> {
    REGISTRY
        .iter()
        .map(|opt| (opt.name.to_string(), opt.default.to_string()))
        .collect()
}

/// Resolve options: defaults -> profile -> overrides.
///
/// Profile values overlay defaults. Overrides overlay profile.
/// An empty override string is treated as "not set" (keeps the default/profile value).
pub fn resolve(
    profile: &HashMap<String, String>,
    overrides: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut resolved = defaults();
    for (k, v) in profile {
        resolved.insert(k.clone(), v.clone());
    }
    for (k, v) in overrides {
        if !v.is_empty() {
            resolved.insert(k.clone(), v.clone());
        }
    }
    resolved
}

// ---------------------------------------------------------------------------
// Typed getters
// ---------------------------------------------------------------------------

/// Get a boolean option. "true" (case-insensitive) = true, everything else = false.
pub fn get_bool(options: &HashMap<String, String>, key: &str) -> bool {
    options
        .get(key)
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Get a string option. Returns empty string if missing.
pub fn get_str<'a>(options: &'a HashMap<String, String>, key: &str) -> &'a str {
    options.get(key).map(|s| s.as_str()).unwrap_or("")
}

/// Get a u64 option. Returns 0 if missing or unparseable.
pub fn get_u64(options: &HashMap<String, String>, key: &str) -> u64 {
    options
        .get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Get an i64 option. Returns 0 if missing or unparseable.
pub fn get_i64(options: &HashMap<String, String>, key: &str) -> i64 {
    options
        .get(key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Get a comma-separated list option as `Vec<String>`.
/// Empty/missing values return an empty vec.
pub fn get_list(options: &HashMap<String, String>, key: &str) -> Vec<String> {
    options
        .get(key)
        .filter(|v| !v.is_empty())
        .map(|v| v.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_contain_all_registry_entries() {
        let d = defaults();
        for opt in REGISTRY {
            assert!(
                d.contains_key(opt.name),
                "missing default for {:?}",
                opt.name
            );
            assert_eq!(d[opt.name], opt.default);
        }
    }

    #[test]
    fn resolve_layers_correctly() {
        let profile: HashMap<String, String> =
            [(NETLOCK.into(), "false".into())].into_iter().collect();
        let overrides: HashMap<String, String> =
            [(NETLOCK.into(), "true".into())].into_iter().collect();

        let opts = resolve(&profile, &overrides);
        // Override wins over profile
        assert_eq!(opts[NETLOCK], "true");
    }

    #[test]
    fn empty_override_does_not_clobber() {
        let profile: HashMap<String, String> =
            [(SERVER.into(), "Castor".into())].into_iter().collect();
        let overrides: HashMap<String, String> =
            [(SERVER.into(), String::new())].into_iter().collect();

        let opts = resolve(&profile, &overrides);
        assert_eq!(opts[SERVER], "Castor");
    }

    #[test]
    fn get_bool_case_insensitive() {
        let opts: HashMap<String, String> = [
            ("a".into(), "true".into()),
            ("b".into(), "True".into()),
            ("c".into(), "TRUE".into()),
            ("d".into(), "false".into()),
            ("e".into(), "yes".into()),
        ]
        .into_iter()
        .collect();

        assert!(get_bool(&opts, "a"));
        assert!(get_bool(&opts, "b"));
        assert!(get_bool(&opts, "c"));
        assert!(!get_bool(&opts, "d"));
        assert!(!get_bool(&opts, "e"));
        assert!(!get_bool(&opts, "missing"));
    }

    #[test]
    fn get_str_returns_value_or_empty() {
        let opts: HashMap<String, String> =
            [("k".into(), "val".into())].into_iter().collect();
        assert_eq!(get_str(&opts, "k"), "val");
        assert_eq!(get_str(&opts, "missing"), "");
    }

    #[test]
    fn get_list_splits_and_trims() {
        let opts: HashMap<String, String> =
            [("servers".into(), " a , b , c ".into())].into_iter().collect();
        assert_eq!(get_list(&opts, "servers"), vec!["a", "b", "c"]);
        assert!(get_list(&opts, "missing").is_empty());
    }

    #[test]
    fn get_list_empty_value_returns_empty_vec() {
        let opts: HashMap<String, String> =
            [("k".into(), String::new())].into_iter().collect();
        assert!(get_list(&opts, "k").is_empty());
    }
}
