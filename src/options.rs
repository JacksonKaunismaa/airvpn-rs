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

// Network
pub const NETWORK_IPV6_MODE: &str = "network.ipv6.mode";
pub const DNS_SERVERS: &str = "dns.servers";

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
    // Network
    OptionDef { name: NETWORK_IPV6_MODE, default: "in-block", description: "IPv6 mode: in, in-block, or block" },
    OptionDef { name: DNS_SERVERS, default: "", description: "Custom DNS servers (comma-separated IPs)" },
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
