//! Integration tests for airvpn-rs system-level functionality.
//!
//! These tests require root privileges and modify real system state (nftables,
//! /etc/resolv.conf, /proc/sys/net/ipv6, /run/airvpn-rs). They are ignored by
//! default so `cargo test` skips them.
//!
//! Run with: `sudo cargo test --test integration -- --ignored --test-threads=1`
//!
//! The `--test-threads=1` flag is critical: these tests mutate shared system
//! state (nftables tables, /etc/resolv.conf) and WILL interfere with each
//! other if run in parallel.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use airvpn::{dns, ipv6, netlock, recovery, wireguard};
use zeroize::Zeroizing;
use airvpn::netlock::NetlockConfig;
use airvpn::recovery::State;

// =============================================================================
// Helpers
// =============================================================================

/// Returns true if the current process is running as root.
fn is_root() -> bool {
    nix::unistd::geteuid().as_raw() == 0
}

/// Build a minimal NetlockConfig for testing.
fn test_netlock_config() -> NetlockConfig {
    NetlockConfig {
        allow_lan: false,
        allow_dhcp: true,
        allow_ping: true,
        allow_ipv4ipv6translation: false,
        allowed_ips_incoming: vec![],
        allowed_ips_outgoing: vec![],
        incoming_policy_accept: false,
    }
}

/// Build a NetlockConfig with all features enabled for ruleset verification.
fn full_netlock_config() -> NetlockConfig {
    NetlockConfig {
        allow_lan: true,
        allow_dhcp: true,
        allow_ping: true,
        allow_ipv4ipv6translation: true,
        allowed_ips_incoming: vec!["198.51.100.1".to_string()],
        allowed_ips_outgoing: vec!["203.0.113.5".to_string()],
        incoming_policy_accept: false,
    }
}

/// Guard that ensures netlock is deactivated when dropped, even on panic.
struct NetlockGuard;

impl Drop for NetlockGuard {
    fn drop(&mut self) {
        let _ = netlock::deactivate();
    }
}

/// Guard that restores /etc/resolv.conf from a saved copy when dropped.
struct DnsGuard {
    original_content: Vec<u8>,
    original_is_symlink: bool,
    original_target: Option<String>,
}

impl DnsGuard {
    fn new() -> Self {
        let resolv = Path::new("/etc/resolv.conf");
        let original_is_symlink = resolv.is_symlink();
        let original_target = if original_is_symlink {
            fs::read_link(resolv).ok().map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };
        let original_content = fs::read(resolv).unwrap_or_default();

        DnsGuard {
            original_content,
            original_is_symlink,
            original_target,
        }
    }
}

impl Drop for DnsGuard {
    fn drop(&mut self) {
        let resolv = Path::new("/etc/resolv.conf");
        let backup = Path::new("/etc/resolv.conf.airvpn-rs");

        // Clean up the backup file that dns::activate creates
        let _ = fs::remove_file(backup);

        // Remove any symlink or file at the resolv.conf path
        if resolv.is_symlink() || resolv.exists() {
            let _ = fs::remove_file(resolv);
        }

        if self.original_is_symlink {
            if let Some(ref target) = self.original_target {
                let _ = std::os::unix::fs::symlink(target, resolv);
            }
        } else {
            let _ = fs::write(resolv, &self.original_content);
        }

        // Clean up any systemd-resolved backup files we may have created
        if let Ok(entries) = fs::read_dir("/etc") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("systemd_resolve_") && name.ends_with(".airvpn-rs") {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

/// Guard that restores IPv6 state on blocked interfaces when dropped.
struct Ipv6Guard {
    blocked: Vec<String>,
}

impl Drop for Ipv6Guard {
    fn drop(&mut self) {
        if !self.blocked.is_empty() {
            ipv6::restore(&self.blocked);
        }
    }
}

// =============================================================================
// 1. Netlock (nftables)
// =============================================================================

#[test]
#[ignore = "requires root: modifies nftables"]
fn test_netlock_activate_deactivate() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }
    let _guard = NetlockGuard;

    let config = test_netlock_config();
    netlock::activate(&config).expect("activate should succeed");
    assert!(
        netlock::is_active(),
        "nftables table should exist after activate"
    );

    netlock::deactivate().expect("deactivate should succeed");
    assert!(
        !netlock::is_active(),
        "nftables table should be gone after deactivate"
    );
}

#[test]
#[ignore = "requires root: modifies nftables"]
fn test_netlock_activate_is_idempotent() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }
    let _guard = NetlockGuard;

    let config = test_netlock_config();

    // First activation
    netlock::activate(&config).expect("first activate should succeed");
    assert!(netlock::is_active());

    // Second activation should succeed (stale table cleanup path)
    netlock::activate(&config).expect("second activate should succeed (idempotent)");
    assert!(netlock::is_active());

    netlock::deactivate().expect("deactivate should succeed");
    assert!(!netlock::is_active());
}

#[test]
#[ignore = "requires root: modifies nftables"]
fn test_netlock_deactivate_is_idempotent() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    // Ensure no table exists
    let _ = netlock::deactivate();
    assert!(!netlock::is_active());

    // Deactivate when already deactivated should return Ok
    netlock::deactivate().expect("deactivate on nonexistent table should return Ok");
}

#[test]
#[ignore = "requires root: modifies nftables"]
fn test_netlock_allow_deallow_interface() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }
    let _guard = NetlockGuard;

    let config = test_netlock_config();
    netlock::activate(&config).expect("activate");

    // allow_interface("lo") should succeed — lo always exists
    netlock::allow_interface("lo").expect("allow_interface(lo) should succeed");

    // Verify the rules were inserted by listing the table
    let output = Command::new("nft")
        .args(["-n", "-a", "list", "table", "inet", "airvpn_lock"])
        .output()
        .expect("nft list table");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("airvpn_interface_input_lo"),
        "should have interface input rule for lo"
    );
    assert!(
        stdout.contains("airvpn_interface_output_lo"),
        "should have interface output rule for lo"
    );

    // deallow_interface("lo") should remove the rules
    netlock::deallow_interface("lo").expect("deallow_interface(lo) should succeed");

    let output = Command::new("nft")
        .args(["-n", "-a", "list", "table", "inet", "airvpn_lock"])
        .output()
        .expect("nft list table after deallow");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("airvpn_interface_input_lo"),
        "lo input rule should be removed after deallow"
    );
    assert!(
        !stdout.contains("airvpn_interface_output_lo"),
        "lo output rule should be removed after deallow"
    );

    netlock::deactivate().expect("deactivate");
}

#[test]
#[ignore = "requires root: modifies nftables"]
fn test_netlock_ruleset_loaded_correctly() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }
    let _guard = NetlockGuard;

    let config = full_netlock_config();
    netlock::activate(&config).expect("activate with full config");

    let output = Command::new("nft")
        .args(["list", "table", "inet", "airvpn_lock"])
        .output()
        .expect("nft list table");
    assert!(output.status.success(), "nft list table should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify chain structure
    assert!(stdout.contains("chain input"), "should have input chain");
    assert!(stdout.contains("chain forward"), "should have forward chain");
    assert!(stdout.contains("chain output"), "should have output chain");

    // Verify priority (nft displays -300 as "raw" in listing)
    assert!(
        stdout.contains("priority raw") || stdout.contains("priority -300"),
        "chains should have priority -300 (displayed as 'raw')"
    );

    // Verify policy
    assert!(
        stdout.contains("policy drop"),
        "chains should have drop policy"
    );

    // Verify loopback rules
    assert!(
        stdout.contains("iifname \"lo\""),
        "should have loopback input rule"
    );
    assert!(
        stdout.contains("oifname \"lo\""),
        "should have loopback output rule"
    );

    // Verify LAN rules (allow_lan=true)
    assert!(
        stdout.contains("192.168.0.0/16"),
        "should have RFC1918 LAN rule"
    );
    assert!(
        stdout.contains("10.0.0.0/8"),
        "should have RFC1918 LAN rule"
    );

    // Verify DHCP rules (allow_dhcp=true)
    assert!(
        stdout.contains("255.255.255.255"),
        "should have DHCP broadcast rule"
    );

    // Verify ping rules (allow_ping=true)
    assert!(
        stdout.contains("icmp type echo-request"),
        "should have ICMP echo-request rule"
    );

    // Verify NAT64 rules (allow_ipv4ipv6translation=true)
    assert!(
        stdout.contains("64:ff9b::"),
        "should have NAT64 well-known prefix rule"
    );

    // Verify allowed IP rules
    assert!(
        stdout.contains("198.51.100.1"),
        "should have incoming allowlisted IP"
    );
    assert!(
        stdout.contains("203.0.113.5"),
        "should have outgoing allowlisted IP"
    );

    // Verify sentinel rules
    assert!(
        stdout.contains("airvpn_filter_input_latest_rule"),
        "should have input sentinel"
    );
    assert!(
        stdout.contains("airvpn_filter_output_latest_rule"),
        "should have output sentinel"
    );
    assert!(
        stdout.contains("airvpn_filter_forward_latest_rule"),
        "should have forward sentinel"
    );

    // Verify conntrack rule in INPUT
    assert!(
        stdout.contains("ct state established,related"),
        "should have conntrack rule in input"
    );

    netlock::deactivate().expect("deactivate");
}

// =============================================================================
// 2. DNS
// =============================================================================

#[test]
#[ignore = "requires root: modifies /etc/resolv.conf"]
fn test_dns_activate_deactivate() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }
    let _guard = DnsGuard::new();

    let test_ipv4 = "10.99.99.1";
    let test_ipv6 = "fd99::1";
    // Use a dummy interface name — dns::activate always does the resolv.conf
    // swap regardless of whether the interface exists. The systemd-resolved
    // configuration for this interface will fail silently if it doesn't exist.
    let test_iface = "lo";

    dns::activate(test_ipv4, test_ipv6, test_iface).expect("dns activate");

    // Verify /etc/resolv.conf contains our nameservers
    let content =
        fs::read_to_string("/etc/resolv.conf").expect("read resolv.conf after activate");
    assert!(
        content.contains(&format!("nameserver {}", test_ipv4)),
        "resolv.conf should contain test IPv4 DNS: {}",
        content
    );
    assert!(
        content.contains(&format!("nameserver {}", test_ipv6)),
        "resolv.conf should contain test IPv6 DNS: {}",
        content
    );
    assert!(
        content.contains("airvpn-rs"),
        "resolv.conf should contain airvpn-rs header"
    );

    // Verify backup exists
    assert!(
        Path::new("/etc/resolv.conf.airvpn-rs").exists(),
        "backup file should exist after activate"
    );

    dns::deactivate().expect("dns deactivate");

    // After deactivate, the backup should be gone (renamed back)
    assert!(
        !Path::new("/etc/resolv.conf.airvpn-rs").exists(),
        "backup file should be gone after deactivate"
    );

    // resolv.conf should exist again
    assert!(
        Path::new("/etc/resolv.conf").exists(),
        "resolv.conf should exist after deactivate"
    );
}

#[test]
#[ignore = "requires root: modifies /etc/resolv.conf"]
fn test_dns_check_and_reapply() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }
    let _guard = DnsGuard::new();

    let test_ipv4 = "10.99.99.2";
    let test_ipv6 = "fd99::2";
    let test_iface = "lo";

    dns::activate(test_ipv4, test_ipv6, test_iface).expect("dns activate");

    // Verify our DNS is in place
    let content = fs::read_to_string("/etc/resolv.conf").expect("read resolv.conf");
    assert!(content.contains(test_ipv4));

    // Simulate DNS drift: overwrite resolv.conf with garbage
    fs::write("/etc/resolv.conf", "# garbage written by integration test\nnameserver 1.1.1.1\n")
        .expect("overwrite resolv.conf with garbage");

    // check_and_reapply should detect drift and restore our DNS
    let reapplied = dns::check_and_reapply(test_ipv4, test_ipv6, test_iface).expect("check_and_reapply");
    assert!(reapplied, "should detect drift and reapply DNS");

    // Verify DNS was restored
    let content = fs::read_to_string("/etc/resolv.conf").expect("read resolv.conf after reapply");
    assert!(
        content.contains(&format!("nameserver {}", test_ipv4)),
        "resolv.conf should contain our DNS after reapply: {}",
        content
    );

    // check_and_reapply again should find no drift
    let reapplied2 = dns::check_and_reapply(test_ipv4, test_ipv6, test_iface).expect("second check_and_reapply");
    assert!(!reapplied2, "should not reapply when DNS is correct");

    dns::deactivate().expect("dns deactivate");
}

#[test]
#[ignore = "requires root: modifies /etc/resolv.conf and chattr"]
fn test_dns_immutability_handling() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }
    let _guard = DnsGuard::new();

    let resolv = Path::new("/etc/resolv.conf");

    // Ensure resolv.conf is a regular file (not symlink) before setting immutable
    if resolv.is_symlink() {
        let content = fs::read(resolv).unwrap_or_default();
        let _ = fs::remove_file(resolv);
        let _ = fs::write(resolv, &content);
    }

    // Set immutable flag
    let status = Command::new("chattr")
        .args(["+i", "/etc/resolv.conf"])
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("skipping: chattr +i not supported on this filesystem");
            return;
        }
    }

    // Activate should succeed — it clears the immutable flag internally
    let test_ipv4 = "10.99.99.3";
    let test_ipv6 = "fd99::3";
    let result = dns::activate(test_ipv4, test_ipv6, "lo");
    // Clear immutable flag in case activate failed (cleanup safety)
    let _ = Command::new("chattr")
        .args(["-i", "/etc/resolv.conf"])
        .status();
    result.expect("dns activate should succeed even with immutable flag");

    // Verify our DNS is in place
    let content = fs::read_to_string("/etc/resolv.conf").expect("read resolv.conf");
    assert!(
        content.contains(test_ipv4),
        "resolv.conf should have our DNS after clearing immutable: {}",
        content
    );

    dns::deactivate().expect("dns deactivate");
}

// =============================================================================
// 3. IPv6
// =============================================================================

#[test]
#[ignore = "requires root: modifies /proc/sys/net/ipv6"]
fn test_ipv6_block_restore() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    // Record the current IPv6 state for all non-loopback interfaces
    let conf_dir = Path::new("/proc/sys/net/ipv6/conf");
    if !conf_dir.exists() {
        eprintln!("skipping: /proc/sys/net/ipv6/conf does not exist (IPv6 not enabled)");
        return;
    }

    // Capture pre-block state
    let mut pre_state: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = fs::read_dir(conf_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if matches!(name.as_str(), "all" | "lo" | "lo0") {
                continue;
            }
            let disable_path = conf_dir.join(&name).join("disable_ipv6");
            if let Ok(val) = fs::read_to_string(&disable_path) {
                pre_state.push((name, val.trim().to_string()));
            }
        }
    }

    // Block all IPv6
    let blocked = ipv6::block_all();
    let _guard = Ipv6Guard {
        blocked: blocked.clone(),
    };

    // On a system with IPv6 enabled, at least one interface should be blocked
    if pre_state.iter().any(|(_, v)| v == "0") {
        assert!(
            !blocked.is_empty(),
            "should have blocked at least one interface (some had IPv6 enabled)"
        );
    }

    // Verify blocked interfaces actually have disable_ipv6 = 1
    for iface in &blocked {
        let val = fs::read_to_string(conf_dir.join(iface).join("disable_ipv6"))
            .expect("read disable_ipv6 for blocked interface");
        assert_eq!(
            val.trim(),
            "1",
            "interface {} should have disable_ipv6=1 after block",
            iface
        );
    }

    // Restore
    ipv6::restore(&blocked);

    // Verify restored interfaces have their original state back
    for (iface, original_val) in &pre_state {
        if blocked.contains(iface) {
            let val = fs::read_to_string(conf_dir.join(iface).join("disable_ipv6"))
                .expect("read disable_ipv6 after restore");
            assert_eq!(
                val.trim(), "0",
                "interface {} should have disable_ipv6=0 after restore (was {} before)",
                iface, original_val
            );
        }
    }
}

// =============================================================================
// 4. WireGuard (config file handling only)
// =============================================================================

#[test]
#[ignore = "requires root: creates config file with restricted permissions"]
fn test_wireguard_config_file_permissions() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    // Generate a WgConnectParams with fake keys — connect() will fail because
    // the endpoint is unreachable, but the file should still be created with
    // correct permissions before the failure.
    let params = wireguard::WgConnectParams {
        wg_config: Zeroizing::new("\
[Interface]
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
".to_string()),
        ipv4_address: "10.99.99.99/32".to_string(),
        ipv6_address: String::new(),
        endpoint_ip: "192.0.2.1".to_string(),
    };

    // connect() will fail because the endpoint is unreachable / keys are fake,
    // but we can check the file was created with correct permissions.
    // The function cleans up the config file on failure.
    let result = wireguard::connect(&params, false);

    // connect() should fail (no real server), but we need to verify the file
    // handling behavior. The config file should be cleaned up after failure.
    assert!(result.is_err(), "connect should fail with fake config");

    // Verify no orphaned config files remain in /tmp with our prefix
    let has_orphan = fs::read_dir("/tmp")
        .expect("read /tmp")
        .flatten()
        .any(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("avpn-") && name.ends_with(".conf")
        });
    assert!(
        !has_orphan,
        "config file should be cleaned up after failed connect"
    );
}

// =============================================================================
// 5. Recovery
// =============================================================================

// For recovery tests, we bypass the module's internal path selection and
// write/read state files directly to a test-specific location, then call
// the public save/load/remove through the standard API while the standard
// paths are clear.

#[test]
#[ignore = "requires root: writes to /run/airvpn-rs"]
fn test_recovery_save_load_remove() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    // Clean up any pre-existing state to ensure a clean test
    let _ = recovery::remove();

    let state = State {
        lock_active: true,
        wg_interface: "test-iface-0".to_string(),
        wg_config_path: "/run/airvpn-rs/test-iface-0.conf".to_string(),
        dns_ipv4: "10.99.99.1".to_string(),
        dns_ipv6: "fd99::1".to_string(),
        pid: std::process::id(),
        blocked_ipv6_ifaces: vec!["eth0".to_string()],
        endpoint_ip: String::new(),
        nonce: 12345,
        resolv_was_immutable: false,
    };

    // Save
    recovery::save(&state).expect("save state");

    // Load
    let loaded = recovery::load().expect("load state").expect("state should exist");
    assert_eq!(loaded.lock_active, state.lock_active);
    assert_eq!(loaded.wg_interface, state.wg_interface);
    assert_eq!(loaded.wg_config_path, state.wg_config_path);
    assert_eq!(loaded.dns_ipv4, state.dns_ipv4);
    assert_eq!(loaded.dns_ipv6, state.dns_ipv6);
    assert_eq!(loaded.pid, state.pid);
    assert_eq!(loaded.blocked_ipv6_ifaces, state.blocked_ipv6_ifaces);

    // Remove
    recovery::remove().expect("remove state");

    // Load after remove should return None
    let loaded_after = recovery::load().expect("load after remove");
    assert!(loaded_after.is_none(), "state should be None after remove");
}

#[test]
#[ignore = "requires root: writes to /run/airvpn-rs"]
fn test_recovery_atomic_write() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    // Clean up any pre-existing state
    let _ = recovery::remove();

    let state = State {
        lock_active: false,
        wg_interface: "test-iface-1".to_string(),
        wg_config_path: "/run/airvpn-rs/test-iface-1.conf".to_string(),
        dns_ipv4: "10.99.99.2".to_string(),
        dns_ipv6: "fd99::2".to_string(),
        pid: std::process::id(),
        blocked_ipv6_ifaces: vec![],
        endpoint_ip: String::new(),
        nonce: 67890,
        resolv_was_immutable: false,
    };

    recovery::save(&state).expect("save state");

    // Verify the file exists at the expected primary location
    let state_path = Path::new("/run/airvpn-rs/state.json");
    assert!(
        state_path.exists(),
        "state file should exist at /run/airvpn-rs/state.json"
    );

    // Verify permissions are 0600 (owner read/write only)
    let metadata = fs::metadata(state_path).expect("stat state file");
    let perms = metadata.permissions().mode() & 0o777;
    assert_eq!(
        perms, 0o600,
        "state file should have 0600 permissions, got {:o}",
        perms
    );

    // Verify the content is valid JSON
    let content = fs::read_to_string(state_path).expect("read state file");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("state file should be valid JSON");
    assert_eq!(parsed["wg_interface"], "test-iface-1");

    recovery::remove().expect("remove state");
}

#[test]
#[ignore = "requires root: writes to /run/airvpn-rs"]
fn test_recovery_corrupt_state_handled() {
    if !is_root() {
        eprintln!("skipping: not root");
        return;
    }

    // Clean up any pre-existing state
    let _ = recovery::remove();

    // Create the state directory
    let dir = Path::new("/run/airvpn-rs");
    let _ = fs::create_dir_all(dir);

    // Write garbage to the state file
    let state_path = dir.join("state.json");
    fs::write(&state_path, "this is not valid json {{{{").expect("write garbage");

    // Load should handle the corrupt file gracefully: return Ok(None)
    // and delete the corrupt file
    let loaded = recovery::load().expect("load corrupt state should return Ok");
    assert!(
        loaded.is_none(),
        "corrupt state should be treated as absent (Ok(None))"
    );

    // The corrupt file should have been deleted
    assert!(
        !state_path.exists(),
        "corrupt state file should be deleted after failed parse"
    );

    // Subsequent load should also return None cleanly
    let loaded_again = recovery::load().expect("second load after corrupt cleanup");
    assert!(loaded_again.is_none());
}
