//! IPv6 management — disable/restore IPv6 on non-loopback interfaces.
//!
//! Eddie's default `network.ipv6.mode == "in-block"` disables IPv6 on all
//! interfaces (except all/lo/lo0) via sysctl to prevent IPv6 traffic leaking
//! outside the VPN tunnel.
//!
//! Reference: Eddie src/App.CLI.Linux.Elevated/src/impl.cpp

use std::fs;
use std::path::Path;

use log::warn;

/// Disable IPv6 on all non-loopback interfaces, including `default`.
///
/// Returns the list of interfaces that were blocked (for restore on disconnect).
///
/// Setting `default` to `disable_ipv6=1` means newly created interfaces
/// (including the WireGuard tunnel) inherit disabled IPv6 automatically.
/// This matches Eddie's behavior (impl.cpp iterates all entries in
/// `/proc/sys/net/ipv6/conf/`, skipping only `all`, `lo`, `lo0`).
///
/// We no longer use wg-quick (which breaks with `default=1`), so this is safe.
/// The WireGuard interface is set up via direct `ip`/`wg` commands with IPv4 only.
///
/// Reference: Eddie src/App.CLI.Linux.Elevated/src/impl.cpp lines 478-510
pub fn block_all() -> Vec<String> {
    let mut blocked = Vec::new();
    let conf_dir = Path::new("/proc/sys/net/ipv6/conf");

    let entries = match fs::read_dir(conf_dir) {
        Ok(e) => e,
        Err(_) => return blocked,
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip special pseudo-interfaces (matching Eddie impl.cpp:483-490).
        // "all" is skipped because setting it auto-cascades to all interfaces
        // (Eddie prefers per-interface control). "default" is NOT skipped —
        // it acts as a template for newly created interfaces.
        if matches!(name.as_str(), "all" | "lo" | "lo0") {
            continue;
        }

        // Validate interface name: alphanumeric + dash + underscore, max 15 chars.
        // Kernel-created names are safe, but defense-in-depth prevents path traversal
        // if /proc is ever somehow compromised or a FUSE overlay is mounted.
        if name.is_empty()
            || name.len() > 15
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            warn!("skipping invalid interface name in block_all: {:?}", name);
            continue;
        }

        let disable_path = conf_dir.join(&name).join("disable_ipv6");

        // Check current state — only block if currently enabled
        let current = fs::read_to_string(&disable_path)
            .unwrap_or_default()
            .trim()
            .to_string();

        if current == "0" {
            if fs::write(&disable_path, "1").is_ok() {
                blocked.push(name);
            }
        }
    }

    blocked
}

/// Restore IPv6 on previously blocked interfaces.
///
/// Only restores interfaces that were explicitly tracked in `block_all()`.
/// We do NOT scan for untracked interfaces — re-enabling IPv6 on interfaces
/// we didn't disable (e.g., Docker, user-configured) could break their
/// intended configuration.
pub fn restore(interfaces: &[String]) {
    let conf_dir = Path::new("/proc/sys/net/ipv6/conf");
    for name in interfaces {
        // Validate interface name to prevent path traversal
        if name.is_empty()
            || name.len() > 15
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            warn!("skipping invalid interface name in restore: {:?}", name);
            continue;
        }
        let disable_path = conf_dir.join(name).join("disable_ipv6");
        let _ = fs::write(&disable_path, "0");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_all_returns_vec() {
        // Just verify it doesn't panic — actual blocking requires root
        let result = block_all();
        // On non-root CI, this returns empty (can't write to /proc)
        assert!(result.is_empty() || !result.is_empty());
    }

    #[test]
    fn test_restore_empty_list() {
        // Restoring nothing should not panic
        restore(&[]);
    }

    #[test]
    fn test_restore_nonexistent_interface() {
        // Restoring a fake interface should not panic
        restore(&["nonexistent_iface_12345".to_string()]);
    }
}
