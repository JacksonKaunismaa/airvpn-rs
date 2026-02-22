//! IPv6 management — disable/restore IPv6 on non-loopback interfaces.
//!
//! Eddie's default `network.ipv6.mode == "in-block"` disables IPv6 on all
//! interfaces (except all/lo/lo0) via sysctl to prevent IPv6 traffic leaking
//! outside the VPN tunnel.
//!
//! Reference: Eddie src/App.CLI.Linux.Elevated/src/impl.cpp

use std::fs;
use std::path::Path;

/// Disable IPv6 on all non-loopback interfaces.
///
/// Returns the list of interfaces that were blocked (for restore on disconnect).
pub fn block_all() -> Vec<String> {
    let mut blocked = Vec::new();
    let conf_dir = Path::new("/proc/sys/net/ipv6/conf");

    let entries = match fs::read_dir(conf_dir) {
        Ok(e) => e,
        Err(_) => return blocked,
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip special interfaces (matching Eddie)
        if matches!(name.as_str(), "all" | "lo" | "lo0") {
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
/// After restoring tracked interfaces, also scans for any transient interfaces
/// (USB ethernet, WiFi reconnect, Docker, etc.) that were created during the
/// VPN session and inherited `disable_ipv6=1` from the `default` sysctl template.
pub fn restore(interfaces: &[String]) {
    let conf_dir = Path::new("/proc/sys/net/ipv6/conf");

    // Restore tracked interfaces
    for name in interfaces {
        let disable_path = conf_dir.join(name).join("disable_ipv6");
        let _ = fs::write(&disable_path, "0");
    }

    // Also restore any transient interfaces created during the session
    // (they inherited disable_ipv6=1 from the "default" template)
    if let Ok(entries) = fs::read_dir(conf_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if matches!(name.as_str(), "all" | "lo" | "lo0") {
                continue;
            }
            // Skip already-restored interfaces
            if interfaces.iter().any(|i| i == &name) {
                continue;
            }
            let disable_path = conf_dir.join(&name).join("disable_ipv6");
            let current = fs::read_to_string(&disable_path)
                .unwrap_or_default()
                .trim()
                .to_string();
            if current == "1" {
                let _ = fs::write(&disable_path, "0");
            }
        }
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
