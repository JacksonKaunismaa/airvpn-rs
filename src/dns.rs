//! DNS manager -- resolv.conf swap + systemd-resolved support.
//!
//! Matches Eddie's DnsManager approach (Platform.Linux.cs + elevated impl.cpp):
//! 1. Backup /etc/resolv.conf to /etc/resolv.conf.airvpn-rs
//! 2. Write VPN DNS nameservers to /etc/resolv.conf
//! 3. If systemd-resolved is active, also configure via resolvectl
//! 4. Periodically check for DNS drift (NetworkManager can revert resolv.conf)
//!
//! Reference: Eddie src/App.CLI.Linux.Elevated/src/impl.cpp (dns-switch-do, dns-switch-restore)

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use log::{info, warn};

static RESOLV_WAS_IMMUTABLE: AtomicBool = AtomicBool::new(false);

/// Return whether resolv.conf was immutable before we modified it.
/// Used by main.rs to persist this flag in recovery state.
pub fn was_immutable() -> bool {
    RESOLV_WAS_IMMUTABLE.load(Ordering::Relaxed)
}

/// Restore the RESOLV_WAS_IMMUTABLE flag from persisted recovery state.
/// Called on recovery/reconnection so deactivate() knows to restore the flag.
pub fn set_was_immutable(val: bool) {
    RESOLV_WAS_IMMUTABLE.store(val, Ordering::Relaxed);
}

const BACKUP_PATH: &str = "/etc/resolv.conf.airvpn-rs";

/// Clear the immutable flag on a file (if set).
/// Eddie: impl.cpp uses FS_IOC_SETFLAGS ioctl. We use chattr for simplicity.
fn clear_immutable(path: &Path) {
    let _ = Command::new("chattr")
        .args(["-i", &path.to_string_lossy()])
        .output();
}

/// Check if a file has the immutable flag set.
fn is_immutable(path: &Path) -> bool {
    Command::new("lsattr")
        .arg(path.to_string_lossy().to_string())
        .output()
        .map(|o| {
            if !o.status.success() {
                return false;
            }
            let stdout = String::from_utf8_lossy(&o.stdout);
            // lsattr output: "----i---------e-- /etc/resolv.conf"
            // Only check the attribute flags field (first column before space)
            // to avoid false positives from 'i' in the filename (e.g. "resolv").
            stdout.lines().any(|line| {
                line.split_whitespace()
                    .next()
                    .map(|attrs| attrs.contains('i'))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false)
}

/// Restore the immutable flag on a file.
///
/// Only used in deactivate() to restore the original immutable state. We NEVER
/// proactively set immutable on resolv.conf — Eddie explicitly considers that a
/// bug (Platform.cs:591-599 CompatibilityAfterProfile).
fn restore_immutable(path: &Path) {
    let _ = Command::new("chattr")
        .args(["+i", &path.to_string_lossy()])
        .output();
}

/// Build the expected resolv.conf content for VPN DNS.
///
/// Matches Eddie's format: header comment block + nameserver lines.
fn build_resolv_conf(dns_ipv4: &str, dns_ipv6: &str) -> String {
    let mut content = format!(
        "\
#
# Created by airvpn-rs. Do not edit.
#
# Your resolv.conf file is temporarily backed up in {}
# To restore your resolv.conf file you need to log in as root
# and execute the below command from the shell:
#
# mv {} /etc/resolv.conf
#
",
        BACKUP_PATH, BACKUP_PATH,
    );

    if !dns_ipv4.is_empty() {
        content.push_str(&format!("nameserver {}\n", dns_ipv4));
    }
    if !dns_ipv6.is_empty() {
        content.push_str(&format!("nameserver {}\n", dns_ipv6));
    }
    content.push('\n');
    content
}

/// Check if systemd-resolved is active.
///
/// Eddie: `systemctl is-active --quiet systemd-resolved`
fn is_systemd_resolved_active() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "systemd-resolved"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Flush DNS caches (matching Eddie's dns-flush handler).
///
/// Restarts common DNS cache services and flushes systemd-resolved.
/// Eddie default: "nscd;dnsmasq;named;bind9"
pub fn flush() {
    // Restart common DNS cache services (best-effort, most won't be running).
    // Must happen BEFORE the resolvectl flush — Eddie does services first,
    // then flush.  A restart re-populates the service's cache, so flushing
    // before the restart is wasted work.
    for service in &["nscd", "dnsmasq", "named", "bind9"] {
        let _ = Command::new("systemctl")
            .args(["try-restart", service])
            .output();
    }

    // Flush systemd-resolved cache (after service restarts)
    if is_systemd_resolved_active() {
        let _ = Command::new("resolvectl")
            .arg("flush-caches")
            .output();
    }
}

/// Read current DNS servers for an interface via resolvectl.
///
/// Returns the raw `resolvectl dns <iface>` output line, e.g.
/// "Link 2 (eth0): 8.8.8.8 8.8.4.4" — the caller parses IPs from this.
fn get_interface_dns(iface: &str) -> Option<String> {
    let output = Command::new("resolvectl")
        .args(["dns", iface])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        None
    }
}

/// Get all network interface names from /sys/class/net/, excluding loopback.
///
/// Eddie uses if_nameindex() to enumerate interfaces. We read /sys/class/net/
/// which is the sysfs equivalent and avoids needing libc bindings.
fn list_interfaces() -> Vec<String> {
    let mut ifaces = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name != "lo" && name != "lo0" {
                ifaces.push(name);
            }
        }
    }
    ifaces
}

/// Configure systemd-resolved for all interfaces: set VPN DNS on VPN interface,
/// disable default-route on all others to prevent DNS leaks.
///
/// Eddie iterates ALL network interfaces and sets default-route=false on every
/// non-VPN interface so systemd-resolved doesn't route DNS through them.
/// Only the VPN interface gets DNS servers + default-route=true.
///
/// Reference: Eddie impl.cpp dns-switch-do (lines ~228-321)
fn configure_systemd_resolved_all(dns_ipv4: &str, dns_ipv6: &str, vpn_iface: &str) -> Result<()> {
    let ifaces = list_interfaces();

    for iface in &ifaces {
        if iface == vpn_iface {
            // VPN interface: set DNS servers and default-route=true
            let mut dns_args = vec!["dns", iface.as_str()];
            if !dns_ipv4.is_empty() {
                dns_args.push(dns_ipv4);
            }
            if !dns_ipv6.is_empty() {
                dns_args.push(dns_ipv6);
            }

            let output = Command::new("resolvectl")
                .args(&dns_args)
                .output()
                .context("failed to execute resolvectl dns")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("resolvectl dns on {} failed: {}", iface, stderr);
            }

            let output = Command::new("resolvectl")
                .args(["default-route", iface.as_str(), "true"])
                .output()
                .context("failed to execute resolvectl default-route")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("resolvectl default-route on {} failed: {}", iface, stderr);
            }
        } else {
            // Non-VPN interface: back up current DNS servers + default-route state.
            // Eddie: backs up /run/systemd/resolve/netif/<index> to
            // /etc/systemd_resolve_netif_<iface>.eddievpn before modifying.
            // We back up both values so we can fully restore on disconnect,
            // rather than factory-resetting the interface with `resolvectl revert`.
            let backup_path = Path::new("/etc").join(format!("systemd_resolve_{}.airvpn-rs", iface));
            if !backup_path.exists() {
                let dns_state = get_interface_dns(iface).unwrap_or_default();
                let dr_output = Command::new("resolvectl")
                    .args(["default-route", iface.as_str()])
                    .output();
                let dr_state = dr_output
                    .ok()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                    .unwrap_or_default();
                let backup_content = format!("dns={}\ndefault_route={}", dns_state, dr_state);
                // Write with restricted permissions (0o600) — these files contain
                // DNS server IPs and live in /etc/, so avoid world-readable default.
                #[cfg(unix)]
                {
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    let result = fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&backup_path)
                        .and_then(|mut f| f.write_all(backup_content.as_bytes()));
                    if let Err(e) = result {
                        warn!("failed to write systemd-resolved backup {}: {}", backup_path.display(), e);
                    }
                }
                #[cfg(not(unix))]
                {
                    let _ = fs::write(&backup_path, &backup_content);
                }
            }

            // Non-VPN interface: set VPN DNS + default-route=false.
            // Eddie sets VPN DNS on EVERY interface (impl.cpp lines 270-288),
            // not just the VPN one. If an app queries a specific non-VPN interface
            // directly, it would use that interface's original DNS → leak.
            // Setting VPN DNS here prevents that.
            let mut dns_args = vec!["dns", iface.as_str()];
            if !dns_ipv4.is_empty() {
                dns_args.push(dns_ipv4);
            }
            if !dns_ipv6.is_empty() {
                dns_args.push(dns_ipv6);
            }
            let _ = Command::new("resolvectl").args(&dns_args).output();

            // Set default-route=false to prevent DNS leak.
            // Non-fatal — interface may not support it (e.g. virtual bridges).
            let output = Command::new("resolvectl")
                .args(["default-route", iface.as_str(), "false"])
                .output();
            if let Ok(o) = &output {
                if !o.status.success() {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    warn!(
                        "resolvectl default-route false on {} failed (non-fatal): {}",
                        iface, stderr
                    );
                }
            }
        }
    }

    Ok(())
}

/// Activate DNS: backup resolv.conf, write VPN DNS, handle systemd-resolved.
///
/// Eddie always writes resolv.conf AND configures systemd-resolved if active.
/// The resolv.conf swap is the universal fallback; systemd-resolved is layered on top.
pub fn activate(dns_ipv4: &str, dns_ipv6: &str, iface: &str) -> Result<()> {
    if dns_ipv4.is_empty() && dns_ipv6.is_empty() {
        anyhow::bail!("no DNS servers provided (both IPv4 and IPv6 are empty)");
    }

    // If systemd-resolved is active, configure all interfaces:
    // VPN interface gets DNS + default-route=true, all others get default-route=false.
    if is_systemd_resolved_active() {
        configure_systemd_resolved_all(dns_ipv4, dns_ipv6, iface)?;
    }

    // Always do the resolv.conf swap (Eddie does both regardless)
    let resolv_path = Path::new("/etc/resolv.conf");
    let backup_path = Path::new(BACKUP_PATH);

    // Save whether resolv.conf was immutable before we clear it, so we can
    // restore the flag on deactivate.
    RESOLV_WAS_IMMUTABLE.store(is_immutable(resolv_path), Ordering::Relaxed);

    // Clear immutable flag before modifying (Fedora/RHEL set this on resolv.conf)
    clear_immutable(resolv_path);

    if resolv_path.exists() && !backup_path.exists() {
        fs::rename(resolv_path, backup_path).context("failed to backup /etc/resolv.conf")?;
    }

    let expected = build_resolv_conf(dns_ipv4, dns_ipv6);

    // If resolv.conf became a symlink (e.g., NetworkManager recreated it),
    // remove the symlink before writing to avoid corrupting the target
    if resolv_path.is_symlink() {
        let _ = fs::remove_file(resolv_path);
    }

    fs::write(resolv_path, &expected).context("failed to write /etc/resolv.conf")?;

    // Eddie sets 0644 explicitly (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
    // so non-root processes can read resolv.conf for DNS resolution
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(resolv_path, fs::Permissions::from_mode(0o644))
            .context("failed to set /etc/resolv.conf permissions")?;
    }

    flush();

    Ok(())
}

/// Deactivate: restore resolv.conf from backup.
///
/// Eddie: move backup back, then restart systemd-resolved if active.
pub fn deactivate() -> Result<()> {
    let resolv_path = Path::new("/etc/resolv.conf");
    let backup_path = Path::new(BACKUP_PATH);

    if backup_path.exists() {
        // Clear immutable flag before modifying (Fedora/RHEL set this on resolv.conf)
        clear_immutable(resolv_path);

        // Remove symlink before rename to avoid EXDEV (cross-filesystem rename)
        if resolv_path.is_symlink() {
            let _ = fs::remove_file(resolv_path);
        }

        // Atomic rename replaces dest on Linux — no gap where resolv.conf is missing
        fs::rename(backup_path, resolv_path).context("failed to restore resolv.conf from backup")?;
    } else {
        // No backup file. Only delete resolv.conf if it's actually ours (contains
        // our header marker). This prevents data loss when deactivate() is called
        // twice: the first call consumes the backup, and a second call would
        // otherwise delete the correctly-restored original resolv.conf.
        if resolv_path.exists() {
            let is_ours = fs::read_to_string(resolv_path)
                .map(|c| c.contains("Created by airvpn-rs"))
                .unwrap_or(false);
            if is_ours {
                clear_immutable(resolv_path);
                let _ = fs::remove_file(resolv_path);
            } else {
                info!("resolv.conf exists but is not ours — leaving it intact");
            }
        }
    }

    // Restore immutable flag if it was set before we activated
    if RESOLV_WAS_IMMUTABLE.load(Ordering::Relaxed) {
        restore_immutable(resolv_path);
    }

    // Restore per-interface systemd-resolved settings from backups.
    // Eddie: reads /etc/systemd_resolve_netif_<iface>.eddievpn, restores DNS servers
    // and default_route via resolvectl, then deletes the backup file.
    //
    // Track which interfaces we successfully restored so we only use
    // `resolvectl revert` as a fallback for interfaces without backup files.
    let mut restored_ifaces: Vec<String> = Vec::new();
    if let Ok(entries) = fs::read_dir("/etc") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("systemd_resolve_") && name.ends_with(".airvpn-rs") {
                let iface = name
                    .strip_prefix("systemd_resolve_")
                    .and_then(|s| s.strip_suffix(".airvpn-rs"))
                    .unwrap_or("");
                if !iface.is_empty() {
                    if let Ok(content) = fs::read_to_string(entry.path()) {
                        let mut dns_line = String::new();
                        let mut dr_line = String::new();
                        for line in content.lines() {
                            if let Some(v) = line.strip_prefix("dns=") {
                                dns_line = v.to_string();
                            }
                            if let Some(v) = line.strip_prefix("default_route=") {
                                dr_line = v.to_string();
                            }
                        }

                        // Restore DNS servers.
                        // resolvectl dns output format: "Link 2 (eth0): 8.8.8.8 8.8.4.4"
                        // Extract just the IP addresses from the saved line.
                        let mut dns_restored = false;
                        if !dns_line.is_empty() {
                            let servers: Vec<&str> = dns_line
                                .split_whitespace()
                                .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
                                .collect();
                            if !servers.is_empty() {
                                let mut args = vec!["dns", iface];
                                args.extend(servers);
                                let result = Command::new("resolvectl").args(&args).output();
                                if result.map(|o| o.status.success()).unwrap_or(false) {
                                    dns_restored = true;
                                }
                            }
                        }

                        // If the interface had no original DNS servers, revert it
                        // instead of leaving VPN DNS in place.
                        if !dns_restored {
                            let _ = Command::new("resolvectl")
                                .args(["revert", iface])
                                .output();
                        }

                        // Restore default-route.
                        // An unset default-route is different from explicitly false.
                        // Only restore if the backup contains an explicit "yes" or "no";
                        // otherwise let `resolvectl revert` (above) handle it.
                        if dr_line.contains("yes") {
                            let _ = Command::new("resolvectl")
                                .args(["default-route", iface, "true"])
                                .output();
                        } else if dr_line.contains("no") {
                            let _ = Command::new("resolvectl")
                                .args(["default-route", iface, "false"])
                                .output();
                        }
                        // else: was unset — resolvectl revert will handle it

                        // Only mark as restored if DNS was actually put back.
                        if dns_restored {
                            restored_ifaces.push(iface.to_string());
                        }
                    }
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }

    // Revert DNS on interfaces that did NOT have backup files.
    // This is a best-effort fallback — `resolvectl revert` factory-resets
    // the interface, but it's better than leaving VPN DNS on an interface
    // we have no saved state for.
    let ifaces = list_interfaces();
    for iface in &ifaces {
        if !restored_ifaces.contains(iface) {
            let _ = Command::new("resolvectl")
                .args(["revert", iface.as_str()])
                .output();
        }
    }

    // Restart systemd-resolved if active so it picks up the restored resolv.conf
    // (Eddie: `service systemd-resolved restart`)
    if is_systemd_resolved_active() {
        let _ = Command::new("systemctl")
            .args(["restart", "systemd-resolved"])
            .output();
    }

    flush();

    Ok(())
}

/// Check if current resolv.conf matches our expected content, re-apply if drifted.
/// Also checks systemd-resolved per-interface settings for drift.
///
/// Eddie's DnsSwitchCheck pattern: NetworkManager and other services can revert
/// resolv.conf behind our back, and can also revert per-interface systemd-resolved
/// settings. This function is called periodically to detect and fix both kinds of drift.
///
/// Returns Ok(true) if any DNS settings were re-applied, Ok(false) if no drift detected.
pub fn check_and_reapply(dns_ipv4: &str, dns_ipv6: &str, vpn_iface: &str) -> Result<bool> {
    let mut reapplied = false;

    // Check resolv.conf drift
    let resolv_path = Path::new("/etc/resolv.conf");

    if resolv_path.exists() {
        let expected = build_resolv_conf(dns_ipv4, dns_ipv6);
        let current = match fs::read_to_string(resolv_path) {
            Ok(c) => c,
            Err(e) => {
                warn!("DNS check_and_reapply: failed to read /etc/resolv.conf: {}", e);
                return Err(e).context("failed to read /etc/resolv.conf");
            }
        };

        if current != expected {
            info!("DNS drift detected in /etc/resolv.conf, re-applying VPN DNS");
            // Clear immutable flag before modifying (Fedora/RHEL set this on resolv.conf)
            clear_immutable(resolv_path);

            // If resolv.conf became a symlink (e.g., NetworkManager recreated it),
            // remove the symlink before writing to avoid corrupting the target
            if resolv_path.is_symlink() {
                let _ = fs::remove_file(resolv_path);
            }

            if let Err(e) = fs::write(resolv_path, &expected) {
                warn!("DNS check_and_reapply: failed to re-apply /etc/resolv.conf: {}", e);
                return Err(e).context("failed to re-apply /etc/resolv.conf");
            }

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Err(e) = fs::set_permissions(resolv_path, fs::Permissions::from_mode(0o644)) {
                    warn!("DNS check_and_reapply: failed to set /etc/resolv.conf permissions: {}", e);
                    return Err(e).context("failed to set /etc/resolv.conf permissions");
                }
            }

            flush();
            reapplied = true;
        }
    }

    // Also re-check systemd-resolved settings (NetworkManager can revert per-interface DNS).
    // Eddie checks ALL interfaces on every DnsSwitchCheck cycle (impl.cpp uses the same
    // code path for both initial setup and periodic checking via the `check` parameter).
    if is_systemd_resolved_active() {
        let ifaces = list_interfaces();
        for iface in &ifaces {
            // Skip the VPN interface — it must keep default-route=true so DNS
            // routes through the tunnel. Only enforce default-route=false on
            // non-VPN interfaces.
            if iface == vpn_iface {
                continue;
            }
            // Check if default-route was reverted to true on a non-VPN interface
            let output = Command::new("resolvectl")
                .args(["default-route", iface.as_str()])
                .output();
            if let Ok(o) = output {
                let state = String::from_utf8_lossy(&o.stdout);
                // If a non-VPN interface has default-route=yes, it was reverted
                if state.contains("yes") {
                    // Re-apply DNS and default-route=false
                    let mut dns_args = vec!["dns", iface.as_str()];
                    if !dns_ipv4.is_empty() {
                        dns_args.push(dns_ipv4);
                    }
                    if !dns_ipv6.is_empty() {
                        dns_args.push(dns_ipv6);
                    }
                    let _ = Command::new("resolvectl").args(&dns_args).output();
                    let _ = Command::new("resolvectl")
                        .args(["default-route", iface.as_str(), "false"])
                        .output();
                    reapplied = true;
                }
            }
        }
    }

    Ok(reapplied)
}

/// Verify that /etc/resolv.conf contains only the expected VPN DNS servers.
/// Returns true if all nameserver entries match the expected VPN DNS IPs.
/// This catches DNS drift that the server-side check cannot detect
/// (the server-side check passes even when DNS leaks to upstream, because
/// the query still reaches AirVPN's authoritative nameserver).
pub fn verify_resolv_conf(expected_ipv4: &str, expected_ipv6: &str, resolv_path: &Path) -> bool {
    let content = match std::fs::read_to_string(resolv_path) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let nameservers: Vec<&str> = content.lines()
        .filter(|l| l.trim_start().starts_with("nameserver"))
        .filter_map(|l| l.split_whitespace().nth(1))
        .collect();
    if nameservers.is_empty() {
        return false;
    }
    nameservers.iter().all(|ns| *ns == expected_ipv4 || *ns == expected_ipv6)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_resolv_conf_format() {
        let content = build_resolv_conf("10.128.0.1", "fd7d:76ee:3c49:9950::1");

        // Header comment
        assert!(content.contains("Created by airvpn-rs"));
        assert!(content.contains(BACKUP_PATH));

        // Nameserver lines
        assert!(content.contains("nameserver 10.128.0.1"));
        assert!(content.contains("nameserver fd7d:76ee:3c49:9950::1"));

        // Nameservers should come after the comment block
        let comment_end = content.rfind('#').expect("comment end");
        let ns_start = content.find("nameserver").expect("nameserver");
        assert!(ns_start > comment_end, "nameservers should come after comments");
    }

    #[test]
    fn test_build_resolv_conf_ipv4_only() {
        let content = build_resolv_conf("10.0.0.1", "");
        assert!(content.contains("nameserver 10.0.0.1"));
        assert!(!content.contains("nameserver \n")); // No empty nameserver line
        // Should not have a second nameserver line
        assert_eq!(content.matches("nameserver").count(), 1);
    }

    #[test]
    fn test_build_resolv_conf_ipv6_only() {
        let content = build_resolv_conf("", "fd00::1");
        assert!(content.contains("nameserver fd00::1"));
        assert_eq!(content.matches("nameserver").count(), 1);
    }

    #[test]
    fn test_build_resolv_conf_neither() {
        let content = build_resolv_conf("", "");
        assert_eq!(content.matches("nameserver").count(), 0);
    }

    #[test]
    fn test_list_interfaces_returns_some() {
        let ifaces = list_interfaces();
        // Every Linux system has at least one non-loopback interface
        // (e.g. eth0, ens3, wlan0, docker0). On a bare container this
        // may be empty if /sys/class/net is missing, which is fine.
        if Path::new("/sys/class/net").exists() {
            assert!(
                !ifaces.is_empty(),
                "/sys/class/net exists but no non-loopback interfaces found"
            );
        }
    }

    #[test]
    fn test_verify_resolv_conf_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 10.128.0.1\nnameserver fd7d::1\n").unwrap();
        assert!(verify_resolv_conf("10.128.0.1", "fd7d::1", &path));
    }

    #[test]
    fn test_verify_resolv_conf_extra_server() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 10.128.0.1\nnameserver 8.8.8.8\n").unwrap();
        assert!(!verify_resolv_conf("10.128.0.1", "fd7d::1", &path));
    }

    #[test]
    fn test_verify_resolv_conf_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "# empty\n").unwrap();
        assert!(!verify_resolv_conf("10.128.0.1", "fd7d::1", &path));
    }

    #[test]
    fn test_verify_resolv_conf_missing_file() {
        let path = Path::new("/nonexistent/resolv.conf");
        assert!(!verify_resolv_conf("10.128.0.1", "fd7d::1", path));
    }

    #[test]
    fn test_verify_resolv_conf_with_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "# Created by airvpn-rs\nnameserver 10.128.0.1\n").unwrap();
        assert!(verify_resolv_conf("10.128.0.1", "fd7d::1", &path));
    }
}
