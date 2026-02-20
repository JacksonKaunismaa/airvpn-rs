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

use anyhow::{Context, Result};

const BACKUP_PATH: &str = "/etc/resolv.conf.airvpn-rs";

/// Build the expected resolv.conf content for VPN DNS.
///
/// Matches Eddie's format: header comment block + nameserver lines.
fn build_resolv_conf(dns_ipv4: &str, dns_ipv6: &str) -> String {
    format!(
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
nameserver {}
nameserver {}

",
        BACKUP_PATH, BACKUP_PATH, dns_ipv4, dns_ipv6,
    )
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

/// Configure systemd-resolved for VPN DNS on the given interface.
///
/// Eddie sets DNS and default-route on the VPN interface so that
/// systemd-resolved routes all queries through the tunnel.
fn configure_systemd_resolved(dns_ipv4: &str, dns_ipv6: &str, iface: &str) -> Result<()> {
    // resolvectl dns <iface> <dns_ipv4> <dns_ipv6>
    let output = Command::new("resolvectl")
        .args(["dns", iface, dns_ipv4, dns_ipv6])
        .output()
        .context("failed to execute resolvectl dns")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("resolvectl dns failed: {}", stderr);
    }

    // resolvectl default-route <iface> true
    let output = Command::new("resolvectl")
        .args(["default-route", iface, "true"])
        .output()
        .context("failed to execute resolvectl default-route")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("resolvectl default-route failed: {}", stderr);
    }

    Ok(())
}

/// Activate DNS: backup resolv.conf, write VPN DNS, handle systemd-resolved.
///
/// Eddie always writes resolv.conf AND configures systemd-resolved if active.
/// The resolv.conf swap is the universal fallback; systemd-resolved is layered on top.
pub fn activate(dns_ipv4: &str, dns_ipv6: &str, iface: &str) -> Result<()> {
    // If systemd-resolved is active, configure it
    if is_systemd_resolved_active() {
        configure_systemd_resolved(dns_ipv4, dns_ipv6, iface)?;
    }

    // Always do the resolv.conf swap (Eddie does both regardless)
    let resolv_path = Path::new("/etc/resolv.conf");
    let backup_path = Path::new(BACKUP_PATH);

    if resolv_path.exists() && !backup_path.exists() {
        fs::copy(resolv_path, backup_path).context("failed to backup /etc/resolv.conf")?;
    }

    let expected = build_resolv_conf(dns_ipv4, dns_ipv6);
    fs::write(resolv_path, &expected).context("failed to write /etc/resolv.conf")?;

    Ok(())
}

/// Deactivate: restore resolv.conf from backup.
///
/// Eddie: move backup back, then restart systemd-resolved if active.
pub fn deactivate() -> Result<()> {
    let resolv_path = Path::new("/etc/resolv.conf");
    let backup_path = Path::new(BACKUP_PATH);

    if backup_path.exists() {
        // Remove the VPN resolv.conf, restore backup
        if resolv_path.exists() {
            fs::remove_file(resolv_path).context("failed to remove VPN resolv.conf")?;
        }
        fs::rename(backup_path, resolv_path).context("failed to restore resolv.conf from backup")?;
    }

    // Restart systemd-resolved if active so it picks up the restored resolv.conf
    // (Eddie: `service systemd-resolved restart`)
    if is_systemd_resolved_active() {
        let _ = Command::new("systemctl")
            .args(["restart", "systemd-resolved"])
            .output();
    }

    Ok(())
}

/// Check if current resolv.conf matches our expected content, re-apply if drifted.
///
/// Eddie's DnsSwitchCheck pattern: NetworkManager and other services can revert
/// resolv.conf behind our back. This function is called periodically to detect
/// and fix drift.
///
/// Returns Ok(true) if resolv.conf was re-applied, Ok(false) if no drift detected.
pub fn check_and_reapply(dns_ipv4: &str, dns_ipv6: &str) -> Result<bool> {
    let resolv_path = Path::new("/etc/resolv.conf");

    if !resolv_path.exists() {
        return Ok(false);
    }

    let expected = build_resolv_conf(dns_ipv4, dns_ipv6);
    let current = fs::read_to_string(resolv_path).context("failed to read /etc/resolv.conf")?;

    if current != expected {
        fs::write(resolv_path, &expected).context("failed to re-apply /etc/resolv.conf")?;
        Ok(true)
    } else {
        Ok(false)
    }
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
    fn test_build_resolv_conf_deterministic() {
        let a = build_resolv_conf("10.0.0.1", "fd00::1");
        let b = build_resolv_conf("10.0.0.1", "fd00::1");
        assert_eq!(a, b, "same inputs should produce same output");
    }

    #[test]
    fn test_build_resolv_conf_different_dns() {
        let a = build_resolv_conf("10.0.0.1", "fd00::1");
        let b = build_resolv_conf("10.0.0.2", "fd00::2");
        assert_ne!(a, b, "different DNS should produce different output");
    }

    #[test]
    fn test_is_systemd_resolved_detection() {
        // This just tests that the function doesn't panic — actual result
        // depends on the system. On CI/containers, systemd-resolved is
        // typically not running.
        let _active = is_systemd_resolved_active();
    }
}
