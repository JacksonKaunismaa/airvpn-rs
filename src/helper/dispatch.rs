//! Dispatch helpers for lock management, profile I/O, and server listing.

use anyhow::{Context, Result};
use log::{info, warn};

use crate::{api, config, connect, ipc, manifest, netlock, options, pinger, server, wireguard};
use super::State;

/// Enable the persistent lock by loading lock.nft rules with nft -f.
pub(super) fn dispatch_lock_enable() -> Result<()> {
    if !std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists() {
        anyhow::bail!("persistent lock not installed -- run `airvpn-rs lock install` first");
    }
    if netlock::is_persist_active() {
        return Ok(());
    }
    let output = std::process::Command::new("nft")
        .args(["-f", netlock::PERSISTENT_RULES_PATH])
        .output()
        .context("failed to run nft")?;
    if !output.status.success() {
        anyhow::bail!(
            "nft -f failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Install the persistent lock: generate nftables rules, write systemd service,
/// enable and load the table.
pub(super) fn dispatch_lock_install() -> Result<String> {
    let provider_config = api::load_provider_config()?;

    // Extract bootstrap IPs from provider.json (skip hostnames — can't resolve
    // without DNS, and that's the whole point of the persistent lock)
    let bootstrap_ips: Vec<String> = provider_config
        .bootstrap_urls
        .iter()
        .filter_map(|url| connect::extract_ip_from_url(url))
        .filter(|host| host.parse::<std::net::IpAddr>().is_ok())
        .collect();

    if bootstrap_ips.is_empty() {
        anyhow::bail!("no bootstrap IPs found in provider config");
    }

    let profile_options = config::load_profile_options();
    let resolved = options::resolve(&profile_options, &std::collections::HashMap::new());
    let iface_name = {
        let v = options::get_str(&resolved, options::NETWORK_IFACE_NAME);
        if v.is_empty() { wireguard::VPN_INTERFACE } else { v }
    };
    let allowlist_ips = options::parse_allowlist_ips(
        options::get_str(&resolved, options::NETLOCK_ALLOWLIST_IPS),
    );
    let local_forward_ifaces: Vec<String> = {
        let v = options::get_str(&resolved, options::NETLOCK_LOCAL_FORWARD_IFACES);
        if v.is_empty() { vec![] } else { v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect() }
    };
    let ruleset = netlock::generate_persistent_ruleset(&bootstrap_ips, iface_name, &allowlist_ips, &local_forward_ifaces);

    // Write rules file
    std::fs::create_dir_all("/etc/airvpn-rs")
        .context("failed to create /etc/airvpn-rs")?;
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(netlock::PERSISTENT_RULES_PATH)
            .context("failed to write lock.nft")?;
        std::io::Write::write_all(&mut f, ruleset.as_bytes())
            .context("failed to write lock.nft")?;
    }
    info!("Wrote {}", netlock::PERSISTENT_RULES_PATH);

    // Write systemd service
    let service = "\
[Unit]
Description=AirVPN persistent kill switch
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nft -f /etc/airvpn-rs/lock.nft
ExecStop=/bin/sh -c 'printf \"add table inet airvpn_persist { flags owner, persist; }\\ndelete table inet airvpn_persist\\n\" | /usr/bin/nft -f -'

[Install]
WantedBy=sysinit.target
";
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o644)
            .open(netlock::PERSISTENT_SERVICE_PATH)
            .context("failed to write systemd service")?;
        std::io::Write::write_all(&mut f, service.as_bytes())
            .context("failed to write systemd service")?;
    }
    info!("Wrote {}", netlock::PERSISTENT_SERVICE_PATH);

    // Enable service
    let output = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output()
        .context("failed to run systemctl daemon-reload")?;
    if !output.status.success() {
        warn!("systemctl daemon-reload failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let output = std::process::Command::new("systemctl")
        .args(["enable", "airvpn-lock.service"])
        .output()
        .context("failed to enable service")?;
    if !output.status.success() {
        anyhow::bail!("systemctl enable failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    info!("Enabled airvpn-lock.service");

    // Load the table now. If airvpn_persist already active, delete it first
    // (owner+persist flags can only be set at table creation time).
    if netlock::is_persist_active() {
        let _ = netlock::reclaim_and_delete();
    }
    let output = std::process::Command::new("nft")
        .args(["-f", netlock::PERSISTENT_RULES_PATH])
        .output()
        .context("failed to load lock.nft")?;
    if !output.status.success() {
        anyhow::bail!("nft -f failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let ip_count = bootstrap_ips.len();
    Ok(format!("Persistent lock installed and active. {} bootstrap IPs allowlisted.", ip_count))
}

/// Uninstall the persistent lock: stop/disable systemd service, remove files,
/// delete nftables table.
pub(super) fn dispatch_lock_uninstall() -> Result<String> {
    // Stop and disable service
    let _ = std::process::Command::new("systemctl")
        .args(["stop", "airvpn-lock.service"])
        .output();
    let _ = std::process::Command::new("systemctl")
        .args(["disable", "airvpn-lock.service"])
        .output();
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();

    // Remove files
    let _ = std::fs::remove_file(netlock::PERSISTENT_SERVICE_PATH);
    let _ = std::fs::remove_file(netlock::PERSISTENT_RULES_PATH);

    // Delete persistent table if active. Safe even while VPN is running —
    // airvpn_persist and airvpn_lock are independent tables.
    if netlock::is_persist_active() {
        match netlock::reclaim_and_delete() {
            Ok(()) => {}
            Err(e) => {
                warn!("Could not delete table: {}", e);
            }
        }
    }

    Ok("Persistent lock uninstalled.".to_string())
}

/// Load all profile options from the config file.
pub(super) fn dispatch_get_profile() -> Result<std::collections::HashMap<String, String>> {
    Ok(config::load_profile_options())
}

/// Save profile options to the config file (single read-modify-write cycle).
pub(super) fn dispatch_save_profile(options: &std::collections::HashMap<String, String>) -> Result<()> {
    config::save_profile_options(options)
}

/// Score and sort servers from a cached manifest + latency cache.
/// Always sorts by score (GUI re-sorts client-side as needed).
pub(super) fn dispatch_list_servers(manifest: &manifest::Manifest, pings: &pinger::LatencyCache, scoring: &server::ScoringConfig) -> Vec<ipc::ServerInfo> {
    let mut servers: Vec<ipc::ServerInfo> = manifest
        .servers
        .iter()
        .map(|s| {
            let ping_ms_raw = pings.get(&s.name);
            let ping_ms = if ping_ms_raw < 0 {
                None
            } else {
                Some(ping_ms_raw)
            };
            let score = server::score_with_ping(s, ping_ms_raw, scoring);
            let load = server::load_perc(s) as f64;
            let warning = if !s.warning_closed.is_empty() {
                Some(s.warning_closed.clone())
            } else if !s.warning_open.is_empty() {
                Some(s.warning_open.clone())
            } else {
                None
            };
            ipc::ServerInfo {
                name: s.name.clone(),
                country_code: s.country_code.clone(),
                location: s.location.clone(),
                users: s.users,
                users_max: s.users_max,
                load_percent: load,
                bandwidth_cur: 2_i64.saturating_mul(s.bandwidth.saturating_mul(8)) / (1_000 * 1_000),
                bandwidth_max: s.bandwidth_max,
                score,
                ping_ms,
                warning,
                ipv4: s.support_ipv4,
                ipv6: s.support_ipv6,
                ips_entry: s.ips_entry.clone(),
            }
        })
        .collect();

    servers.sort_by_key(|s| s.score);

    servers
}

/// Re-populate the persistent lock's ping_allow chain from current server IPs.
/// Called after any operation that recreates the persistent table (enable, install).
pub(super) fn repopulate_ping_allow(state: &State) {
    let ips: Vec<String> = {
        let st = state.0.lock().unwrap();
        st.latency.server_ips().values().cloned().collect()
    };
    if !ips.is_empty() {
        if let Err(e) = netlock::populate_ping_allow(&ips) {
            warn!("Failed to repopulate ping_allow after lock operation: {e}");
        }
    }
}
