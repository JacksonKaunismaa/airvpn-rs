//! VPN connection lifecycle: connect, disconnect, reconnection loop.
//!
//! This module contains the main `run()` function (formerly `cmd_connect`),
//! along with disconnect helpers and supporting types that were previously
//! in main.rs.

use crate::{api, common, config, dns, ipv6, manifest, netlock, options, pinger, recovery, server, verify, wireguard};

use std::sync::atomic::Ordering;

use log::{debug, error, info, warn};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// ConnectConfig — replaces the 20+ parameters to cmd_connect
// ---------------------------------------------------------------------------

/// All CLI flags and options for the `connect` subcommand, gathered into
/// a single struct to avoid a 20-parameter function signature.
pub struct ConnectConfig {
    pub server_name: Option<String>,
    pub no_lock: bool,
    pub allow_lan: bool,
    pub no_reconnect: bool,
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub allow_server: Vec<String>,
    pub deny_server: Vec<String>,
    pub allow_country: Vec<String>,
    pub deny_country: Vec<String>,
    pub no_verify: bool,
    pub no_lock_last: bool,
    pub no_start_last: bool,
    pub cli_ipv6_mode: Option<String>,
    pub cli_dns_servers: Vec<String>,
    pub event_tx: std::sync::mpsc::Sender<crate::ipc::EngineEvent>,
    /// Pre-populated latency cache from the background pinger.
    pub cached_latency: pinger::LatencyCache,
    /// Cached manifest from the background manifest refresh loop.
    pub manifest: manifest::Manifest,
    /// Pre-resolved options (defaults -> profile -> session overrides).
    pub resolved: std::collections::HashMap<String, String>,
}

/// Emit an engine event to the event channel.
/// For CLI the receiver is immediately dropped, so send() returns Err — ignored.
/// For the helper daemon the receiver forwards events to the GUI over IPC.
fn emit(config: &ConnectConfig, event: crate::ipc::EngineEvent) {
    let _ = config.event_tx.send(event);
}

// ---------------------------------------------------------------------------
// IPv6 mode (Eddie: network.ipv6.mode)
// ---------------------------------------------------------------------------

/// IPv6 mode matching Eddie's `network.ipv6.mode` setting.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Ipv6Mode {
    /// Always route IPv6 through the VPN tunnel.
    In,
    /// Route IPv6 through tunnel if server supports it, block otherwise (Eddie default).
    InBlock,
    /// Always block IPv6.
    Block,
}

impl Ipv6Mode {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "in" => Ok(Ipv6Mode::In),
            "in-block" => Ok(Ipv6Mode::InBlock),
            "block" => Ok(Ipv6Mode::Block),
            _ => anyhow::bail!("invalid --ipv6-mode '{}': expected 'in', 'in-block', or 'block'", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Reset levels (Eddie: Session.cs)
// ---------------------------------------------------------------------------

/// Determines what happens when a connection ends or fails.
///
/// Mirrors Eddie's `m_reset` string values ("", "RETRY", "ERROR", "SWITCH", "FATAL")
/// from Session.cs, but as a proper enum.
#[allow(dead_code)] // Switch is defined for Eddie protocol completeness
enum ResetLevel {
    /// User requested disconnect (Ctrl+C / SIGTERM). Clean exit.
    None,
    /// Retry the same server (Eddie: "RETRY"). Short delay.
    Retry,
    /// Server error — penalize and rotate (Eddie: "ERROR" + Penality += penality_on_error).
    Error,
    /// Immediate server switch (Eddie: "SWITCH"). No delay.
    Switch,
    /// Fatal error — give up entirely (Eddie: "FATAL").
    Fatal,
}

// ---------------------------------------------------------------------------
// Pre-flight checks
// ---------------------------------------------------------------------------

/// Verify system prerequisites before connecting.
///
/// Checks that we're running as root (needed for nft and wg/ip) and that
/// required binaries are in PATH.
pub fn preflight_checks() -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("must run as root (need nft + wg + ip access)");
    }
    if std::process::Command::new("wg").arg("--version").output().is_err() {
        anyhow::bail!("wg (wireguard-tools) not found in PATH");
    }
    if std::process::Command::new("nft").arg("--version").output().is_err() {
        anyhow::bail!("nft not found in PATH");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Disconnect helpers
// ---------------------------------------------------------------------------

/// Full disconnect: tear down WireGuard, DNS, netlock, and IPv6 blocking.
///
/// Used by both `cmd_connect` (on clean shutdown) and `cmd_disconnect` (external command).
/// `server_route_ips` and `original_gw` are used to clean up the /32 host routes
/// added for the background pinger. Pass empty slices/strings if not available.
pub fn cmd_disconnect_internal(config_path: &str, iface: &str, lock_active: bool, blocked_ipv6: &[String], endpoint_ip: &str, server_route_ips: &[String], original_gw: &str) -> anyhow::Result<()> {
    // 1. Remove interface-specific nft rules before deactivating table
    if lock_active && !iface.is_empty() {
        let _ = netlock::deallow_interface(iface);
    }
    // 1b. Remove /32 server host routes (background pinger routes)
    if !server_route_ips.is_empty() && !original_gw.is_empty() {
        let _ = wireguard::remove_server_host_routes(server_route_ips, original_gw);
    }
    // 2. Tear down WireGuard (also tears down routing + endpoint host route)
    let _ = wireguard::disconnect(config_path, endpoint_ip, iface);
    // 3. Restore DNS
    let _ = dns::deactivate();
    dns::flush();
    // 4. Remove netlock
    if lock_active {
        let _ = netlock::deactivate();
    }
    // 5. Restore IPv6 (AFTER netlock is gone — avoids window where IPv6 is live
    //    but firewall rules have stale state)
    ipv6::restore(blocked_ipv6);
    // 6. Remove state
    let _ = recovery::remove();
    info!("Disconnected.");
    Ok(())
}

/// Partial disconnect: tear down WireGuard only, keeping netlock, DNS, and IPv6
/// blocking active. Used during reconnection to avoid a leak window.
///
/// DNS is intentionally NOT deactivated here. Restoring the original resolv.conf
/// during reconnection would leak DNS queries to the pre-VPN DNS server (e.g., a
/// LAN router at 192.168.1.1 when --allow-lan is active). The VPN DNS config is
/// left in place; dns::activate() will overwrite it when the next connection
/// succeeds. DNS is only fully deactivated during cmd_disconnect_internal().
pub fn partial_disconnect(config_path: &str, iface: &str, lock_active: bool, endpoint_ip: &str) -> anyhow::Result<()> {
    // 1. Remove interface-specific nft rules (but keep the base netlock table)
    if lock_active && !iface.is_empty() {
        let _ = netlock::deallow_interface(iface);
    }
    // 2. Tear down WireGuard
    let _ = wireguard::disconnect(config_path, endpoint_ip, iface);
    // NOTE: DNS is intentionally kept active — deactivating would restore the
    // original resolv.conf, leaking queries through --allow-lan LAN rules.
    // netlock base table and IPv6 blocking also remain active — no leak window.
    Ok(())
}


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sleep for `secs` seconds, checking the shutdown flag each second.
///
/// Returns early if the shutdown signal is received, so reconnection delays
/// don't prevent responsive Ctrl+C handling.
fn interruptible_sleep(shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>, secs: u64) {
    for _ in 0..secs {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Extract the host (IP or hostname) from a URL like "http://63.33.78.166"
/// or "http://[2a03:b0c0::1]" or "http://bootme.org".
///
/// Handles IPv6 bracket notation: returns the bare address without brackets.
pub fn extract_ip_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Handle IPv6 bracket notation: [addr] or [addr]:port
    if without_scheme.starts_with('[') {
        let end = without_scheme.find(']')?;
        let addr = &without_scheme[1..end];
        return if addr.is_empty() { None } else { Some(addr.to_string()) };
    }
    // IPv4 or hostname: take everything before the first '/' or ':' (port)
    let host = without_scheme
        .split('/')
        .next()?
        .split(':')
        .next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Resolve a hostname to IP addresses via DNS.
///
/// Eddie resolves all bootstrap hostnames to IPs before activating netlock
/// (NetworkLockManager.cs:132-135) so that hostname-based bootstrap URLs
/// (e.g. "bootme.org") are properly allowlisted in the firewall rules.
/// Without this, classify_ip() silently skips hostnames and the auth API
/// call fails through the lock.
fn resolve_bootstrap_host(host: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    match (host, 443).to_socket_addrs() {
        Ok(addrs) => addrs.map(|a| a.ip().to_string()).collect(),
        Err(e) => {
            warn!("failed to resolve bootstrap host {}: {}", host, e);
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// Connect — sub-functions and parameter structs
// ---------------------------------------------------------------------------

/// Resolved session parameters that are constant for the entire session.
///
/// Computed once before the reconnection loop from CLI flags, profile options,
/// and system state. Passed by reference to sub-functions.
struct SessionParams {
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    nonce: u64,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    ipv6_mode: Ipv6Mode,
    custom_dns_ips: Vec<String>,
    blocked_ipv6_ifaces: Vec<String>,
    scoring: server::ScoringConfig,
    profile_options: std::collections::HashMap<String, String>,
}

/// Pre-flight checks and orphaned state cleanup.
///
/// Verifies root, wg, nft are available, then cleans up orphaned DNS backups,
/// nftables tables, and WireGuard config files from crashed sessions.
fn preflight_and_cleanup() -> anyhow::Result<()> {
    // 0. Pre-flight checks (root, wg, nft)
    preflight_checks()?;

    // Unconditional cleanup: restore orphaned state from SIGKILL (Eddie: OnRecoveryAlways).
    // Check once whether another airvpn instance is running — if so, skip all cleanup.
    let no_running_instance = recovery::load()
        .ok()
        .flatten()
        .is_none_or(|s| !recovery::is_pid_alive(s.pid));

    if no_running_instance {
        // Restore orphaned DNS backup
        let dns_backup = std::path::Path::new("/etc/resolv.conf.airvpn-rs");
        if dns_backup.exists() {
            warn!("Restoring orphaned DNS backup...");
            let _ = dns::deactivate();
        }

        // Remove orphaned nftables table
        if netlock::is_active() {
            warn!("Removing orphaned nftables table...");
            let _ = netlock::deactivate();
        }

        // Cleanup orphaned WireGuard config files (contain private key material).
        // Only scan /run/airvpn-rs/ (our config directory) — never /tmp (symlink attack surface).
        if let Ok(entries) = std::fs::read_dir("/run/airvpn-rs") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if (name == "avpn0.conf" || name.starts_with("avpn-")) && name.ends_with(".conf") {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    // 1. Check for stale state / running instance
    recovery::check_and_recover()?;

    Ok(())
}

/// Resolve all session-constant parameters from CLI flags, profile, and system state.
///
/// Installs the signal handler, resolves credentials, IPv6 mode,
/// custom DNS, and blocks IPv6 on all interfaces.
fn resolve_session(config: &ConnectConfig) -> anyhow::Result<SessionParams> {
    // Install signal handler EARLY — before any infrastructure changes
    // so Ctrl+C / SIGTERM during netlock/WireGuard/DNS setup sets the flag
    // instead of killing the process with no cleanup.
    let shutdown = recovery::setup_signal_handler()?;
    let nonce = recovery::generate_nonce();

    // Credentials arrive pre-resolved from the caller (CLI or helper daemon).
    // Wrapped in Zeroizing to clear from memory on drop.
    let username = config.username.clone();
    let password = config.password.clone();

    // All options are pre-resolved by the helper (defaults -> profile -> overrides).
    // No need to load the profile again here.

    // IPv6 mode from pre-resolved options
    let ipv6_mode = {
        let mode_str = options::get_str(&config.resolved, options::NETWORK_IPV6_MODE);
        let mode_str = if mode_str.is_empty() { "in-block" } else { mode_str };
        Ipv6Mode::parse(mode_str)?
    };
    info!("IPv6 mode: {:?}", ipv6_mode);

    // Custom DNS from pre-resolved options
    let custom_dns_ips = options::get_list(&config.resolved, options::DNS_SERVERS);
    if !custom_dns_ips.is_empty() {
        // Validate all custom DNS IPs upfront
        for ip in &custom_dns_ips {
            ip.parse::<std::net::IpAddr>()
                .map_err(|_| anyhow::anyhow!("invalid DNS server IP: {}", ip))?;
        }
        info!("Custom DNS servers: {}", custom_dns_ips.join(", "));
    }

    // Block IPv6 on all interfaces ONCE before the main loop.
    // Always blocks everything (including default) regardless of ipv6_mode.
    // In "in" mode, IPv6 is selectively re-enabled on just the WG interface
    // after creation — this prevents any race where a non-VPN interface gets IPv6.
    // Done here rather than inside the loop because ipv6::block_all() returns
    // an empty list when interfaces are already blocked. Calling it again on
    // reconnection would overwrite the recovery state with an empty list,
    // losing the original blocked interfaces needed for crash recovery.
    let blocked_ipv6_ifaces = ipv6::block_all();
    if !blocked_ipv6_ifaces.is_empty() {
        info!("IPv6 disabled on {} interfaces", blocked_ipv6_ifaces.len());
    }

    // Scoring config from pre-resolved options (score type + all factors)
    let scoring = server::ScoringConfig::from_options(&config.resolved);

    Ok(SessionParams {
        shutdown,
        nonce,
        username,
        password,
        ipv6_mode,
        custom_dns_ips,
        blocked_ipv6_ifaces,
        scoring,
        profile_options: config.resolved.clone(),
    })
}

/// Mutable session data: manifest, user info, filtered servers, ping results,
/// and lock/start-last preferences. Refreshed on reconnection.
struct SessionData {
    manifest: manifest::Manifest,
    user_info: manifest::UserInfo,
    filtered_servers: Vec<manifest::Server>,
    ping_results: pinger::LatencyCache,
    lock_last: bool,
    start_last_name: Option<String>,
}

/// Fetch user data (WireGuard keys) from AirVPN API.
fn fetch_user(
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    http_timeout_secs: u64,
) -> anyhow::Result<manifest::UserInfo> {
    info!("Fetching user data (WireGuard keys)...");
    let user_xml = api::fetch_user_with_urls_timeout(provider_config, &params.username, &params.password, &[], http_timeout_secs)?;
    let user_info = manifest::parse_user(&user_xml)?;
    debug!("User info: login={}, {} WireGuard keys", user_info.login, user_info.keys.len());
    Ok(user_info)
}

/// Check account status from the UserInfo response.
///
/// The AirVPN API sets a `message` attribute on the `<user>` element when there
/// is an account-level issue (expired subscription, renewal needed, etc.).
/// If a message is present and `connections.allow_anyway` is false, this function
/// returns an error with a clear explanation. If `allow_anyway` is true, it logs
/// a warning and proceeds.
///
/// Also checks that WireGuard keys are available — expired accounts typically
/// have no keys, which would cause a cryptic WireGuard error downstream.
fn check_account_status(
    user_info: &manifest::UserInfo,
    resolved: &std::collections::HashMap<String, String>,
) -> anyhow::Result<()> {
    let allow_anyway = options::get_bool(resolved, options::CONNECTIONS_ALLOW_ANYWAY);

    if !user_info.message.is_empty() {
        if allow_anyway {
            warn!(
                "Account warning from server: {} (proceeding because connections.allow_anyway=true)",
                user_info.message,
            );
        } else {
            anyhow::bail!(
                "Account issue: {}. \
                 Set connections.allow_anyway=true in your profile to connect anyway.",
                user_info.message,
            );
        }
    }

    if user_info.keys.is_empty() {
        if allow_anyway {
            warn!("No WireGuard keys found — account may be expired or inactive (proceeding because connections.allow_anyway=true)");
        } else {
            anyhow::bail!(
                "No WireGuard keys found — your AirVPN subscription may be expired or inactive. \
                 Check your account at https://airvpn.org or set connections.allow_anyway=true to attempt connection anyway."
            );
        }
    }

    Ok(())
}

/// Select a WireGuard key by name from the user's device list.
///
/// Matches the `key` profile option (Eddie: `key`, default "Default").
/// Falls back to the first key with a warning if the named key is not found.
fn select_key<'a>(
    keys: &'a [manifest::WireGuardKey],
    resolved: &std::collections::HashMap<String, String>,
) -> Option<&'a manifest::WireGuardKey> {
    if keys.is_empty() {
        return None;
    }
    let key_name = options::get_str(resolved, options::KEY);
    if key_name.is_empty() || key_name.eq_ignore_ascii_case("default") {
        // "Default" matches the first key (standard AirVPN behavior)
        return keys.first();
    }
    // Match by exact name
    if let Some(k) = keys.iter().find(|k| k.name == key_name) {
        info!("Using WireGuard key/device: {}", k.name);
        return Some(k);
    }
    // Case-insensitive fallback
    if let Some(k) = keys.iter().find(|k| k.name.eq_ignore_ascii_case(key_name)) {
        info!("Using WireGuard key/device: {} (case-insensitive match for '{}')", k.name, key_name);
        return Some(k);
    }
    let available: Vec<&str> = keys.iter().map(|k| k.name.as_str()).collect();
    warn!(
        "Key '{}' not found, falling back to first key '{}'. Available keys: {:?}",
        key_name,
        keys[0].name,
        available,
    );
    keys.first()
}

/// Fetch initial data, filter servers, resolve preferences.
///
/// Uses the cached manifest from SharedState (populated by the background
/// manifest loop) instead of fetching its own. Only user data (WireGuard
/// keys) is fetched fresh per-connect.
fn fetch_initial_data(
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    config: &ConnectConfig,
) -> anyhow::Result<SessionData> {
    emit(config, crate::ipc::EngineEvent::Log {
        level: "info".into(),
        message: format!("Using cached server list ({} servers)", config.manifest.servers.len()),
    });

    // Fetch user info (WG keys — needed fresh per-connect)
    let http_timeout_secs = options::get_u64(&config.resolved, options::HTTP_TIMEOUT);
    let user_info = fetch_user(provider_config, params, http_timeout_secs)?;

    // Check account status before proceeding — expired accounts get a clear
    // error instead of a cryptic WireGuard failure downstream.
    check_account_status(&user_info, &config.resolved)?;

    // Server filtering (Eddie: GetConnections allow/deny filtering)
    let filtered_servers: Vec<manifest::Server> = server::filter_servers(
        &config.manifest.servers,
        &config.allow_server,
        &config.deny_server,
        &config.allow_country,
        &config.deny_country,
    )
    .into_iter()
    .cloned()
    .collect();
    if filtered_servers.is_empty() {
        anyhow::bail!("no servers match the allow/deny filters");
    }
    let has_filters = !config.allow_server.is_empty()
        || !config.deny_server.is_empty()
        || !config.allow_country.is_empty()
        || !config.deny_country.is_empty();
    if has_filters {
        info!(
            "Filters applied: {} of {} servers eligible",
            filtered_servers.len(),
            config.manifest.servers.len()
        );
    }

    // Resolve lock_last / start_last from profile options BEFORE pinging,
    // so we can skip pinging when we already know which server to use.
    let lock_last = !config.no_lock_last
        && params.profile_options
            .get("servers.locklast")
            .is_some_and(|v| v == "True"); // default false (matches Eddie); network-down detection handles WiFi drops
    let start_last = !config.no_start_last
        && params.profile_options
            .get("servers.startlast")
            .is_some_and(|v| v == "True"); // default false (matches Eddie)

    let start_last_name: Option<String> = if config.server_name.is_some() {
        None
    } else if start_last {
        params.profile_options.get("servers.last").and_then(|hash| {
            let names: Vec<&str> = filtered_servers.iter().map(|s| s.name.as_str()).collect();
            let resolved = config::reverse_server_hash(hash, &names);
            if let Some(ref name) = resolved {
                info!("Resuming last server: {} (servers.startlast)", name);
            }
            resolved
        })
    } else {
        None
    };

    // Latency data comes from the background pinger. On first-ever connect the
    // cache will be empty and ping simply contributes 0 to scoring — that's fine.
    let ping_results = config.cached_latency.clone();

    Ok(SessionData {
        manifest: config.manifest.clone(),
        user_info,
        filtered_servers,
        ping_results,
        lock_last,
        start_last_name,
    })
}

/// Re-fetch manifest and user data on reconnection (2nd+ iteration).
///
/// Non-fatal: if the re-fetch fails (e.g. network disrupted during
/// reconnection), we fall back to the existing manifest data.
fn refresh_manifest_if_needed(
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    data: &mut SessionData,
    config: &ConnectConfig,
) {
    let http_timeout_secs = options::get_u64(&config.resolved, options::HTTP_TIMEOUT);
    info!("Re-fetching manifest for updated server data...");
    match api::fetch_manifest_with_timeout(provider_config, &params.username, &params.password, http_timeout_secs) {
        Ok(new_xml) => match manifest::parse_manifest(&new_xml) {
            Ok(new_manifest) => {
                let new_filtered: Vec<manifest::Server> = server::filter_servers(
                    &new_manifest.servers,
                    &config.allow_server,
                    &config.deny_server,
                    &config.allow_country,
                    &config.deny_country,
                )
                .into_iter()
                .cloned()
                .collect();
                if new_filtered.is_empty() {
                    warn!("Re-fetched manifest has no servers matching filters, keeping previous data");
                } else {
                    info!(
                        "Manifest refreshed: {} servers ({} after filters)",
                        new_manifest.servers.len(),
                        new_filtered.len(),
                    );
                    if let (Some(modulus), Some(exponent)) = (&new_manifest.rsa_modulus, &new_manifest.rsa_exponent) {
                        debug!("Updating RSA key from re-fetched manifest");
                        provider_config.rsa_modulus = modulus.clone();
                        provider_config.rsa_exponent = exponent.clone();
                    }
                    data.filtered_servers = new_filtered;
                    data.manifest = new_manifest;
                }
            }
            Err(e) => warn!("Failed to parse re-fetched manifest, using stale data: {:#}", e),
        },
        Err(e) => warn!("Failed to re-fetch manifest, using stale data: {:#}", e),
    }
    // Also refresh user data (WireGuard keys may have changed)
    match api::fetch_user_with_urls_timeout(provider_config, &params.username, &params.password, &data.manifest.bootstrap_urls, http_timeout_secs) {
        Ok(new_user_xml) => match manifest::parse_user(&new_user_xml) {
            Ok(new_user) => {
                data.user_info = new_user;
            }
            Err(e) => warn!("Failed to parse re-fetched user data, using stale data: {:#}", e),
        },
        Err(e) => warn!("Failed to re-fetch user data, using stale data: {:#}", e),
    }
}

/// Monitor loop: checks interface, handshake, DNS, kill switch every 1s.
///
/// Returns the ResetLevel when the connection ends or a problem is detected.
fn run_monitor_loop(
    shutdown: &std::sync::atomic::AtomicBool,
    iface: &str,
    no_lock: bool,
    dns_ipv4: &str,
    dns_ipv6: &str,
    handshake_timeout_connected: u64,
) -> ResetLevel {
    let mut dns_fail_count: u32 = 0;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!("Disconnecting...");
            break ResetLevel::None;
        }

        if !wireguard::is_connected(iface) {
            error!("WireGuard interface {} disappeared!", iface);
            break ResetLevel::Error;
        }

        if wireguard::is_handshake_stale(iface, handshake_timeout_connected) {
            error!("WireGuard handshake stale (>{}s) -- tunnel may be dead", handshake_timeout_connected);
            break ResetLevel::Error;
        }

        if !no_lock && !netlock::is_active() {
            error!("Kill switch nftables table deleted externally! Triggering reconnection to restore it.");
            break ResetLevel::Error;
        }

        match dns::check_and_reapply(dns_ipv4, dns_ipv6, iface) {
            Ok(_) => { dns_fail_count = 0; }
            Err(e) => {
                dns_fail_count += 1;
                warn!("DNS re-apply failed ({} consecutive): {:#}", dns_fail_count, e);
                if dns_fail_count >= 10 {
                    error!(
                        "DNS re-apply failed {} consecutive times, triggering reconnection",
                        dns_fail_count,
                    );
                    break ResetLevel::Error;
                }
            }
        }

        if !dns::verify_resolv_conf(dns_ipv4, dns_ipv6, std::path::Path::new("/etc/resolv.conf")) {
            warn!("resolv.conf contains non-VPN nameservers — potential DNS leak (check_and_reapply should fix on next cycle)");
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Activate the session network lock with the given server entry IPs.
///
/// Builds full allowlist (server + bootstrap IPs with hostname resolution)
/// and activates the nftables table.
fn activate_netlock(
    params: &SessionParams,
    config: &ConnectConfig,
    provider_config: &api::ProviderConfig,
    manifest_bootstrap_urls: &[String],
    server_entry_ips: &[String],
) -> anyhow::Result<()> {
    info!("Activating network lock...");
    emit(config, crate::ipc::EngineEvent::Log {
        level: "info".into(),
        message: "Activating network lock...".into(),
    });
    let mut allowed_ips: Vec<String> = server_entry_ips.to_vec();
    for url in &provider_config.bootstrap_urls {
        if let Some(host) = extract_ip_from_url(url) {
            allowed_ips.push(host);
        }
    }
    for url in manifest_bootstrap_urls {
        if let Some(host) = extract_ip_from_url(url) {
            allowed_ips.push(host);
        }
    }
    // Resolve hostnames to IPs before netlock activation
    let mut resolved_ips: Vec<String> = Vec::new();
    for entry in &allowed_ips {
        if entry.parse::<std::net::IpAddr>().is_ok() {
            resolved_ips.push(entry.clone());
        } else {
            let addrs = resolve_bootstrap_host(entry);
            if addrs.is_empty() {
                warn!("dropping unresolvable bootstrap host from allowlist: {}", entry);
            } else {
                debug!("resolved bootstrap host {} -> {:?}", entry, addrs);
                resolved_ips.extend(addrs);
            }
        }
    }
    let allowed_ips = resolved_ips;
    let iface_name = {
        let v = options::get_str(&config.resolved, options::NETWORK_IFACE_NAME);
        if v.is_empty() { wireguard::VPN_INTERFACE } else { v }
    };
    let lock_config = netlock::NetlockConfig {
        allow_lan: config.allow_lan,
        allow_dhcp: true,
        allow_ping: options::get_bool(&config.resolved, options::NETLOCK_ALLOW_PING),
        allow_ipv4ipv6translation: true,
        allowed_ips_incoming: vec![],
        allowed_ips_outgoing: allowed_ips,
        incoming_policy_accept: options::get_str(&config.resolved, options::NETLOCK_INCOMING) == "allow",
        iface_name: iface_name.to_string(),
    };
    netlock::activate(&lock_config)?;
    info!("Network lock active (dedicated nftables table)");
    debug!(
        "Network lock: {} outgoing IPs whitelisted, allow_lan={}",
        lock_config.allowed_ips_outgoing.len(),
        lock_config.allow_lan,
    );
    recovery::save(&recovery::State {
        lock_active: true,
        wg_interface: String::new(),
        wg_config_path: String::new(),
        dns_ipv4: String::new(),
        dns_ipv6: String::new(),
        pid: std::process::id(),
        blocked_ipv6_ifaces: params.blocked_ipv6_ifaces.clone(),
        endpoint_ip: String::new(),
        nonce: params.nonce,
        resolv_was_immutable: dns::was_immutable(),
    })?;
    Ok(())
}

/// Post-connect setup: allow VPN interface in netlock, activate DNS, save credentials
/// and recovery state. Returns Ok(()) or an error (caller handles cleanup).
#[allow(clippy::too_many_arguments)]
fn post_connect_setup(
    params: &SessionParams,
    config: &ConnectConfig,
    server_name: &str,
    config_path: &str,
    iface: &str,
    endpoint_ip: &str,
    effective_dns_ipv4: &str,
    effective_dns_ipv6: &str,
) -> anyhow::Result<()> {
    if !config.no_lock {
        emit(config, crate::ipc::EngineEvent::Log {
            level: "info".into(),
            message: "Configuring network lock...".into(),
        });
        netlock::allow_interface(iface)?;
    }
    if params.shutdown.load(Ordering::Relaxed) {
        anyhow::bail!("shutdown requested during setup");
    }
    emit(config, crate::ipc::EngineEvent::Log {
        level: "info".into(),
        message: "Configuring DNS...".into(),
    });
    debug!("Activating DNS: ipv4={}, ipv6={}, iface={}", effective_dns_ipv4, effective_dns_ipv6, iface);
    dns::activate(effective_dns_ipv4, effective_dns_ipv6, iface)?;
    info!("DNS configured: {}{}", effective_dns_ipv4,
          if effective_dns_ipv6.is_empty() { String::new() } else { format!(", {}", effective_dns_ipv6) });
    if !dns::verify_resolv_conf(effective_dns_ipv4, effective_dns_ipv6, std::path::Path::new("/etc/resolv.conf")) {
        warn!("resolv.conf contains non-VPN nameservers after DNS activation — potential DNS leak");
    }
    if let Err(e) = config::save_credentials(&params.username, &params.password) {
        warn!("failed to save credentials: {:#}", e);
    }
    if let Err(e) = config::save_profile_option(
        "servers.last",
        &config::sha256_hex(server_name),
    ) {
        warn!("failed to save servers.last: {:#}", e);
    }
    save_recovery(params, config.no_lock, iface, config_path, effective_dns_ipv4, effective_dns_ipv6, endpoint_ip)?;
    Ok(())
}

/// Penalize server and compute backoff, with network-down and lock_last awareness.
///
/// Returns whether the server was penalized (and forced_server cleared). When
/// `lock_last` is true or network is down, the server is not penalized and
/// forced_server remains unchanged.
fn handle_connection_failure(
    server_name: &str,
    lock_last: bool,
    check_network: bool,
    penalties: &mut server::ServerPenalties,
    forced_server: &mut Option<String>,
    consecutive_failures: &mut u32,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    penality_on_error: i64,
) {
    let network_down = check_network && !wireguard::has_default_gateway();
    if network_down || lock_last {
        if network_down {
            warn!("Network appears down (no default gateway). Will retry same server.");
        }
        // Don't penalize, don't clear forced_server (retry same server)
    } else {
        penalties.penalize(server_name, penality_on_error);
        *forced_server = None;
    }
    *consecutive_failures += 1;
    let backoff_secs = common::backoff_secs(*consecutive_failures);
    if network_down || lock_last {
        warn!("Reconnecting in {}s (retrying {})...", backoff_secs, server_name);
    } else {
        warn!("Reconnecting in {}s (penalized {})...", backoff_secs, server_name);
    }
    interruptible_sleep(shutdown, backoff_secs);
}

/// Bail out: clean up netlock, IPv6, and recovery state before returning an error.
/// Used when --no-reconnect prevents continuing after a failure.
fn cleanup_and_bail(no_lock: bool, blocked_ipv6_ifaces: &[String]) {
    if !no_lock { let _ = netlock::deactivate(); }
    ipv6::restore(blocked_ipv6_ifaces);
    let _ = recovery::remove();
}

// ---------------------------------------------------------------------------
// Connect — main entry point
// ---------------------------------------------------------------------------

/// Verify tunnel, DNS, and resolv.conf after connection is established.
///
/// Returns true if verification passed (or was skipped), false if it failed.
fn verify_connection(
    shutdown: &std::sync::atomic::AtomicBool,
    manifest: &manifest::Manifest,
    server_ref: &manifest::Server,
    wg_ipv4: &str,
    dns_ipv4: &str,
    dns_ipv6: &str,
    checking_ntry: u32,
) -> bool {
    let check_domain = manifest.check_domain.as_str();
    let check_dns_query = manifest.check_dns_query.as_str();
    let check_protocol = manifest.check_protocol.as_str();
    let exit_ip = server_ref.ips_exit.first().map(|s| s.as_str()).unwrap_or("");
    debug!("Verification: check_domain={:?}, check_dns_query={:?}, exit_ip={:?}, server={}", check_domain, check_dns_query, exit_ip, server_ref.name);

    info!("Verifying tunnel...");
    match verify::check_tunnel(&server_ref.name, wg_ipv4, check_domain, exit_ip, check_protocol, checking_ntry) {
        Ok(()) => info!("Tunnel verified."),
        Err(e) => {
            warn!("Tunnel verification failed: {:#}", e);
            return false;
        }
    }

    if shutdown.load(Ordering::Relaxed) { return true; }

    info!("Verifying DNS...");
    match verify::check_dns(&server_ref.name, check_domain, exit_ip, check_dns_query, check_protocol, checking_ntry) {
        Ok(()) => info!("DNS verified."),
        Err(e) => {
            warn!("DNS verification failed: {:#}", e);
            return false;
        }
    }

    if shutdown.load(Ordering::Relaxed) { return true; }

    if !dns::verify_resolv_conf(dns_ipv4, dns_ipv6, std::path::Path::new("/etc/resolv.conf")) {
        warn!("resolv.conf contains non-VPN nameservers — potential DNS leak");
        return false;
    }

    true
}

/// Compute effective DNS servers for a connection (server-specific).
///
/// Custom dns.servers override AirVPN's DNS. IPv6 DNS is only included when
/// the server supports it according to the IPv6 mode.
fn resolve_effective_dns(
    custom_dns_ips: &[String],
    wg_key: &manifest::WireGuardKey,
    ipv6_enabled: bool,
) -> (String, String) {
    if !custom_dns_ips.is_empty() {
        let ipv4 = custom_dns_ips.iter()
            .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
            .cloned().unwrap_or_default();
        let ipv6 = if ipv6_enabled {
            custom_dns_ips.iter()
                .find(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok())
                .cloned().unwrap_or_default()
        } else {
            String::new()
        };
        (ipv4, ipv6)
    } else {
        let ipv6 = if ipv6_enabled { wg_key.wg_dns_ipv6.clone() } else { String::new() };
        (wg_key.wg_dns_ipv4.clone(), ipv6)
    }
}

/// Handle the reset level after the monitor loop detects a connection end.
///
/// Returns Ok(true) to break the outer loop, Ok(false) to continue reconnecting.
#[allow(clippy::too_many_arguments)]
fn handle_reset_level(
    reset_level: ResetLevel,
    config: &ConnectConfig,
    params: &SessionParams,
    config_path: &str,
    iface: &str,
    endpoint_ip: &str,
    server_name: &str,
    lock_last: bool,
    penalties: &mut server::ServerPenalties,
    forced_server: &mut Option<String>,
    consecutive_failures: &mut u32,
    server_route_ips: &[String],
    original_gw: &str,
) -> anyhow::Result<bool> {
    match reset_level {
        ResetLevel::None | ResetLevel::Fatal => {
            cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, server_route_ips, original_gw)?;
            Ok(true)
        }
        ResetLevel::Error => {
            if config.no_reconnect {
                cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, server_route_ips, original_gw)?;
                warn!("Connection lost (--no-reconnect, exiting).");
                return Ok(true);
            }
            let _ = partial_disconnect(config_path, iface, !config.no_lock, endpoint_ip);
            let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
            handle_connection_failure(
                server_name, lock_last, true,
                penalties, forced_server, consecutive_failures,
                &params.shutdown, penality_on_error,
            );
            Ok(false)
        }
        ResetLevel::Retry => {
            if config.no_reconnect {
                cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, server_route_ips, original_gw)?;
                warn!("Connection lost (--no-reconnect, exiting).");
                return Ok(true);
            }
            let _ = partial_disconnect(config_path, iface, !config.no_lock, endpoint_ip);
            warn!("Retrying same server in 1s...");
            interruptible_sleep(&params.shutdown, 1);
            Ok(false)
        }
        ResetLevel::Switch => {
            if config.no_reconnect {
                cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, server_route_ips, original_gw)?;
                warn!("Server switch requested (--no-reconnect, exiting).");
                return Ok(true);
            }
            let _ = partial_disconnect(config_path, iface, !config.no_lock, endpoint_ip);
            *forced_server = None;
            info!("Switching server...");
            Ok(false)
        }
    }
}

/// Save recovery state with the current connection parameters.
fn save_recovery(
    params: &SessionParams,
    no_lock: bool,
    iface: &str,
    config_path: &str,
    dns_ipv4: &str,
    dns_ipv6: &str,
    endpoint_ip: &str,
) -> anyhow::Result<()> {
    recovery::save(&recovery::State {
        lock_active: !no_lock,
        wg_interface: iface.to_string(),
        wg_config_path: config_path.to_string(),
        dns_ipv4: dns_ipv4.to_string(),
        dns_ipv6: dns_ipv6.to_string(),
        pid: std::process::id(),
        blocked_ipv6_ifaces: params.blocked_ipv6_ifaces.clone(),
        endpoint_ip: endpoint_ip.to_string(),
        nonce: params.nonce,
        resolv_was_immutable: dns::was_immutable(),
    })
}

/// Connect to AirVPN (formerly `cmd_connect` in main.rs).
///
/// Handles the full connection lifecycle: pre-flight checks, credential
/// resolution, manifest fetch, server selection, netlock, WireGuard setup,
/// DNS configuration, verification, and the reconnection loop.
pub fn run(
    provider_config: &mut api::ProviderConfig,
    config: &ConnectConfig,
) -> anyhow::Result<()> {
    preflight_and_cleanup()?;
    let params = resolve_session(config)?;

    // Fetch initial data (manifest, user info, server filtering, ping)
    let mut data = fetch_initial_data(provider_config, &params, config)?;

    // -----------------------------------------------------------------------
    // Reconnection loop (Eddie: Session.cs outer `for (; CancelRequested == false;)`)
    //
    // servers.locklast: lock to same server within this session (never rotate)
    // servers.startlast: prefer last-used server on startup
    // --server: explicit server name overrides both
    // -----------------------------------------------------------------------

    let mut penalties = server::ServerPenalties::new();
    let mut forced_server: Option<String> = config.server_name
        .clone()
        .or(data.start_last_name.clone());
    let mut first_iteration = true;
    let mut consecutive_failures: u32 = 0;

    // Collect ALL server entry IPs for the network lock allowlist (Eddie: allowlists
    // all servers so reconnection to a different server doesn't require lock rebuild).
    let mut all_entry_ips: Vec<String> = data.filtered_servers
        .iter()
        .flat_map(|s| s.ips_entry.iter().cloned())
        .collect();

    // Activate network lock once before the loop with all server IPs.
    if !config.no_lock {
        activate_netlock(&params, config, provider_config, &data.manifest.bootstrap_urls, &all_entry_ips)?;
    }

    loop {
        // Check for shutdown before attempting connection
        if params.shutdown.load(Ordering::Relaxed) {
            info!("Shutdown requested before connection attempt.");
            break;
        }

        // Re-fetch manifest on reconnection (2nd+ iteration)
        if !first_iteration {
            refresh_manifest_if_needed(provider_config, &params, &mut data, config);
            // New servers may have appeared — rebuild allowlist and reload lock atomically.
            let new_entry_ips: Vec<String> = data.filtered_servers
                .iter()
                .flat_map(|s| s.ips_entry.iter().cloned())
                .collect();
            if new_entry_ips != all_entry_ips {
                all_entry_ips = new_entry_ips;
                if !config.no_lock {
                    if let Err(e) = activate_netlock(&params, config, provider_config, &data.manifest.bootstrap_urls, &all_entry_ips) {
                        warn!("Failed to reload netlock with updated server IPs: {}", e);
                    }
                }
            }
        }
        first_iteration = false;

        // Select WireGuard mode and key from (possibly refreshed) manifest/user data.
        let mode = match data.manifest.modes.first() {
            Some(m) => m,
            None => {
                warn!("Refreshed manifest has no WireGuard modes, cannot connect");
                interruptible_sleep(&params.shutdown, 10);
                continue;
            }
        };
        let wg_key = match select_key(&data.user_info.keys, &config.resolved) {
            Some(k) => k,
            None => {
                warn!("Refreshed user data has no WireGuard keys, cannot connect");
                interruptible_sleep(&params.shutdown, 10);
                continue;
            }
        };

        // 6. Select server (penalty-aware + ping-aware, from filtered list)
        let server_ref = server::select_server_with_penalties(
            &data.filtered_servers,
            forced_server.as_deref(),
            &penalties,
            &data.ping_results,
            &params.scoring,
        )?;
        info!(
            "Selected server: {} ({}, {})",
            server_ref.name, server_ref.location, server_ref.country_code
        );
        emit(config, crate::ipc::EngineEvent::ServerSelected {
            name: server_ref.name.clone(),
            country: server_ref.country_code.clone(),
            location: server_ref.location.clone(),
        });
        debug!(
            "Server details: name={}, group={}, entry_ips={:?}, exit_ips={:?}, score={}, bw={}/{}, users={}/{}, ipv4={}, ipv6={}",
            server_ref.name,
            server_ref.group,
            server_ref.ips_entry,
            server_ref.ips_exit,
            server::score(server_ref, &params.scoring),
            server_ref.bandwidth,
            server_ref.bandwidth_max,
            server_ref.users,
            server_ref.users_max,
            server_ref.support_ipv4,
            server_ref.support_ipv6,
        );

        // Validate server supports required protocols
        if !server_ref.support_ipv4 {
            warn!("server {} does not advertise IPv4 support", server_ref.name);
        }

        // Compute effective IPv6 for this connection (depends on server + mode)
        let ipv6_enabled = match params.ipv6_mode {
            Ipv6Mode::In => true,
            Ipv6Mode::InBlock => server_ref.support_ipv6,
            Ipv6Mode::Block => false,
        };
        if ipv6_enabled {
            info!("IPv6 enabled for {} (mode={:?}, server.support_ipv6={})",
                  server_ref.name, params.ipv6_mode, server_ref.support_ipv6);
        }
        // Effective DNS: custom dns.servers override AirVPN's DNS (Eddie: WireGuard.cs line 69).
        let (effective_dns_ipv4, effective_dns_ipv6_owned) =
            resolve_effective_dns(&params.custom_dns_ips, wg_key, ipv6_enabled);
        let dns_ipv6: &str = &effective_dns_ipv6_owned;

        // 7b. Pre-connection authorization (Eddie: Session.cs:173-218)
        let http_timeout_secs = options::get_u64(&config.resolved, options::HTTP_TIMEOUT);
        let reset_from_auth = match api::fetch_connect_with_urls_timeout(
            provider_config,
            &params.username,
            &params.password,
            &server_ref.name,
            &data.manifest.bootstrap_urls,
            http_timeout_secs,
        ) {
            Ok(api::ConnectDirective::Ok) => {
                info!("Authorizing connection... OK");
                Option::<ResetLevel>::None
            }
            Ok(api::ConnectDirective::Stop(msg)) => {
                error!("Server rejected connection: {}", msg);
                Some(ResetLevel::Fatal)
            }
            Ok(api::ConnectDirective::Next(msg)) => {
                warn!("Server says try another: {}", msg);
                Some(ResetLevel::Error)
            }
            Ok(api::ConnectDirective::Retry(msg)) => {
                warn!("Server message: {}", msg);
                Some(ResetLevel::Retry)
            }
            Err(e) => {
                warn!("pre-connection authorization failed: {:#}", e);
                Option::<ResetLevel>::None
            }
        };

        // Handle auth-level reset
        if let Some(level) = reset_from_auth {
            match level {
                ResetLevel::Fatal => {
                    cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                    anyhow::bail!("Fatal: server rejected connection");
                }
                ResetLevel::Error => {
                    // Server explicitly directed us to try another — always rotate.
                    let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
                    penalties.penalize(&server_ref.name, penality_on_error);
                    forced_server = Option::None;
                    if config.no_reconnect {
                        cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                        anyhow::bail!("Server directed to try another (--no-reconnect)");
                    }
                    warn!("Penalized {}. Trying another server in 5s...", server_ref.name);
                    interruptible_sleep(&params.shutdown, 5);
                    emit(config, crate::ipc::EngineEvent::StateChanged(
                        crate::ipc::ConnectionState::Reconnecting,
                    ));
                    continue;
                }
                ResetLevel::Retry => {
                    if config.no_reconnect {
                        cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                        anyhow::bail!("Server asked to retry (--no-reconnect)");
                    }
                    warn!("Retrying in 10s...");
                    interruptible_sleep(&params.shutdown, 10);
                    emit(config, crate::ipc::EngineEvent::StateChanged(
                        crate::ipc::ConnectionState::Reconnecting,
                    ));
                    continue;
                }
                _ => {} // None/Switch don't occur from auth
            }
        }

        // Save recovery state with blocked IPv6 interfaces
        save_recovery(&params, config.no_lock, "", "", "", "", "")?;

        // 8. Generate WireGuard config and connect
        let wg_keepalive = options::get_u64(&config.resolved, options::WG_KEEPALIVE) as u16;
        let wg_params = wireguard::generate_config(wg_key, server_ref, mode, &data.user_info, wg_keepalive)?;
        let endpoint_ip = wg_params.endpoint_ip.clone();
        debug!(
            "WireGuard config: endpoint={}, ipv4={}, ipv6={}, dns={}/{}, mode={} (keys redacted)",
            endpoint_ip,
            wg_key.wg_ipv4,
            wg_key.wg_ipv6,
            effective_dns_ipv4,
            effective_dns_ipv6_owned,
            mode.title,
        );
        info!("Connecting to {} via mode {}...", server_ref.name, mode.title);
        emit(config, crate::ipc::EngineEvent::StateChanged(
            crate::ipc::ConnectionState::Connecting,
        ));
        emit(config, crate::ipc::EngineEvent::Log {
            level: "info".into(),
            message: format!("Connecting to {} via {}...", server_ref.name, mode.title),
        });
        let wg_mtu = options::get_u64(&config.resolved, options::WG_MTU) as u16;
        let iface_name = {
            let v = options::get_str(&config.resolved, options::NETWORK_IFACE_NAME);
            if v.is_empty() { wireguard::VPN_INTERFACE } else { v }
        };
        let (config_path, iface, original_gw) = match wireguard::connect(&wg_params, ipv6_enabled, wg_mtu, iface_name) {
            Ok(result) => {
                consecutive_failures = 0;
                result
            }
            Err(e) => {
                error!("WireGuard connection failed: {:#}", e);
                if config.no_reconnect {
                    cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                    return Err(e.context("WireGuard connection failed"));
                }
                let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
                handle_connection_failure(
                    &server_ref.name, data.lock_last, true,
                    &mut penalties, &mut forced_server, &mut consecutive_failures,
                    &params.shutdown, penality_on_error,
                );
                emit(config, crate::ipc::EngineEvent::StateChanged(
                    crate::ipc::ConnectionState::Reconnecting,
                ));
                continue;
            }
        };
        save_recovery(&params, config.no_lock, &iface, &config_path, "", "", &endpoint_ip)?;
        info!("WireGuard interface: {}", iface);
        emit(config, crate::ipc::EngineEvent::Log {
            level: "info".into(),
            message: format!("WireGuard interface {} created", iface),
        });

        // Add /32 host routes for all server entry IPs via physical gateway.
        // These let the background pinger reach servers outside the tunnel.
        if let Err(e) = wireguard::add_server_host_routes(&all_entry_ips, &original_gw) {
            warn!("Failed to add server host routes (pinger may not work): {e}");
        }

        // Wait for first WireGuard handshake (Eddie: handshake_timeout_first=50s)
        info!("Waiting for handshake...");
        emit(config, crate::ipc::EngineEvent::Log {
            level: "info".into(),
            message: "Waiting for WireGuard handshake...".into(),
        });
        let handshake_timeout_first = options::get_u64(&config.resolved, options::WG_HANDSHAKE_FIRST);
        if let Err(e) = wireguard::wait_for_handshake(&iface, handshake_timeout_first) {
            error!("Handshake failed: {:#}", e);
            let _ = wireguard::disconnect(&config_path, &endpoint_ip, &iface);
            if config.no_reconnect {
                let _ = wireguard::remove_server_host_routes(&all_entry_ips, &original_gw);
                cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                return Err(e);
            }
            let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
            handle_connection_failure(
                &server_ref.name, data.lock_last, false,
                &mut penalties, &mut forced_server, &mut consecutive_failures,
                &params.shutdown, penality_on_error,
            );
            emit(config, crate::ipc::EngineEvent::StateChanged(
                crate::ipc::ConnectionState::Reconnecting,
            ));
            continue;
        }
        info!("Handshake established.");
        emit(config, crate::ipc::EngineEvent::Log {
            level: "info".into(),
            message: "Handshake established".into(),
        });

        // 9-12: Remaining setup — if any step fails, clean up and treat as fatal
        if let Err(e) = post_connect_setup(
            &params, config, &server_ref.name,
            &config_path, &iface, &endpoint_ip,
            &effective_dns_ipv4, dns_ipv6,
        ) {
            if params.shutdown.load(Ordering::Relaxed) {
                warn!("Setup interrupted by shutdown signal, disconnecting...");
                let _ = cmd_disconnect_internal(&config_path, &iface, !config.no_lock, &params.blocked_ipv6_ifaces, &endpoint_ip, &all_entry_ips, &original_gw);
                break;
            }
            error!("Setup failed after WireGuard connected: {:#}", e);
            warn!("Cleaning up...");
            let _ = cmd_disconnect_internal(&config_path, &iface, !config.no_lock, &params.blocked_ipv6_ifaces, &endpoint_ip, &all_entry_ips, &original_gw);
            return Err(e);
        }

        // 10b-10c: Post-connection verification
        if !config.no_verify && !params.shutdown.load(Ordering::Relaxed) {
            emit(config, crate::ipc::EngineEvent::Log {
                level: "info".into(),
                message: "Verifying tunnel and DNS...".into(),
            });
            let checking_ntry = options::get_u64(&config.resolved, options::CHECKING_NTRY) as u32;
            let verify_ok = verify_connection(
                &params.shutdown, &data.manifest, server_ref,
                &wg_key.wg_ipv4, &effective_dns_ipv4, dns_ipv6,
                checking_ntry,
            );
            if !verify_ok && !params.shutdown.load(Ordering::Relaxed) {
                warn!("Verification failed, treating as connection failure, reconnecting...");
                let _ = partial_disconnect(&config_path, &iface, !config.no_lock, &endpoint_ip);
                if config.no_reconnect {
                    let _ = wireguard::remove_server_host_routes(&all_entry_ips, &original_gw);
                    cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                    anyhow::bail!("Verification failed (--no-reconnect)");
                }
                let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
                handle_connection_failure(
                    &server_ref.name, data.lock_last, false,
                    &mut penalties, &mut forced_server, &mut consecutive_failures,
                    &params.shutdown, penality_on_error,
                );
                emit(config, crate::ipc::EngineEvent::StateChanged(
                    crate::ipc::ConnectionState::Reconnecting,
                ));
                continue;
            }
        }

        info!(
            "Connected to {} via {}.{}",
            server_ref.name,
            iface,
            if config.no_reconnect {
                " Press Ctrl+C to disconnect."
            } else {
                " Press Ctrl+C to disconnect. Auto-reconnect enabled."
            }
        );
        emit(config, crate::ipc::EngineEvent::StateChanged(
            crate::ipc::ConnectionState::Connected {
                server_name: server_ref.name.clone(),
                server_country: server_ref.country_code.clone(),
                server_location: server_ref.location.clone(),
            },
        ));

        // 13. Monitor loop — determines ResetLevel when connection ends
        let handshake_timeout_connected = options::get_u64(&config.resolved, options::WG_HANDSHAKE_CONNECTED);
        let reset_level = run_monitor_loop(
            &params.shutdown,
            &iface,
            config.no_lock,
            &effective_dns_ipv4,
            dns_ipv6,
            handshake_timeout_connected,
        );

        // Handle reset level (Eddie: Session.cs phase 6 cleanup + wait)
        let should_break = handle_reset_level(
            reset_level, config, &params,
            &config_path, &iface, &endpoint_ip,
            &server_ref.name, data.lock_last,
            &mut penalties, &mut forced_server, &mut consecutive_failures,
            &all_entry_ips, &original_gw,
        )?;
        if should_break {
            break;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_ip_from_url_http() {
        assert_eq!(
            extract_ip_from_url("http://63.33.78.166"),
            Some("63.33.78.166".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_url_https() {
        assert_eq!(
            extract_ip_from_url("https://1.2.3.4"),
            Some("1.2.3.4".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_url_with_path() {
        assert_eq!(
            extract_ip_from_url("http://10.0.0.1/api/v1"),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_url_with_port() {
        assert_eq!(
            extract_ip_from_url("http://10.0.0.1:8080/"),
            Some("10.0.0.1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_url_bare_ip() {
        assert_eq!(
            extract_ip_from_url("192.168.1.1"),
            Some("192.168.1.1".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_url_ipv6_brackets() {
        assert_eq!(
            extract_ip_from_url("http://[2a03:b0c0:0:1010::9b:c001]"),
            Some("2a03:b0c0:0:1010::9b:c001".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_url_hostname() {
        assert_eq!(
            extract_ip_from_url("http://bootme.org"),
            Some("bootme.org".to_string())
        );
    }

    #[test]
    fn test_extract_ip_from_bootstrap_urls() {
        // Verify it works on every actual provider config bootstrap URL
        let config = api::load_provider_config().expect("failed to load provider config");
        for url in &config.bootstrap_urls {
            let host = extract_ip_from_url(url);
            assert!(host.is_some(), "failed to extract host from {}", url);
            let host = host.unwrap();
            assert!(
                !host.is_empty(),
                "extracted empty host from '{}'",
                url
            );
        }
    }
}
