//! VPN connection lifecycle: connect, disconnect, reconnection loop.
//!
//! This module contains the main `run()` function (formerly `cmd_connect`),
//! along with disconnect helpers and supporting types that were previously
//! in main.rs.

use crate::{api, common, config, ddns, dns, duckdns, ipv6, manifest, netlock, options, pinger, recovery, server, verify, wireguard};

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
    /// External shutdown flag (helper daemon sets this on disconnect).
    /// When provided, the connect engine uses this instead of installing
    /// its own signal handler — avoids poisoning the helper's accept loop.
    pub shutdown: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
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
// IPv4 mode (Eddie: network.ipv4.mode)
// ---------------------------------------------------------------------------

/// IPv4 mode matching Eddie's `network.ipv4.mode` setting.
///
/// For WireGuard-only, only "in" (default, all IPv4 through tunnel) and "block"
/// (disable IPv4 entirely) are meaningful. Eddie's "in-out", "in-block", "out"
/// modes are OpenVPN split-tunnel concepts that don't apply to WireGuard.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Ipv4Mode {
    /// Route all IPv4 through the VPN tunnel (default).
    In,
    /// Block all IPv4 traffic (IPv6-only VPN).
    Block,
}

impl Ipv4Mode {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "in" => Ok(Ipv4Mode::In),
            "block" => Ok(Ipv4Mode::Block),
            _ => anyhow::bail!("invalid network.ipv4.mode '{}': expected 'in' or 'block'", s),
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
/// `original_gw` is used to clean up the custom "out" routes (tunnel bypass routes).
/// Pass an empty string if not available.
pub fn cmd_disconnect_internal(config_path: &str, iface: &str, lock_active: bool, blocked_ipv6: &[String], endpoint_ip: &str, original_gw: &str, custom_route_out_cidrs: &[String]) -> anyhow::Result<()> {
    // 1. Remove interface-specific nft rules before deactivating table
    if lock_active && !iface.is_empty() {
        let _ = netlock::deallow_interface(iface);
    }
    // 1c. Remove custom "out" routes (tunnel bypass routes)
    if !custom_route_out_cidrs.is_empty() && !original_gw.is_empty() {
        remove_custom_out_routes(custom_route_out_cidrs, original_gw);
    }
    // 2. Tear down WireGuard (also tears down routing + endpoint host route)
    let _ = wireguard::disconnect(config_path, endpoint_ip, iface);
    // 3. Remove netlock BEFORE restoring DNS — the session lock's policy drop
    //    blocks DNS to restored nameservers while dns::deactivate() runs slow
    //    cleanup (resolvectl/systemctl calls that fail when resolved is inactive).
    if lock_active {
        let _ = netlock::deactivate();
    }
    // 4. Restore DNS (resolv.conf, systemd-resolved if active, flush caches)
    let _ = dns::deactivate(std::path::Path::new(dns::RESOLV_CONF));
    dns::flush();
    // 5. Restore IPv6
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
// Custom route helpers
// ---------------------------------------------------------------------------

/// Add IP routes for custom "out" CIDRs via the original default gateway.
///
/// These routes bypass the VPN tunnel by sending traffic for specified CIDRs
/// through the physical interface's gateway instead of the tunnel.
fn add_custom_out_routes(cidrs: &[String], gateway: &str) {
    for cidr in cidrs {
        // Determine ip version from CIDR
        let ip_version = if cidr.contains(':') { "-6" } else { "-4" };
        let output = std::process::Command::new("ip")
            .args([ip_version, "route", "add", cidr, "via", gateway])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                info!("Custom route: {} via {} (bypass tunnel)", cidr, gateway);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // "File exists" is OK — route was already added (e.g. reconnection)
                if stderr.contains("File exists") {
                    debug!("Custom route {} already exists", cidr);
                } else {
                    warn!("Failed to add custom route {} via {}: {}", cidr, gateway, stderr.trim());
                }
            }
            Err(e) => {
                warn!("Failed to run ip route for custom route {}: {}", cidr, e);
            }
        }
    }
}

/// Remove IP routes for custom "out" CIDRs. Called during disconnect.
fn remove_custom_out_routes(cidrs: &[String], gateway: &str) {
    for cidr in cidrs {
        let ip_version = if cidr.contains(':') { "-6" } else { "-4" };
        let output = std::process::Command::new("ip")
            .args([ip_version, "route", "del", cidr, "via", gateway])
            .output();
        match output {
            Ok(o) if o.status.success() => {
                debug!("Removed custom route: {} via {}", cidr, gateway);
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // "No such process" = route already gone — not an error
                if !stderr.contains("No such process") {
                    debug!("Failed to remove custom route {} via {}: {}", cidr, gateway, stderr.trim());
                }
            }
            Err(e) => {
                debug!("Failed to run ip route del for custom route {}: {}", cidr, e);
            }
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
    ipv4_mode: Ipv4Mode,
    custom_dns_ips: Vec<String>,
    blocked_ipv6_ifaces: Vec<String>,
    scoring: server::ScoringConfig,
    profile_options: std::collections::HashMap<String, String>,
    dns_mode: dns::DnsMode,
    dns_services: Vec<String>,
    /// Physical NIC to bind WireGuard endpoint traffic to (empty = system default).
    entry_iface: String,
    /// Verify routing table after connect.
    check_route: bool,
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
            let _ = dns::deactivate(std::path::Path::new(dns::RESOLV_CONF));
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
    // Use externally-provided shutdown flag (helper daemon) or install our own
    // signal handler (standalone CLI). The helper provides a per-connection flag
    // so that disconnect doesn't poison the helper's accept loop.
    let shutdown = match &config.shutdown {
        Some(flag) => flag.clone(),
        None => recovery::setup_signal_handler()?,
    };
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

    // IPv4 mode from pre-resolved options
    let ipv4_mode = {
        let mode_str = options::get_str(&config.resolved, options::NETWORK_IPV4_MODE);
        let mode_str = if mode_str.is_empty() { "in" } else { mode_str };
        Ipv4Mode::parse(mode_str)?
    };
    if ipv4_mode == Ipv4Mode::Block {
        info!("IPv4 mode: Block (IPv6-only VPN)");
    }

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
    let blocked_ipv6_ifaces = match ipv6::block_all() {
        Ok(ifaces) => ifaces,
        Err(e) => {
            // IPv6 could not be confirmed disabled on every interface. With the
            // kill switch on, nftables drops non-tunnel IPv6 egress, so this is a
            // degraded-but-backstopped state — warn and continue. With no kill
            // switch there is nothing to stop an IPv6 leak, so fail closed:
            // refuse to connect rather than come up while leaking.
            if config.no_lock {
                return Err(e.context(
                    "refusing to connect: IPv6 could not be blocked and the kill switch is disabled (would risk an IPv6 leak)",
                ));
            }
            warn!(
                "IPv6 block incomplete ({:#}) — relying on the nftables kill switch to drop non-tunnel IPv6",
                e
            );
            Vec::new()
        }
    };
    if !blocked_ipv6_ifaces.is_empty() {
        info!("IPv6 disabled on {} interfaces", blocked_ipv6_ifaces.len());
    }

    // Scoring config from pre-resolved options (score type + all factors)
    let scoring = server::ScoringConfig::from_options(&config.resolved);

    // DNS mode and services from pre-resolved options
    let dns_mode = dns::DnsMode::parse(options::get_str(&config.resolved, options::DNS_MODE));
    info!("DNS mode: {:?}", dns_mode);
    let dns_services = options::get_list(&config.resolved, options::LINUX_DNS_SERVICES);

    // Entry interface and route check from pre-resolved options
    let entry_iface = options::get_str(&config.resolved, options::NETWORK_ENTRY_IFACE).to_string();
    if !entry_iface.is_empty() {
        info!("Entry interface: {}", entry_iface);
    }
    let check_route = options::get_bool(&config.resolved, options::CHECK_ROUTE);

    Ok(SessionParams {
        shutdown,
        nonce,
        username,
        password,
        ipv6_mode,
        ipv4_mode,
        custom_dns_ips,
        blocked_ipv6_ifaces,
        scoring,
        profile_options: config.resolved.clone(),
        dns_mode,
        dns_services,
        entry_iface,
        check_route,
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

/// Per-connection context for the DuckDNS record writer. Unlike the removed
/// AirDNS self-heal there is no cross-reconnect state to carry: every write
/// is acked (OK/KO), the interval loop is the retry policy, and pager dedup
/// resets per connection.
struct DuckdnsCtx {
    domain: String,
    token: Zeroizing<String>,
    /// Exit IP written to the record — the port forward listens on the exit;
    /// an entry IP would point the record at the wrong side of the tunnel.
    write_ip: std::net::Ipv4Addr,
    notify_url: String,
    notify_user: String,
    notify_password: String,
    consecutive_failures: u32,
    /// One transport-failure page per failure streak (re-armed on success).
    failure_paged: bool,
    /// One KO page per connection — KO is permanent until config changes.
    rejected_paged: bool,
}

/// Resolve the ntfy pager options, disabling loudly on a rejected URL — the
/// pager must fail at connect time, not silently when a page is needed
/// Returns (url, user, password); empty url =
/// pager disabled.
fn resolve_pager_options(
    resolved: &std::collections::HashMap<String, String>,
) -> (String, String, String) {
    let mut url = options::get_str(resolved, options::DDNS_NOTIFY_URL).to_string();
    let user = options::get_str(resolved, options::DDNS_NOTIFY_USER).to_string();
    let password = options::get_str(resolved, options::DDNS_NOTIFY_PASSWORD).to_string();
    if let Err(e) = ddns::validate_notify_url(&url) {
        error!(
            "ddns.notify_url rejected ({}) — pager DISABLED, DuckDNS failure pages will NOT send. \
             Fix: credential-free URL + ddns.notify_user/notify_password \
             via `airvpn config set`.",
            e,
        );
        url.clear();
    }
    (url, user, password)
}

/// Monitor loop: checks interface, handshake, DNS, kill switch every 1s.
///
/// Returns `(ResetLevel, net_flapped)` when the connection ends. `net_flapped`
/// is true if the physical egress link lost carrier or the default gateway
/// disappeared at any point during the connection — used to distinguish a
/// transient WiFi blip from a genuine server failure.
#[allow(clippy::too_many_arguments)]
fn run_monitor_loop(
    shutdown: &std::sync::atomic::AtomicBool,
    iface: &str,
    no_lock: bool,
    dns_ipv4: &str,
    dns_ipv6: &str,
    handshake_timeout_connected: u64,
    dns_mode: dns::DnsMode,
    dns_services: &[String],
    mut duckdns_ctx: Option<DuckdnsCtx>,
) -> (ResetLevel, bool) {
    // Physical NIC while connected (main-table default route still points at it).
    let phys_iface = wireguard::default_route_iface().ok();
    let mut net_flapped = false;
    let mut dns_fail_count: u32 = 0;
    let connected_at = std::time::Instant::now();
    let mut tick: u64 = 0;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!("Disconnecting...");
            break (ResetLevel::None, net_flapped);
        }

        // Carrier down on the egress NIC, or no default gateway, means the
        // underlying network blipped during this connection.
        if (phys_iface.as_deref().and_then(wireguard::iface_carrier_up) == Some(false))
            || !wireguard::has_default_gateway()
        {
            net_flapped = true;
        }

        if !wireguard::is_connected(iface) {
            error!("WireGuard interface {} disappeared!", iface);
            break (ResetLevel::Error, net_flapped);
        }

        if wireguard::is_handshake_stale(iface, handshake_timeout_connected) {
            error!("WireGuard handshake stale (>{}s) -- tunnel may be dead", handshake_timeout_connected);
            break (ResetLevel::Error, net_flapped);
        }

        if !no_lock && !netlock::is_active() {
            error!("Kill switch nftables table deleted externally! Triggering reconnection to restore it.");
            break (ResetLevel::Error, net_flapped);
        }

        match dns::check_and_reapply(dns_ipv4, dns_ipv6, iface, dns_mode, dns_services, std::path::Path::new(dns::RESOLV_CONF)) {
            Ok(_) => { dns_fail_count = 0; }
            Err(e) => {
                dns_fail_count += 1;
                warn!("DNS re-apply failed ({} consecutive): {:#}", dns_fail_count, e);
                if dns_fail_count >= 10 {
                    error!(
                        "DNS re-apply failed {} consecutive times, triggering reconnection",
                        dns_fail_count,
                    );
                    break (ResetLevel::Error, net_flapped);
                }
            }
        }

        if !dns::verify_resolv_conf(dns_ipv4, dns_ipv6, std::path::Path::new("/etc/resolv.conf")) {
            warn!("resolv.conf contains non-VPN nameservers — potential DNS leak (check_and_reapply should fix on next cycle)");
        }

        tick += 1;

        // DuckDNS record writer: unconditional idempotent rewrite right after
        // connect (tick 1, tunnel already verified) and every
        // WRITE_INTERVAL_SECS. Every write is acked, so there is no drift
        // detection — the interval loop IS the retry policy and the pager
        // covers sustained failure. The blocking GET (10s cap, includes DNS)
        // can stall this loop's 1s cadence; at one write per 300s against a
        // 200s handshake-staleness threshold that's harmless.
        if let Some(ctx) = duckdns_ctx.as_mut() {
            if tick == 1 || tick.is_multiple_of(duckdns::WRITE_INTERVAL_SECS) {
                let name = duckdns::record_name(&ctx.domain);
                let outcome = duckdns::update(&ctx.domain, &ctx.token, Some(ctx.write_ip));
                let verdict = match &outcome {
                    duckdns::WriteOutcome::Accepted => "duckdns_ok",
                    duckdns::WriteOutcome::Rejected => "duckdns_ko",
                    duckdns::WriteOutcome::Failed(_) => "duckdns_err",
                };
                ddns::log_observation(
                    &name, None, &[ctx.write_ip], connected_at.elapsed().as_secs(), verdict,
                );
                match outcome {
                    duckdns::WriteOutcome::Accepted => {
                        if ctx.consecutive_failures > 0 {
                            info!(
                                "duckdns: write recovered after {} failures — {} -> {}",
                                ctx.consecutive_failures, name, ctx.write_ip,
                            );
                        } else if tick == 1 {
                            info!("duckdns: {} -> {} (acked)", name, ctx.write_ip);
                        } else {
                            debug!("duckdns: {} -> {} (acked)", name, ctx.write_ip);
                        }
                        ctx.consecutive_failures = 0;
                        ctx.failure_paged = false;
                        // KO can heal server-side (token regenerated, domain
                        // re-added) without a reconnect — re-arm so a later
                        // regression pages again.
                        ctx.rejected_paged = false;
                    }
                    duckdns::WriteOutcome::Rejected => {
                        // A KO reached DuckDNS and back — transport worked,
                        // so it must not count toward the transport streak.
                        ctx.consecutive_failures = 0;
                        error!(
                            "duckdns: write REJECTED (KO) — token wrong or domain not in the \
                             account; {} is NOT updating",
                            name,
                        );
                        if !ctx.rejected_paged {
                            ctx.rejected_paged = true;
                            ddns::notify(
                                &ctx.notify_url, &ctx.notify_user, &ctx.notify_password,
                                "DuckDNS write rejected",
                                &format!(
                                    "DuckDNS returned KO for {} — token or domain misconfigured; \
                                     the record is NOT updating. Fix ddns.duckdns_domain/_token, \
                                     then verify with `sudo airvpn ddns test-duckdns`.",
                                    name,
                                ),
                            );
                        }
                    }
                    duckdns::WriteOutcome::Failed(cause) => {
                        ctx.consecutive_failures += 1;
                        warn!(
                            "duckdns: write failed ({} consecutive): {}",
                            ctx.consecutive_failures, cause,
                        );
                        if ctx.consecutive_failures >= duckdns::FAILURES_BEFORE_PAGE
                            && !ctx.failure_paged
                        {
                            ctx.failure_paged = true;
                            ddns::notify(
                                &ctx.notify_url, &ctx.notify_user, &ctx.notify_password,
                                "DuckDNS writes failing",
                                &format!(
                                    "{} consecutive DuckDNS write failures (~{} min) — {} may be \
                                     stale (current exit {}). Latest error: {}",
                                    ctx.consecutive_failures,
                                    ctx.consecutive_failures as u64 * duckdns::WRITE_INTERVAL_SECS
                                        / 60,
                                    name, ctx.write_ip, cause,
                                ),
                            );
                        }
                    }
                }
            }
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
    // Resolve hostnames to IPs before netlock activation.
    // Skip DNS resolution when the persistent lock is active — outbound DNS is
    // blocked by the persistent lock (port 53/853 dropped on non-tunnel interfaces),
    // so getaddrinfo() blocks for ~30s per nameserver before timing out.
    // The persistent lock already allowlists bootstrap IPs, so the session lock
    // only needs the server entry IPs (always numeric) for its allowlist.
    let persist_active = netlock::is_persist_active();
    let mut resolved_ips: Vec<String> = Vec::new();
    for entry in &allowed_ips {
        if entry.parse::<std::net::IpAddr>().is_ok() {
            resolved_ips.push(entry.clone());
        } else if persist_active {
            debug!("skipping hostname resolution for {} (persistent lock active, DNS blocked)", entry);
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
    // Parse custom routes and allowlist IPs from resolved profile options
    let custom_routes = options::parse_custom_routes(
        options::get_str(&config.resolved, options::ROUTES_CUSTOM),
    );
    let custom_route_out_cidrs: Vec<String> = custom_routes
        .iter()
        .filter(|r| r.action == "out")
        .map(|r| r.cidr.clone())
        .collect();
    let allowlist_out_cidrs = options::parse_allowlist_ips(
        options::get_str(&config.resolved, options::NETLOCK_ALLOWLIST_IPS),
    );
    if !custom_route_out_cidrs.is_empty() {
        info!("Custom routes (out): {} CIDRs will bypass tunnel", custom_route_out_cidrs.len());
    }
    if !allowlist_out_cidrs.is_empty() {
        info!("Netlock allowlist: {} CIDRs allowed through firewall", allowlist_out_cidrs.len());
    }
    let lock_config = netlock::NetlockConfig {
        allow_lan: config.allow_lan,
        allow_dhcp: true,
        allow_ping: options::get_bool(&config.resolved, options::NETLOCK_ALLOW_PING),
        allow_ipv4ipv6translation: true,
        allowed_ips_incoming: vec![],
        allowed_ips_outgoing: allowed_ips,
        incoming_policy_accept: options::get_str(&config.resolved, options::NETLOCK_INCOMING) == "allow",
        iface_name: iface_name.to_string(),
        custom_route_out_cidrs,
        allowlist_out_cidrs,
        local_forward_ifaces: {
            let v = options::get_str(&config.resolved, options::NETLOCK_LOCAL_FORWARD_IFACES);
            if v.is_empty() { vec![] } else { v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect() }
        },
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
    dns::activate(effective_dns_ipv4, effective_dns_ipv6, iface, params.dns_mode, &params.dns_services, std::path::Path::new(dns::RESOLV_CONF))?;
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

/// Decide whether a failure should be attributed to the network rather than the
/// server. Pure helper so the classification can be unit-tested without the
/// side effects of `handle_connection_failure`.
fn is_network_down(check_network: bool, net_flapped: bool, has_gw: bool) -> bool {
    // Flap-during-connection: a physical-link carrier drop or missing gateway
    // *while connected* means the WiFi/ethernet blipped, not the server. The
    // gateway is often back by the time we check (WiFi reassociated), so the
    // carrier-flap signal is what catches the transient case.
    check_network && (net_flapped || !has_gw)
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
    net_flapped: bool,
    penalties: &mut server::ServerPenalties,
    forced_server: &mut Option<String>,
    consecutive_failures: &mut u32,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    penality_on_error: i64,
) {
    let network_down = is_network_down(check_network, net_flapped, wireguard::has_default_gateway());
    if network_down || lock_last {
        if network_down {
            warn!("Network blipped during connection (carrier flap or no gateway), not a server fault. Will retry same server.");
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
    iface_name: &str,
    do_check_route: bool,
) -> bool {
    let check_domain = manifest.check_domain.as_str();
    let check_dns_query = manifest.check_dns_query.as_str();
    let check_protocol = manifest.check_protocol.as_str();
    let exit_ip = server_ref.ips_exit.first().map(|s| s.as_str()).unwrap_or("");
    debug!("Verification: check_domain={:?}, check_dns_query={:?}, exit_ip={:?}, server={}", check_domain, check_dns_query, exit_ip, server_ref.name);

    // Route verification (Eddie: advanced.check.route)
    if do_check_route {
        info!("Verifying routes...");
        match verify::check_route(iface_name, wg_ipv4) {
            Ok(()) => info!("Routes verified."),
            Err(e) => {
                warn!("Route verification failed: {:#}", e);
                return false;
            }
        }
        if shutdown.load(Ordering::Relaxed) { return true; }
    }

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
    net_flapped: bool,
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
    original_gw: &str,
    custom_route_out_cidrs: &[String],
) -> anyhow::Result<bool> {
    match reset_level {
        ResetLevel::None | ResetLevel::Fatal => {
            cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, original_gw, custom_route_out_cidrs)?;
            Ok(true)
        }
        ResetLevel::Error => {
            if config.no_reconnect {
                cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, original_gw, custom_route_out_cidrs)?;
                warn!("Connection lost (--no-reconnect, exiting).");
                return Ok(true);
            }
            let _ = partial_disconnect(config_path, iface, !config.no_lock, endpoint_ip);
            let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
            handle_connection_failure(
                server_name, lock_last, true, net_flapped,
                penalties, forced_server, consecutive_failures,
                &params.shutdown, penality_on_error,
            );
            Ok(false)
        }
        ResetLevel::Retry => {
            if config.no_reconnect {
                cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, original_gw, custom_route_out_cidrs)?;
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
                cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, original_gw, custom_route_out_cidrs)?;
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
    })
}

/// Bring up a minimal, DNS-free "drop everything except the server entry IPs"
/// kill switch. Used as a fail-closed fallback during reconnect when the full
/// `activate_netlock` could not install a lock and nothing else is protecting
/// the physical route.
///
/// Uses only the numeric server entry IPs — no bootstrap-hostname resolution,
/// which would block ~30s while VPN DNS is unreachable mid-reconnect — so it can
/// go up fast. The next successful `activate_netlock` atomically replaces it.
/// Worst case it over-blocks (LAN/custom routes) for the brief reconnect window,
/// which is the safe direction for a kill switch.
fn activate_emergency_lock(config: &ConnectConfig, entry_ips: &[String]) -> anyhow::Result<()> {
    let iface_name = {
        let v = options::get_str(&config.resolved, options::NETWORK_IFACE_NAME);
        if v.is_empty() { wireguard::VPN_INTERFACE } else { v }
    };
    let lock_config = netlock::NetlockConfig {
        allow_lan: config.allow_lan,
        allow_dhcp: true,
        allow_ping: false,
        allow_ipv4ipv6translation: true,
        allowed_ips_incoming: vec![],
        allowed_ips_outgoing: entry_ips
            .iter()
            .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
            .cloned()
            .collect(),
        incoming_policy_accept: false,
        iface_name: iface_name.to_string(),
        custom_route_out_cidrs: vec![],
        allowlist_out_cidrs: vec![],
        local_forward_ifaces: vec![],
    };
    netlock::activate(&lock_config)
}

// ---------------------------------------------------------------------------
// LoopState — mutable per-loop state for the reconnection loop
// ---------------------------------------------------------------------------

/// Mutable state that persists across reconnection loop iterations.
///
/// Extracted from `run()` so that phase functions can take `&mut LoopState`
/// instead of 5+ individual `&mut` parameters.
struct LoopState {
    penalties: server::ServerPenalties,
    forced_server: Option<String>,
    first_iteration: bool,
    consecutive_failures: u32,
    all_entry_ips: Vec<String>,
    /// Custom "out" route CIDRs (session-constant, parsed once before the loop).
    custom_route_out_cidrs: Vec<String>,
}

/// Control flow signal from phase functions back to the main loop.
enum LoopAction {
    /// Continue to the next phase within this iteration.
    Continue,
    /// Restart the loop from the top (`continue` in the original code).
    Retry,
    /// Exit the loop (`break` in the original code).
    Break,
    /// Return an error from `run()`.
    Bail(anyhow::Error),
}

// ---------------------------------------------------------------------------
// Phase functions — each handles one logical step of the reconnection loop
// ---------------------------------------------------------------------------

/// Phase 1: Refresh manifest on reconnection and rebuild lock if entry IPs changed.
fn refresh_and_rebuild_lock(
    state: &mut LoopState,
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    data: &mut SessionData,
    config: &ConnectConfig,
) {
    if !state.first_iteration {
        refresh_manifest_if_needed(provider_config, params, data, config);
        // New servers may have appeared — rebuild allowlist and reload lock atomically.
        let new_entry_ips: Vec<String> = data.filtered_servers
            .iter()
            .flat_map(|s| s.ips_entry.iter().cloned())
            .collect();
        let ips_changed = new_entry_ips != state.all_entry_ips;
        if ips_changed {
            state.all_entry_ips = new_entry_ips;
        }
        // Rebuild the lock if the server set changed OR the kill-switch table is
        // missing. The !is_active() case is load-bearing: when the monitor
        // detects an externally-deleted lock (run_monitor_loop, "deleted
        // externally") it reconnects, but a same-server reconnect leaves the
        // entry IPs unchanged — so without this the lock would never be rebuilt.
        // The reconnect tears the tunnel down, and policy routing then re-exposes
        // the physical default route, so a missing lock here is an IPv4 leak, not
        // just lost protection. Rebuilding at the top of the loop puts the lock
        // back before the pre-connection auth call and tunnel re-establishment.
        if !config.no_lock && (ips_changed || !netlock::is_active()) {
            if let Err(e) = activate_netlock(params, config, provider_config, &data.manifest.bootstrap_urls, &state.all_entry_ips) {
                if netlock::is_active() || netlock::is_persist_active() {
                    // No leak: activate() replaces the table atomically, so a
                    // failed reload leaves the previous session table in place
                    // (stale allowlist at worst, which fails closed) — or the
                    // persistent lock is blocking the physical route anyway.
                    warn!("Failed to (re)activate netlock on reconnect: {}", e);
                } else {
                    // No session table AND no persistent lock: nothing is blocking
                    // the physical route right now. Fail closed by installing a
                    // minimal DNS-free drop-all-except-server lock BEFORE we go on
                    // to rebuild the tunnel, instead of proceeding exposed. (The
                    // full activate_netlock just failed and may block on bootstrap
                    // DNS mid-reconnect, so we don't simply retry it here.)
                    match activate_emergency_lock(config, &state.all_entry_ips) {
                        Ok(()) => info!(
                            "Emergency kill switch installed on reconnect — blocking all but server IPs until the tunnel is up"
                        ),
                        Err(emerg_err) => {
                            // nft itself appears broken. Proceeding still stops the
                            // leak fastest (the tunnel is the next thing to come
                            // up), but the user must hear they were unprotected.
                            error!("Kill switch could not be restored on reconnect: {} (emergency lock also failed: {}) — traffic may bypass the VPN until the tunnel is up", e, emerg_err);
                            emit(config, crate::ipc::EngineEvent::Log {
                                level: "error".into(),
                                message: format!("Kill switch could not be restored: {} — traffic may bypass the VPN until reconnection completes", e),
                            });
                        }
                    }
                }
            }
        }
    }
    state.first_iteration = false;
}

/// Phase 2: Select WireGuard mode and key from manifest/user data.
///
/// Returns `None` if no mode or key is available (caller should sleep and retry).
fn resolve_wg_mode_and_key<'a>(
    params: &SessionParams,
    data: &'a SessionData,
    config: &ConnectConfig,
) -> Option<(&'a manifest::Mode, &'a manifest::WireGuardKey)> {
    // If mode.port is set, prefer the mode with that port; fall back to first available.
    let forced_port: u16 = options::get_str(&config.resolved, options::MODE_PORT)
        .parse()
        .unwrap_or(0);
    let mode = if forced_port > 0 {
        data.manifest.modes.iter()
            .find(|m| m.port == forced_port)
            .or_else(|| {
                warn!("Requested port {} not found in manifest modes, using first available", forced_port);
                data.manifest.modes.first()
            })
    } else {
        data.manifest.modes.first()
    };
    let mode = match mode {
        Some(m) => m,
        None => {
            warn!("Refreshed manifest has no WireGuard modes, cannot connect");
            interruptible_sleep(&params.shutdown, 10);
            return None;
        }
    };
    let wg_key = match select_key(&data.user_info.keys, &config.resolved) {
        Some(k) => k,
        None => {
            warn!("Refreshed user data has no WireGuard keys, cannot connect");
            interruptible_sleep(&params.shutdown, 10);
            return None;
        }
    };
    Some((mode, wg_key))
}

/// Phase 3: Select server and resolve connection-specific parameters (IPv6, DNS).
///
/// Returns the selected server reference, ipv6_enabled flag, and effective DNS addresses.
fn select_and_resolve_server<'a>(
    state: &LoopState,
    params: &SessionParams,
    data: &'a SessionData,
    config: &ConnectConfig,
    wg_key: &manifest::WireGuardKey,
) -> anyhow::Result<(&'a manifest::Server, bool, String, String)> {
    let server_ref = server::select_server_with_penalties(
        &data.filtered_servers,
        state.forced_server.as_deref(),
        &state.penalties,
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
    let (effective_dns_ipv4, effective_dns_ipv6) =
        resolve_effective_dns(&params.custom_dns_ips, wg_key, ipv6_enabled);

    Ok((server_ref, ipv6_enabled, effective_dns_ipv4, effective_dns_ipv6))
}

/// Phase 4: Pre-connection authorization (Eddie: Session.cs:173-218).
///
/// Returns `LoopAction::Continue` to proceed, or `Retry`/`Break`/`Bail` to
/// short-circuit the current iteration.
fn perform_pre_connection_auth(
    state: &mut LoopState,
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    data: &SessionData,
    config: &ConnectConfig,
    server_name: &str,
) -> LoopAction {
    let http_timeout_secs = options::get_u64(&config.resolved, options::HTTP_TIMEOUT);
    let reset_from_auth = match api::fetch_connect_with_urls_timeout(
        provider_config,
        &params.username,
        &params.password,
        server_name,
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
                return LoopAction::Bail(anyhow::anyhow!("Fatal: server rejected connection"));
            }
            ResetLevel::Error => {
                // Server explicitly directed us to try another — always rotate.
                let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
                state.penalties.penalize(server_name, penality_on_error);
                state.forced_server = Option::None;
                if config.no_reconnect {
                    cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                    return LoopAction::Bail(anyhow::anyhow!("Server directed to try another (--no-reconnect)"));
                }
                warn!("Penalized {}. Trying another server in 5s...", server_name);
                interruptible_sleep(&params.shutdown, 5);
                emit(config, crate::ipc::EngineEvent::StateChanged(
                    crate::ipc::ConnectionState::Reconnecting,
                ));
                return LoopAction::Retry;
            }
            ResetLevel::Retry => {
                if config.no_reconnect {
                    cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                    return LoopAction::Bail(anyhow::anyhow!("Server asked to retry (--no-reconnect)"));
                }
                warn!("Retrying in 10s...");
                interruptible_sleep(&params.shutdown, 10);
                emit(config, crate::ipc::EngineEvent::StateChanged(
                    crate::ipc::ConnectionState::Reconnecting,
                ));
                return LoopAction::Retry;
            }
            _ => {} // None/Switch don't occur from auth
        }
    }

    LoopAction::Continue
}

/// Phase 5: Generate WireGuard config and establish tunnel.
///
/// On success, returns `(config_path, iface, original_gw, endpoint_ip)`.
/// On failure, returns a `LoopAction` indicating how to proceed.
#[allow(clippy::too_many_arguments)]
fn establish_wireguard_tunnel(
    state: &mut LoopState,
    params: &SessionParams,
    data: &SessionData,
    config: &ConnectConfig,
    server_ref: &manifest::Server,
    mode: &manifest::Mode,
    wg_key: &manifest::WireGuardKey,
    ipv6_enabled: bool,
    effective_dns_ipv4: &str,
    effective_dns_ipv6: &str,
) -> Result<(String, String, String, String), LoopAction> {
    // Save recovery state with blocked IPv6 interfaces
    if let Err(e) = save_recovery(params, config.no_lock, "", "", "", "", "") {
        return Err(LoopAction::Bail(e));
    }

    // Generate WireGuard config and connect
    let wg_keepalive = options::get_u64(&config.resolved, options::WG_KEEPALIVE) as u16;
    let ip_layer = options::get_str(&config.resolved, options::NETWORK_ENTRY_IPLAYER);
    let wg_params = match wireguard::generate_config(wg_key, server_ref, mode, &data.user_info, wg_keepalive, ip_layer) {
        Ok(p) => p,
        Err(e) => return Err(LoopAction::Bail(e)),
    };
    let endpoint_ip = wg_params.endpoint_ip.clone();
    debug!(
        "WireGuard config: endpoint={}, ipv4={}, ipv6={}, dns={}/{}, mode={} (keys redacted)",
        endpoint_ip,
        wg_key.wg_ipv4,
        wg_key.wg_ipv6,
        effective_dns_ipv4,
        effective_dns_ipv6,
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
    let ipv4_enabled = params.ipv4_mode != Ipv4Mode::Block;
    let (config_path, iface, original_gw) = match wireguard::connect(&wg_params, ipv6_enabled, ipv4_enabled, wg_mtu, iface_name, &params.entry_iface) {
        Ok(result) => {
            state.consecutive_failures = 0;
            result
        }
        Err(e) => {
            error!("WireGuard connection failed: {:#}", e);
            if config.no_reconnect {
                cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                return Err(LoopAction::Bail(e.context("WireGuard connection failed")));
            }
            let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
            // Setup-time failure (no monitor loop yet): no tracked flap, so
            // net_flapped=false keeps the original gateway-only classification.
            handle_connection_failure(
                &server_ref.name, data.lock_last, true, false,
                &mut state.penalties, &mut state.forced_server, &mut state.consecutive_failures,
                &params.shutdown, penality_on_error,
            );
            emit(config, crate::ipc::EngineEvent::StateChanged(
                crate::ipc::ConnectionState::Reconnecting,
            ));
            return Err(LoopAction::Retry);
        }
    };
    if let Err(e) = save_recovery(params, config.no_lock, &iface, &config_path, "", "", &endpoint_ip) {
        return Err(LoopAction::Bail(e));
    }
    info!("WireGuard interface: {}", iface);
    emit(config, crate::ipc::EngineEvent::Log {
        level: "info".into(),
        message: format!("WireGuard interface {} created", iface),
    });

    // Add IP routes for custom "out" routes — these bypass the VPN tunnel
    // by routing through the original default gateway.
    if !state.custom_route_out_cidrs.is_empty() {
        add_custom_out_routes(&state.custom_route_out_cidrs, &original_gw);
    }

    Ok((config_path, iface, original_gw, endpoint_ip))
}

/// Phase 6: Wait for handshake, run post-connect setup, and verify connection.
///
/// Returns `LoopAction::Continue` on success (proceed to monitor loop), or
/// a `LoopAction` variant to short-circuit.
#[allow(clippy::too_many_arguments)]
fn wait_and_verify_connection(
    state: &mut LoopState,
    params: &SessionParams,
    data: &SessionData,
    config: &ConnectConfig,
    server_ref: &manifest::Server,
    wg_key: &manifest::WireGuardKey,
    effective_dns_ipv4: &str,
    effective_dns_ipv6: &str,
    config_path: &str,
    iface: &str,
    original_gw: &str,
    endpoint_ip: &str,
) -> LoopAction {
    // Wait for first WireGuard handshake (Eddie: handshake_timeout_first=50s)
    info!("Waiting for handshake...");
    emit(config, crate::ipc::EngineEvent::Log {
        level: "info".into(),
        message: "Waiting for WireGuard handshake...".into(),
    });
    let handshake_timeout_first = options::get_u64(&config.resolved, options::WG_HANDSHAKE_FIRST);
    if let Err(e) = wireguard::wait_for_handshake(iface, handshake_timeout_first, &params.shutdown) {
        error!("Handshake failed: {:#}", e);
        let _ = wireguard::disconnect(config_path, endpoint_ip, iface);
        if params.shutdown.load(Ordering::Relaxed) {
            return LoopAction::Break;
        }
        if config.no_reconnect {
            cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
            return LoopAction::Bail(e);
        }
        let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
        // No monitor loop ran yet (check_network=false), so net_flapped is moot.
        handle_connection_failure(
            &server_ref.name, data.lock_last, false, false,
            &mut state.penalties, &mut state.forced_server, &mut state.consecutive_failures,
            &params.shutdown, penality_on_error,
        );
        emit(config, crate::ipc::EngineEvent::StateChanged(
            crate::ipc::ConnectionState::Reconnecting,
        ));
        return LoopAction::Retry;
    }
    info!("Handshake established.");
    emit(config, crate::ipc::EngineEvent::Log {
        level: "info".into(),
        message: "Handshake established".into(),
    });

    // Post-connect setup — if any step fails, clean up and treat as fatal
    if let Err(e) = post_connect_setup(
        params, config, &server_ref.name,
        config_path, iface, endpoint_ip,
        effective_dns_ipv4, effective_dns_ipv6,
    ) {
        if params.shutdown.load(Ordering::Relaxed) {
            warn!("Setup interrupted by shutdown signal, disconnecting...");
            let _ = cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, original_gw, &state.custom_route_out_cidrs);
            return LoopAction::Break;
        }
        error!("Setup failed after WireGuard connected: {:#}", e);
        warn!("Cleaning up...");
        let _ = cmd_disconnect_internal(config_path, iface, !config.no_lock, &params.blocked_ipv6_ifaces, endpoint_ip, original_gw, &state.custom_route_out_cidrs);
        return LoopAction::Bail(e);
    }

    // Post-connection verification
    if !config.no_verify && !params.shutdown.load(Ordering::Relaxed) {
        emit(config, crate::ipc::EngineEvent::Log {
            level: "info".into(),
            message: "Verifying tunnel and DNS...".into(),
        });
        let checking_ntry = options::get_u64(&config.resolved, options::CHECKING_NTRY) as u32;
        let verify_ok = verify_connection(
            &params.shutdown, &data.manifest, server_ref,
            &wg_key.wg_ipv4, effective_dns_ipv4, effective_dns_ipv6,
            checking_ntry, iface, params.check_route,
        );
        if !verify_ok && !params.shutdown.load(Ordering::Relaxed) {
            warn!("Verification failed, treating as connection failure, reconnecting...");
            let _ = partial_disconnect(config_path, iface, !config.no_lock, endpoint_ip);
            if config.no_reconnect {
                cleanup_and_bail(config.no_lock, &params.blocked_ipv6_ifaces);
                return LoopAction::Bail(anyhow::anyhow!("Verification failed (--no-reconnect)"));
            }
            let penality_on_error = options::get_i64(&config.resolved, options::PENALITY_ON_ERROR);
            // No monitor loop ran yet (check_network=false), so net_flapped is moot.
            handle_connection_failure(
                &server_ref.name, data.lock_last, false, false,
                &mut state.penalties, &mut state.forced_server, &mut state.consecutive_failures,
                &params.shutdown, penality_on_error,
            );
            emit(config, crate::ipc::EngineEvent::StateChanged(
                crate::ipc::ConnectionState::Reconnecting,
            ));
            return LoopAction::Retry;
        }
    }

    LoopAction::Continue
}

// ---------------------------------------------------------------------------
// Connect — main entry point
// ---------------------------------------------------------------------------

/// Connect to AirVPN (formerly `cmd_connect` in main.rs).
///
/// Handles the full connection lifecycle: pre-flight checks, credential
/// resolution, manifest fetch, server selection, netlock, WireGuard setup,
/// DNS configuration, verification, and the reconnection loop.
///
/// The loop body is decomposed into phase functions, each taking `&mut LoopState`
/// for mutable per-loop state and references to session-constant config/params.
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

    // Parse custom routes once (session-constant, from resolved profile options).
    // "out" routes bypass the VPN tunnel via the original default gateway.
    let custom_routes = options::parse_custom_routes(
        options::get_str(&config.resolved, options::ROUTES_CUSTOM),
    );
    let custom_route_out_cidrs: Vec<String> = custom_routes
        .iter()
        .filter(|r| r.action == "out")
        .map(|r| r.cidr.clone())
        .collect();

    let mut state = LoopState {
        penalties: server::ServerPenalties::new(),
        forced_server: config.server_name
            .clone()
            .or(data.start_last_name.clone()),
        first_iteration: true,
        consecutive_failures: 0,
        // Collect ALL server entry IPs for the network lock allowlist (Eddie: allowlists
        // all servers so reconnection to a different server doesn't require lock rebuild).
        all_entry_ips: data.filtered_servers
            .iter()
            .flat_map(|s| s.ips_entry.iter().cloned())
            .collect(),
        custom_route_out_cidrs,
    };

    // Activate network lock once before the loop with all server IPs.
    if !config.no_lock {
        activate_netlock(&params, config, provider_config, &data.manifest.bootstrap_urls, &state.all_entry_ips)?;
    }

    loop {
        // Check for shutdown before attempting connection
        if params.shutdown.load(Ordering::Relaxed) {
            info!("Shutdown requested before connection attempt.");
            break;
        }

        // Phase 1: Refresh manifest on reconnection + rebuild lock if IPs changed
        refresh_and_rebuild_lock(&mut state, provider_config, &params, &mut data, config);

        // Phase 2: Select WireGuard mode and key
        let (mode, wg_key) = match resolve_wg_mode_and_key(&params, &data, config) {
            Some(pair) => pair,
            None => continue, // no mode/key available, sleep already done
        };

        // Phase 3: Select server and resolve IPv6/DNS
        let (server_ref, ipv6_enabled, effective_dns_ipv4, effective_dns_ipv6) =
            match select_and_resolve_server(&state, &params, &data, config, wg_key) {
                Ok(sel) => sel,
                Err(e) => return Err(e),
            };

        // Phase 4: Pre-connection authorization
        match perform_pre_connection_auth(&mut state, provider_config, &params, &data, config, &server_ref.name) {
            LoopAction::Continue => {}
            LoopAction::Retry => continue,
            LoopAction::Break => break,
            LoopAction::Bail(e) => return Err(e),
        }

        // Phase 5: Establish WireGuard tunnel
        let (config_path, iface, original_gw, endpoint_ip) = match establish_wireguard_tunnel(
            &mut state, &params, &data, config,
            server_ref, mode, wg_key, ipv6_enabled,
            &effective_dns_ipv4, &effective_dns_ipv6,
        ) {
            Ok(result) => result,
            Err(LoopAction::Retry) => continue,
            Err(LoopAction::Break) => break,
            Err(LoopAction::Bail(e)) => return Err(e),
            Err(LoopAction::Continue) => unreachable!(),
        };

        // Phase 6: Wait for handshake, post-connect setup, verification
        match wait_and_verify_connection(
            &mut state, &params, &data, config,
            server_ref, wg_key,
            &effective_dns_ipv4, &effective_dns_ipv6,
            &config_path, &iface, &original_gw, &endpoint_ip,
        ) {
            LoopAction::Continue => {}
            LoopAction::Retry => continue,
            LoopAction::Break => break,
            LoopAction::Bail(e) => return Err(e),
        }

        // Connected successfully
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

        // DuckDNS record writer for this connection (None = disabled). Not
        // gated on no_reconnect: it writes a DNS record, never reconnects.
        let duckdns_ctx = {
            let domain =
                options::get_str(&config.resolved, options::DDNS_DUCKDNS_DOMAIN).to_string();
            let token = Zeroizing::new(
                options::get_str(&config.resolved, options::DDNS_DUCKDNS_TOKEN).to_string(),
            );
            match duckdns::validate_config(&domain, &token) {
                Err(e) => {
                    error!("duckdns record writer DISABLED: {}", e);
                    None
                }
                Ok(()) if domain.is_empty() => None,
                Ok(()) => match duckdns::exit_ips(server_ref).first() {
                    None => {
                        warn!(
                            "duckdns: server {} has no parseable exit IPs — record writer \
                             inactive for this connection",
                            server_ref.name,
                        );
                        None
                    }
                    Some(&ip) => {
                        let (notify_url, notify_user, notify_password) =
                            resolve_pager_options(&config.resolved);
                        Some(DuckdnsCtx {
                            domain,
                            token,
                            write_ip: ip,
                            notify_url,
                            notify_user,
                            notify_password,
                            consecutive_failures: 0,
                            failure_paged: false,
                            rejected_paged: false,
                        })
                    }
                },
            }
        };

        // Monitor loop — determines ResetLevel when connection ends
        let handshake_timeout_connected = options::get_u64(&config.resolved, options::WG_HANDSHAKE_CONNECTED);
        let (reset_level, net_flapped) = run_monitor_loop(
            &params.shutdown,
            &iface,
            config.no_lock,
            &effective_dns_ipv4,
            &effective_dns_ipv6,
            handshake_timeout_connected,
            params.dns_mode,
            &params.dns_services,
            duckdns_ctx,
        );

        // Handle reset level (Eddie: Session.cs phase 6 cleanup + wait)
        let should_break = handle_reset_level(
            reset_level, net_flapped, config, &params,
            &config_path, &iface, &endpoint_ip,
            &server_ref.name, data.lock_last,
            &mut state.penalties, &mut state.forced_server, &mut state.consecutive_failures,
            &original_gw, &state.custom_route_out_cidrs,
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
    fn test_is_network_down_flap_is_network() {
        // A carrier flap during the connection => network-down (retry same server).
        assert!(is_network_down(true, true, true));
        assert!(is_network_down(true, true, false));
    }

    #[test]
    fn test_is_network_down_no_gateway_is_network() {
        assert!(is_network_down(true, false, false));
    }

    #[test]
    fn test_is_network_down_genuine_server_failure() {
        // No flap, gateway present => server failure (penalize + clear forced_server).
        assert!(!is_network_down(true, false, true));
    }

    #[test]
    fn test_is_network_down_check_disabled() {
        // check_network=false short-circuits to server failure regardless.
        assert!(!is_network_down(false, true, false));
    }

    #[test]
    fn test_handle_connection_failure_flap_retries_same_server() {
        // net_flapped=true is treated as network-down even if a gateway is
        // present, so the server is NOT penalized and forced_server is retained.
        // Pre-set shutdown so interruptible_sleep returns immediately.
        let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let mut penalties = server::ServerPenalties::new();
        let mut forced_server = Some("us-server-1".to_string());
        let mut consecutive_failures = 0u32;
        handle_connection_failure(
            "us-server-1", false, true, /* net_flapped */ true,
            &mut penalties, &mut forced_server, &mut consecutive_failures,
            &shutdown, 30,
        );
        assert_eq!(forced_server.as_deref(), Some("us-server-1"), "should retry same server");
        assert_eq!(penalties.get("us-server-1"), 0, "should not penalize on a network flap");
        assert_eq!(consecutive_failures, 1);
    }

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
