use airvpn::{api, config, dns, ipv6, manifest, netlock, recovery, server, wireguard};

use std::sync::atomic::Ordering;

use anyhow::Context;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "airvpn", about = "AirVPN WireGuard client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to AirVPN
    Connect {
        /// Server name (auto-select if omitted)
        #[arg(long)]
        server: Option<String>,
        /// Disable network lock
        #[arg(long)]
        no_lock: bool,
        /// Allow LAN traffic through lock
        #[arg(long)]
        allow_lan: bool,
        /// AirVPN username (overrides saved credentials)
        #[arg(long)]
        username: Option<String>,
        /// AirVPN password (overrides saved credentials)
        #[arg(long)]
        password: Option<String>,
    },
    /// Disconnect from AirVPN
    Disconnect,
    /// Show connection status
    Status,
    /// List available servers
    Servers {
        /// Sort by: score, load, users, name
        #[arg(long, default_value = "score")]
        sort: String,
        /// Dump raw manifest XML instead of table
        #[arg(long)]
        debug: bool,
        /// AirVPN username (overrides saved credentials)
        #[arg(long)]
        username: Option<String>,
        /// AirVPN password (overrides saved credentials)
        #[arg(long)]
        password: Option<String>,
    },
    /// Clean up stale state after crash
    Recover,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Connect {
            server,
            no_lock,
            allow_lan,
            username,
            password,
        } => cmd_connect(server, no_lock, allow_lan, username, password),
        Commands::Disconnect => cmd_disconnect(),
        Commands::Status => cmd_status(),
        Commands::Servers { sort, debug, username, password } => cmd_servers(&sort, debug, username, password),
        Commands::Recover => cmd_recover(),
    }
}

// ---------------------------------------------------------------------------
// Pre-flight checks
// ---------------------------------------------------------------------------

/// Verify system prerequisites before connecting.
///
/// Checks that we're running as root (needed for nft and wg-quick) and that
/// required binaries are in PATH.
fn preflight_checks() -> anyhow::Result<()> {
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("must run as root (need nft + wg-quick access)");
    }
    if std::process::Command::new("wg-quick").arg("--help").output().is_err() {
        anyhow::bail!("wg-quick not found in PATH");
    }
    if std::process::Command::new("nft").arg("--version").output().is_err() {
        anyhow::bail!("nft not found in PATH");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------

fn cmd_connect(
    server_name: Option<String>,
    no_lock: bool,
    allow_lan: bool,
    cli_username: Option<String>,
    cli_password: Option<String>,
) -> anyhow::Result<()> {
    // 0. Pre-flight checks (root, wg-quick, nft)
    preflight_checks()?;

    // 1. Check for stale state / running instance
    recovery::check_and_recover()?;

    // 1b. Install signal handler EARLY — before any infrastructure changes
    // so Ctrl+C / SIGTERM during netlock/WireGuard/DNS setup sets the flag
    // instead of killing the process with no cleanup.
    let shutdown = recovery::setup_signal_handler()?;

    // 2. Resolve credentials
    let (username, password) = config::resolve_credentials(
        cli_username.as_deref(),
        cli_password.as_deref(),
    )?;

    // 3. Fetch manifest + user data (two separate API calls)
    println!("Fetching server list...");
    let manifest_xml = api::fetch_manifest(&username, &password)?;
    let manifest = manifest::parse_manifest(&manifest_xml)?;
    println!(
        "Found {} servers, {} WireGuard modes",
        manifest.servers.len(),
        manifest.modes.len()
    );

    // Use rotated RSA key from manifest if provided
    let rsa_mod = manifest.rsa_modulus.as_deref();
    let rsa_exp = manifest.rsa_exponent.as_deref();

    println!("Fetching user data...");
    let user_xml = api::fetch_user_with_key(&username, &password, rsa_mod, rsa_exp)?;
    let user_info = manifest::parse_user(&user_xml)?;

    // 5. Select server
    let server_ref = server::select_server(&manifest.servers, server_name.as_deref())?;
    println!(
        "Selected server: {} ({}, {})",
        server_ref.name, server_ref.location, server_ref.country_code
    );

    // 5b. Pre-connection authorization
    println!("Authorizing connection...");
    api::fetch_connect_with_key(&username, &password, &server_ref.name, rsa_mod, rsa_exp)
        .context("pre-connection authorization failed")?;

    // 6. Select WireGuard mode (first available)
    let mode = manifest
        .modes
        .first()
        .ok_or_else(|| anyhow::anyhow!("No WireGuard modes available"))?;

    // 7. Get WireGuard key (first/default)
    let wg_key = user_info
        .keys
        .first()
        .ok_or_else(|| anyhow::anyhow!("No WireGuard keys in user data"))?;

    // 8. Activate network lock (BEFORE connecting -- this is critical)
    if !no_lock {
        println!("Activating network lock...");
        let mut allowed_ips: Vec<String> = server_ref.ips_entry.clone();
        // Also whitelist API bootstrap IPs (extract bare IP from URLs like "http://1.2.3.4")
        for url in api::BOOTSTRAP_IPS {
            if let Some(ip) = extract_ip_from_url(url) {
                allowed_ips.push(ip);
            }
        }
        let lock_config = netlock::NetlockConfig {
            allow_lan,
            allow_dhcp: true,
            allow_ping: true,
            allow_ipv4ipv6translation: true,
            allowed_ips,
        };
        netlock::activate(&lock_config)?;
        recovery::save(&recovery::State {
            lock_active: true,
            wg_interface: String::new(),
            wg_config_path: String::new(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            pid: std::process::id(),
            blocked_ipv6_ifaces: vec![],
        })?;
        println!("Network lock active (dedicated nftables table)");
    }

    // 8b. Block IPv6 on all interfaces (Eddie default: network.ipv6.mode="in-block")
    let blocked_ipv6_ifaces = ipv6::block_all();
    if !blocked_ipv6_ifaces.is_empty() {
        println!("IPv6 disabled on {} interfaces", blocked_ipv6_ifaces.len());
    }

    // 9. Generate WireGuard config and connect
    let wg_config = wireguard::generate_config(wg_key, server_ref, mode, &user_info)?;
    println!("Connecting to {} via mode {}...", server_ref.name, mode.title);
    let (config_path, iface) = match wireguard::connect(&wg_config) {
        Ok(result) => result,
        Err(e) => {
            // Restore IPv6 before removing netlock
            ipv6::restore(&blocked_ipv6_ifaces);
            // Clean up netlock before bailing — otherwise the firewall
            // stays active and blocks all traffic
            if !no_lock {
                eprintln!("WireGuard connection failed, removing network lock...");
                let _ = netlock::deactivate();
            }
            let _ = recovery::remove();
            return Err(e.context("WireGuard connection failed"));
        }
    };
    recovery::save(&recovery::State {
        lock_active: !no_lock,
        wg_interface: iface.clone(),
        wg_config_path: config_path.clone(),
        dns_ipv4: String::new(),
        dns_ipv6: String::new(),
        pid: std::process::id(),
        blocked_ipv6_ifaces: blocked_ipv6_ifaces.clone(),
    })?;
    println!("WireGuard interface: {}", iface);

    // Wait for first WireGuard handshake (Eddie: handshake_timeout_first=50s)
    println!("Waiting for handshake...");
    if let Err(e) = wireguard::wait_for_handshake(&iface, 50) {
        eprintln!("Handshake failed: {:#}", e);
        eprintln!("Cleaning up...");
        ipv6::restore(&blocked_ipv6_ifaces);
        if !no_lock {
            let _ = netlock::deactivate();
        }
        let _ = wireguard::disconnect(&config_path);
        let _ = recovery::remove();
        return Err(e);
    }
    println!("Handshake established.");

    // 10-13: Remaining setup — if any step fails, clean up established connection
    if let Err(e) = (|| -> anyhow::Result<()> {
        // 10. Allow VPN interface in netlock
        if !no_lock {
            netlock::allow_interface(&iface)?;
        }

        // 11. Activate DNS
        dns::activate(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, &iface)?;
        println!("DNS configured: {}, {}", wg_key.wg_dns_ipv4, wg_key.wg_dns_ipv6);

        // 12. Save credentials (non-fatal — don't kill connection over keyring issues)
        if let Err(e) = config::save_credentials(&username, &password) {
            eprintln!("warning: failed to save credentials: {:#}", e);
        }

        // 13. Save recovery state
        recovery::save(&recovery::State {
            lock_active: !no_lock,
            wg_interface: iface.clone(),
            wg_config_path: config_path.clone(),
            dns_ipv4: wg_key.wg_dns_ipv4.clone(),
            dns_ipv6: wg_key.wg_dns_ipv6.clone(),
            pid: std::process::id(),
            blocked_ipv6_ifaces: blocked_ipv6_ifaces.clone(),
        })?;

        Ok(())
    })() {
        eprintln!("Setup failed after WireGuard connected: {:#}", e);
        eprintln!("Cleaning up...");
        let _ = cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces);
        return Err(e);
    }

    println!(
        "\nConnected to {} via {}. Press Ctrl+C to disconnect.",
        server_ref.name, iface
    );

    // 15. Monitor loop
    loop {
        if shutdown.load(Ordering::Relaxed) {
            println!("\nDisconnecting...");
            break;
        }

        // Check interface still exists
        if !wireguard::is_connected(&iface) {
            eprintln!("WireGuard interface {} disappeared!", iface);
            break;
        }

        // Check handshake staleness (Eddie: handshake_timeout_connected=200s)
        if wireguard::is_handshake_stale(&iface, 200) {
            eprintln!("WireGuard handshake stale (>200s) — tunnel may be dead");
            break;
        }

        // Periodic DNS re-check (matching Eddie's DnsSwitchCheck)
        let _ = dns::check_and_reapply(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6);

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Clean disconnect
    cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

fn cmd_disconnect() -> anyhow::Result<()> {
    preflight_checks()?;
    let state = recovery::load()?.ok_or_else(|| anyhow::anyhow!("No active connection found"))?;

    // If the connect process is still running, signal it to shut down gracefully
    if recovery::is_pid_alive(state.pid) && state.pid != std::process::id() {
        eprintln!("Signaling PID {} to disconnect...", state.pid);
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(state.pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        // Wait up to 5 seconds for graceful shutdown
        for _ in 0..50 {
            if !recovery::is_pid_alive(state.pid) {
                println!("Disconnected.");
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        eprintln!("PID {} did not exit, forcing cleanup...", state.pid);
    }

    cmd_disconnect_internal(&state.wg_config_path, &state.wg_interface, state.lock_active, &state.blocked_ipv6_ifaces)
}

fn cmd_disconnect_internal(config_path: &str, _iface: &str, lock_active: bool, blocked_ipv6: &[String]) -> anyhow::Result<()> {
    // Same order as Eddie:
    // 1. wg-quick down
    let _ = wireguard::disconnect(config_path);
    // 2. Restore IPv6
    ipv6::restore(blocked_ipv6);
    // 3. Restore DNS
    let _ = dns::deactivate();
    // 4. Remove netlock
    if lock_active {
        let _ = netlock::deactivate();
    }
    // 5. Remove state
    let _ = recovery::remove();
    println!("Disconnected.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

fn cmd_status() -> anyhow::Result<()> {
    match recovery::load()? {
        Some(state) => {
            let connected = wireguard::is_connected(&state.wg_interface);
            println!(
                "Interface: {} ({})",
                state.wg_interface,
                if connected { "up" } else { "down" }
            );
            println!("Lock active: {}", state.lock_active);
            println!("DNS: {}, {}", state.dns_ipv4, state.dns_ipv6);
            println!("PID: {}", state.pid);
        }
        None => println!("Not connected."),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

fn cmd_servers(
    sort: &str,
    debug: bool,
    cli_username: Option<String>,
    cli_password: Option<String>,
) -> anyhow::Result<()> {
    let (username, password) = config::resolve_credentials(
        cli_username.as_deref(),
        cli_password.as_deref(),
    )?;
    let xml = api::fetch_manifest(&username, &password)?;

    if debug {
        // Redact credentials from the raw XML before printing
        let redacted = xml
            .replace(&username, "[REDACTED_USER]")
            .replace(&password, "[REDACTED_PASS]");
        println!("{}", redacted);
        return Ok(());
    }

    let manifest = manifest::parse_manifest(&xml)?;

    let mut servers: Vec<&manifest::Server> = manifest.servers.iter().collect();
    match sort {
        "score" => servers.sort_by(|a, b| server::score(a).cmp(&server::score(b))),
        "load" => servers.sort_by(|a, b| {
            let load_a = if a.bandwidth_max == 0 {
                100
            } else {
                let bw_cur = 2 * (a.bandwidth * 8) / (1_000 * 1_000);
                (bw_cur * 100) / a.bandwidth_max
            };
            let load_b = if b.bandwidth_max == 0 {
                100
            } else {
                let bw_cur = 2 * (b.bandwidth * 8) / (1_000 * 1_000);
                (bw_cur * 100) / b.bandwidth_max
            };
            load_a.cmp(&load_b)
        }),
        "users" => servers.sort_by(|a, b| a.users.cmp(&b.users)),
        "name" => servers.sort_by(|a, b| a.name.cmp(&b.name)),
        _ => {
            eprintln!("Unknown sort key '{}', defaulting to score", sort);
            servers.sort_by(|a, b| server::score(a).cmp(&server::score(b)));
        }
    }

    println!(
        "{:<20} {:<6} {:<12} {:>6} {:>6} {:>8}",
        "NAME", "CC", "LOCATION", "USERS", "LOAD%", "SCORE"
    );
    println!("{}", "-".repeat(64));

    for s in &servers {
        let load = if s.bandwidth_max == 0 {
            100
        } else {
            let bw_cur = 2 * (s.bandwidth * 8) / (1_000 * 1_000);
            (bw_cur * 100) / s.bandwidth_max
        };
        println!(
            "{:<20} {:<6} {:<12} {:>6} {:>5}% {:>8}",
            s.name,
            s.country_code,
            s.location,
            s.users,
            load,
            server::score(s)
        );
    }

    println!("\n{} servers total.", servers.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// Recover
// ---------------------------------------------------------------------------

fn cmd_recover() -> anyhow::Result<()> {
    preflight_checks()?;
    recovery::force_recover()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the host (IP or hostname) from a URL like "http://63.33.78.166"
/// or "http://[2a03:b0c0::1]" or "http://bootme.org".
///
/// Handles IPv6 bracket notation: returns the bare address without brackets.
fn extract_ip_from_url(url: &str) -> Option<String> {
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
    fn test_extract_ip_from_bootstrap_ips() {
        // Verify it works on every actual BOOTSTRAP_IPS entry
        for url in api::BOOTSTRAP_IPS {
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
