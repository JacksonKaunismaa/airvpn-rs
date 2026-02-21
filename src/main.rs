use airvpn::{api, config, dns, manifest, netlock, recovery, server, wireguard};

use std::sync::atomic::Ordering;

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

    println!("Fetching user data...");
    let user_xml = api::fetch_user(&username, &password)?;
    let user_info = manifest::parse_user(&user_xml)?;

    // 5. Select server
    let server_ref = server::select_server(&manifest.servers, server_name.as_deref())?;
    println!(
        "Selected server: {} ({}, {})",
        server_ref.name, server_ref.location, server_ref.country_code
    );

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
            allowed_ips,
        };
        netlock::activate(&lock_config)?;
        println!("Network lock active (dedicated nftables table)");
    }

    // 9. Generate WireGuard config and connect
    let wg_config = wireguard::generate_config(wg_key, server_ref, mode, &user_info)?;
    println!("Connecting to {} via mode {}...", server_ref.name, mode.title);
    let (config_path, iface) = wireguard::connect(&wg_config)?;
    println!("WireGuard interface: {}", iface);

    // 10. Allow VPN interface in netlock
    if !no_lock {
        netlock::allow_interface(&iface)?;
    }

    // 11. Activate DNS
    dns::activate(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, &iface)?;
    println!("DNS configured: {}, {}", wg_key.wg_dns_ipv4, wg_key.wg_dns_ipv6);

    // 12. Save credentials for next time
    config::save_credentials(&username, &password)?;

    // 13. Save recovery state
    recovery::save(&recovery::State {
        lock_active: !no_lock,
        wg_interface: iface.clone(),
        wg_config_path: config_path.clone(),
        dns_ipv4: wg_key.wg_dns_ipv4.clone(),
        dns_ipv6: wg_key.wg_dns_ipv6.clone(),
        pid: std::process::id(),
    })?;

    // 14. Set up signal handler
    let shutdown = recovery::setup_signal_handler()?;

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

        // Periodic DNS re-check (matching Eddie's DnsSwitchCheck)
        let _ = dns::check_and_reapply(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6);

        std::thread::sleep(std::time::Duration::from_secs(5));
    }

    // Clean disconnect
    cmd_disconnect_internal(&config_path, &iface, !no_lock)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

fn cmd_disconnect() -> anyhow::Result<()> {
    let state = recovery::load()?.ok_or_else(|| anyhow::anyhow!("No active connection found"))?;
    cmd_disconnect_internal(&state.wg_config_path, &state.wg_interface, state.lock_active)
}

fn cmd_disconnect_internal(config_path: &str, _iface: &str, lock_active: bool) -> anyhow::Result<()> {
    // Same order as Eddie:
    // 1. wg-quick down
    let _ = wireguard::disconnect(config_path);
    // 2. Restore DNS
    let _ = dns::deactivate();
    // 3. Remove netlock
    if lock_active {
        let _ = netlock::deactivate();
    }
    // 4. Remove state
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
        "score" => servers.sort_by(|a, b| {
            server::score(a)
                .partial_cmp(&server::score(b))
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
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
            servers.sort_by(|a, b| {
                server::score(a)
                    .partial_cmp(&server::score(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
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
            "{:<20} {:<6} {:<12} {:>6} {:>5}% {:>8.1}",
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
    recovery::force_recover()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the IP address from a URL like "http://63.33.78.166".
///
/// Strips the scheme and any trailing path/port to get the bare IP.
fn extract_ip_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // Take everything before the first '/' or ':' (port)
    let ip = without_scheme
        .split('/')
        .next()?
        .split(':')
        .next()?;
    if ip.is_empty() {
        None
    } else {
        Some(ip.to_string())
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
    fn test_extract_ip_from_bootstrap_ips() {
        // Verify it works on every actual BOOTSTRAP_IPS entry
        for url in api::BOOTSTRAP_IPS {
            let ip = extract_ip_from_url(url);
            assert!(ip.is_some(), "failed to extract IP from {}", url);
            let ip = ip.unwrap();
            assert!(
                ip.parse::<std::net::Ipv4Addr>().is_ok(),
                "extracted '{}' from '{}' is not a valid IPv4 address",
                ip,
                url
            );
        }
    }
}
