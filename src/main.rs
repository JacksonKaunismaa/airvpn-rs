use airvpn::{api, common, config, connect, manifest, netlock, recovery, server, wireguard};

use anyhow::Context;
use clap::{Parser, Subcommand};
use log::{info, warn};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "airvpn", about = "AirVPN WireGuard client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
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
        /// Disable auto-reconnection (single-shot mode)
        #[arg(long)]
        no_reconnect: bool,
        /// AirVPN username (overrides saved credentials)
        #[arg(long)]
        username: Option<String>,
        /// Read password from stdin (one line, for scripted use)
        #[arg(long)]
        password_stdin: bool,
        /// Only connect to these servers (repeatable)
        #[arg(long)]
        allow_server: Vec<String>,
        /// Never connect to these servers (repeatable)
        #[arg(long)]
        deny_server: Vec<String>,
        /// Only connect to servers in these countries (repeatable, 2-letter code)
        #[arg(long)]
        allow_country: Vec<String>,
        /// Never connect to servers in these countries (repeatable, 2-letter code)
        #[arg(long)]
        deny_country: Vec<String>,
        /// Skip server latency measurement (faster startup, uses score without ping)
        #[arg(long)]
        skip_ping: bool,
        /// Skip post-connection tunnel and DNS verification
        #[arg(long)]
        no_verify: bool,
        /// Don't lock to the same server within this session (Eddie: servers.locklast)
        #[arg(long)]
        no_lock_last: bool,
        /// Don't prefer the last-used server on startup (Eddie: servers.startlast)
        #[arg(long)]
        no_start_last: bool,
        /// IPv6 mode (Eddie: network.ipv6.mode). Overrides profile setting.
        /// "in" = always through tunnel, "in-block" = through tunnel if server
        /// supports it, "block" = always block. Default: read from profile.
        #[arg(long)]
        ipv6_mode: Option<String>,
        /// Custom DNS server (repeatable). Overrides AirVPN DNS.
        /// (Eddie: dns.servers — comma-separated in profile)
        #[arg(long = "dns")]
        dns_servers: Vec<String>,
        // Event hooks (Eddie: ProfileOptions.EnsureDefaultsEvent, Engine.RunEventCommand).
        // CLI overrides profile, not saved.
        /// Script to run before VPN connection (Eddie: event.vpn.pre.filename)
        #[arg(long = "event.vpn.pre.filename")]
        event_vpn_pre_filename: Option<String>,
        /// Arguments for vpn.pre script (Eddie: event.vpn.pre.arguments)
        #[arg(long = "event.vpn.pre.arguments")]
        event_vpn_pre_arguments: Option<String>,
        /// Wait for vpn.pre script to finish (Eddie: event.vpn.pre.waitend, default: true)
        #[arg(long = "event.vpn.pre.waitend")]
        event_vpn_pre_waitend: Option<String>,
        /// Script to run after VPN connects (Eddie: event.vpn.up.filename)
        #[arg(long = "event.vpn.up.filename")]
        event_vpn_up_filename: Option<String>,
        /// Arguments for vpn.up script (Eddie: event.vpn.up.arguments)
        #[arg(long = "event.vpn.up.arguments")]
        event_vpn_up_arguments: Option<String>,
        /// Wait for vpn.up script to finish (Eddie: event.vpn.up.waitend, default: true)
        #[arg(long = "event.vpn.up.waitend")]
        event_vpn_up_waitend: Option<String>,
        /// Script to run after VPN disconnects (Eddie: event.vpn.down.filename)
        #[arg(long = "event.vpn.down.filename")]
        event_vpn_down_filename: Option<String>,
        /// Arguments for vpn.down script (Eddie: event.vpn.down.arguments)
        #[arg(long = "event.vpn.down.arguments")]
        event_vpn_down_arguments: Option<String>,
        /// Wait for vpn.down script to finish (Eddie: event.vpn.down.waitend, default: true)
        #[arg(long = "event.vpn.down.waitend")]
        event_vpn_down_waitend: Option<String>,
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
        /// Read password from stdin (one line, for scripted use)
        #[arg(long)]
        password_stdin: bool,
        /// Skip server latency measurement (faster startup, uses score without ping)
        #[arg(long)]
        skip_ping: bool,
    },
    /// Clean up stale state after crash
    Recover,
    /// Manage persistent network lock (kill switch)
    Lock {
        #[command(subcommand)]
        action: LockAction,
    },
}

#[derive(Subcommand)]
enum LockAction {
    /// Install persistent lock (generate rules, enable systemd service)
    Install,
    /// Uninstall persistent lock (remove rules, disable service, delete table)
    Uninstall,
    /// Reload persistent lock table now
    Enable,
    /// Temporarily disable persistent lock (returns on reboot)
    Disable,
    /// Show persistent lock status
    Status,
}

/// Rotate log file if it exceeds 5MB. Keeps at most 3 files:
/// {path}, {path}.1, {path}.2. Called before opening the log file.
fn rotate_log(path: &str) {
    const MAX_SIZE: u64 = 5 * 1024 * 1024; // 5 MB
    let p = std::path::Path::new(path);
    let size = match std::fs::metadata(p) {
        Ok(m) => m.len(),
        Err(_) => return, // file doesn't exist yet, nothing to rotate
    };
    if size < MAX_SIZE {
        return;
    }
    // Rotate: .2 is deleted, .1 → .2, current → .1
    let p2 = format!("{}.2", path);
    let p1 = format!("{}.1", path);
    let _ = std::fs::remove_file(&p2);
    let _ = std::fs::rename(&p1, &p2);
    let _ = std::fs::rename(path, &p1);
}

fn init_logging() {
    use simplelog::*;
    use std::os::unix::fs::OpenOptionsExt;

    let log_path = std::env::var("AIRVPN_LOG").unwrap_or_default();
    // Prefer /var/log (root-owned, standard location), fall back to /run/airvpn-rs/
    // (root-owned, restricted permissions). Never use /tmp — symlink attack vector.
    let log_path = if !log_path.is_empty() {
        // Validate AIRVPN_LOG: reject path traversal and symlinks to prevent
        // arbitrary file writes when running as root (e.g. sudo -E).
        let log_p = std::path::Path::new(&log_path);
        let allowed_prefixes = ["/var/log/", "/run/airvpn-rs/"];
        if log_path.contains("..") {
            eprintln!("warning: AIRVPN_LOG contains '..', ignoring (path traversal rejected)");
            String::new()
        } else if log_p.is_symlink() {
            eprintln!("warning: AIRVPN_LOG points to a symlink, ignoring (symlink rejected)");
            String::new()
        } else if !allowed_prefixes.iter().any(|p| log_path.starts_with(p)) {
            eprintln!("warning: AIRVPN_LOG must be under /var/log/ or /run/airvpn-rs/, ignoring");
            String::new()
        } else {
            log_path
        }
    } else {
        String::new()
    };
    let log_path = if !log_path.is_empty() {
        log_path
    } else {
        let preferred = "/var/log/airvpn-rs.log";
        // Test if we can open/create the preferred path
        if std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(preferred)
            .is_ok()
        {
            preferred.to_string()
        } else {
            // Create /run/airvpn-rs/ with mode 0o700 (root-only) to prevent
            // symlink attacks that /tmp would be vulnerable to.
            let run_dir = std::path::Path::new("/run/airvpn-rs");
            if !run_dir.exists() {
                if let Err(e) = std::fs::create_dir(run_dir) {
                    eprintln!("warning: could not create {}: {}", run_dir.display(), e);
                } else {
                    let _ = std::fs::set_permissions(
                        run_dir,
                        std::os::unix::fs::PermissionsExt::from_mode(0o700),
                    );
                }
            }
            "/run/airvpn-rs/airvpn-rs.log".to_string()
        }
    };

    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![
        // stderr: INFO level, no timestamps (clean user-facing output)
        TermLogger::new(
            LevelFilter::Info,
            ConfigBuilder::new()
                .set_time_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .build(),
            TerminalMode::Stderr,
            ColorChoice::Auto,
        ),
    ];

    // Rotate log file if it's grown too large (>5MB → keep 3 files max).
    rotate_log(&log_path);

    // File logger: DEBUG level with timestamps — mode 0o600 (owner-only read/write)
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)
    {
        Ok(file) => {
            loggers.push(WriteLogger::new(
                LevelFilter::Debug,
                ConfigBuilder::new()
                    .set_target_level(LevelFilter::Off)
                    .set_thread_level(LevelFilter::Off)
                    .build(),
                file,
            ));
        }
        Err(e) => {
            eprintln!("warning: could not open log file {}: {}", log_path, e);
        }
    }

    CombinedLogger::init(loggers).unwrap_or_else(|e| {
        eprintln!("warning: failed to initialize logging: {}", e);
    });
}

/// Load provider.json and verify RSA key integrity.
/// Only needed for commands that talk to the AirVPN API (connect, servers).
fn load_provider() -> anyhow::Result<api::ProviderConfig> {
    let config = api::load_provider_config()
        .context("failed to load provider configuration")?;
    // Verify the provider.json RSA key hasn't been tampered with (binary integrity).
    // This check only applies to the initial bootstrap key. Once the manifest
    // provides a rotated RSA key (Fix 1), that key is authenticated by the
    // RSA+AES envelope and doesn't need integrity checking.
    api::verify_rsa_key_integrity(&config);
    Ok(config)
}

fn main() -> anyhow::Result<()> {
    init_logging();
    let cli = Cli::parse();
    match cli.command {
        Commands::Connect {
            server,
            no_lock,
            allow_lan,
            no_reconnect,
            username,
            password_stdin,
            allow_server,
            deny_server,
            allow_country,
            deny_country,
            skip_ping,
            no_verify,
            no_lock_last,
            no_start_last,
            ipv6_mode,
            dns_servers,
            event_vpn_pre_filename,
            event_vpn_pre_arguments,
            event_vpn_pre_waitend,
            event_vpn_up_filename,
            event_vpn_up_arguments,
            event_vpn_up_waitend,
            event_vpn_down_filename,
            event_vpn_down_arguments,
            event_vpn_down_waitend,
        } => {
            let mut provider_config = load_provider()?;
            let connect_config = connect::ConnectConfig {
                server_name: server,
                no_lock,
                allow_lan,
                no_reconnect,
                cli_username: username,
                password_stdin,
                allow_server,
                deny_server,
                allow_country,
                deny_country,
                skip_ping,
                no_verify,
                no_lock_last,
                no_start_last,
                cli_ipv6_mode: ipv6_mode,
                cli_dns_servers: dns_servers,
                cli_event_pre: [event_vpn_pre_filename, event_vpn_pre_arguments, event_vpn_pre_waitend],
                cli_event_up: [event_vpn_up_filename, event_vpn_up_arguments, event_vpn_up_waitend],
                cli_event_down: [event_vpn_down_filename, event_vpn_down_arguments, event_vpn_down_waitend],
            };
            connect::run(&mut provider_config, &connect_config)
        }
        Commands::Disconnect => cmd_disconnect(),
        Commands::Status => cmd_status(),
        Commands::Servers { sort, debug, username, password_stdin, skip_ping } => {
            let mut provider_config = load_provider()?;
            cmd_servers(&mut provider_config, &sort, debug, username, password_stdin, skip_ping)
        }
        Commands::Recover => cmd_recover(),
        Commands::Lock { action } => cmd_lock(action),
    }
}

// ---------------------------------------------------------------------------
// (Ipv6Mode, ResetLevel, EventHook, run_hook, run() [formerly cmd_connect],
// preflight_checks, cmd_disconnect_internal, partial_disconnect,
// teardown_lock_state, extract_ip_from_url, resolve_bootstrap_host,
// interruptible_sleep — all moved to src/connect.rs)
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Disconnect
// ---------------------------------------------------------------------------

fn cmd_disconnect() -> anyhow::Result<()> {
    connect::preflight_checks()?;
    let state = recovery::load()?.ok_or_else(|| anyhow::anyhow!("No active connection found"))?;

    // Resolve vpn.down hook from profile (no CLI flags in disconnect path)
    let profile_options = config::load_profile_options();
    let hook_down = connect::EventHook::resolve("vpn.down", &None, &None, &None, &profile_options);

    // If the connect process is still running, signal it to shut down gracefully
    if recovery::is_pid_alive(state.pid) && state.pid != std::process::id() {
        info!("Signaling PID {} to disconnect...", state.pid);
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(state.pid as i32),
            nix::sys::signal::Signal::SIGTERM,
        );
        // Wait up to 5 seconds for graceful shutdown
        for _ in 0..50 {
            if !recovery::is_pid_alive(state.pid) {
                info!("Disconnected.");
                return Ok(());
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        warn!("PID {} did not exit, forcing cleanup...", state.pid);
    }

    connect::cmd_disconnect_internal(&state.wg_config_path, &state.wg_interface, state.lock_active, &state.blocked_ipv6_ifaces, &state.endpoint_ip, &hook_down)
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
    provider_config: &mut api::ProviderConfig,
    sort: &str,
    debug: bool,
    cli_username: Option<String>,
    password_stdin: bool,
    _skip_ping: bool,
) -> anyhow::Result<()> {
    let stdin_password = common::read_stdin_password(password_stdin)?;
    let profile_options = config::load_profile_options();
    let (username, password) = config::resolve_credentials(
        cli_username.as_deref(),
        stdin_password.as_deref().map(|s| s.as_str()),
        &profile_options,
    )?;
    let password = Zeroizing::new(password);
    let xml = Zeroizing::new(api::fetch_manifest(provider_config, &username, &password)?);

    if debug {
        // Redact credentials from the raw XML before printing
        let redacted = xml
            .replace(&username, "[REDACTED_USER]")
            .replace(password.as_str(), "[REDACTED_PASS]");
        println!("{}", redacted);
        return Ok(());
    }

    let manifest = manifest::parse_manifest(&xml)?;

    let mut servers: Vec<&manifest::Server> = manifest.servers.iter().collect();
    match sort {
        "score" => servers.sort_by_key(|s| server::score(s)),
        "load" => servers.sort_by(|a, b| {
            server::load_perc(a).cmp(&server::load_perc(b))
        }),
        "users" => servers.sort_by(|a, b| a.users.cmp(&b.users)),
        "name" => servers.sort_by(|a, b| a.name.cmp(&b.name)),
        _ => {
            warn!("Unknown sort key '{}', defaulting to score", sort);
            servers.sort_by_key(|s| server::score(s));
        }
    }

    println!(
        "{:<20} {:<6} {:<12} {:>6} {:>6} {:>8}",
        "NAME", "CC", "LOCATION", "USERS", "LOAD%", "SCORE"
    );
    println!("{}", "-".repeat(64));

    for s in &servers {
        let load = server::load_perc(s);
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
    connect::preflight_checks()?;
    recovery::force_recover()
}

// ---------------------------------------------------------------------------
// Lock — persistent kill switch management
// ---------------------------------------------------------------------------

fn cmd_lock(action: LockAction) -> anyhow::Result<()> {
    // lock commands need root (nft access)
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("must run as root");
    }
    match action {
        LockAction::Install => cmd_lock_install(),
        LockAction::Uninstall => cmd_lock_uninstall(),
        LockAction::Enable => cmd_lock_enable(),
        LockAction::Disable => cmd_lock_disable(),
        LockAction::Status => cmd_lock_status(),
    }
}

fn cmd_lock_install() -> anyhow::Result<()> {
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

    let ruleset = netlock::generate_persistent_ruleset(&bootstrap_ips);

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
ExecStop=/usr/bin/nft delete table inet airvpn_persist

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

    info!("Persistent lock installed and active.");
    info!("{} bootstrap IPs allowlisted.", bootstrap_ips.len());
    info!("To temporarily disable: airvpn-rs lock disable");
    Ok(())
}

fn cmd_lock_uninstall() -> anyhow::Result<()> {
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

    info!("Persistent lock uninstalled.");
    Ok(())
}

fn cmd_lock_enable() -> anyhow::Result<()> {
    if !std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists() {
        anyhow::bail!("persistent lock not installed — run `airvpn-rs lock install` first");
    }
    if netlock::is_persist_active() {
        info!("Persistent lock table already active.");
        return Ok(());
    }
    let output = std::process::Command::new("nft")
        .args(["-f", netlock::PERSISTENT_RULES_PATH])
        .output()
        .context("failed to load lock.nft")?;
    if !output.status.success() {
        anyhow::bail!("nft -f failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    info!("Persistent lock re-enabled.");
    Ok(())
}

fn cmd_lock_disable() -> anyhow::Result<()> {
    if !netlock::is_persist_active() {
        info!("Persistent lock table not active.");
        return Ok(());
    }
    // Safe even while VPN is running — airvpn_persist and airvpn_lock are
    // independent tables. Deleting airvpn_persist doesn't affect the session lock.
    netlock::reclaim_and_delete()?;
    info!("Persistent lock disabled (will return on next reboot if service enabled).");
    Ok(())
}

fn cmd_lock_status() -> anyhow::Result<()> {
    let table_active = netlock::is_persist_active();
    let rules_exist = std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists();
    let service_exists = std::path::Path::new(netlock::PERSISTENT_SERVICE_PATH).exists();

    // Check if service is enabled
    let service_enabled = std::process::Command::new("systemctl")
        .args(["is-enabled", "airvpn-lock.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    println!("Persistent lock:");
    println!("  Table active:     {}", if table_active { "yes" } else { "no" });
    println!("  Rules file:       {}", if rules_exist { netlock::PERSISTENT_RULES_PATH } else { "not installed" });
    println!("  Service enabled:  {}", if service_enabled { "yes" } else { "no" });

    if !rules_exist && !service_exists {
        println!("\nNot installed. Run `airvpn-rs lock install` to set up.");
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
    fn test_lock_subcommand_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["airvpn", "lock", "status"]);
        assert!(cli.is_ok(), "lock status should parse: {:?}", cli.err());

        let cli = Cli::try_parse_from(["airvpn", "lock", "install"]);
        assert!(cli.is_ok(), "lock install should parse: {:?}", cli.err());

        let cli = Cli::try_parse_from(["airvpn", "lock", "uninstall"]);
        assert!(cli.is_ok(), "lock uninstall should parse: {:?}", cli.err());

        let cli = Cli::try_parse_from(["airvpn", "lock", "enable"]);
        assert!(cli.is_ok(), "lock enable should parse: {:?}", cli.err());

        let cli = Cli::try_parse_from(["airvpn", "lock", "disable"]);
        assert!(cli.is_ok(), "lock disable should parse: {:?}", cli.err());
    }
}
