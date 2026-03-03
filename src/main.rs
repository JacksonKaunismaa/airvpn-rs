use airvpn::{api, cli_client, common, config, ipc, manifest, server};

use anyhow::Context;
use clap::{Parser, Subcommand};
use log::warn;
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
    /// Run as root helper daemon for GUI IPC
    Helper,
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
    let cli = Cli::parse();

    // Only init full logging (file + stderr) for commands that run in-process.
    // Thin-client commands (connect, disconnect, status, lock) get their output
    // from the helper via cli_client — no log file needed.
    match &cli.command {
        Commands::Helper | Commands::Servers { .. } => init_logging(),
        _ => {}
    }

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
            // Read stdin password if --password-stdin was passed.
            // Credentials are resolved by the helper (it has root access to
            // the profile). CLI only sends explicit --username / --password-stdin.
            let stdin_password = common::read_stdin_password(password_stdin)?;

            let cmd = ipc::HelperCommand::Connect {
                server,
                no_lock,
                allow_lan,
                skip_ping,
                allow_country,
                deny_country,
                username: username.unwrap_or_default(),
                password: stdin_password.map(|z| z.to_string()).unwrap_or_default(),
                allow_server,
                deny_server,
                no_reconnect,
                no_verify,
                no_lock_last,
                no_start_last,
                ipv6_mode,
                dns_servers,
                event_pre: [event_vpn_pre_filename, event_vpn_pre_arguments, event_vpn_pre_waitend],
                event_up: [event_vpn_up_filename, event_vpn_up_arguments, event_vpn_up_waitend],
                event_down: [event_vpn_down_filename, event_vpn_down_arguments, event_vpn_down_waitend],
            };
            cli_client::send_command(&cmd)
        }
        Commands::Disconnect => {
            cli_client::send_command(&ipc::HelperCommand::Disconnect)
        }
        Commands::Status => cli_client::send_status(),
        Commands::Servers { sort, debug, username, password_stdin, skip_ping } => {
            let mut provider_config = load_provider()?;
            cmd_servers(&mut provider_config, &sort, debug, username, password_stdin, skip_ping)
        }
        Commands::Recover => cli_client::send_command(&ipc::HelperCommand::Recover),
        Commands::Lock { action } => {
            let cmd = match action {
                LockAction::Install => ipc::HelperCommand::LockInstall,
                LockAction::Uninstall => ipc::HelperCommand::LockUninstall,
                LockAction::Enable => ipc::HelperCommand::LockEnable,
                LockAction::Disable => ipc::HelperCommand::LockDisable,
                LockAction::Status => ipc::HelperCommand::LockStatus,
            };
            cli_client::send_command(&cmd)
        }
        Commands::Helper => {
            use airvpn::helper;
            helper::run()
        }
    }
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
