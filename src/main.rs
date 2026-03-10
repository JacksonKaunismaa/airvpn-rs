use std::collections::HashMap;

use airvpn::{cli_client, ipc, options};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

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
        /// WireGuard device/key name (default: "Default")
        /// (Eddie: key — selects which AirVPN device to use)
        #[arg(long)]
        key: Option<String>,
    },
    /// Disconnect from AirVPN
    Disconnect,
    /// Show connection status
    Status,
    /// List available servers
    Servers,
    /// Clean up stale state after crash
    Recover,
    /// Manage persistent network lock (kill switch)
    Lock {
        #[command(subcommand)]
        action: LockAction,
    },
    /// Run as root helper daemon for GUI IPC
    Helper,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
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

/// Validate a log file path: reject traversal, symlinks, and paths outside allowed prefixes.
fn validate_log_path(path: &str) -> Option<String> {
    let log_p = std::path::Path::new(path);
    let allowed_prefixes = ["/var/log/", "/run/airvpn-rs/"];
    if path.contains("..") {
        eprintln!("warning: log path contains '..', ignoring (path traversal rejected)");
        None
    } else if log_p.is_symlink() {
        eprintln!("warning: log path points to a symlink, ignoring (symlink rejected)");
        None
    } else if !allowed_prefixes.iter().any(|p| path.starts_with(p)) {
        eprintln!("warning: log path must be under /var/log/ or /run/airvpn-rs/, ignoring");
        None
    } else {
        Some(path.to_string())
    }
}

fn init_logging(file_logging_enabled: bool, profile_log_path: &str, debug_level: bool) {
    use simplelog::*;
    use std::os::unix::fs::OpenOptionsExt;

    // Determine stderr log level: debug if profile says so, else info
    let stderr_level = if debug_level { LevelFilter::Debug } else { LevelFilter::Info };

    let mut loggers: Vec<Box<dyn SharedLogger>> = vec![
        TermLogger::new(
            stderr_level,
            ConfigBuilder::new()
                .set_time_level(LevelFilter::Off)
                .set_target_level(LevelFilter::Off)
                .set_thread_level(LevelFilter::Off)
                .build(),
            TerminalMode::Stderr,
            ColorChoice::Auto,
        ),
    ];

    // File logging: use AIRVPN_LOG env var (highest priority), then profile option,
    // then auto-detect a writable path.
    let env_log_path = std::env::var("AIRVPN_LOG").unwrap_or_default();
    let log_path = if !env_log_path.is_empty() {
        validate_log_path(&env_log_path).unwrap_or_default()
    } else if file_logging_enabled && !profile_log_path.is_empty() {
        validate_log_path(profile_log_path).unwrap_or_default()
    } else if file_logging_enabled {
        // Enabled but no explicit path — use default
        let preferred = "/var/log/airvpn-rs/helper.log";
        validate_log_path(preferred).unwrap_or_default()
    } else {
        // File logging disabled — use default auto-detect (backwards compat)
        String::new()
    };

    // Resolve to a concrete file path if empty (auto-detect mode)
    let log_path = if !log_path.is_empty() {
        log_path
    } else if !file_logging_enabled && env_log_path.is_empty() {
        // File logging explicitly disabled and no env override — stderr only
        return CombinedLogger::init(loggers).unwrap_or_else(|e| {
            eprintln!("warning: failed to initialize logging: {}", e);
        });
    } else {
        let preferred = "/var/log/airvpn-rs.log";
        if std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(preferred)
            .is_ok()
        {
            preferred.to_string()
        } else {
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

    // Ensure parent directory exists for profile-specified paths
    if let Some(parent) = std::path::Path::new(&log_path).parent() {
        if !parent.exists() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("warning: could not create log directory {}: {}", parent.display(), e);
            } else {
                let _ = std::fs::set_permissions(
                    parent,
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                );
            }
        }
    }

    rotate_log(&log_path);

    let file_level = if debug_level { LevelFilter::Debug } else { LevelFilter::Debug };
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&log_path)
    {
        Ok(file) => {
            loggers.push(WriteLogger::new(
                file_level,
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Only init full logging for the helper daemon process.
    // All other commands are thin socket clients — output comes from the helper.
    match &cli.command {
        Commands::Helper => {
            // Read logging options from profile BEFORE initializing logging.
            // This lets profile settings control file logging and debug level.
            use airvpn::config;
            let profile_opts = config::load_profile_options();
            let file_enabled = options::get_bool(&profile_opts, options::LOG_FILE_ENABLED);
            let file_path = options::get_str(&profile_opts, options::LOG_FILE_PATH).to_string();
            let debug_level = options::get_bool(&profile_opts, options::LOG_LEVEL_DEBUG);
            init_logging(file_enabled, &file_path, debug_level);
        }
        _ => {}
    }

    match cli.command {
        Commands::Connect {
            server,
            no_lock,
            allow_lan,
            no_reconnect,
            allow_server,
            deny_server,
            allow_country,
            deny_country,
            no_verify,
            no_lock_last,
            no_start_last,
            ipv6_mode,
            dns_servers,
            key,
        } => {
            let mut overrides = HashMap::new();
            // CLI flags are negative (--no-lock = disable), options are positive
            // Only set override if flag is non-default
            if no_lock { overrides.insert(options::NETLOCK.into(), "false".into()); }
            if allow_lan { overrides.insert(options::NETLOCK_ALLOW_PRIVATE.into(), "true".into()); }
            if no_reconnect { overrides.insert(options::RECONNECT.into(), "false".into()); }
            if no_verify { overrides.insert(options::VERIFY.into(), "false".into()); }
            if no_lock_last { overrides.insert(options::SERVERS_LOCKLAST.into(), "false".into()); }
            if no_start_last { overrides.insert(options::SERVERS_STARTLAST.into(), "false".into()); }
            if !allow_server.is_empty() { overrides.insert(options::SERVERS_ALLOWLIST.into(), allow_server.join(",")); }
            if !deny_server.is_empty() { overrides.insert(options::SERVERS_DENYLIST.into(), deny_server.join(",")); }
            if !allow_country.is_empty() { overrides.insert(options::AREAS_ALLOWLIST.into(), allow_country.join(",")); }
            if !deny_country.is_empty() { overrides.insert(options::AREAS_DENYLIST.into(), deny_country.join(",")); }
            if let Some(ref mode) = ipv6_mode { overrides.insert(options::NETWORK_IPV6_MODE.into(), mode.clone()); }
            if !dns_servers.is_empty() { overrides.insert(options::DNS_SERVERS.into(), dns_servers.join(",")); }
            if let Some(ref k) = key { overrides.insert(options::KEY.into(), k.clone()); }

            let req = ipc::ConnectRequest { server, overrides };
            cli_client::send_connect(&req)
        }
        Commands::Disconnect => cli_client::send_simple("POST", "/disconnect", None),
        Commands::Status => cli_client::send_status(),
        Commands::Servers => cli_client::send_list_servers(),
        Commands::Recover => cli_client::send_simple("POST", "/recover", None),
        Commands::Lock { action } => {
            let (method, path) = match action {
                LockAction::Install => ("POST", "/lock/install"),
                LockAction::Uninstall => ("POST", "/lock/uninstall"),
                LockAction::Enable => ("POST", "/lock/enable"),
                LockAction::Disable => ("POST", "/lock/disable"),
                LockAction::Status => ("GET", "/lock/status"),
            };
            cli_client::send_simple(method, path, None)
        }
        Commands::Helper => {
            use airvpn::helper;
            helper::run()
        }
        Commands::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "airvpn", &mut std::io::stdout());
            Ok(())
        }
    }
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
