use airvpn::{cli_client, ipc};

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
    },
    /// Disconnect from AirVPN
    Disconnect,
    /// Show connection status
    Status,
    /// List available servers
    Servers {
        /// Sort order: score (default), name, load, users
        #[arg(long, default_value = "score")]
        sort: String,
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Only init full logging for the helper daemon process.
    // All other commands are thin socket clients — output comes from the helper.
    match &cli.command {
        Commands::Helper => init_logging(),
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
        } => {
            let req = ipc::ConnectRequest {
                server,
                no_lock,
                allow_lan,
                allow_country,
                deny_country,
                allow_server,
                deny_server,
                no_reconnect,
                no_verify,
                no_lock_last,
                no_start_last,
                ipv6_mode,
                dns_servers,
            };
            cli_client::send_connect(&req)
        }
        Commands::Disconnect => cli_client::send_simple("POST", "/disconnect", None),
        Commands::Status => cli_client::send_status(),
        Commands::Servers { sort } => {
            cli_client::send_list_servers(&sort)
        }
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
