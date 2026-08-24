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
    /// Connect at boot if enabled in the profile (used by airvpn-autoconnect.service)
    Autoconnect,
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
    /// Get or set profile options (root; changes take effect on next connect)
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Dynamic-DNS utilities (DuckDNS record writer + pager)
    Ddns {
        #[command(subcommand)]
        action: DdnsAction,
    },
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print an option's effective value (profile override or default)
    Get {
        key: String,
        /// Print secret options (passwords, credentialed URLs) unredacted
        #[arg(long)]
        reveal: bool,
    },
    /// Set a profile option (key must exist in the options registry)
    Set {
        key: String,
        /// Value; omit together with --stdin to read it from stdin instead
        value: Option<String>,
        /// Read the value from stdin (keeps secrets out of argv/process lists)
        #[arg(long)]
        stdin: bool,
    },
    /// List all options with their effective values
    List,
}

#[derive(Subcommand)]
enum DdnsAction {
    /// Send a test page through the exact DDNS pager path
    TestNotify,
    /// One live DuckDNS record write through the real path (empty ip= =
    /// source-detect: the VPN exit when connected, the raw WAN IP when not)
    TestDuckdns,
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

    let file_level = if debug_level { LevelFilter::Debug } else { LevelFilter::Info };
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
        Commands::Autoconnect => run_autoconnect(),
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
        Commands::Config { action } => run_config(action),
        Commands::Ddns { action } => run_ddns(action),
        Commands::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "airvpn", &mut std::io::stdout());
            Ok(())
        }
    }
}

/// `airvpn config` entry point: read/write profile options directly (the
/// profile is V2N, root-decryptable). Keys are validated against the options
/// registry so a typo can't plant a dead entry. Writes take effect on the next
/// connect — the running session resolved its options at connect time.
fn run_config(action: ConfigAction) -> anyhow::Result<()> {
    use airvpn::config;

    if !matches!(action, ConfigAction::Set { .. }) && !config::profile_readable() {
        eprintln!("warning: profile not readable (run as root to see actual values); showing defaults");
    }

    match action {
        ConfigAction::Get { key, reveal } => {
            let def = options::REGISTRY
                .iter()
                .find(|d| d.name == key)
                .ok_or_else(|| anyhow::anyhow!("unknown option '{}' (see `airvpn config list`)", key))?;
            let profile = config::load_profile_options();
            match profile.get(key.as_str()) {
                Some(v) if is_secret_option(&key) && !reveal => {
                    println!("<set — redacted; use --reveal>  (profile)")
                }
                Some(v) => println!("{}  (profile)", v),
                None => println!("{}  (default)", def.default),
            }
            Ok(())
        }
        ConfigAction::Set { key, value, stdin } => {
            let value = match (value, stdin) {
                (Some(v), false) => v,
                (None, true) => {
                    use std::io::Read;
                    let mut v = String::new();
                    std::io::stdin().read_to_string(&mut v)?;
                    // Strip the trailing newline a shell pipe or heredoc adds;
                    // anything else in the value is intentional.
                    v.trim_end_matches(['\r', '\n']).to_string()
                }
                (Some(_), true) => anyhow::bail!("pass either a value or --stdin, not both"),
                (None, false) => anyhow::bail!("missing value (or pass --stdin to read it from stdin)"),
            };
            let def = options::REGISTRY
                .iter()
                .find(|d| d.name == key)
                .ok_or_else(|| anyhow::anyhow!("unknown option '{}' (see `airvpn config list`)", key))?;
            // Boolean-typed options (default "true"/"false"): reject typos —
            // a stored "ture" would silently parse as false forever.
            if matches!(def.default, "true" | "false")
                && !matches!(value.to_ascii_lowercase().as_str(), "true" | "false")
            {
                anyhow::bail!("option '{}' is boolean — value must be 'true' or 'false'", key);
            }
            // Integer-typed options (default parses as i64): same hazard — get_i64
            // turns an unparseable stored value into 0, which e.g. silently disables
            // the congestion penalty or re-enables the Speed-mode users term at full
            // strength (0 -> .max(1) -> divisor 1).
            if def.default.parse::<i64>().is_ok() && value.parse::<i64>().is_err() {
                anyhow::bail!("option '{}' is an integer — '{}' does not parse", key, value);
            }
            config::save_profile_option(&key, &value)?;
            // Never echo secret values back — a config set of the notify
            // password printed to a terminal/transcript is a credential leak
            // and transcripts outlive terminals.
            if is_secret_option(&key) {
                println!("{} = <set — redacted>  (takes effect on next connect)", key);
            } else {
                println!("{} = {}  (takes effect on next connect)", key, value);
            }
            Ok(())
        }
        ConfigAction::List => {
            let profile = config::load_profile_options();
            for def in options::REGISTRY {
                match profile.get(def.name) {
                    Some(v) if v != def.default && is_secret_option(def.name) => {
                        println!("{} = <set — redacted>", def.name)
                    }
                    Some(v) if v != def.default => {
                        println!("{} = {}  (default: {})", def.name, v, def.default)
                    }
                    _ => println!("{} = {}", def.name, def.default),
                }
            }
            Ok(())
        }
    }
}

/// Options whose values must never be echoed by config get/set/list.
/// Single source of truth lives in the options registry (shared with the
/// helper's GET /profile redaction).
fn is_secret_option(key: &str) -> bool {
    options::is_secret(key)
}

/// `airvpn ddns` entry point.
fn run_ddns(action: DdnsAction) -> anyhow::Result<()> {
    use airvpn::{config, ddns};
    match action {
        DdnsAction::TestNotify => {
            if !config::profile_readable() {
                anyhow::bail!("profile not readable — run as root (sudo airvpn ddns test-notify)");
            }
            // notify() reports failures through log::warn! — give this thin
            // CLI path a stderr logger so they're visible.
            let _ = simplelog::TermLogger::init(
                simplelog::LevelFilter::Info,
                simplelog::Config::default(),
                simplelog::TerminalMode::Stderr,
                simplelog::ColorChoice::Auto,
            );
            let profile = config::load_profile_options();
            let url = options::get_str(&profile, options::DDNS_NOTIFY_URL).to_string();
            let user = options::get_str(&profile, options::DDNS_NOTIFY_USER).to_string();
            let password = options::get_str(&profile, options::DDNS_NOTIFY_PASSWORD).to_string();
            if url.is_empty() {
                anyhow::bail!("ddns.notify_url is empty — pager disabled, nothing to test");
            }
            ddns::validate_notify_url(&url)
                .map_err(|e| anyhow::anyhow!("ddns.notify_url does not parse: {}", e))?;
            println!("sending test page through the DDNS pager path...");
            if ddns::notify(
                &url,
                &user,
                &password,
                "DDNS pager test",
                "Manual test via `airvpn ddns test-notify` — if this reached the phone, the pager works.",
            ) {
                println!("server accepted the page (2xx) — check the phone.");
                Ok(())
            } else {
                anyhow::bail!("page NOT delivered — see the warning above for the cause");
            }
        }
        DdnsAction::TestDuckdns => {
            use airvpn::duckdns;
            if !config::profile_readable() {
                anyhow::bail!("profile not readable — run as root (sudo airvpn ddns test-duckdns)");
            }
            let profile = config::load_profile_options();
            let domain = options::get_str(&profile, options::DDNS_DUCKDNS_DOMAIN).to_string();
            let token = zeroize::Zeroizing::new(
                options::get_str(&profile, options::DDNS_DUCKDNS_TOKEN).to_string(),
            );
            duckdns::validate_config(&domain, &token).map_err(|e| anyhow::anyhow!(e))?;
            if domain.is_empty() {
                anyhow::bail!("ddns.duckdns_domain is empty — record writer disabled, nothing to test");
            }
            let name = duckdns::record_name(&domain);
            println!("writing {} via the DuckDNS API (source-detected IP)...", name);
            match duckdns::update(&domain, &token, None) {
                duckdns::WriteOutcome::Accepted => {
                    println!(
                        "DuckDNS acked the write (OK) — {} now points at this machine's egress IP \
                         (the VPN exit if connected). Propagation TTL is 60s.",
                        name,
                    );
                    Ok(())
                }
                duckdns::WriteOutcome::Rejected => anyhow::bail!(
                    "DuckDNS returned KO — the token is wrong or {} is not in that account", name,
                ),
                duckdns::WriteOutcome::Failed(cause) => {
                    anyhow::bail!("write failed: {}", cause)
                }
            }
        }
    }
}

/// Boot-time auto-connect entry point, invoked by `airvpn-autoconnect.service`.
///
/// Reads the `connect` profile option (our profile is V2N — decryptable as root
/// without a desktop keyring, so this works before any user logs in). If the
/// option is disabled, exits successfully without contacting the helper. If
/// enabled, issues a best-scored-server connect (no server override), retrying a
/// few times to ride out the socket-activated helper's warmup and any brief
/// post-boot network flux.
fn run_autoconnect() -> anyhow::Result<()> {
    use airvpn::config;

    let options = config::load_profile_options();
    if !options::get_bool(&options, options::CONNECT) {
        println!("autoconnect: disabled in profile (connect=false), nothing to do");
        return Ok(());
    }

    println!("autoconnect: enabled — connecting to best-scored server...");
    let req = ipc::ConnectRequest { server: None, overrides: HashMap::new() };

    const MAX_ATTEMPTS: u32 = 5;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);
    let mut last_err = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match cli_client::send_connect_detached(&req) {
            Ok(()) => return Ok(()),
            Err(e) => {
                eprintln!("autoconnect: attempt {attempt}/{MAX_ATTEMPTS} failed: {e}");
                last_err = Some(e);
                if attempt < MAX_ATTEMPTS {
                    std::thread::sleep(RETRY_DELAY);
                }
            }
        }
    }
    Err(last_err
        .expect("loop runs at least once so last_err is set on failure")
        .context("autoconnect: giving up after retries"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_autoconnect_subcommand_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from(["airvpn", "autoconnect"]);
        assert!(cli.is_ok(), "autoconnect should parse: {:?}", cli.err());
    }

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
