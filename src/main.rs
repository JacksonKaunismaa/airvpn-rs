use airvpn::{api, config, dns, ipv6, manifest, netlock, pinger, recovery, server, verify, wireguard};

use std::sync::atomic::Ordering;

use clap::{Parser, Subcommand};
use log::{debug, error, info, warn};
use zeroize::Zeroizing;

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
    init_logging();
    let provider_config = api::load_provider_config()
        .expect("failed to load provider configuration");
    api::verify_rsa_key_integrity(&provider_config);
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
        } => cmd_connect(
            &provider_config,
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
        ),
        Commands::Disconnect => cmd_disconnect(),
        Commands::Status => cmd_status(),
        Commands::Servers { sort, debug, username, password_stdin, skip_ping } => cmd_servers(&provider_config, &sort, debug, username, password_stdin, skip_ping),
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
// Connect — reconnection levels (Eddie: Session.cs reset levels)
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
// Connect
// ---------------------------------------------------------------------------

fn cmd_connect(
    provider_config: &api::ProviderConfig,
    server_name: Option<String>,
    no_lock: bool,
    allow_lan: bool,
    no_reconnect: bool,
    cli_username: Option<String>,
    password_stdin: bool,
    allow_server: Vec<String>,
    deny_server: Vec<String>,
    allow_country: Vec<String>,
    deny_country: Vec<String>,
    skip_ping: bool,
    no_verify: bool,
) -> anyhow::Result<()> {
    // 0. Pre-flight checks (root, wg-quick, nft)
    preflight_checks()?;

    // Unconditional cleanup: restore orphaned DNS backup from SIGKILL (Eddie: OnRecoveryAlways)
    let dns_backup = std::path::Path::new("/etc/resolv.conf.airvpn-rs");
    if dns_backup.exists() {
        // Only restore if no airvpn process is running
        if recovery::load().ok().flatten().map_or(true, |s| !recovery::is_pid_alive(s.pid)) {
            warn!("Restoring orphaned DNS backup...");
            let _ = dns::deactivate();
        }
    }

    // Unconditional cleanup: remove orphaned nftables table (Eddie: OnRecoveryAlways)
    if netlock::is_active() {
        if recovery::load().ok().flatten().map_or(true, |s| !recovery::is_pid_alive(s.pid)) {
            warn!("Removing orphaned nftables table...");
            let _ = netlock::deactivate();
        }
    }

    // Cleanup orphaned WireGuard config files (contain private key material).
    // Only scan /run/airvpn-rs/ (our config directory) — never /tmp (symlink attack surface).
    if let Ok(entries) = std::fs::read_dir("/run/airvpn-rs") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("avpn-") && name.ends_with(".conf") {
                if recovery::load().ok().flatten().map_or(true, |s| !recovery::is_pid_alive(s.pid)) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }

    // 1. Check for stale state / running instance
    recovery::check_and_recover()?;

    // 1b. Install signal handler EARLY — before any infrastructure changes
    // so Ctrl+C / SIGTERM during netlock/WireGuard/DNS setup sets the flag
    // instead of killing the process with no cleanup.
    let shutdown = recovery::setup_signal_handler()?;
    let nonce = recovery::generate_nonce();

    // 2. Resolve credentials (password via profile, interactive prompt, or --password-stdin)
    //    Wrapped in Zeroizing to clear from memory on drop.
    let stdin_password: Option<Zeroizing<String>> = if password_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut line)
            .map_err(|e| anyhow::anyhow!("failed to read password from stdin: {}", e))?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r').to_string();
        if trimmed.is_empty() {
            anyhow::bail!("--password-stdin: received empty password");
        }
        Some(Zeroizing::new(trimmed))
    } else {
        None
    };
    let (username, password) = config::resolve_credentials(
        cli_username.as_deref(),
        stdin_password.as_deref().map(|s| s.as_str()),
    )?;
    let username = Zeroizing::new(username);
    let password = Zeroizing::new(password);

    // 3. Fetch manifest + user data (two separate API calls)
    info!("Fetching server list...");
    debug!("API request: act=manifest (credentials redacted)");
    let manifest_xml = Zeroizing::new(api::fetch_manifest(provider_config, &username, &password)?);
    debug!("Manifest XML response: {} bytes", manifest_xml.len());
    let manifest = manifest::parse_manifest(&manifest_xml)?;
    info!(
        "Found {} servers, {} WireGuard modes",
        manifest.servers.len(),
        manifest.modes.len()
    );
    debug!(
        "Manifest parse results: {} servers, {} modes, {} bootstrap URLs, check_domain={:?}",
        manifest.servers.len(),
        manifest.modes.len(),
        manifest.bootstrap_urls.len(),
        manifest.check_domain,
    );

    // Display any service messages from AirVPN
    for msg in &manifest.messages {
        match msg.kind.as_str() {
            "error" => error!("[AirVPN] {}", msg.text),
            "warning" => warn!("[AirVPN] {}", msg.text),
            _ => info!("[AirVPN] {}", msg.text),
        }
    }

    info!("Fetching user data...");
    debug!("API request: act=user (credentials redacted)");
    let user_xml = Zeroizing::new(api::fetch_user_with_urls(provider_config, &username, &password, &manifest.bootstrap_urls)?);
    debug!("User XML response: {} bytes", user_xml.len());
    let user_info = manifest::parse_user(&user_xml)?;
    debug!("User info: login={}, {} WireGuard keys", user_info.login, user_info.keys.len());

    // Mode and key selection moved inside the loop (after manifest re-fetch)
    // since user_info and manifest can be refreshed on reconnection.

    // Validate initial manifest has modes and keys before entering the loop.
    if manifest.modes.is_empty() {
        anyhow::bail!("No WireGuard modes available");
    }
    if user_info.keys.is_empty() {
        anyhow::bail!("No WireGuard keys in user data");
    }

    // -----------------------------------------------------------------------
    // Server filtering (Eddie: GetConnections allow/deny filtering)
    //
    // Apply CLI allow/deny filters once before the reconnection loop. The
    // filtered list is used for all server selection attempts.
    // -----------------------------------------------------------------------

    let filtered_servers: Vec<manifest::Server> = server::filter_servers(
        &manifest.servers,
        &allow_server,
        &deny_server,
        &allow_country,
        &deny_country,
    )
    .into_iter()
    .cloned()
    .collect();
    if filtered_servers.is_empty() {
        anyhow::bail!("no servers match the allow/deny filters");
    }
    let has_filters = !allow_server.is_empty()
        || !deny_server.is_empty()
        || !allow_country.is_empty()
        || !deny_country.is_empty();
    if has_filters {
        info!(
            "Filters applied: {} of {} servers eligible",
            filtered_servers.len(),
            manifest.servers.len()
        );
    }

    // -----------------------------------------------------------------------
    // Latency measurement (Eddie: Jobs/Latency.cs)
    //
    // Ping each server's first IPv4 entry IP before the reconnection loop.
    // Results feed into score_with_ping() for Eddie-compatible server scoring.
    // -----------------------------------------------------------------------

    let ping_results = if skip_ping {
        info!("Skipping latency measurement (--skip-ping).");
        pinger::PingResults::new()
    } else {
        info!("Measuring server latencies...");
        let results = pinger::measure_all(&filtered_servers);
        info!("Pinged {} servers.", results.latencies.len());
        results
    };

    // -----------------------------------------------------------------------
    // Reconnection loop (Eddie: Session.cs outer `for (; CancelRequested == false;)`)
    //
    // The --server flag forces a specific server only on the FIRST attempt.
    // On ResetLevel::Error, we clear it so select_server_with_penalties can
    // pick a different (non-penalized) server.
    // -----------------------------------------------------------------------

    let mut penalties = server::ServerPenalties::new();
    let mut forced_server: Option<&str> = server_name.as_deref();
    let mut first_iteration = true;
    let mut consecutive_failures: u32 = 0;

    // Mutable copies of manifest data that can be refreshed on reconnection.
    // The initial fetch (above) populates these; subsequent loop iterations
    // may update them with fresher server load/status data.
    let mut filtered_servers = filtered_servers;
    let mut manifest = manifest;
    let mut user_info = user_info;

    // 7b. Block IPv6 on all interfaces ONCE before the main loop
    // (Eddie default: network.ipv6.mode="in-block").
    // Done here rather than inside the loop because ipv6::block_all() returns
    // an empty list when interfaces are already blocked. Calling it again on
    // reconnection would overwrite the recovery state with an empty list,
    // losing the original blocked interfaces needed for crash recovery.
    let blocked_ipv6_ifaces = ipv6::block_all();
    if !blocked_ipv6_ifaces.is_empty() {
        info!("IPv6 disabled on {} interfaces", blocked_ipv6_ifaces.len());
    }

    loop {
        // Check for shutdown before attempting connection
        if shutdown.load(Ordering::Relaxed) {
            info!("Shutdown requested before connection attempt.");
            break;
        }

        // Re-fetch manifest on reconnection (2nd+ iteration) to get current
        // server load/status. Eddie refreshes periodically; we refresh on each
        // reconnection attempt since the server landscape may have changed.
        // Non-fatal: if the re-fetch fails (e.g. network disrupted during
        // reconnection), we fall back to the existing manifest data.
        if !first_iteration {
            info!("Re-fetching manifest for updated server data...");
            match api::fetch_manifest(provider_config, &username, &password).map(Zeroizing::new) {
                Ok(new_xml) => match manifest::parse_manifest(&new_xml) {
                    Ok(new_manifest) => {
                        // Re-apply server filters to the fresh manifest
                        let new_filtered: Vec<manifest::Server> = server::filter_servers(
                            &new_manifest.servers,
                            &allow_server,
                            &deny_server,
                            &allow_country,
                            &deny_country,
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
                            filtered_servers = new_filtered;
                            manifest = new_manifest;
                        }
                    }
                    Err(e) => warn!("Failed to parse re-fetched manifest, using stale data: {:#}", e),
                },
                Err(e) => warn!("Failed to re-fetch manifest, using stale data: {:#}", e),
            }
            // Also refresh user data (WireGuard keys may have changed)
            match api::fetch_user_with_urls(provider_config, &username, &password, &manifest.bootstrap_urls).map(Zeroizing::new) {
                Ok(new_user_xml) => match manifest::parse_user(&new_user_xml) {
                    Ok(new_user) => {
                        user_info = new_user;
                    }
                    Err(e) => warn!("Failed to parse re-fetched user data, using stale data: {:#}", e),
                },
                Err(e) => warn!("Failed to re-fetch user data, using stale data: {:#}", e),
            }
        }
        first_iteration = false;

        // Select WireGuard mode and key from (possibly refreshed) manifest/user data.
        let mode = match manifest.modes.first() {
            Some(m) => m,
            None => {
                warn!("Refreshed manifest has no WireGuard modes, cannot connect");
                interruptible_sleep(&shutdown, 10);
                continue;
            }
        };
        let wg_key = match user_info.keys.first() {
            Some(k) => k,
            None => {
                warn!("Refreshed user data has no WireGuard keys, cannot connect");
                interruptible_sleep(&shutdown, 10);
                continue;
            }
        };

        // 6. Select server (penalty-aware + ping-aware, from filtered list)
        let server_ref = server::select_server_with_penalties(
            &filtered_servers,
            forced_server,
            &penalties,
            &ping_results,
        )?;
        info!(
            "Selected server: {} ({}, {})",
            server_ref.name, server_ref.location, server_ref.country_code
        );
        debug!(
            "Server details: name={}, group={}, entry_ips={:?}, exit_ips={:?}, score={}, bw={}/{}, users={}/{}, ipv4={}, ipv6={}",
            server_ref.name,
            server_ref.group,
            server_ref.ips_entry,
            server_ref.ips_exit,
            server::score(server_ref),
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

        // 7. Activate network lock BEFORE auth (Eddie: Session.cs:57-64 —
        // netlock activates at session start, before server selection or auth.
        // NetworkLockManager.cs:132-135 resolves hostnames before lock).
        // Bootstrap IPs are allowlisted so the auth API call works through the lock.
        if !no_lock {
            info!("Activating network lock...");
            let mut allowed_ips: Vec<String> = server_ref.ips_entry.clone();
            // Also whitelist API bootstrap IPs (extract bare IP from URLs like "http://1.2.3.4")
            for url in &provider_config.bootstrap_urls {
                if let Some(host) = extract_ip_from_url(url) {
                    allowed_ips.push(host);
                }
            }
            // Also whitelist manifest bootstrap URLs (Eddie merges these into the URL list)
            for url in &manifest.bootstrap_urls {
                if let Some(host) = extract_ip_from_url(url) {
                    allowed_ips.push(host);
                }
            }
            // Resolve hostnames to IPs before netlock activation (Eddie:
            // NetworkLockManager.cs:132-135 "resolve hostnames before a possible
            // lock of DNS server"). Entries that parse as IPs are kept as-is;
            // hostnames are resolved via DNS and replaced with the resolved IPs.
            let mut resolved_ips: Vec<String> = Vec::new();
            for entry in &allowed_ips {
                if entry.parse::<std::net::IpAddr>().is_ok() {
                    resolved_ips.push(entry.clone());
                } else {
                    // Not a valid IP — try resolving as hostname
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
            let lock_config = netlock::NetlockConfig {
                allow_lan,
                allow_dhcp: true,
                allow_ping: true,
                allow_ipv4ipv6translation: true,
                allowed_ips_incoming: vec![],
                allowed_ips_outgoing: allowed_ips,
                incoming_policy_accept: false,
            };
            netlock::activate(&lock_config)?;
            recovery::save(&recovery::State {
                lock_active: true,
                wg_interface: String::new(),
                wg_config_path: String::new(),
                dns_ipv4: String::new(),
                dns_ipv6: String::new(),
                pid: std::process::id(),
                blocked_ipv6_ifaces: blocked_ipv6_ifaces.clone(),
                endpoint_ip: String::new(),
                nonce,
                resolv_was_immutable: dns::was_immutable(),
            })?;
            info!("Network lock active (dedicated nftables table)");
            debug!(
                "Network lock: {} outgoing IPs whitelisted, allow_lan={}",
                lock_config.allowed_ips_outgoing.len(),
                lock_config.allow_lan,
            );
        }

        // 7b. Pre-connection authorization (Eddie: Session.cs:173-218)
        // Netlock is already active with bootstrap IPs allowlisted, so the
        // auth API call works through the lock.
        let reset_from_auth = match api::fetch_connect_with_urls(
            provider_config,
            &username,
            &password,
            &server_ref.name,
            &manifest.bootstrap_urls,
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
                // Eddie: Penality += penality_on_error, waitingSecs = 5
                warn!("Server says try another: {}", msg);
                Some(ResetLevel::Error)
            }
            Ok(api::ConnectDirective::Retry(msg)) => {
                warn!("Server message: {}", msg);
                Some(ResetLevel::Retry)
            }
            Err(e) => {
                // Non-fatal — Eddie: "If failed, continue anyway"
                warn!("pre-connection authorization failed: {:#}", e);
                Option::<ResetLevel>::None
            }
        };

        // Handle auth-level reset. Netlock and IPv6 blocking are active at this
        // point (netlock was activated above, IPv6 blocking before the loop).
        // Any bail!() must clean up first to avoid locking the user out.
        if let Some(level) = reset_from_auth {
            match level {
                ResetLevel::Fatal => {
                    if !no_lock { let _ = netlock::deactivate(); }
                    ipv6::restore(&blocked_ipv6_ifaces);
                    let _ = recovery::remove();
                    anyhow::bail!("Fatal: server rejected connection");
                }
                ResetLevel::Error => {
                    penalties.penalize(&server_ref.name, 30);
                    forced_server = Option::None; // clear forced server for rotation
                    if no_reconnect {
                        if !no_lock { let _ = netlock::deactivate(); }
                        ipv6::restore(&blocked_ipv6_ifaces);
                        let _ = recovery::remove();
                        anyhow::bail!("Server directed to try another (--no-reconnect)");
                    }
                    warn!("Penalized {}. Trying another server in 5s...", server_ref.name);
                    interruptible_sleep(&shutdown, 5);
                    continue;
                }
                ResetLevel::Retry => {
                    if no_reconnect {
                        if !no_lock { let _ = netlock::deactivate(); }
                        ipv6::restore(&blocked_ipv6_ifaces);
                        let _ = recovery::remove();
                        anyhow::bail!("Server asked to retry (--no-reconnect)");
                    }
                    warn!("Retrying in 10s...");
                    interruptible_sleep(&shutdown, 10);
                    continue;
                }
                _ => {} // None/Switch don't occur from auth
            }
        }

        // 7b. Save recovery state with blocked IPv6 interfaces (computed before loop)
        recovery::save(&recovery::State {
            lock_active: !no_lock,
            wg_interface: String::new(),
            wg_config_path: String::new(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            pid: std::process::id(),
            blocked_ipv6_ifaces: blocked_ipv6_ifaces.clone(),
            endpoint_ip: String::new(),
            nonce,
            resolv_was_immutable: dns::was_immutable(),
        })?;

        // 8. Generate WireGuard config and connect
        let (wg_config, endpoint_ip) = wireguard::generate_config(wg_key, server_ref, mode, &user_info)?;
        debug!(
            "WireGuard config: endpoint={}, ipv4={}, ipv6={}, dns={}/{}, mode={} (keys redacted)",
            endpoint_ip,
            wg_key.wg_ipv4,
            wg_key.wg_ipv6,
            wg_key.wg_dns_ipv4,
            wg_key.wg_dns_ipv6,
            mode.title,
        );
        info!("Connecting to {} via mode {}...", server_ref.name, mode.title);
        let (config_path, iface) = match wireguard::connect(&wg_config, &endpoint_ip) {
            Ok(result) => {
                consecutive_failures = 0;
                result
            }
            Err(e) => {
                error!("WireGuard connection failed: {:#}", e);
                // Keep netlock and IPv6 blocking active across reconnection
                // attempts (Eddie pattern: lock persists until explicit disconnect).
                // Only deactivate on --no-reconnect exit.
                penalties.penalize(&server_ref.name, 30);
                forced_server = Option::None;
                if no_reconnect {
                    // Tearing down — full cleanup
                    if !no_lock {
                        let _ = netlock::deactivate();
                    }
                    ipv6::restore(&blocked_ipv6_ifaces);
                    let _ = recovery::remove();
                    return Err(e.context("WireGuard connection failed"));
                }
                consecutive_failures += 1;
                let backoff_secs = std::cmp::min(3u64.saturating_mul(2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(6))), 300);
                warn!("Reconnecting in {}s (penalized {})...", backoff_secs, server_ref.name);
                interruptible_sleep(&shutdown, backoff_secs);
                continue;
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
            endpoint_ip: endpoint_ip.clone(),
            nonce,
            resolv_was_immutable: dns::was_immutable(),
        })?;
        info!("WireGuard interface: {}", iface);

        // Wait for first WireGuard handshake (Eddie: handshake_timeout_first=50s)
        info!("Waiting for handshake...");
        if let Err(e) = wireguard::wait_for_handshake(&iface, 50) {
            error!("Handshake failed: {:#}", e);
            // Tear down WireGuard interface but keep netlock and IPv6 blocking
            // active across reconnection (Eddie pattern).
            let _ = wireguard::disconnect(&config_path, &endpoint_ip);
            penalties.penalize(&server_ref.name, 30);
            forced_server = Option::None;
            if no_reconnect {
                // Tearing down — full cleanup
                if !no_lock {
                    let _ = netlock::deactivate();
                }
                ipv6::restore(&blocked_ipv6_ifaces);
                let _ = recovery::remove();
                return Err(e);
            }
            consecutive_failures += 1;
            let backoff_secs = std::cmp::min(3u64.saturating_mul(2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(6))), 300);
            warn!("Reconnecting in {}s (penalized {})...", backoff_secs, server_ref.name);
            interruptible_sleep(&shutdown, backoff_secs);
            continue;
        }
        info!("Handshake established.");

        // 9-12: Remaining setup — if any step fails, clean up and treat as fatal
        // (DNS/netlock setup failures are not transient server issues).
        if let Err(e) = (|| -> anyhow::Result<()> {
            // 9. Allow VPN interface in netlock
            if !no_lock {
                netlock::allow_interface(&iface)?;
            }

            // Bail early if shutdown was requested during netlock setup
            if shutdown.load(Ordering::Relaxed) {
                anyhow::bail!("shutdown requested during setup");
            }

            // 10. Activate DNS
            debug!("Activating DNS: ipv4={}, ipv6={}, iface={}", wg_key.wg_dns_ipv4, wg_key.wg_dns_ipv6, iface);
            dns::activate(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, &iface)?;
            info!("DNS configured: {}, {}", wg_key.wg_dns_ipv4, wg_key.wg_dns_ipv6);

            // Client-side DNS verification: ensure resolv.conf contains only VPN DNS
            if !dns::verify_resolv_conf(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, std::path::Path::new("/etc/resolv.conf")) {
                warn!("resolv.conf contains non-VPN nameservers after DNS activation — potential DNS leak");
            }

            // 11. Save credentials (non-fatal — don't kill connection over keyring issues)
            if let Err(e) = config::save_credentials(&username, &password) {
                warn!("failed to save credentials: {:#}", e);
            }

            // 12. Save recovery state
            recovery::save(&recovery::State {
                lock_active: !no_lock,
                wg_interface: iface.clone(),
                wg_config_path: config_path.clone(),
                dns_ipv4: wg_key.wg_dns_ipv4.clone(),
                dns_ipv6: wg_key.wg_dns_ipv6.clone(),
                pid: std::process::id(),
                blocked_ipv6_ifaces: blocked_ipv6_ifaces.clone(),
                endpoint_ip: endpoint_ip.clone(),
                nonce,
                resolv_was_immutable: dns::was_immutable(),
            })?;

            Ok(())
        })() {
            // If the error was a shutdown request, don't treat it as a fatal
            // setup failure — fall through to the monitor loop which will see
            // the shutdown flag and disconnect cleanly.
            if shutdown.load(Ordering::Relaxed) {
                warn!("Setup interrupted by shutdown signal, disconnecting...");
                let _ = cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces, &endpoint_ip);
                break;
            }
            error!("Setup failed after WireGuard connected: {:#}", e);
            warn!("Cleaning up...");
            let _ = cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces, &endpoint_ip);
            return Err(e);
        }

        // 10b-10c: Post-connection verification (Eddie: Service.cs check/tun + check/dns)
        //
        // Verification failures are treated as connection failures and trigger
        // reconnection (matching Eddie's behavior). Use --no-verify to skip
        // during testing.
        if !no_verify && !shutdown.load(Ordering::Relaxed) {
            let check_domain = manifest.check_domain.as_str();
            let check_dns_query = manifest.check_dns_query.as_str();
            let exit_ip = server_ref.ips_exit.first().map(|s| s.as_str()).unwrap_or("");
            debug!("Verification: check_domain={:?}, check_dns_query={:?}, exit_ip={:?}, server={}", check_domain, check_dns_query, exit_ip, server_ref.name);
            let mut verify_failed = false;

            // 10b. Verify tunnel is working
            info!("Verifying tunnel...");
            match verify::check_tunnel(&server_ref.name, &wg_key.wg_ipv4, check_domain, exit_ip) {
                Ok(()) => info!("Tunnel verified."),
                Err(e) => {
                    warn!("Tunnel verification failed: {:#}", e);
                    verify_failed = true;
                }
            }

            // 10c. Verify DNS goes through VPN
            if !verify_failed && !shutdown.load(Ordering::Relaxed) {
                info!("Verifying DNS...");
                match verify::check_dns(&server_ref.name, check_domain, exit_ip, check_dns_query) {
                    Ok(()) => info!("DNS verified."),
                    Err(e) => {
                        warn!("DNS verification failed: {:#}", e);
                        verify_failed = true;
                    }
                }
            }

            // 10d. Client-side DNS verification: resolv.conf should only contain VPN DNS
            if !verify_failed && !shutdown.load(Ordering::Relaxed) {
                if !dns::verify_resolv_conf(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, std::path::Path::new("/etc/resolv.conf")) {
                    warn!("resolv.conf contains non-VPN nameservers — potential DNS leak");
                    verify_failed = true;
                }
            }

            if verify_failed && !shutdown.load(Ordering::Relaxed) {
                warn!("Verification failed, treating as connection failure, reconnecting...");
                // Use partial_disconnect: tear down WG + DNS only, keep netlock
                // and IPv6 blocking active to prevent leak window during reconnection.
                let _ = partial_disconnect(&config_path, &iface, !no_lock, &endpoint_ip);
                penalties.penalize(&server_ref.name, 30);
                forced_server = Option::None;
                if no_reconnect {
                    // Full cleanup on exit — tear down netlock and IPv6 too
                    if !no_lock {
                        let _ = netlock::deactivate();
                    }
                    ipv6::restore(&blocked_ipv6_ifaces);
                    let _ = recovery::remove();
                    anyhow::bail!("Verification failed (--no-reconnect)");
                }
                consecutive_failures += 1;
                let backoff_secs = std::cmp::min(3u64.saturating_mul(2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(6))), 300);
                interruptible_sleep(&shutdown, backoff_secs);
                continue;
            }
        }

        info!(
            "Connected to {} via {}.{}",
            server_ref.name,
            iface,
            if no_reconnect {
                " Press Ctrl+C to disconnect."
            } else {
                " Press Ctrl+C to disconnect. Auto-reconnect enabled."
            }
        );

        // 13. Monitor loop — determines ResetLevel when connection ends
        let mut dns_fail_count: u32 = 0;
        let reset_level = loop {
            if shutdown.load(Ordering::Relaxed) {
                info!("Disconnecting...");
                break ResetLevel::None;
            }

            // Check interface still exists
            if !wireguard::is_connected(&iface) {
                error!("WireGuard interface {} disappeared!", iface);
                break ResetLevel::Error;
            }

            // Check handshake staleness (Eddie: handshake_timeout_connected=200s)
            if wireguard::is_handshake_stale(&iface, 200) {
                error!("WireGuard handshake stale (>200s) -- tunnel may be dead");
                break ResetLevel::Error;
            }

            // Check kill switch is still active
            if !no_lock && !netlock::is_active() {
                error!("Kill switch nftables table deleted externally! Triggering reconnection to restore it.");
                break ResetLevel::Error;
            }

            // Periodic DNS re-check (matching Eddie's DnsSwitchCheck)
            match dns::check_and_reapply(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, &iface) {
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

            // Client-side resolv.conf verification: catch DNS leaks that the
            // server-side check cannot detect (non-VPN nameservers in resolv.conf).
            if !dns::verify_resolv_conf(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, std::path::Path::new("/etc/resolv.conf")) {
                warn!("resolv.conf contains non-VPN nameservers — potential DNS leak (check_and_reapply should fix on next cycle)");
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        };

        // Handle reset level (Eddie: Session.cs phase 6 cleanup + wait)
        match reset_level {
            ResetLevel::None | ResetLevel::Fatal => {
                // User-requested disconnect or fatal error — full cleanup
                cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces, &endpoint_ip)?;
                break;
            }
            ResetLevel::Error => {
                if no_reconnect {
                    // Exiting — full cleanup
                    cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces, &endpoint_ip)?;
                    warn!("Connection lost (--no-reconnect, exiting).");
                    break;
                }
                // Reconnecting — partial disconnect only (keep netlock + IPv6 blocking)
                let _ = partial_disconnect(&config_path, &iface, !no_lock, &endpoint_ip);
                penalties.penalize(&server_ref.name, 30);
                forced_server = Option::None; // clear forced server for rotation
                consecutive_failures += 1;
                let backoff_secs = std::cmp::min(3u64.saturating_mul(2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(6))), 300);
                warn!(
                    "Connection lost. Reconnecting in {}s (penalized {})...",
                    backoff_secs, server_ref.name
                );
                interruptible_sleep(&shutdown, backoff_secs);
            }
            ResetLevel::Retry => {
                if no_reconnect {
                    // Exiting — full cleanup
                    cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces, &endpoint_ip)?;
                    warn!("Connection lost (--no-reconnect, exiting).");
                    break;
                }
                // Reconnecting — partial disconnect only (keep netlock + IPv6 blocking)
                let _ = partial_disconnect(&config_path, &iface, !no_lock, &endpoint_ip);
                warn!("Retrying same server in 1s...");
                interruptible_sleep(&shutdown, 1);
            }
            ResetLevel::Switch => {
                if no_reconnect {
                    // Exiting — full cleanup
                    cmd_disconnect_internal(&config_path, &iface, !no_lock, &blocked_ipv6_ifaces, &endpoint_ip)?;
                    warn!("Server switch requested (--no-reconnect, exiting).");
                    break;
                }
                // Reconnecting — partial disconnect only (keep netlock + IPv6 blocking)
                let _ = partial_disconnect(&config_path, &iface, !no_lock, &endpoint_ip);
                forced_server = Option::None;
                info!("Switching server...");
            }
        }
    }

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

    cmd_disconnect_internal(&state.wg_config_path, &state.wg_interface, state.lock_active, &state.blocked_ipv6_ifaces, &state.endpoint_ip)
}

/// Partial disconnect: tear down WireGuard only, keeping netlock, DNS, and IPv6
/// blocking active. Used during reconnection to avoid a leak window.
///
/// DNS is intentionally NOT deactivated here. Restoring the original resolv.conf
/// during reconnection would leak DNS queries to the pre-VPN DNS server (e.g., a
/// LAN router at 192.168.1.1 when --allow-lan is active). The VPN DNS config is
/// left in place; dns::activate() will overwrite it when the next connection
/// succeeds. DNS is only fully deactivated during cmd_disconnect_internal().
fn partial_disconnect(config_path: &str, iface: &str, lock_active: bool, endpoint_ip: &str) -> anyhow::Result<()> {
    // 1. Remove interface-specific nft rules (but keep the base netlock table)
    if lock_active && !iface.is_empty() {
        let _ = netlock::deallow_interface(iface);
    }
    // 2. wg-quick down
    let _ = wireguard::disconnect(config_path, endpoint_ip);
    // NOTE: DNS is intentionally kept active — deactivating would restore the
    // original resolv.conf, leaking queries through --allow-lan LAN rules.
    // netlock base table and IPv6 blocking also remain active — no leak window.
    Ok(())
}

fn cmd_disconnect_internal(config_path: &str, iface: &str, lock_active: bool, blocked_ipv6: &[String], endpoint_ip: &str) -> anyhow::Result<()> {
    // 1. Remove interface-specific nft rules before deactivating table
    if lock_active {
        if !iface.is_empty() {
            let _ = netlock::deallow_interface(iface);
        }
    }
    // 2. wg-quick down (also tears down routing + endpoint host route)
    let _ = wireguard::disconnect(config_path, endpoint_ip);
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
    provider_config: &api::ProviderConfig,
    sort: &str,
    debug: bool,
    cli_username: Option<String>,
    password_stdin: bool,
    _skip_ping: bool,
) -> anyhow::Result<()> {
    let stdin_password: Option<Zeroizing<String>> = if password_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut line)
            .map_err(|e| anyhow::anyhow!("failed to read password from stdin: {}", e))?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r').to_string();
        if trimmed.is_empty() {
            anyhow::bail!("--password-stdin: received empty password");
        }
        Some(Zeroizing::new(trimmed))
    } else {
        None
    };
    let (username, password) = config::resolve_credentials(
        cli_username.as_deref(),
        stdin_password.as_deref().map(|s| s.as_str()),
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
        "score" => servers.sort_by(|a, b| server::score(a).cmp(&server::score(b))),
        "load" => servers.sort_by(|a, b| {
            server::load_perc(a).cmp(&server::load_perc(b))
        }),
        "users" => servers.sort_by(|a, b| a.users.cmp(&b.users)),
        "name" => servers.sort_by(|a, b| a.name.cmp(&b.name)),
        _ => {
            warn!("Unknown sort key '{}', defaulting to score", sort);
            servers.sort_by(|a, b| server::score(a).cmp(&server::score(b)));
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
    preflight_checks()?;
    recovery::force_recover()
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
