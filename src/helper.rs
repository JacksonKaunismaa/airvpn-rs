//! Root helper daemon for GUI IPC over Unix socket.
//!
//! Runs as root (launched via pkexec), listens on a Unix socket, and bridges
//! GUI commands to the connect engine. The connect engine runs in a thread
//! within the helper process. Stats are polled separately every 2s.
//!
//! Designed for single-client use (one GUI at a time). If the client
//! disconnects, handle_client returns and the accept loop waits for a new
//! connection.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};

use crate::{api, config, connect, ipc, manifest, netlock, pinger, recovery, server, wireguard};

pub const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";

/// Run the helper daemon: bind socket, accept clients in a loop.
pub fn run() -> Result<()> {
    connect::preflight_checks()?;

    // Remove stale socket file if it exists
    if std::path::Path::new(SOCKET_PATH).exists() {
        std::fs::remove_file(SOCKET_PATH)
            .with_context(|| format!("failed to remove stale socket: {}", SOCKET_PATH))?;
    }

    // Ensure /run/airvpn-rs/ exists with mode 0o755
    let run_dir = std::path::Path::new("/run/airvpn-rs");
    if !run_dir.exists() {
        std::fs::create_dir_all(run_dir).context("failed to create /run/airvpn-rs")?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(run_dir, std::fs::Permissions::from_mode(0o755))
            .context("failed to set permissions on /run/airvpn-rs")?;
    }

    let listener = UnixListener::bind(SOCKET_PATH)
        .with_context(|| format!("failed to bind socket: {}", SOCKET_PATH))?;

    // Set socket permissions to 0o660 (owner + group read/write)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o660))
            .context("failed to set socket permissions")?;
    }

    // Chown socket group to the unprivileged user's primary group so the GUI
    // can connect. Try $SUDO_USER first, then $PKEXEC_UID.
    chown_socket_to_caller_group()?;

    info!("Helper listening on {}", SOCKET_PATH);

    // Set up signal handler so Ctrl+C / SIGTERM triggers graceful shutdown.
    let shutdown = recovery::setup_signal_handler()?;

    // Refuse to start if a CLI connection is already running — the helper
    // can't manage a connection it didn't create.
    if let Ok(Some(state)) = recovery::load() {
        if recovery::is_pid_alive(state.pid) {
            anyhow::bail!(
                "A CLI connection is already running (PID {}). \
                 Disconnect it first with `sudo airvpn disconnect`.",
                state.pid
            );
        }
    }

    // Connection state persists across GUI client sessions so the helper
    // knows about running VPN connections when a new GUI connects.
    let mut conn_state = ConnState::new();

    // Use a 1s accept timeout so we periodically check the shutdown flag.
    // Rust's UnixListener retries on EINTR internally, so we can't rely on
    // signals to break out of accept() — we need the timeout.
    listener
        .set_nonblocking(false)
        .context("failed to set listener blocking")?;

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Shutdown signal received, exiting helper");
            break;
        }

        // Poll with 1s timeout: set nonblocking, try accept, sleep if no client
        listener.set_nonblocking(true).ok();
        match listener.accept() {
            Ok((stream, _addr)) => {
                // Switch back to blocking for the next cycle
                listener.set_nonblocking(false).ok();
                info!("Client connected");
                if let Err(e) = handle_client(stream, &mut conn_state) {
                    warn!("Client session ended with error: {}", e);
                }
                // If no VPN connection is running, exit when GUI disconnects.
                // This prevents orphaned helper processes after the GUI closes.
                let vpn_running = conn_state.connect_handle.as_ref().map_or(false, |h| !h.is_finished());
                if vpn_running {
                    info!("Client disconnected, VPN still running — waiting for new client");
                } else {
                    info!("Client disconnected, no VPN running — shutting down helper");
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                listener.set_nonblocking(false).ok();
                thread::sleep(Duration::from_secs(1));
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    // Clean up socket on exit
    let _ = std::fs::remove_file(SOCKET_PATH);
    Ok(())
}

/// Chown the socket's group to the unprivileged caller's primary group.
///
/// Tries $SUDO_USER first, then looks up the username for $PKEXEC_UID.
fn chown_socket_to_caller_group() -> Result<()> {
    let username = if let Ok(user) = std::env::var("SUDO_USER") {
        if !user.is_empty() {
            Some(user)
        } else {
            None
        }
    } else {
        None
    };

    let username = username.or_else(|| {
        std::env::var("PKEXEC_UID").ok().and_then(|uid_str| {
            let uid = uid_str.parse::<u32>().ok()?;
            let uid = nix::unistd::Uid::from_raw(uid);
            nix::unistd::User::from_uid(uid).ok().flatten().map(|u| u.name)
        })
    });

    let username = match username {
        Some(u) => u,
        None => {
            warn!("Could not determine unprivileged user ($SUDO_USER / $PKEXEC_UID not set)");
            return Ok(());
        }
    };

    // Look up the user's primary group
    let user = nix::unistd::User::from_name(&username)
        .with_context(|| format!("failed to look up user: {}", username))?
        .with_context(|| format!("user not found: {}", username))?;

    nix::unistd::chown(
        std::path::Path::new(SOCKET_PATH),
        None,
        Some(user.gid),
    )
    .with_context(|| format!("failed to chown socket group for user {}", username))?;

    debug!("Socket group set to {} (gid {})", username, user.gid);
    Ok(())
}

/// Send a HelperEvent as a JSON line to the client stream. Ignores write
/// errors (client may have disconnected).
fn send_event(stream: &mut UnixStream, event: &ipc::HelperEvent) {
    match ipc::encode_line(event) {
        Ok(line) => {
            let _ = stream.write_all(line.as_bytes());
            let _ = stream.flush();
        }
        Err(e) => {
            debug!("Failed to encode event: {}", e);
        }
    }
}

/// Build a LockStatus event from current system state.
fn build_lock_status() -> ipc::HelperEvent {
    ipc::HelperEvent::LockStatus {
        session_active: netlock::is_active(),
        persistent_active: netlock::is_persist_active(),
        persistent_installed: std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists(),
    }
}

/// VPN connection state that persists across GUI client sessions.
/// Lives in run(), passed to each handle_client() by &mut reference.
struct ConnState {
    connect_handle: Option<thread::JoinHandle<()>>,
    stats_handle: Option<thread::JoinHandle<()>>,
    stats_stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Server info captured from engine events, readable across GUI sessions.
    server_info: std::sync::Arc<std::sync::Mutex<(String, String, String)>>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            connect_handle: None,
            stats_handle: None,
            stats_stop: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            server_info: std::sync::Arc::new(std::sync::Mutex::new((String::new(), String::new(), String::new()))),
        }
    }

    /// Is the VPN connect thread still running?
    fn is_connected(&self) -> bool {
        self.connect_handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

/// Handle a single client connection: read commands, dispatch, send events.
fn handle_client(stream: UnixStream, state: &mut ConnState) -> Result<()> {
    let mut writer = stream.try_clone().context("failed to clone stream")?;
    let reader = BufReader::new(stream);

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                debug!("Read error (client disconnected?): {}", e);
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let cmd: ipc::HelperCommand = match ipc::decode_line(&line) {
            Ok(c) => c,
            Err(e) => {
                send_event(
                    &mut writer,
                    &ipc::HelperEvent::Error {
                        message: format!("invalid command: {}", e),
                    },
                );
                continue;
            }
        };

        debug!("Received command: {:?}", cmd);

        match cmd {
            ipc::HelperCommand::Connect {
                server,
                no_lock,
                allow_lan,
                skip_ping,
                no_reconnect,
                no_verify,
                allow_country,
                deny_country,
            } => {
                // Check if already connected (connect thread alive)
                if let Some(ref h) = state.connect_handle {
                    if !h.is_finished() {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: "already connected — disconnect first".to_string(),
                            },
                        );
                        continue;
                    }
                }

                // Reset shutdown flag for the new connection
                recovery::reset_shutdown();

                // Create mpsc channel for engine events
                let (event_tx, event_rx) = mpsc::channel::<ipc::EngineEvent>();

                // Spawn event-forwarding thread: reads EngineEvents from mpsc,
                // translates to HelperEvents, writes to socket.
                // Also captures server info for GUI reconnection.
                let mut event_writer = writer.try_clone().context("failed to clone stream for events")?;
                let server_info = state.server_info.clone();
                let event_fwd = thread::spawn(move || {
                    for engine_event in event_rx {
                        let helper_event = match engine_event {
                            ipc::EngineEvent::StateChanged(s) => {
                                ipc::HelperEvent::StateChanged { state: s }
                            }
                            ipc::EngineEvent::Log { level, message } => {
                                ipc::HelperEvent::Log { level, message }
                            }
                            ipc::EngineEvent::ServerSelected {
                                name,
                                country,
                                location,
                            } => {
                                // Capture for GUI reconnection
                                if let Ok(mut info) = server_info.lock() {
                                    *info = (name.clone(), country.clone(), location.clone());
                                }
                                // Don't emit Connected here — that comes after
                                // handshake + verification. This is just a log.
                                ipc::HelperEvent::Log {
                                    level: "info".to_string(),
                                    message: format!("Selected server: {} ({}, {})", name, location, country),
                                }
                            }
                        };
                        send_event(&mut event_writer, &helper_event);
                    }
                });

                // Stop any previous stats poller
                state.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Some(h) = state.stats_handle.take() {
                    let _ = h.join();
                }

                // Spawn connect thread
                let connect_event_tx = event_tx.clone();
                let connect_config = connect::ConnectConfig {
                    server_name: server,
                    no_lock,
                    allow_lan,
                    no_reconnect,
                    cli_username: None,
                    password_stdin: false,
                    allow_server: vec![],
                    deny_server: vec![],
                    allow_country,
                    deny_country,
                    skip_ping,
                    no_verify,
                    no_lock_last: false,
                    no_start_last: false,
                    cli_ipv6_mode: None,
                    cli_dns_servers: vec![],
                    cli_event_pre: [None, None, None],
                    cli_event_up: [None, None, None],
                    cli_event_down: [None, None, None],
                    event_tx: Some(connect_event_tx),
                };

                let mut disconnected_writer = writer.try_clone().context("failed to clone stream for connect thread")?;
                let conn_handle = thread::spawn(move || {
                    let result = (|| -> Result<()> {
                        let mut provider_config = api::load_provider_config()?;
                        api::verify_rsa_key_integrity(&provider_config);
                        connect::run(&mut provider_config, &connect_config)?;
                        Ok(())
                    })();

                    if let Err(e) = &result {
                        error!("Connect thread exited with error: {}", e);
                    }

                    // Signal disconnected (drop event_tx by moving connect_config
                    // into scope, then send Disconnected on the socket directly)
                    drop(result);
                    send_event(
                        &mut disconnected_writer,
                        &ipc::HelperEvent::StateChanged {
                            state: ipc::ConnectionState::Disconnected,
                        },
                    );
                });

                state.connect_handle = Some(conn_handle);

                // Spawn stats polling thread (every 2s)
                state.stats_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                let stats_stop_clone = state.stats_stop.clone();
                let mut stats_writer = writer.try_clone().context("failed to clone stream for stats")?;
                state.stats_handle = Some(thread::spawn(move || {
                    loop {
                        thread::sleep(Duration::from_secs(2));
                        if stats_stop_clone.load(std::sync::atomic::Ordering::SeqCst) {
                            break;
                        }

                        // Read recovery state to find the interface name
                        let iface = match recovery::load() {
                            Ok(Some(state)) => state.wg_interface,
                            _ => continue,
                        };

                        if iface.is_empty() || !wireguard::is_connected(&iface) {
                            continue;
                        }

                        match wireguard::get_transfer_stats(&iface) {
                            Ok((rx, tx)) => {
                                send_event(
                                    &mut stats_writer,
                                    &ipc::HelperEvent::Stats {
                                        rx_bytes: rx,
                                        tx_bytes: tx,
                                    },
                                );
                            }
                            Err(e) => {
                                debug!("Failed to get transfer stats: {}", e);
                            }
                        }
                    }
                }));

                // Wait for the event forwarder to finish in a background thread
                // (it will exit when event_tx is dropped by the connect thread)
                thread::spawn(move || {
                    let _ = event_fwd.join();
                });
            }

            ipc::HelperCommand::Disconnect => {
                recovery::trigger_shutdown();
                send_event(
                    &mut writer,
                    &ipc::HelperEvent::StateChanged {
                        state: ipc::ConnectionState::Disconnecting,
                    },
                );

                // Wait for connect thread to finish cleanup, then send Disconnected
                if let Some(h) = state.connect_handle.take() {
                    let _ = h.join();
                }
                // Stop stats poller
                state.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Some(h) = state.stats_handle.take() {
                    let _ = h.join();
                }
                // Clear server info
                if let Ok(mut info) = state.server_info.lock() {
                    *info = Default::default();
                }
                send_event(
                    &mut writer,
                    &ipc::HelperEvent::StateChanged {
                        state: ipc::ConnectionState::Disconnected,
                    },
                );
            }

            ipc::HelperCommand::Status => {
                // Determine connection state from connect thread + recovery state.
                // The connect thread may be from a previous GUI session.
                let conn_state = if state.is_connected() {
                    // Connect thread alive — check if WireGuard interface is up
                    match recovery::load() {
                        Ok(Some(rec)) if wireguard::is_connected(&rec.wg_interface) => {
                            let (name, country, location) = state.server_info
                                .lock()
                                .map(|info| info.clone())
                                .unwrap_or_default();
                            ipc::ConnectionState::Connected {
                                server_name: name,
                                server_country: country,
                                server_location: location,
                            }
                        }
                        _ => ipc::ConnectionState::Connecting,
                    }
                } else {
                    ipc::ConnectionState::Disconnected
                };
                send_event(&mut writer, &ipc::HelperEvent::StateChanged { state: conn_state.clone() });
                send_event(&mut writer, &build_lock_status());

                // If VPN is connected, start a stats poller for this GUI session
                if matches!(conn_state, ipc::ConnectionState::Connected { .. }) {
                    state.stats_stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let stop = state.stats_stop.clone();
                    let mut sw = writer.try_clone().context("clone writer for stats")?;
                    state.stats_handle = Some(thread::spawn(move || {
                        loop {
                            thread::sleep(Duration::from_secs(2));
                            if stop.load(std::sync::atomic::Ordering::SeqCst) { break; }
                            let iface = match recovery::load() {
                                Ok(Some(s)) => s.wg_interface,
                                _ => continue,
                            };
                            if iface.is_empty() || !wireguard::is_connected(&iface) { continue; }
                            match wireguard::get_transfer_stats(&iface) {
                                Ok((rx, tx)) => send_event(&mut sw, &ipc::HelperEvent::Stats { rx_bytes: rx, tx_bytes: tx }),
                                Err(_) => {}
                            }
                        }
                    }));
                }
            }

            ipc::HelperCommand::LockEnable => {
                match dispatch_lock_enable() {
                    Ok(()) => {}
                    Err(e) => {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("lock enable failed: {}", e),
                            },
                        );
                    }
                }
                send_event(&mut writer, &build_lock_status());
            }

            ipc::HelperCommand::LockDisable => {
                match netlock::reclaim_and_delete() {
                    Ok(()) => {}
                    Err(e) => {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("lock disable failed: {}", e),
                            },
                        );
                    }
                }
                send_event(&mut writer, &build_lock_status());
            }

            ipc::HelperCommand::LockInstall => {
                let result = (|| -> Result<()> {
                    let provider_config = api::load_provider_config()?;
                    let bootstrap_ips: Vec<String> = provider_config
                        .bootstrap_urls
                        .iter()
                        .filter_map(|url| connect::extract_ip_from_url(url))
                        .filter(|host| host.parse::<std::net::IpAddr>().is_ok())
                        .collect();
                    if bootstrap_ips.is_empty() {
                        anyhow::bail!("no bootstrap IPs found in provider config");
                    }
                    netlock::install_persistent(&bootstrap_ips)
                })();
                match result {
                    Ok(()) => {
                        send_event(&mut writer, &build_lock_status());
                    }
                    Err(e) => {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("Lock install failed: {:#}", e),
                            },
                        );
                    }
                }
            }

            ipc::HelperCommand::LockUninstall => {
                match netlock::uninstall_persistent() {
                    Ok(()) => {
                        send_event(&mut writer, &build_lock_status());
                    }
                    Err(e) => {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("Lock uninstall failed: {:#}", e),
                            },
                        );
                    }
                }
            }

            ipc::HelperCommand::LockStatus => {
                send_event(&mut writer, &build_lock_status());
            }

            ipc::HelperCommand::ListServers { skip_ping, sort } => {
                match dispatch_list_servers(skip_ping, sort.as_deref()) {
                    Ok(servers) => {
                        send_event(&mut writer, &ipc::HelperEvent::ServerList { servers });
                    }
                    Err(e) => {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("Failed to list servers: {:#}", e),
                            },
                        );
                    }
                }
            }

            ipc::HelperCommand::GetProfile => {
                match dispatch_get_profile() {
                    Ok(options) => {
                        send_event(&mut writer, &ipc::HelperEvent::Profile { options });
                    }
                    Err(e) => {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("Failed to load profile: {:#}", e),
                            },
                        );
                    }
                }
            }

            ipc::HelperCommand::SaveProfile { ref options } => {
                match dispatch_save_profile(options) {
                    Ok(()) => {
                        send_event(&mut writer, &ipc::HelperEvent::ProfileSaved);
                    }
                    Err(e) => {
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("Failed to save profile: {:#}", e),
                            },
                        );
                    }
                }
            }

            ipc::HelperCommand::Shutdown => {
                recovery::trigger_shutdown();

                // Wait for the connect thread to finish
                if let Some(h) = state.connect_handle.take() {
                    let _ = h.join();
                }

                // Stop stats poller
                state.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                if let Some(h) = state.stats_handle.take() {
                    let _ = h.join();
                }

                send_event(&mut writer, &ipc::HelperEvent::Shutdown);
                break;
            }
        }
    }

    // Stop stats poller when GUI disconnects — it writes to the now-dead socket.
    // A new one will be started when the next GUI connects and sends Status.
    state.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
    if let Some(h) = state.stats_handle.take() {
        let _ = h.join();
    }

    Ok(())
}

/// Enable the persistent lock by loading lock.nft rules with nft -f.
fn dispatch_lock_enable() -> Result<()> {
    if !std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists() {
        anyhow::bail!("persistent lock not installed -- run `airvpn-rs lock install` first");
    }
    if netlock::is_persist_active() {
        return Ok(());
    }
    let output = std::process::Command::new("nft")
        .args(["-f", netlock::PERSISTENT_RULES_PATH])
        .output()
        .context("failed to run nft")?;
    if !output.status.success() {
        anyhow::bail!(
            "nft -f failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

/// Load all profile options from the config file.
fn dispatch_get_profile() -> Result<std::collections::HashMap<String, String>> {
    Ok(config::load_profile_options())
}

/// Save profile options to the config file (one key at a time).
fn dispatch_save_profile(options: &std::collections::HashMap<String, String>) -> Result<()> {
    for (key, value) in options {
        config::save_profile_option(key, value)?;
    }
    Ok(())
}

/// Fetch the server list from the API, optionally measure pings, and return
/// scored ServerInfo structs for the GUI.
fn dispatch_list_servers(skip_ping: bool, sort: Option<&str>) -> Result<Vec<ipc::ServerInfo>> {
    let provider_config = api::load_provider_config()?;
    let options = config::load_profile_options();
    let (username, password) = config::resolve_credentials(None, None, &options)?;

    let manifest_xml = api::fetch_manifest(&provider_config, &username, &password)?;
    let manifest = manifest::parse_manifest(&manifest_xml)?;

    let pings = if skip_ping {
        pinger::PingResults::default()
    } else {
        pinger::measure_all(&manifest.servers)
    };

    let mut servers: Vec<ipc::ServerInfo> = manifest
        .servers
        .iter()
        .map(|s| {
            let ping_ms_raw = pings.get(&s.name);
            let ping_ms = if ping_ms_raw < 0 {
                None
            } else {
                Some(ping_ms_raw)
            };
            let score = server::score_with_ping(s, ping_ms_raw);
            let load = server::load_perc(s) as f64;
            let warning = if !s.warning_closed.is_empty() {
                Some(s.warning_closed.clone())
            } else if !s.warning_open.is_empty() {
                Some(s.warning_open.clone())
            } else {
                None
            };
            ipc::ServerInfo {
                name: s.name.clone(),
                country_code: s.country_code.clone(),
                location: s.location.clone(),
                users: s.users,
                users_max: s.users_max,
                load_percent: load,
                score,
                ping_ms,
                warning,
                ipv4: s.support_ipv4,
                ipv6: s.support_ipv6,
            }
        })
        .collect();

    // Sort the results (None = no sorting, GUI sorts client-side)
    if let Some(sort_field) = sort {
        match sort_field {
            "name" => servers.sort_by(|a, b| a.name.cmp(&b.name)),
            "load" => servers.sort_by(|a, b| {
                a.load_percent
                    .partial_cmp(&b.load_percent)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }),
            "users" => servers.sort_by_key(|s| s.users),
            _ => servers.sort_by_key(|s| s.score), // "score" or default
        }
    }

    Ok(servers)
}
