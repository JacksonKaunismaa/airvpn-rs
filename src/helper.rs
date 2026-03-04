//! Root helper daemon for GUI IPC over Unix socket.
//!
//! Runs as root via systemd socket activation (`airvpn-helper.socket` +
//! `airvpn-helper.service`). Inherits the pre-bound Unix socket from
//! systemd and bridges GUI commands to the connect engine. The connect
//! engine runs in a thread within the helper process. Stats are polled
//! separately every 2s.
//!
//! Designed for single-client use (one GUI at a time). If the client
//! disconnects, handle_client returns and the accept loop waits for a new
//! connection.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};

use crate::{api, config, connect, ipc, manifest, netlock, recovery, server, wireguard};

pub const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";
const PID_FILE: &str = "/run/airvpn-rs/helper.pid";

/// Obtain the listening socket from systemd socket activation.
///
/// Uses `sd_notify::listen_fds()` which checks `LISTEN_PID` / `LISTEN_FDS`
/// and returns the inherited file descriptors. We expect exactly one (fd 3).
/// If not socket-activated, bails with a helpful error message.
fn get_systemd_listener() -> Result<UnixListener> {
    let mut fds = sd_notify::listen_fds()
        .context("failed to query systemd socket activation")?;

    match fds.next() {
        Some(fd) => {
            // SAFETY: `fd` (SD_LISTEN_FDS_START, i.e. 3 for a single-socket
            // service) is passed by systemd and is a valid, open Unix socket
            // file descriptor. sd_notify set O_CLOEXEC before returning.
            let listener = unsafe { UnixListener::from_raw_fd(fd) };
            Ok(listener)
        }
        None => {
            anyhow::bail!(
                "No socket passed via systemd socket activation.\n\
                 \n\
                 The helper must be started by systemd, not run directly.\n\
                 Enable the socket unit:\n\
                 \n\
                   sudo systemctl enable --now airvpn-helper.socket\n\
                 \n\
                 Then the GUI will auto-start the helper on first connection."
            );
        }
    }
}

/// Log the UID, GID, and PID of the connecting peer process.
/// Returns the peer UID (needed for Eddie profile discovery).
fn log_peer_credentials(stream: &UnixStream) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    match getsockopt(stream, PeerCredentials) {
        Ok(creds) => {
            info!(
                "Client connected: pid={} uid={} gid={}",
                creds.pid(),
                creds.uid(),
                creds.gid()
            );
            Some(creds.uid())
        }
        Err(e) => {
            warn!("Client connected (failed to get peer credentials: {})", e);
            None
        }
    }
}

/// Write the current PID to the PID file (mode 0o644).
fn write_pid_file() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let pid = std::process::id().to_string();
    std::fs::write(PID_FILE, pid.as_bytes())
        .with_context(|| format!("failed to write PID file: {}", PID_FILE))?;
    std::fs::set_permissions(PID_FILE, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("failed to set PID file permissions: {}", PID_FILE))?;
    Ok(())
}

/// Read and parse the PID from the PID file.
pub fn read_pid_file() -> Option<u32> {
    std::fs::read_to_string(PID_FILE)
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Run the helper daemon: get socket from systemd, accept clients in a loop.
pub fn run() -> Result<()> {
    connect::preflight_checks()?;

    let listener = get_systemd_listener()?;
    write_pid_file()?;
    info!("Helper listening on {} (systemd socket activation)", SOCKET_PATH);

    // Set up signal handler so Ctrl+C / SIGTERM triggers graceful shutdown.
    let shutdown = recovery::setup_signal_handler()?;

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
                let peer_uid = log_peer_credentials(&stream);
                if let Err(e) = handle_client(stream, &mut conn_state, peer_uid) {
                    warn!("Client session ended with error: {}", e);
                }
                info!("Client disconnected");
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

    // If a VPN connection is active, disconnect gracefully before exiting.
    // This handles systemctl stop / SIGTERM during an active session.
    if conn_state.is_connected() {
        info!("Disconnecting active VPN before shutdown...");
        // trigger_shutdown was already called (that's how we got here),
        // which tells connect::run() to exit its loop.
        if let Some(h) = conn_state.connect_handle.take() {
            let _ = h.join();
        }
        conn_state.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = conn_state.stats_handle.take() {
            let _ = h.join();
        }
    }

    // Clean up PID file on exit. Do NOT remove the socket — systemd owns it.
    let _ = std::fs::remove_file(PID_FILE);
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
fn handle_client(stream: UnixStream, state: &mut ConnState, peer_uid: Option<u32>) -> Result<()> {
    let mut writer = stream.try_clone().context("failed to clone stream")?;
    let mut reader = BufReader::new(stream);

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {}
            Err(e) => {
                debug!("Read error (client disconnected?): {}", e);
                break;
            }
        }

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

        // Log command variant without payload (Connect contains credentials).
        debug!("Received command: {}", match &cmd {
            ipc::HelperCommand::Connect { .. } => "Connect",
            ipc::HelperCommand::Disconnect => "Disconnect",
            ipc::HelperCommand::Status => "Status",
            ipc::HelperCommand::LockInstall => "LockInstall",
            ipc::HelperCommand::LockUninstall => "LockUninstall",
            ipc::HelperCommand::LockEnable => "LockEnable",
            ipc::HelperCommand::LockDisable => "LockDisable",
            ipc::HelperCommand::LockStatus => "LockStatus",
            ipc::HelperCommand::Recover => "Recover",
            ipc::HelperCommand::ImportEddieProfile { .. } => "ImportEddieProfile",
            ipc::HelperCommand::Servers { .. } => "Servers",
            ipc::HelperCommand::Shutdown => "Shutdown",
        });

        match cmd {
            ipc::HelperCommand::Connect {
                server,
                no_lock,
                allow_lan,
                skip_ping,
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
                event_pre,
                event_up,
                event_down,
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

                // Resolve credentials:
                // 1. Our saved profile (root-readable)
                // 2. Eddie profile import (helper reads as root, asks client to confirm)
                // 3. Error — user must run `sudo airvpn connect` for first-time setup
                let profile_options = config::load_profile_options();
                let prof_user = profile_options.get("login").cloned().unwrap_or_default();
                let prof_pass = profile_options.get("password").cloned().unwrap_or_default();

                let (resolved_username, resolved_password) = if !prof_user.is_empty() && !prof_pass.is_empty() {
                    (prof_user, prof_pass)
                } else if let Some(eddie_path) = peer_uid.and_then(config::eddie_profile_path_for_uid) {
                    // Found Eddie profile for the connecting user. Ask them to confirm.
                    send_event(&mut writer, &ipc::HelperEvent::EddieProfileFound {
                        path: eddie_path.display().to_string(),
                    });

                    // Wait for ImportEddieProfile response from the client
                    let mut accepted = false;
                    loop {
                        let mut resp = String::new();
                        match reader.read_line(&mut resp) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                        if resp.trim().is_empty() { continue; }
                        if let Ok(ipc::HelperCommand::ImportEddieProfile { accept }) = ipc::decode_line(&resp) {
                            accepted = accept;
                            break;
                        }
                    }

                    if !accepted {
                        send_event(&mut writer, &ipc::HelperEvent::Error {
                            message: "no credentials available — run `sudo airvpn connect` for first-time setup".to_string(),
                        });
                        continue;
                    }

                    // Import Eddie profile as root (can read user files + keyring via UID)
                    match config::load_eddie_profile_for_uid(&eddie_path, peer_uid.unwrap()) {
                        Ok((opts, _is_v2n)) => {
                            let eddie_user = opts.get("login").cloned().unwrap_or_default();
                            let eddie_pass = opts.get("password").cloned().unwrap_or_default();
                            if eddie_user.is_empty() || eddie_pass.is_empty() {
                                send_event(&mut writer, &ipc::HelperEvent::Error {
                                    message: "Eddie profile has no credentials".to_string(),
                                });
                                continue;
                            }
                            // Save imported credentials + other settings
                            if let Err(e) = config::save_credentials(&eddie_user, &eddie_pass) {
                                warn!("Could not save credentials to profile: {:#}", e);
                            }
                            send_event(&mut writer, &ipc::HelperEvent::Log {
                                level: "info".to_string(),
                                message: "Imported credentials from Eddie profile.".to_string(),
                            });
                            send_event(&mut writer, &ipc::HelperEvent::Log {
                                level: "warn".to_string(),
                                message: format!(
                                    "Your Eddie profile at {} stores credentials accessible to your \
                                     user account (v2n = plaintext, v2s = user keyring). \
                                     They are now saved in the root-owned airvpn-rs profile (0600). \
                                     Consider deleting the Eddie profile if you no longer use Eddie.",
                                    eddie_path.display()
                                ),
                            });
                            (eddie_user, eddie_pass)
                        }
                        Err(e) => {
                            send_event(&mut writer, &ipc::HelperEvent::Error {
                                message: format!("Failed to import Eddie profile: {:#}", e),
                            });
                            continue;
                        }
                    }
                } else {
                    send_event(&mut writer, &ipc::HelperEvent::Error {
                        message: "no credentials available — run `sudo airvpn connect` for first-time setup".to_string(),
                    });
                    continue;
                };

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
                    username: resolved_username,
                    password: resolved_password,
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
                    cli_event_pre: event_pre,
                    cli_event_up: event_up,
                    cli_event_down: event_down,
                    event_tx: connect_event_tx,
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
                        send_event(
                            &mut disconnected_writer,
                            &ipc::HelperEvent::Error {
                                message: format!("{}", e),
                            },
                        );
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
                if state.is_connected() {
                    // Normal disconnect: connect thread is alive, signal it to stop.
                    recovery::trigger_shutdown();
                    send_event(
                        &mut writer,
                        &ipc::HelperEvent::StateChanged {
                            state: ipc::ConnectionState::Disconnecting,
                        },
                    );

                    // Wait for connect thread to finish cleanup
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
                    // Send Disconnected on THIS socket (the one that sent Disconnect).
                    // The connect thread also sends Disconnected on its own writer clone,
                    // but that goes to the original Connect client (possibly a dead socket).
                    send_event(
                        &mut writer,
                        &ipc::HelperEvent::StateChanged {
                            state: ipc::ConnectionState::Disconnected,
                        },
                    );
                } else if matches!(
                    recovery::load(),
                    Ok(Some(ref rec)) if wireguard::is_connected(&rec.wg_interface)
                ) {
                    // Orphaned connection: no connect thread (e.g. helper restarted)
                    // but WireGuard interface is still up. Use force_recover() to tear
                    // down the interface, restore DNS, IPv6, netlock, and state file.
                    info!("no connect thread but orphaned WireGuard interface found, recovering");
                    send_event(
                        &mut writer,
                        &ipc::HelperEvent::StateChanged {
                            state: ipc::ConnectionState::Disconnecting,
                        },
                    );

                    if let Err(e) = recovery::force_recover() {
                        error!("orphaned disconnect recovery failed: {}", e);
                        send_event(
                            &mut writer,
                            &ipc::HelperEvent::Error {
                                message: format!("orphaned disconnect failed: {}", e),
                            },
                        );
                    }

                    // Stop stats poller (may have been started by Status handler)
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
                } else {
                    send_event(&mut writer, &ipc::HelperEvent::Error {
                        message: "no active connection".to_string(),
                    });
                }
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
                    // No connect thread — check recovery state for orphaned
                    // connections (e.g. helper restarted while VPN was active).
                    match recovery::load() {
                        Ok(Some(rec)) if wireguard::is_connected(&rec.wg_interface) => {
                            ipc::ConnectionState::Connected {
                                server_name: rec.wg_interface.clone(),
                                server_country: String::new(),
                                server_location: String::new(),
                            }
                        }
                        _ => ipc::ConnectionState::Disconnected,
                    }
                };
                send_event(&mut writer, &ipc::HelperEvent::StateChanged { state: conn_state.clone() });
                send_event(&mut writer, &build_lock_status());

                // If VPN is connected, start a stats poller for this GUI session
                if matches!(conn_state, ipc::ConnectionState::Connected { .. }) {
                    // Stop any existing stats poller first (avoids thread leak on reconnect)
                    state.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
                    if let Some(h) = state.stats_handle.take() {
                        let _ = h.join();
                    }
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
                match dispatch_lock_install() {
                    Ok(msg) => {
                        send_event(&mut writer, &ipc::HelperEvent::Log {
                            level: "info".to_string(),
                            message: msg,
                        });
                    }
                    Err(e) => {
                        send_event(&mut writer, &ipc::HelperEvent::Error {
                            message: format!("lock install failed: {}", e),
                        });
                    }
                }
                send_event(&mut writer, &build_lock_status());
            }

            ipc::HelperCommand::LockUninstall => {
                match dispatch_lock_uninstall() {
                    Ok(msg) => {
                        send_event(&mut writer, &ipc::HelperEvent::Log {
                            level: "info".to_string(),
                            message: msg,
                        });
                    }
                    Err(e) => {
                        send_event(&mut writer, &ipc::HelperEvent::Error {
                            message: format!("lock uninstall failed: {}", e),
                        });
                    }
                }
                send_event(&mut writer, &build_lock_status());
            }

            ipc::HelperCommand::LockStatus => {
                send_event(&mut writer, &build_lock_status());
            }

            ipc::HelperCommand::Recover => {
                match recovery::force_recover() {
                    Ok(()) => {
                        send_event(&mut writer, &ipc::HelperEvent::Log {
                            level: "info".to_string(),
                            message: "Recovery complete.".to_string(),
                        });
                    }
                    Err(e) => {
                        send_event(&mut writer, &ipc::HelperEvent::Error {
                            message: format!("recovery failed: {}", e),
                        });
                    }
                }
                send_event(&mut writer, &ipc::HelperEvent::Shutdown);
            }

            ipc::HelperCommand::Servers { sort, debug: debug_xml } => {
                match dispatch_servers(&sort, debug_xml) {
                    Ok(table) => {
                        send_event(&mut writer, &ipc::HelperEvent::ServerList { table });
                    }
                    Err(e) => {
                        send_event(&mut writer, &ipc::HelperEvent::Error {
                            message: format!("{:#}", e),
                        });
                    }
                }
                send_event(&mut writer, &ipc::HelperEvent::Shutdown);
            }

            ipc::HelperCommand::ImportEddieProfile { .. } => {
                // Only valid as a response during Connect's Eddie import flow.
                // Ignore if received out of context.
                debug!("ImportEddieProfile received outside Connect flow, ignoring");
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

/// Install the persistent lock: generate nftables rules, write systemd service,
/// enable and load the table.
fn dispatch_lock_install() -> Result<String> {
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
ExecStop=/bin/sh -c 'printf \"add table inet airvpn_persist { flags owner, persist; }\\ndelete table inet airvpn_persist\\n\" | /usr/bin/nft -f -'

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

    let ip_count = bootstrap_ips.len();
    Ok(format!("Persistent lock installed and active. {} bootstrap IPs allowlisted.", ip_count))
}

/// Uninstall the persistent lock: stop/disable systemd service, remove files,
/// delete nftables table.
fn dispatch_lock_uninstall() -> Result<String> {
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

    Ok("Persistent lock uninstalled.".to_string())
}

/// Fetch the server manifest and format it as a table string (or redacted XML
/// in debug mode). Credentials come from the saved profile — the helper runs
/// as root and can read `/etc/airvpn-rs/default.profile`.
fn dispatch_servers(sort: &str, debug_xml: bool) -> Result<String> {
    use std::fmt::Write;
    use zeroize::Zeroizing;

    let mut provider_config = api::load_provider_config()?;
    api::verify_rsa_key_integrity(&provider_config);

    // Resolve credentials from saved profile (helper is root).
    let profile_options = config::load_profile_options();
    let username = profile_options.get("login").cloned().unwrap_or_default();
    let password = profile_options.get("password").cloned().unwrap_or_default();
    if username.is_empty() || password.is_empty() {
        anyhow::bail!(
            "no credentials available — run `sudo airvpn connect` first to set up a profile"
        );
    }
    let password = Zeroizing::new(password);

    let xml = Zeroizing::new(api::fetch_manifest(&mut provider_config, &username, &password)?);

    if debug_xml {
        let redacted = xml
            .replace(&username, "[REDACTED_USER]")
            .replace(password.as_str(), "[REDACTED_PASS]");
        return Ok(redacted);
    }

    let m = manifest::parse_manifest(&xml)?;
    let mut servers: Vec<&manifest::Server> = m.servers.iter().collect();
    match sort {
        "score" => servers.sort_by_key(|s| server::score(s)),
        "load" => servers.sort_by(|a, b| server::load_perc(a).cmp(&server::load_perc(b))),
        "users" => servers.sort_by(|a, b| a.users.cmp(&b.users)),
        "name" => servers.sort_by(|a, b| a.name.cmp(&b.name)),
        _ => {
            warn!("Unknown sort key '{}', defaulting to score", sort);
            servers.sort_by_key(|s| server::score(s));
        }
    }

    let mut table = String::new();
    writeln!(
        table,
        "{:<20} {:<6} {:<12} {:>6} {:>6} {:>8}",
        "NAME", "CC", "LOCATION", "USERS", "LOAD%", "SCORE"
    )?;
    writeln!(table, "{}", "-".repeat(64))?;
    for s in &servers {
        let load = server::load_perc(s);
        writeln!(
            table,
            "{:<20} {:<6} {:<12} {:>6} {:>5}% {:>8}",
            s.name,
            s.country_code,
            s.location,
            s.users,
            load,
            server::score(s)
        )?;
    }
    write!(table, "\n{} servers total.", servers.len())?;
    Ok(table)
}
