//! HTTP/1.1 helper daemon over Unix socket — multi-client, thread-per-connection.
//!
//! Runs as root via systemd socket activation (`airvpn-helper.socket` +
//! `airvpn-helper.service`). Inherits the pre-bound Unix socket from
//! systemd and accepts multiple concurrent HTTP connections. Each connection
//! is handled in its own thread.
//!
//! The connect engine runs in a thread within the helper process. Stats are
//! polled separately every 2s. Long-lived streaming connections (SSE-style
//! chunked responses) are used for `/connect` and `/events`.

use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use serde_json::json;

use crate::{api, config, connect, http, ipc, manifest, netlock, pinger, recovery, server, wireguard};

pub const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";
const PID_FILE: &str = "/run/airvpn-rs/helper.pid";

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// VPN connection state that persists across client sessions.
struct ConnState {
    connect_handle: Option<thread::JoinHandle<()>>,
    stats_handle: Option<thread::JoinHandle<()>>,
    stats_stop: Arc<std::sync::atomic::AtomicBool>,
    /// Server info captured from engine events, readable across sessions.
    server_info: Arc<Mutex<(String, String, String)>>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            connect_handle: None,
            stats_handle: None,
            stats_stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            server_info: Arc::new(Mutex::new((String::new(), String::new(), String::new()))),
        }
    }

    /// Is the VPN connect thread still running?
    fn is_connected(&self) -> bool {
        self.connect_handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

/// State shared across all client connection threads.
struct SharedState {
    conn: ConnState,
    /// Event subscribers (long-lived `/events` connections).
    subscribers: Vec<mpsc::Sender<ipc::HelperEvent>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            conn: ConnState::new(),
            subscribers: Vec::new(),
        }
    }

    /// Broadcast an event to all subscribers, retaining only live ones.
    fn broadcast(&mut self, event: &ipc::HelperEvent) {
        self.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

type State = Arc<Mutex<SharedState>>;

// ---------------------------------------------------------------------------
// Systemd socket activation + PID file (unchanged from old code)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Accept loop (multi-client, thread-per-connection)
// ---------------------------------------------------------------------------

/// Run the helper daemon: get socket from systemd, accept clients in a loop.
pub fn run() -> Result<()> {
    connect::preflight_checks()?;

    let listener = get_systemd_listener()?;
    write_pid_file()?;
    info!("Helper listening on {} (systemd socket activation, HTTP/1.1)", SOCKET_PATH);

    // Set up signal handler so Ctrl+C / SIGTERM triggers graceful shutdown.
    let shutdown = recovery::setup_signal_handler()?;

    let state: State = Arc::new(Mutex::new(SharedState::new()));

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Shutdown signal received, exiting helper");
            break;
        }

        // Poll with 1s timeout: set nonblocking, try accept, sleep if no client
        listener.set_nonblocking(true).ok();
        match listener.accept() {
            Ok((stream, _addr)) => {
                listener.set_nonblocking(false).ok();
                let peer_uid = log_peer_credentials(&stream);
                let state = Arc::clone(&state);
                thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, state, peer_uid) {
                        debug!("Connection ended: {}", e);
                    }
                });
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
    {
        let mut st = state.lock().unwrap();
        if st.conn.is_connected() {
            info!("Disconnecting active VPN before shutdown...");
            // Take handles before dropping lock
            let connect_handle = st.conn.connect_handle.take();
            st.conn.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let stats_handle = st.conn.stats_handle.take();
            drop(st); // Drop lock before joining threads

            if let Some(h) = connect_handle {
                let _ = h.join();
            }
            if let Some(h) = stats_handle {
                let _ = h.join();
            }
        }
    }

    // Clean up PID file on exit. Do NOT remove the socket — systemd owns it.
    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}

// ---------------------------------------------------------------------------
// Connection handler — parse HTTP request, dispatch to route
// ---------------------------------------------------------------------------

/// Handle a single HTTP connection: parse request, route, respond.
fn handle_connection(stream: UnixStream, state: State, peer_uid: Option<u32>) -> Result<()> {
    let mut req = http::parse_request(&stream)?;
    req.peer_uid = peer_uid;

    debug!("HTTP {} {}", req.method, req.path);

    let mut resp = http::ResponseWriter::new(
        stream.try_clone().context("failed to clone stream for response writer")?,
    );

    match (req.method.as_str(), req.path.as_str()) {
        ("GET", "/status") => handle_status(&state, &mut resp),
        ("POST", "/connect") => handle_connect(&req, state, resp),
        ("POST", "/disconnect") => handle_disconnect(&state, &mut resp),
        ("GET", "/events") => handle_events(state, resp),
        ("POST", "/import-eddie") => handle_import_eddie(&req, &mut resp),
        ("GET", "/servers") => handle_list_servers(&req, &mut resp),
        ("GET", "/profile") => handle_get_profile(&mut resp),
        ("POST", "/profile") => handle_save_profile(&req, &mut resp),
        ("POST", "/lock/enable") => handle_lock_enable(&mut resp),
        ("POST", "/lock/disable") => handle_lock_disable(&mut resp),
        ("POST", "/lock/install") => handle_lock_install(&mut resp),
        ("POST", "/lock/uninstall") => handle_lock_uninstall(&mut resp),
        ("GET", "/lock/status") => handle_lock_status(&mut resp),
        ("POST", "/recover") => handle_recover(&mut resp),
        ("POST", "/shutdown") => handle_shutdown(&state, &mut resp),
        _ => {
            resp.error(404, &format!("not found: {} {}", req.method, req.path))?;
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// Build a LockStatusInfo from current system state.
fn build_lock_status_info() -> ipc::LockStatusInfo {
    ipc::LockStatusInfo {
        session_active: netlock::is_active(),
        persistent_active: netlock::is_persist_active(),
        persistent_installed: std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists(),
    }
}

/// GET /status — return connection state + lock status.
fn handle_status(state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    let st = state.lock().unwrap();

    let conn_state = if st.conn.is_connected() {
        match recovery::load() {
            Ok(Some(rec)) if wireguard::is_connected(&rec.wg_interface) => {
                let (name, country, location) = st.conn.server_info
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
    drop(st);

    let status = ipc::StatusResponse {
        state: conn_state,
        lock: build_lock_status_info(),
    };
    resp.json(200, &status)
}

/// POST /connect — start VPN connection, stream events via chunked response.
fn handle_connect(
    req: &http::Request,
    state: State,
    mut resp: http::ResponseWriter,
) -> Result<()> {
    let connect_req: ipc::ConnectRequest = serde_json::from_slice(&req.body)
        .context("invalid ConnectRequest JSON")?;

    let peer_uid = req.peer_uid;

    // Lock briefly to check if already connected and set up state
    {
        let st = state.lock().unwrap();
        if st.conn.is_connected() {
            return resp.json(409, &json!({"error": "already connected — disconnect first"}));
        }
    }

    // Resolve credentials from saved profile
    let profile_options = config::load_profile_options();
    let prof_user = profile_options.get("login").cloned().unwrap_or_default();
    let prof_pass = profile_options.get("password").cloned().unwrap_or_default();

    let (resolved_username, resolved_password) = if !prof_user.is_empty() && !prof_pass.is_empty() {
        (prof_user, prof_pass)
    } else if let Some(eddie_path) = peer_uid.and_then(config::eddie_profile_path_for_uid) {
        // Found Eddie profile — tell client to import first via POST /import-eddie
        return resp.json(409, &ipc::EddieImportNeeded {
            eddie_profile: eddie_path.display().to_string(),
        });
    } else {
        return resp.error(400, "no credentials available — run `sudo airvpn connect` for first-time setup");
    };

    // Reset shutdown flag for the new connection
    recovery::reset_shutdown();

    // Create mpsc channel for engine events
    let (event_tx, event_rx) = mpsc::channel::<ipc::EngineEvent>();

    // Capture server info for the shared state
    let server_info = {
        let st = state.lock().unwrap();
        st.conn.server_info.clone()
    };

    // Spawn engine→broadcast forwarder thread: reads EngineEvents from mpsc,
    // translates to HelperEvents, broadcasts to all subscribers.
    let broadcast_state = Arc::clone(&state);
    let fwd_server_info = server_info.clone();
    let event_fwd = thread::spawn(move || {
        for engine_event in event_rx {
            let helper_event = match engine_event {
                ipc::EngineEvent::StateChanged(s) => {
                    ipc::HelperEvent::StateChanged { state: s }
                }
                ipc::EngineEvent::Log { level, message } => {
                    ipc::HelperEvent::Log { level, message }
                }
                ipc::EngineEvent::ServerSelected { name, country, location } => {
                    if let Ok(mut info) = fwd_server_info.lock() {
                        *info = (name.clone(), country.clone(), location.clone());
                    }
                    ipc::HelperEvent::Log {
                        level: "info".to_string(),
                        message: format!("Selected server: {} ({}, {})", name, location, country),
                    }
                }
            };
            if let Ok(mut st) = broadcast_state.lock() {
                st.broadcast(&helper_event);
            }
        }
    });

    // Stop any previous stats poller
    {
        let mut st = state.lock().unwrap();
        st.conn.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let prev_stats = st.conn.stats_handle.take();
        drop(st);
        if let Some(h) = prev_stats {
            let _ = h.join();
        }
    }

    // Spawn connect thread
    let connect_broadcast_state = Arc::clone(&state);
    let connect_config = connect::ConnectConfig {
        server_name: connect_req.server,
        no_lock: connect_req.no_lock,
        allow_lan: connect_req.allow_lan,
        no_reconnect: connect_req.no_reconnect,
        username: resolved_username,
        password: resolved_password,
        allow_server: connect_req.allow_server,
        deny_server: connect_req.deny_server,
        allow_country: connect_req.allow_country,
        deny_country: connect_req.deny_country,
        skip_ping: connect_req.skip_ping,
        no_verify: connect_req.no_verify,
        no_lock_last: connect_req.no_lock_last,
        no_start_last: connect_req.no_start_last,
        cli_ipv6_mode: connect_req.ipv6_mode,
        cli_dns_servers: connect_req.dns_servers,
        cli_event_pre: connect_req.event_pre,
        cli_event_up: connect_req.event_up,
        cli_event_down: connect_req.event_down,
        event_tx: event_tx.clone(),
    };

    let conn_handle = thread::spawn(move || {
        let result = (|| -> Result<()> {
            let mut provider_config = api::load_provider_config()?;
            api::verify_rsa_key_integrity(&provider_config);
            connect::run(&mut provider_config, &connect_config)?;
            Ok(())
        })();

        if let Err(e) = &result {
            error!("Connect thread exited with error: {}", e);
            if let Ok(mut st) = connect_broadcast_state.lock() {
                st.broadcast(&ipc::HelperEvent::Error {
                    message: format!("{}", e),
                });
            }
        }

        // Signal disconnected
        drop(result);
        if let Ok(mut st) = connect_broadcast_state.lock() {
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnected,
            });
        }
    });

    // Spawn stats polling thread
    let stats_state = Arc::clone(&state);
    let stats_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stats_stop_clone = stats_stop.clone();
    let stats_handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));
            if stats_stop_clone.load(std::sync::atomic::Ordering::SeqCst) {
                break;
            }

            let iface = match recovery::load() {
                Ok(Some(state)) => state.wg_interface,
                _ => continue,
            };

            if iface.is_empty() || !wireguard::is_connected(&iface) {
                continue;
            }

            match wireguard::get_transfer_stats(&iface) {
                Ok((rx, tx)) => {
                    if let Ok(mut st) = stats_state.lock() {
                        st.broadcast(&ipc::HelperEvent::Stats {
                            rx_bytes: rx,
                            tx_bytes: tx,
                        });
                    }
                }
                Err(e) => {
                    debug!("Failed to get transfer stats: {}", e);
                }
            }
        }
    });

    // Store handles in shared state
    {
        let mut st = state.lock().unwrap();
        st.conn.connect_handle = Some(conn_handle);
        st.conn.stats_stop = stats_stop;
        st.conn.stats_handle = Some(stats_handle);
    }

    // Wait for the event forwarder in a background thread
    thread::spawn(move || {
        let _ = event_fwd.join();
    });

    // Subscribe to events and stream them back as chunked response
    let (sub_tx, sub_rx) = mpsc::channel::<ipc::HelperEvent>();
    {
        let mut st = state.lock().unwrap();
        st.subscribers.push(sub_tx);
    }

    resp.begin_chunked(200)?;

    // Stream events until Disconnected or client disconnects
    loop {
        match sub_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(event) => {
                let is_disconnected = matches!(
                    event,
                    ipc::HelperEvent::StateChanged { state: ipc::ConnectionState::Disconnected }
                );
                if resp.send_chunk(&event).is_err() {
                    break; // Client disconnected
                }
                if is_disconnected {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Send a keepalive comment chunk to detect dead connections
                // (empty JSON object)
                if resp.send_chunk(&json!({"keepalive": true})).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break; // All senders dropped
            }
        }
    }

    let _ = resp.end_chunked();
    Ok(())
}

/// POST /disconnect — stop VPN connection.
fn handle_disconnect(state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    let is_connected;
    let has_orphan;

    {
        let st = state.lock().unwrap();
        is_connected = st.conn.is_connected();
        has_orphan = !is_connected && matches!(
            recovery::load(),
            Ok(Some(ref rec)) if wireguard::is_connected(&rec.wg_interface)
        );
    }

    if is_connected {
        // Normal disconnect: connect thread is alive, signal it to stop.
        recovery::trigger_shutdown();

        {
            let mut st = state.lock().unwrap();
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnecting,
            });
        }

        // Take handles — drop lock before joining threads (they may need the lock)
        let (connect_handle, stats_handle) = {
            let mut st = state.lock().unwrap();
            let ch = st.conn.connect_handle.take();
            st.conn.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let sh = st.conn.stats_handle.take();
            (ch, sh)
        };

        if let Some(h) = connect_handle {
            let _ = h.join();
        }
        if let Some(h) = stats_handle {
            let _ = h.join();
        }

        // Clear server info and broadcast disconnected
        {
            let mut st = state.lock().unwrap();
            if let Ok(mut info) = st.conn.server_info.lock() {
                *info = Default::default();
            }
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnected,
            });
        }

        resp.json(200, &json!({"disconnected": true}))
    } else if has_orphan {
        // Orphaned connection: no connect thread but WireGuard interface is still up.
        info!("no connect thread but orphaned WireGuard interface found, recovering");

        {
            let mut st = state.lock().unwrap();
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnecting,
            });
        }

        if let Err(e) = recovery::force_recover() {
            error!("orphaned disconnect recovery failed: {}", e);
            return resp.error(500, &format!("orphaned disconnect failed: {}", e));
        }

        // Stop stats poller and clear server info
        {
            let mut st = state.lock().unwrap();
            st.conn.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let sh = st.conn.stats_handle.take();
            drop(st);
            if let Some(h) = sh {
                let _ = h.join();
            }
        }

        {
            let mut st = state.lock().unwrap();
            if let Ok(mut info) = st.conn.server_info.lock() {
                *info = Default::default();
            }
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnected,
            });
        }

        resp.json(200, &json!({"disconnected": true}))
    } else {
        resp.error(400, "no active connection")
    }
}

/// GET /events — long-lived chunked stream of helper events (for GUI).
fn handle_events(state: State, mut resp: http::ResponseWriter) -> Result<()> {
    // Send initial status + lock info
    let initial_state;
    let lock_info = build_lock_status_info();

    {
        let st = state.lock().unwrap();
        initial_state = if st.conn.is_connected() {
            match recovery::load() {
                Ok(Some(rec)) if wireguard::is_connected(&rec.wg_interface) => {
                    let (name, country, location) = st.conn.server_info
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
    }

    // Create subscriber channel
    let (sub_tx, sub_rx) = mpsc::channel::<ipc::HelperEvent>();
    {
        let mut st = state.lock().unwrap();
        st.subscribers.push(sub_tx);
    }

    resp.begin_chunked(200)?;

    // Send initial state
    resp.send_chunk(&ipc::HelperEvent::StateChanged { state: initial_state })?;
    resp.send_chunk(&ipc::HelperEvent::LockStatus {
        session_active: lock_info.session_active,
        persistent_active: lock_info.persistent_active,
        persistent_installed: lock_info.persistent_installed,
    })?;

    // Stream events until client disconnects
    loop {
        match sub_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(event) => {
                if resp.send_chunk(&event).is_err() {
                    break; // Client disconnected
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Keepalive
                if resp.send_chunk(&json!({"keepalive": true})).is_err() {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    let _ = resp.end_chunked();
    Ok(())
}

/// POST /import-eddie — import credentials from Eddie profile.
fn handle_import_eddie(req: &http::Request, resp: &mut http::ResponseWriter) -> Result<()> {
    let import_req: ipc::ImportEddieRequest = serde_json::from_slice(&req.body)
        .context("invalid ImportEddieRequest JSON")?;

    let peer_uid = req.peer_uid;

    if !import_req.accept {
        return resp.json(200, &json!({"imported": false}));
    }

    let eddie_path = match peer_uid.and_then(config::eddie_profile_path_for_uid) {
        Some(p) => p,
        None => return resp.error(400, "no Eddie profile found for peer UID"),
    };

    match config::load_eddie_profile_for_uid(&eddie_path, peer_uid.unwrap()) {
        Ok((opts, _is_v2n)) => {
            let eddie_user = opts.get("login").cloned().unwrap_or_default();
            let eddie_pass = opts.get("password").cloned().unwrap_or_default();
            if eddie_user.is_empty() || eddie_pass.is_empty() {
                return resp.error(400, "Eddie profile has no credentials");
            }
            if let Err(e) = config::save_credentials(&eddie_user, &eddie_pass) {
                warn!("Could not save credentials to profile: {:#}", e);
            }
            resp.json(200, &json!({"imported": true}))
        }
        Err(e) => {
            resp.error(500, &format!("Failed to import Eddie profile: {:#}", e))
        }
    }
}

/// GET /servers — fetch and return scored server list.
fn handle_list_servers(req: &http::Request, resp: &mut http::ResponseWriter) -> Result<()> {
    let skip_ping = req.query.get("skip_ping").map_or(false, |v| v == "true");
    let sort = req.query.get("sort").map(|s| s.as_str());

    // Resolve credentials from profile
    let profile_options = config::load_profile_options();
    let prof_user = profile_options.get("login").cloned().unwrap_or_default();
    let prof_pass = profile_options.get("password").cloned().unwrap_or_default();

    if prof_user.is_empty() || prof_pass.is_empty() {
        return resp.error(400, "No credentials configured. Run `sudo airvpn connect` first to set up credentials.");
    }

    match dispatch_list_servers(skip_ping, sort, &prof_user, &prof_pass) {
        Ok(servers) => resp.json(200, &json!({"servers": servers})),
        Err(e) => resp.error(500, &format!("Failed to list servers: {:#}", e)),
    }
}

/// GET /profile — return profile options (credentials stripped).
fn handle_get_profile(resp: &mut http::ResponseWriter) -> Result<()> {
    match dispatch_get_profile() {
        Ok(mut options) => {
            let credentials_configured = options.get("login").map_or(false, |v| !v.is_empty())
                && options.get("password").map_or(false, |v| !v.is_empty());
            options.remove("login");
            options.remove("password");
            resp.json(200, &json!({
                "options": options,
                "credentials_configured": credentials_configured,
            }))
        }
        Err(e) => resp.error(500, &format!("Failed to load profile: {:#}", e)),
    }
}

/// POST /profile — save profile options.
fn handle_save_profile(req: &http::Request, resp: &mut http::ResponseWriter) -> Result<()> {
    let save_req: ipc::SaveProfileRequest = serde_json::from_slice(&req.body)
        .context("invalid SaveProfileRequest JSON")?;

    match dispatch_save_profile(&save_req.options) {
        Ok(()) => resp.json(200, &json!({"saved": true})),
        Err(e) => resp.error(500, &format!("Failed to save profile: {:#}", e)),
    }
}

/// POST /lock/enable
fn handle_lock_enable(resp: &mut http::ResponseWriter) -> Result<()> {
    if let Err(e) = dispatch_lock_enable() {
        resp.error(500, &format!("lock enable failed: {}", e))?;
        return Ok(());
    }
    resp.json(200, &build_lock_status_info())
}

/// POST /lock/disable
fn handle_lock_disable(resp: &mut http::ResponseWriter) -> Result<()> {
    if let Err(e) = netlock::reclaim_and_delete() {
        resp.error(500, &format!("lock disable failed: {}", e))?;
        return Ok(());
    }
    resp.json(200, &build_lock_status_info())
}

/// POST /lock/install
fn handle_lock_install(resp: &mut http::ResponseWriter) -> Result<()> {
    match dispatch_lock_install() {
        Ok(msg) => resp.json(200, &json!({"message": msg, "lock": build_lock_status_info()})),
        Err(e) => resp.error(500, &format!("lock install failed: {}", e)),
    }
}

/// POST /lock/uninstall
fn handle_lock_uninstall(resp: &mut http::ResponseWriter) -> Result<()> {
    match dispatch_lock_uninstall() {
        Ok(msg) => resp.json(200, &json!({"message": msg, "lock": build_lock_status_info()})),
        Err(e) => resp.error(500, &format!("lock uninstall failed: {}", e)),
    }
}

/// GET /lock/status
fn handle_lock_status(resp: &mut http::ResponseWriter) -> Result<()> {
    resp.json(200, &build_lock_status_info())
}

/// POST /recover
fn handle_recover(resp: &mut http::ResponseWriter) -> Result<()> {
    match recovery::force_recover() {
        Ok(()) => resp.json(200, &json!({"recovered": true})),
        Err(e) => resp.error(500, &format!("recovery failed: {}", e)),
    }
}

/// POST /shutdown — trigger shutdown and exit helper.
fn handle_shutdown(state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    recovery::trigger_shutdown();

    // Take handles — drop lock before joining
    let (connect_handle, stats_handle) = {
        let mut st = state.lock().unwrap();
        st.conn.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
        (st.conn.connect_handle.take(), st.conn.stats_handle.take())
    };

    if let Some(h) = connect_handle {
        let _ = h.join();
    }
    if let Some(h) = stats_handle {
        let _ = h.join();
    }

    resp.json(200, &json!({"shutdown": true}))
}

// ---------------------------------------------------------------------------
// Dispatch helpers (unchanged from old code)
// ---------------------------------------------------------------------------

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
fn dispatch_list_servers(skip_ping: bool, sort: Option<&str>, username: &str, password: &str) -> Result<Vec<ipc::ServerInfo>> {
    let provider_config = api::load_provider_config()?;

    let manifest_xml = api::fetch_manifest(&provider_config, username, password)?;
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
