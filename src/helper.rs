//! HTTP/1.1 helper daemon over Unix socket — multi-client, powered by hyper v1.
//!
//! Runs as root via systemd socket activation (`airvpn-helper.socket` +
//! `airvpn-helper.service`). Inherits the pre-bound Unix socket from
//! systemd and accepts multiple concurrent HTTP connections via hyper.
//!
//! The connect engine runs in a thread within the helper process. Stats are
//! polled separately every 2s. Long-lived streaming connections (NDJSON
//! chunked responses) are used for `/connect` and `/events`.

use std::collections::HashMap;
use std::convert::Infallible;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use serde_json::json;
use tokio::net::UnixListener as TokioUnixListener;

use crate::{api, config, connect, ipc, manifest, netlock, pinger, recovery, server, wireguard};

pub const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";
const PID_FILE: &str = "/run/airvpn-rs/helper.pid";

// ---------------------------------------------------------------------------
// Hyper body helpers
// ---------------------------------------------------------------------------

type HyperBody = BoxBody<Bytes, Infallible>;

fn json_response(status: StatusCode, body: &impl serde::Serialize) -> Response<HyperBody> {
    let json = serde_json::to_vec(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)).map_err(|never| match never {}).boxed())
        .unwrap()
}

fn error_response(status: StatusCode, msg: &str) -> Response<HyperBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(msg.to_string())).map_err(|never| match never {}).boxed())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Query string parser (moved from deleted http.rs)
// ---------------------------------------------------------------------------

/// Parse a `key=value&key2=value2` query string into a map.
fn parse_query_string(qs: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in qs.split('&') {
        if pair.is_empty() {
            continue;
        }
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        } else {
            map.insert(pair.to_string(), String::new());
        }
    }
    map
}

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
// Accept loop (hyper v1, async)
// ---------------------------------------------------------------------------

/// Run the helper daemon: get socket from systemd, accept clients via hyper.
pub fn run() -> Result<()> {
    connect::preflight_checks()?;

    let std_listener = get_systemd_listener()?;
    std_listener.set_nonblocking(true)?; // Required for tokio
    write_pid_file()?;
    info!("Helper listening on {} (hyper, systemd socket activation)", SOCKET_PATH);

    let rt = tokio::runtime::Runtime::new().context("failed to create tokio runtime")?;
    rt.block_on(async_run(std_listener))
}

async fn async_run(std_listener: std::os::unix::net::UnixListener) -> Result<()> {
    let listener = TokioUnixListener::from_std(std_listener)
        .context("failed to create tokio UnixListener")?;

    let shutdown = recovery::setup_signal_handler()?;
    let state: State = Arc::new(Mutex::new(SharedState::new()));

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Shutdown signal received, exiting helper");
            break;
        }

        // Use tokio::select with a timeout to periodically check shutdown flag
        let accept_result = tokio::time::timeout(
            Duration::from_secs(1),
            listener.accept()
        ).await;

        match accept_result {
            Ok(Ok((stream, _addr))) => {
                // Get peer credentials from the tokio UnixStream
                let peer_uid = stream.peer_cred()
                    .ok()
                    .map(|cred| {
                        info!("Client connected: uid={} pid={}", cred.uid(), cred.pid().unwrap_or(0));
                        cred.uid()
                    });

                let io = TokioIo::new(stream);
                let state = Arc::clone(&state);

                tokio::task::spawn(async move {
                    let service = service_fn(move |req| {
                        let state = Arc::clone(&state);
                        async move { Ok::<_, Infallible>(router(req, state, peer_uid).await) }
                    });

                    if let Err(e) = http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(io, service)
                        .await
                    {
                        debug!("Connection error: {}", e);
                    }
                });
            }
            Ok(Err(e)) => {
                error!("Failed to accept connection: {}", e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(_) => {} // Timeout, loop back to check shutdown
        }
    }

    // Graceful shutdown
    {
        let mut st = state.lock().unwrap();
        if st.conn.is_connected() {
            info!("Disconnecting active VPN before shutdown...");
            let connect_handle = st.conn.connect_handle.take();
            st.conn.stats_stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let stats_handle = st.conn.stats_handle.take();
            drop(st);
            if let Some(h) = connect_handle { let _ = h.join(); }
            if let Some(h) = stats_handle { let _ = h.join(); }
        }
    }
    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

async fn router(req: Request<hyper::body::Incoming>, state: State, peer_uid: Option<u32>) -> Response<HyperBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let _query: HashMap<String, String> = req.uri().query()
        .map(|q| parse_query_string(q))
        .unwrap_or_default();

    debug!("HTTP {} {}", method, path);

    // Read body for all requests (no-op for GET with empty body)
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "failed to read body"),
    };

    // Dispatch to handlers — streaming handlers (events, connect) are async,
    // all others are sync and run in spawn_blocking
    match (method.as_str(), path.as_str()) {
        ("GET", "/events") => handle_events_async(state).await,
        ("POST", "/connect") => handle_connect_async(body_bytes, state, peer_uid).await,
        _ => {
            let state = state.clone();
            tokio::task::spawn_blocking(move || {
                match (method.as_str(), path.as_str()) {
                    ("GET", "/status") => handle_status(&state),
                    ("POST", "/disconnect") => handle_disconnect(&state),
                    ("GET", "/servers") => handle_list_servers(&query),
                    ("GET", "/profile") => handle_get_profile(),
                    ("POST", "/profile") => handle_save_profile(&body_bytes),
                    ("POST", "/import-eddie") => handle_import_eddie(&body_bytes, peer_uid),
                    ("POST", "/lock/enable") => handle_lock_enable(),
                    ("POST", "/lock/disable") => handle_lock_disable(),
                    ("POST", "/lock/install") => handle_lock_install(),
                    ("POST", "/lock/uninstall") => handle_lock_uninstall(),
                    ("GET", "/lock/status") => handle_lock_status(),
                    ("POST", "/recover") => handle_recover(),
                    ("POST", "/shutdown") => handle_shutdown(&state),
                    _ => error_response(StatusCode::NOT_FOUND, &format!("not found: {} {}", method, path)),
                }
            }).await.unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "handler panicked"))
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming event helper
// ---------------------------------------------------------------------------

fn send_event_frame(tx: &tokio::sync::mpsc::Sender<Result<Frame<Bytes>, Infallible>>, event: &impl serde::Serialize) -> Result<(), ()> {
    let mut json = serde_json::to_vec(event).map_err(|_| ())?;
    json.push(b'\n');
    tx.blocking_send(Ok(Frame::data(Bytes::from(json)))).map_err(|_| ())
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
fn handle_status(state: &State) -> Response<HyperBody> {
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
    json_response(StatusCode::OK, &status)
}

/// POST /connect — start VPN connection, stream events via chunked response.
async fn handle_connect_async(
    body_bytes: Bytes,
    state: State,
    peer_uid: Option<u32>,
) -> Response<HyperBody> {
    let connect_req: ipc::ConnectRequest = match serde_json::from_slice(&body_bytes) {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid ConnectRequest JSON: {}", e)),
    };

    // Lock briefly to check if already connected
    {
        let st = state.lock().unwrap();
        if st.conn.is_connected() {
            return json_response(StatusCode::CONFLICT, &json!({"error": "already connected — disconnect first"}));
        }
    }

    // Resolve credentials from saved profile
    let profile_options = config::load_profile_options();
    let prof_user = profile_options.get("login").cloned().unwrap_or_default();
    let prof_pass = profile_options.get("password").cloned().unwrap_or_default();

    let (resolved_username, resolved_password) = if !prof_user.is_empty() && !prof_pass.is_empty() {
        (prof_user, prof_pass)
    } else if let Some(eddie_path) = peer_uid.and_then(config::eddie_profile_path_for_uid) {
        return json_response(StatusCode::CONFLICT, &ipc::EddieImportNeeded {
            eddie_profile: eddie_path.display().to_string(),
        });
    } else {
        return error_response(StatusCode::BAD_REQUEST, "no credentials available — run `sudo airvpn connect` for first-time setup");
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

    // Spawn engine→broadcast forwarder thread
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

    // Subscribe to events and stream them back as chunked NDJSON response
    let (sub_tx, sub_rx) = mpsc::channel::<ipc::HelperEvent>();
    {
        let mut st = state.lock().unwrap();
        st.subscribers.push(sub_tx);
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);

    // Spawn blocking thread that reads from sub_rx and sends to tokio tx
    tokio::task::spawn_blocking(move || {
        // Stream events until Disconnected or client disconnects
        loop {
            match sub_rx.recv_timeout(Duration::from_secs(30)) {
                Ok(event) => {
                    let is_disconnected = matches!(
                        event,
                        ipc::HelperEvent::StateChanged { state: ipc::ConnectionState::Disconnected }
                    );
                    if send_event_frame(&tx, &event).is_err() {
                        break;
                    }
                    if is_disconnected {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if send_event_frame(&tx, &json!({"keepalive": true})).is_err() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream).boxed();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-ndjson")
        .header("Transfer-Encoding", "chunked")
        .body(body)
        .unwrap()
}

/// POST /disconnect — stop VPN connection.
fn handle_disconnect(state: &State) -> Response<HyperBody> {
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

        json_response(StatusCode::OK, &json!({"disconnected": true}))
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
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("orphaned disconnect failed: {}", e));
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

        json_response(StatusCode::OK, &json!({"disconnected": true}))
    } else {
        error_response(StatusCode::BAD_REQUEST, "no active connection")
    }
}

/// GET /events — long-lived chunked stream of helper events (for GUI).
async fn handle_events_async(state: State) -> Response<HyperBody> {
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

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);

    // Spawn blocking thread that reads from sub_rx and sends to tokio tx
    let tx_clone = tx.clone();
    tokio::task::spawn_blocking(move || {
        // Send initial events
        let _ = send_event_frame(&tx_clone, &ipc::HelperEvent::StateChanged { state: initial_state });
        let _ = send_event_frame(&tx_clone, &ipc::HelperEvent::LockStatus {
            session_active: lock_info.session_active,
            persistent_active: lock_info.persistent_active,
            persistent_installed: lock_info.persistent_installed,
        });

        // Stream events
        loop {
            match sub_rx.recv_timeout(Duration::from_secs(30)) {
                Ok(event) => {
                    if send_event_frame(&tx_clone, &event).is_err() { break; }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if send_event_frame(&tx_clone, &json!({"keepalive": true})).is_err() { break; }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    // Build streaming response from receiver
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = StreamBody::new(stream).boxed();

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/x-ndjson")
        .header("Transfer-Encoding", "chunked")
        .body(body)
        .unwrap()
}

/// POST /import-eddie — import credentials from Eddie profile.
fn handle_import_eddie(body_bytes: &Bytes, peer_uid: Option<u32>) -> Response<HyperBody> {
    let import_req: ipc::ImportEddieRequest = match serde_json::from_slice(body_bytes) {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid ImportEddieRequest JSON: {}", e)),
    };

    if !import_req.accept {
        return json_response(StatusCode::OK, &json!({"imported": false}));
    }

    let eddie_path = match peer_uid.and_then(config::eddie_profile_path_for_uid) {
        Some(p) => p,
        None => return error_response(StatusCode::BAD_REQUEST, "no Eddie profile found for peer UID"),
    };

    match config::load_eddie_profile_for_uid(&eddie_path, peer_uid.unwrap()) {
        Ok((opts, _is_v2n)) => {
            let eddie_user = opts.get("login").cloned().unwrap_or_default();
            let eddie_pass = opts.get("password").cloned().unwrap_or_default();
            if eddie_user.is_empty() || eddie_pass.is_empty() {
                return error_response(StatusCode::BAD_REQUEST, "Eddie profile has no credentials");
            }
            if let Err(e) = config::save_credentials(&eddie_user, &eddie_pass) {
                warn!("Could not save credentials to profile: {:#}", e);
            }
            json_response(StatusCode::OK, &json!({"imported": true}))
        }
        Err(e) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to import Eddie profile: {:#}", e))
        }
    }
}

/// GET /servers — fetch and return scored server list.
fn handle_list_servers(query: &HashMap<String, String>) -> Response<HyperBody> {
    let skip_ping = query.get("skip_ping").map_or(false, |v| v == "true");
    let sort = query.get("sort").map(|s| s.as_str());

    // Resolve credentials from profile
    let profile_options = config::load_profile_options();
    let prof_user = profile_options.get("login").cloned().unwrap_or_default();
    let prof_pass = profile_options.get("password").cloned().unwrap_or_default();

    if prof_user.is_empty() || prof_pass.is_empty() {
        return error_response(StatusCode::BAD_REQUEST, "No credentials configured. Run `sudo airvpn connect` first to set up credentials.");
    }

    match dispatch_list_servers(skip_ping, sort, &prof_user, &prof_pass) {
        Ok(servers) => json_response(StatusCode::OK, &json!({"servers": servers})),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to list servers: {:#}", e)),
    }
}

/// GET /profile — return profile options (credentials stripped).
fn handle_get_profile() -> Response<HyperBody> {
    match dispatch_get_profile() {
        Ok(mut options) => {
            let credentials_configured = options.get("login").map_or(false, |v| !v.is_empty())
                && options.get("password").map_or(false, |v| !v.is_empty());
            options.remove("login");
            options.remove("password");
            json_response(StatusCode::OK, &json!({
                "options": options,
                "credentials_configured": credentials_configured,
            }))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to load profile: {:#}", e)),
    }
}

/// POST /profile — save profile options.
fn handle_save_profile(body_bytes: &Bytes) -> Response<HyperBody> {
    let save_req: ipc::SaveProfileRequest = match serde_json::from_slice(body_bytes) {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid SaveProfileRequest JSON: {}", e)),
    };

    match dispatch_save_profile(&save_req.options) {
        Ok(()) => json_response(StatusCode::OK, &json!({"saved": true})),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to save profile: {:#}", e)),
    }
}

/// POST /lock/enable
fn handle_lock_enable() -> Response<HyperBody> {
    if let Err(e) = dispatch_lock_enable() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock enable failed: {}", e));
    }
    json_response(StatusCode::OK, &build_lock_status_info())
}

/// POST /lock/disable
fn handle_lock_disable() -> Response<HyperBody> {
    if let Err(e) = netlock::reclaim_and_delete() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock disable failed: {}", e));
    }
    json_response(StatusCode::OK, &build_lock_status_info())
}

/// POST /lock/install
fn handle_lock_install() -> Response<HyperBody> {
    match dispatch_lock_install() {
        Ok(msg) => json_response(StatusCode::OK, &json!({"message": msg, "lock": build_lock_status_info()})),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock install failed: {}", e)),
    }
}

/// POST /lock/uninstall
fn handle_lock_uninstall() -> Response<HyperBody> {
    match dispatch_lock_uninstall() {
        Ok(msg) => json_response(StatusCode::OK, &json!({"message": msg, "lock": build_lock_status_info()})),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock uninstall failed: {}", e)),
    }
}

/// GET /lock/status
fn handle_lock_status() -> Response<HyperBody> {
    json_response(StatusCode::OK, &build_lock_status_info())
}

/// POST /recover
fn handle_recover() -> Response<HyperBody> {
    match recovery::force_recover() {
        Ok(()) => json_response(StatusCode::OK, &json!({"recovered": true})),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("recovery failed: {}", e)),
    }
}

/// POST /shutdown — trigger shutdown and exit helper.
fn handle_shutdown(state: &State) -> Response<HyperBody> {
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

    json_response(StatusCode::OK, &json!({"shutdown": true}))
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

    let profile_options = config::load_profile_options();
    let resolved = options::resolve(&profile_options, &std::collections::HashMap::new());
    let iface_name = {
        let v = options::get_str(&resolved, options::NETWORK_IFACE_NAME);
        if v.is_empty() { wireguard::VPN_INTERFACE } else { v }
    };
    let ruleset = netlock::generate_persistent_ruleset(&bootstrap_ips, iface_name);

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

/// Save profile options to the config file (single read-modify-write cycle).
fn dispatch_save_profile(options: &std::collections::HashMap<String, String>) -> Result<()> {
    config::save_profile_options(options)
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

    servers.sort_by_key(|s| s.score);

    Ok(servers)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_query_string_basic() {
        let qs = parse_query_string("skip_ping=true&sort=name");
        assert_eq!(qs.get("skip_ping").unwrap(), "true");
        assert_eq!(qs.get("sort").unwrap(), "name");
    }

    #[test]
    fn test_parse_query_string_empty() {
        let qs = parse_query_string("");
        assert!(qs.is_empty());
    }

    #[test]
    fn test_parse_query_string_no_value() {
        let qs = parse_query_string("flag&key=val");
        assert_eq!(qs.get("flag").unwrap(), "");
        assert_eq!(qs.get("key").unwrap(), "val");
    }
}
