//! HTTP/1.1 helper daemon over Unix socket — multi-client, powered by hyper v1.
//!
//! Runs as root via systemd socket activation (`airvpn-helper.socket` +
//! `airvpn-helper.service`). Inherits the pre-bound Unix socket from
//! systemd and accepts multiple concurrent HTTP connections via hyper.
//!
//! The connect engine runs in a thread within the helper process. Stats are
//! polled separately every 2s. Long-lived streaming connections (NDJSON
//! chunked responses) are used for `/connect` and `/events`.

mod background;
mod dispatch;
mod handlers;

use std::convert::Infallible;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use tokio::net::UnixListener as TokioUnixListener;

use crate::{ipc, manifest, netlock, pinger, recovery};

pub const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";
const PID_FILE: &str = "/run/airvpn-rs/helper.pid";

// ---------------------------------------------------------------------------
// Hyper body helpers
// ---------------------------------------------------------------------------

pub(super) type HyperBody = BoxBody<Bytes, Infallible>;

pub(super) fn json_response(status: StatusCode, body: &impl serde::Serialize) -> Response<HyperBody> {
    let json = serde_json::to_vec(body).unwrap_or_default();
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        // Infallible → Infallible: Full<Bytes> never errors
        .body(Full::new(Bytes::from(json)).map_err(|never| match never {}).boxed())
        .unwrap()
}

pub(super) fn error_response(status: StatusCode, msg: &str) -> Response<HyperBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(msg.to_string())).map_err(|never| match never {}).boxed())
        .unwrap()
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// VPN connection state that persists across client sessions.
pub(super) struct ConnState {
    pub(super) connect_handle: Option<thread::JoinHandle<()>>,
    pub(super) stats_handle: Option<thread::JoinHandle<()>>,
    pub(super) stats_stop: Arc<AtomicBool>,
    /// Per-connection shutdown flag. Set by perform_disconnect() to stop the
    /// connect thread without poisoning the helper's global shutdown flag.
    pub(super) disconnect_flag: Arc<AtomicBool>,
    /// Server info captured from engine events, readable across sessions.
    pub(super) server_info: Arc<Mutex<(String, String, String)>>,
    /// Guards against concurrent connect operations (direct or server_switch).
    /// Set to true when a connect starts, cleared when the connect thread exits
    /// or when perform_disconnect completes. Checked at the top of
    /// handle_connect_async to reject rapid-fire requests.
    pub(super) connect_in_progress: Arc<AtomicBool>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            connect_handle: None,
            stats_handle: None,
            stats_stop: Arc::new(AtomicBool::new(false)),
            disconnect_flag: Arc::new(AtomicBool::new(false)),
            server_info: Arc::new(Mutex::new((String::new(), String::new(), String::new()))),
            connect_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Is the VPN connect thread still running?
    pub(super) fn is_connected(&self) -> bool {
        self.connect_handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

/// State shared across all client connection threads.
pub(super) struct SharedState {
    pub(super) conn: ConnState,
    /// Event subscribers (long-lived `/events` connections).
    pub(super) subscribers: Vec<mpsc::Sender<ipc::HelperEvent>>,
    /// EWMA-smoothed latency cache, updated by background pinger.
    pub(super) latency: pinger::LatencyCache,
    /// Cached manifest from background refresh loop.
    pub(super) manifest: Option<manifest::Manifest>,
    /// True after the background pinger completes its first cycle.
    pub(super) ready: bool,
    /// Cached WireGuard key names from user info (for GUI device dropdown).
    pub(super) key_names: Vec<String>,
}

impl SharedState {
    fn new() -> Self {
        let latency = pinger::LatencyCache::load(pinger::LATENCY_CACHE_PATH);
        // Populate persistent lock's ping_allow from cached server IPs so the
        // background pinger can reach servers immediately on startup.
        if !latency.server_ips().is_empty() {
            let ips: Vec<String> = latency.server_ips().values().cloned().collect();
            if let Err(e) = netlock::populate_ping_allow(&ips) {
                log::warn!("Failed to populate ping_allow from cached IPs: {e}");
            }
        }
        let cached_manifest = manifest::load_manifest(manifest::MANIFEST_CACHE_PATH);
        if let Some(ref m) = cached_manifest {
            log::info!("Loaded cached manifest from disk ({} servers)", m.servers.len());
        }
        let ready = latency.has_data(); // warm start = ready immediately
        Self {
            conn: ConnState::new(),
            subscribers: Vec::new(),
            latency,
            manifest: cached_manifest,
            ready,
            key_names: Vec::new(),
        }
    }

    /// Broadcast an event to all subscribers, retaining only live ones.
    pub(super) fn broadcast(&mut self, event: &ipc::HelperEvent) {
        self.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

/// Condvars for cold-start coordination between background loops and connect.
pub(super) struct Notify {
    /// Signaled when credentials become available (eddie import, profile save).
    pub(super) manifest_cv: Condvar,
    /// Signaled when manifest loop populates server IPs.
    pub(super) pinger_cv: Condvar,
    /// Signaled when pinger completes its first cycle.
    pub(super) ready_cv: Condvar,
}

pub(super) type State = Arc<(Mutex<SharedState>, Notify)>;

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
    crate::connect::preflight_checks()?;

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

    // Signal handler: sets the recovery shutdown flag AND notifies the accept loop.
    let shutdown = recovery::setup_signal_handler()?;
    let state: State = Arc::new((
        Mutex::new(SharedState::new()),
        Notify {
            manifest_cv: Condvar::new(),
            pinger_cv: Condvar::new(),
            ready_cv: Condvar::new(),
        },
    ));

    // Spawn background pinger task (runs every 3 minutes)
    {
        let state_for_pinger = Arc::clone(&state);
        let shutdown_for_pinger = Arc::clone(&shutdown);
        tokio::task::spawn_blocking(move || {
            background::background_pinger_loop(state_for_pinger, shutdown_for_pinger);
        });
    }

    // Spawn background manifest refresh task (runs every 30 minutes)
    {
        let state_for_manifest = Arc::clone(&state);
        let shutdown_for_manifest = Arc::clone(&shutdown);
        tokio::task::spawn_blocking(move || {
            background::background_manifest_loop(state_for_manifest, shutdown_for_manifest);
        });
    }

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _addr)) => {
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

                            // One request per connection — CLI/GUI clients don't reuse connections
                            if let Err(e) = http1::Builder::new()
                                .keep_alive(false)
                                .serve_connection(io, service)
                                .await
                            {
                                debug!("Connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            // Check shutdown flag every second (signal handler sets it)
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if shutdown.load(Ordering::Relaxed) {
                    info!("Shutdown signal received, exiting helper");
                    break;
                }
            }
        }
    }

    // Graceful shutdown
    {
        let mut st = state.0.lock().unwrap();
        if st.conn.is_connected() {
            info!("Disconnecting active VPN before shutdown...");
            // Signal the connect thread via its per-connection flag
            // (the global shutdown flag is already set by the signal handler).
            st.conn.disconnect_flag.store(true, Ordering::SeqCst);
            let connect_handle = st.conn.connect_handle.take();
            st.conn.stats_stop.store(true, Ordering::SeqCst);
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
    debug!("HTTP {} {}", method, path);

    // Read body for all requests (no-op for GET with empty body)
    let body_bytes = match req.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "failed to read body"),
    };

    // Dispatch to handlers — streaming handlers (events, connect) are async,
    // all others are sync and run in spawn_blocking
    match (method.as_str(), path.as_str()) {
        ("GET", "/events") => handlers::handle_events_async(state).await,
        ("POST", "/connect") => handlers::handle_connect_async(body_bytes, state, peer_uid).await,
        _ => {
            let state = state.clone();
            tokio::task::spawn_blocking(move || {
                match (method.as_str(), path.as_str()) {
                    ("GET", "/status") => handlers::handle_status(&state),
                    ("POST", "/disconnect") => handlers::handle_disconnect(&state),
                    ("GET", "/servers") => handlers::handle_list_servers(&state),
                    ("GET", "/keys") => handlers::handle_get_keys(&state),
                    ("GET", "/profile") => handlers::handle_get_profile(),
                    ("POST", "/profile") => handlers::handle_save_profile(&body_bytes, &state),
                    ("POST", "/import-eddie") => handlers::handle_import_eddie(&body_bytes, peer_uid, &state),
                    ("POST", "/lock/enable") => handlers::handle_lock_enable(&state),
                    ("POST", "/lock/disable") => handlers::handle_lock_disable(),
                    ("POST", "/lock/install") => handlers::handle_lock_install(&state),
                    ("POST", "/lock/uninstall") => handlers::handle_lock_uninstall(),
                    ("GET", "/lock/status") => handlers::handle_lock_status(),
                    ("POST", "/recover") => handlers::handle_recover(&state),
                    ("POST", "/shutdown") => handlers::handle_shutdown(&state),
                    _ => error_response(StatusCode::NOT_FOUND, &format!("not found: {} {}", method, path)),
                }
            }).await.unwrap_or_else(|_| error_response(StatusCode::INTERNAL_SERVER_ERROR, "handler panicked"))
        }
    }
}

/// Helper to lock SharedState, recovering from poisoned mutex.
pub(super) fn lock_state(state: &State) -> std::sync::MutexGuard<'_, SharedState> {
    state.0.lock().unwrap_or_else(|e| {
        warn!("SharedState mutex was poisoned, recovering");
        e.into_inner()
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

}
