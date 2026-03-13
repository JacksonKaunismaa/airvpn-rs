//! HTTP/1.1 helper daemon over Unix socket — multi-client, powered by hyper v1.
//!
//! Runs as root via systemd socket activation (`airvpn-helper.socket` +
//! `airvpn-helper.service`). Inherits the pre-bound Unix socket from
//! systemd and accepts multiple concurrent HTTP connections via hyper.
//!
//! The connect engine runs in a thread within the helper process. Stats are
//! polled separately every 2s. Long-lived streaming connections (NDJSON
//! chunked responses) are used for `/connect` and `/events`.

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
use http_body_util::{combinators::BoxBody, BodyExt, Full, StreamBody};
use hyper::body::Frame;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use log::{debug, error, info, warn};
use serde_json::json;
use tokio::net::UnixListener as TokioUnixListener;
use zeroize::Zeroizing;

use crate::{api, config, connect, ipc, manifest, netlock, options, pinger, recovery, server, wireguard};

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
        // Infallible → Infallible: Full<Bytes> never errors
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
// Shared state
// ---------------------------------------------------------------------------

/// VPN connection state that persists across client sessions.
struct ConnState {
    connect_handle: Option<thread::JoinHandle<()>>,
    stats_handle: Option<thread::JoinHandle<()>>,
    stats_stop: Arc<AtomicBool>,
    /// Per-connection shutdown flag. Set by perform_disconnect() to stop the
    /// connect thread without poisoning the helper's global shutdown flag.
    disconnect_flag: Arc<AtomicBool>,
    /// Server info captured from engine events, readable across sessions.
    server_info: Arc<Mutex<(String, String, String)>>,
    /// Guards against concurrent connect operations (direct or server_switch).
    /// Set to true when a connect starts, cleared when the connect thread exits
    /// or when perform_disconnect completes. Checked at the top of
    /// handle_connect_async to reject rapid-fire requests.
    connect_in_progress: Arc<AtomicBool>,
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
    fn is_connected(&self) -> bool {
        self.connect_handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

/// State shared across all client connection threads.
struct SharedState {
    conn: ConnState,
    /// Event subscribers (long-lived `/events` connections).
    subscribers: Vec<mpsc::Sender<ipc::HelperEvent>>,
    /// EWMA-smoothed latency cache, updated by background pinger.
    latency: pinger::LatencyCache,
    /// Cached manifest from background refresh loop.
    manifest: Option<manifest::Manifest>,
    /// True after the background pinger completes its first cycle.
    ready: bool,
    /// Cached WireGuard key names from user info (for GUI device dropdown).
    key_names: Vec<String>,
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
        let ready = latency.has_data(); // warm start = ready immediately
        Self {
            conn: ConnState::new(),
            subscribers: Vec::new(),
            latency,
            manifest: None,
            ready,
            key_names: Vec::new(),
        }
    }

    /// Broadcast an event to all subscribers, retaining only live ones.
    fn broadcast(&mut self, event: &ipc::HelperEvent) {
        self.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

/// Condvars for cold-start coordination between background loops and connect.
struct Notify {
    /// Signaled when credentials become available (eddie import, profile save).
    manifest_cv: Condvar,
    /// Signaled when manifest loop populates server IPs.
    pinger_cv: Condvar,
    /// Signaled when pinger completes its first cycle.
    ready_cv: Condvar,
}

type State = Arc<(Mutex<SharedState>, Notify)>;

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
            background_pinger_loop(state_for_pinger, shutdown_for_pinger);
        });
    }

    // Spawn background manifest refresh task (runs every 30 minutes)
    {
        let state_for_manifest = Arc::clone(&state);
        let shutdown_for_manifest = Arc::clone(&shutdown);
        tokio::task::spawn_blocking(move || {
            background_manifest_loop(state_for_manifest, shutdown_for_manifest);
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
// Background pinger
// ---------------------------------------------------------------------------

/// Background pinger loop — runs every 3 minutes, measures all server latencies.
///
/// Copies the server IP list out of SharedState (quick lock), pings without
/// holding the lock (~30-60s), then merges results back (quick lock).
fn lock_state(state: &State) -> std::sync::MutexGuard<'_, SharedState> {
    state.0.lock().unwrap_or_else(|e| {
        warn!("SharedState mutex was poisoned, recovering");
        e.into_inner()
    })
}

fn background_pinger_loop(state: State, shutdown: Arc<AtomicBool>) {
    const CYCLE_INTERVAL_SECS: u64 = 180; // 3 minutes
    // Resolve pinger options from profile
    let profile_opts = config::load_profile_options();
    let resolved = options::resolve(&profile_opts, &std::collections::HashMap::new());
    let ping_timeout_secs = options::get_u64(&resolved, options::PINGER_TIMEOUT);
    let pinger_enabled = options::get_bool(&resolved, options::PINGER_ENABLED);
    let pinger_jobs = options::get_u64(&resolved, options::PINGER_JOBS) as usize;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Wait until server IPs are available (manifest loop signals pinger_cv)
        {
            let guard = lock_state(&state);
            let _guard = state.1.pinger_cv.wait_while(guard, |st| {
                if shutdown.load(Ordering::Relaxed) {
                    return false; // unblock on shutdown
                }
                st.latency.server_ips().is_empty()
            }).unwrap_or_else(|e| e.into_inner());
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        debug!("Pinger woke: server IPs available, starting cycle");

        // When pinger is disabled, skip pinging but keep the loop alive
        // to avoid blocking the condvar chain (ready_cv must still fire).
        if !pinger_enabled {
            {
                let mut st = lock_state(&state);
                if !st.ready {
                    st.ready = true;
                    state.1.ready_cv.notify_all();
                }
            }
            debug!("Pinger disabled, skipping ping cycle");
            interruptible_sleep_secs(&shutdown, CYCLE_INTERVAL_SECS);
            continue;
        }

        // Copy IPs out of shared state (quick lock)
        let ips: Vec<(String, String)> = {
            let st = lock_state(&state);
            st.latency.server_ips()
                .iter()
                .map(|(n, ip)| (n.clone(), ip.clone()))
                .collect()
        };

        if ips.is_empty() {
            continue; // spurious wakeup
        }

        debug!("Starting ping cycle ({} servers, max {} concurrent)", ips.len(), pinger_jobs);

        // Ping all servers via host routes (direct, not through tunnel).
        // All servers are treated equally — no special-casing for the
        // connected server. This gives consistent raw network latency.
        let results = pinger::measure_all_from_ips(&ips, ping_timeout_secs, pinger_jobs);

        // Merge results back into shared state (quick lock)
        {
            let mut st = lock_state(&state);
            for (name, latency) in &results {
                if *latency >= 0 {
                    st.latency.update(name, *latency);
                } else {
                    st.latency.update_failed(name);
                }
            }
            if !st.ready {
                st.ready = true;
                state.1.ready_cv.notify_all();
            }
            if let Err(e) = st.latency.save(pinger::LATENCY_CACHE_PATH) {
                warn!("Failed to persist latency cache: {e}");
            }
        }

        let measured = results.iter().filter(|(_, l)| *l >= 0).count();
        let failed = results.len() - measured;
        // One line per cycle: concise summary. Warn only if significant failures.
        {
            let st = lock_state(&state);
            if let Some((_count, min, avg, max)) = st.latency.summary() {
                if failed > results.len() / 4 {
                    warn!(
                        "Ping: {}/{} measured ({} failed) — {}ms/{}ms/{}ms min/avg/max",
                        measured, results.len(), failed, min, avg, max,
                    );
                } else {
                    info!(
                        "Ping: {}/{} — {}ms/{}ms/{}ms min/avg/max",
                        measured, results.len(), min, avg, max,
                    );
                }
            } else {
                info!("Ping: {}/{} measured — no latency data yet", measured, results.len());
            }
        }

        // Sleep for 3 minutes (interruptible by shutdown)
        interruptible_sleep_secs(&shutdown, CYCLE_INTERVAL_SECS);
    }
}

/// Sleep for the given duration, checking shutdown flag every second.
fn interruptible_sleep_secs(shutdown: &AtomicBool, seconds: u64) {
    for _ in 0..seconds {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

// ---------------------------------------------------------------------------
// Background manifest refresh
// ---------------------------------------------------------------------------

/// Background manifest refresh loop — fetches manifest every 30 minutes.
///
/// On startup, waits for credentials (via manifest_cv) if none available.
/// After each successful fetch, populates server IPs and signals pinger_cv.
fn background_manifest_loop(state: State, shutdown: Arc<AtomicBool>) {
    // Resolve from profile; falls back to registry defaults
    let profile_opts = config::load_profile_options();
    let resolved = options::resolve(&profile_opts, &std::collections::HashMap::new());
    let refresh_interval_secs = options::get_u64(&resolved, options::MANIFEST_REFRESH);
    let ip_layer = options::get_str(&resolved, options::NETWORK_ENTRY_IPLAYER).to_string();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Load credentials from profile
        let profile_options = config::load_profile_options();
        let username = Zeroizing::new(profile_options.get("login").cloned().unwrap_or_default());
        let password = Zeroizing::new(profile_options.get("password").cloned().unwrap_or_default());

        if username.is_empty() || password.is_empty() {
            // No creds yet — clear cached keys and wait for manifest_cv signal
            {
                let mut st = lock_state(&state);
                st.key_names.clear();
            }
            info!("No credentials available, manifest loop waiting for profile setup...");
            let guard = lock_state(&state);
            // wait_while blocks until the predicate returns false (i.e., creds available or shutdown)
            let _guard = state.1.manifest_cv.wait_while(guard, |_st| {
                if shutdown.load(Ordering::Relaxed) {
                    return false; // unblock on shutdown
                }
                let opts = config::load_profile_options();
                let u = opts.get("login").cloned().unwrap_or_default();
                let p = opts.get("password").cloned().unwrap_or_default();
                u.is_empty() || p.is_empty() // keep waiting while creds empty
            }).unwrap_or_else(|e| e.into_inner());
            continue; // re-check creds at top of loop
        }

        // Fetch manifest
        match api::load_provider_config() {
            Ok(provider_config) => {
                match api::fetch_manifest(&provider_config, &username, &password) {
                    Ok(manifest_xml) => {
                        match manifest::parse_manifest(&manifest_xml) {
                            Ok(new_manifest) => {
                                info!("Background manifest refresh: {} servers", new_manifest.servers.len());

                                // Extract (name, preferred_entry_ip) pairs,
                                // respecting ip_layer preference with fallback.
                                let prefer_ipv6 = ip_layer == "ipv6";
                                let server_ip_pairs: Vec<(String, String)> = new_manifest.servers
                                    .iter()
                                    .filter_map(|s| {
                                        let ip = if prefer_ipv6 {
                                            s.ips_entry.iter()
                                                .find(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok())
                                                .or_else(|| s.ips_entry.iter()
                                                    .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok()))
                                                .or_else(|| s.ips_entry.first())
                                        } else {
                                            s.ips_entry.iter()
                                                .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                                                .or_else(|| s.ips_entry.first())
                                        };
                                        ip.map(|ip| (s.name.clone(), ip.clone()))
                                    })
                                    .collect();

                                // Update shared state
                                {
                                    let mut st = lock_state(&state);
                                    st.manifest = Some(new_manifest);
                                    if !server_ip_pairs.is_empty() {
                                        let ips: Vec<String> = server_ip_pairs.iter()
                                            .map(|(_, ip)| ip.clone()).collect();
                                        st.latency.set_server_ips(server_ip_pairs);
                                        drop(st);
                                        if let Err(e) = netlock::populate_ping_allow(&ips) {
                                            warn!("Failed to update ping_allow: {e}");
                                        }
                                    }
                                }

                                // Signal pinger that IPs are available
                                state.1.pinger_cv.notify_all();
                                // Signal ready_cv so warm-start connects unblock
                                // (ready=true from latency.json, was just waiting for manifest)
                                state.1.ready_cv.notify_all();
                            }
                            Err(e) => warn!("Failed to parse manifest: {:#}", e),
                        }
                    }
                    Err(e) => warn!("Failed to fetch manifest: {:#}", e),
                }

                // Fetch user info for key names (needed by GUI device dropdown).
                // Called outside the lock — network call can take 5-30s.
                match api::fetch_user(&provider_config, &username, &password) {
                    Ok(user_xml) => {
                        match manifest::parse_user(&user_xml) {
                            Ok(user_info) => {
                                let names: Vec<String> = user_info.keys.iter()
                                    .map(|k| k.name.clone())
                                    .collect();
                                debug!("Cached {} WireGuard key names", names.len());
                                let mut st = lock_state(&state);
                                st.key_names = names;
                            }
                            Err(e) => {
                                warn!("Failed to parse user info for keys: {:#}", e);
                                let mut st = lock_state(&state);
                                st.key_names.clear();
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to fetch user info for keys: {:#}", e);
                        let mut st = lock_state(&state);
                        st.key_names.clear();
                    }
                }
            }
            Err(e) => warn!("Failed to load provider config: {:#}", e),
        }

        interruptible_sleep_secs(&shutdown, refresh_interval_secs);
    }
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
        ("GET", "/events") => handle_events_async(state).await,
        ("POST", "/connect") => handle_connect_async(body_bytes, state, peer_uid).await,
        _ => {
            let state = state.clone();
            tokio::task::spawn_blocking(move || {
                match (method.as_str(), path.as_str()) {
                    ("GET", "/status") => handle_status(&state),
                    ("POST", "/disconnect") => handle_disconnect(&state),
                    ("GET", "/servers") => handle_list_servers(&state),
                    ("GET", "/keys") => handle_get_keys(&state),
                    ("GET", "/profile") => handle_get_profile(),
                    ("POST", "/profile") => handle_save_profile(&body_bytes, &state),
                    ("POST", "/import-eddie") => handle_import_eddie(&body_bytes, peer_uid, &state),
                    ("POST", "/lock/enable") => handle_lock_enable(&state),
                    ("POST", "/lock/disable") => handle_lock_disable(),
                    ("POST", "/lock/install") => handle_lock_install(&state),
                    ("POST", "/lock/uninstall") => handle_lock_uninstall(),
                    ("GET", "/lock/status") => handle_lock_status(),
                    ("POST", "/recover") => handle_recover(&state),
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

/// Determine the current connection state from shared state + recovery + wireguard.
fn current_connection_state(st: &SharedState) -> ipc::ConnectionState {
    if st.conn.is_connected() {
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
    }
}

/// GET /status — return connection state + lock status + pinger health.
fn handle_status(state: &State) -> Response<HyperBody> {
    let st = state.0.lock().unwrap();
    let conn_state = current_connection_state(&st);
    let pinger = build_pinger_info(&st);
    drop(st);

    let status = ipc::StatusResponse {
        state: conn_state,
        lock: build_lock_status_info(),
        pinger,
    };
    json_response(StatusCode::OK, &status)
}

fn build_pinger_info(st: &SharedState) -> ipc::PingerInfo {
    let total = st.latency.server_ips().len();
    let measured = st.latency.len();
    let (latency_min_ms, latency_avg_ms, latency_max_ms) = match st.latency.summary() {
        Some((_, min, avg, max)) => (Some(min), Some(avg), Some(max)),
        None => (None, None, None),
    };
    ipc::PingerInfo {
        ready: st.ready,
        measured,
        total,
        latency_min_ms,
        latency_avg_ms,
        latency_max_ms,
    }
}

/// RAII guard that clears `connect_in_progress` on drop.
/// Defused via `forget()` when the connect thread takes ownership of the flag.
struct ConnectGuard(Arc<AtomicBool>);
impl Drop for ConnectGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
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

    // Reject concurrent connect operations. This prevents rapid-fire requests
    // (e.g., GUI spam-clicking) from spawning multiple server_switch threads
    // that race on state.json cleanup.
    let connect_guard = {
        let st = state.0.lock().unwrap();
        if st.conn.connect_in_progress.load(Ordering::SeqCst) {
            return error_response(StatusCode::CONFLICT, "connect already in progress");
        }
        st.conn.connect_in_progress.store(true, Ordering::SeqCst);
        // RAII guard: clears the flag if we return early (credential errors,
        // warmup timeout, etc.). The connect thread clears it on normal exit.
        ConnectGuard(st.conn.connect_in_progress.clone())
    };

    // Resolve credentials from saved profile (fast, no blocking)
    let profile_options = config::load_profile_options();
    let prof_user = Zeroizing::new(profile_options.get("login").cloned().unwrap_or_default());
    let prof_pass = Zeroizing::new(profile_options.get("password").cloned().unwrap_or_default());

    let (resolved_username, resolved_password) = if !prof_user.is_empty() && !prof_pass.is_empty() {
        (prof_user, prof_pass)
    } else if let Some(eddie_path) = peer_uid.and_then(config::eddie_profile_path_for_uid) {
        return json_response(StatusCode::CONFLICT, &ipc::EddieImportNeeded {
            eddie_profile: eddie_path.display().to_string(),
        });
    } else {
        return error_response(StatusCode::BAD_REQUEST, "no credentials available — run `sudo airvpn connect` for first-time setup");
    };

    // Check warmup (fast, no blocking in steady state)
    {
        let guard = lock_state(&state);
        if !guard.ready || guard.manifest.is_none() {
            info!("Waiting for helper warmup (manifest + first ping cycle)...");
            let result = state.1.ready_cv.wait_timeout_while(
                guard,
                Duration::from_secs(60),
                |st| !st.ready || st.manifest.is_none(),
            ).unwrap_or_else(|e| e.into_inner());
            if !result.0.ready || result.0.manifest.is_none() {
                return error_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Helper still warming up (waiting for first latency measurement). Try again shortly.",
                );
            }
        }
    }

    // If already connected, do the full disconnect→connect in a detached thread
    // and return immediately. The HTTP connection may die during disconnect
    // (cancelling this handler), so we must not await the disconnect.
    // Events flow through the /events stream.
    {
        let is_connected = state.0.lock().unwrap().conn.is_connected();
        if is_connected {
            // Defuse — the server_switch thread's start_connect will spawn a
            // connect thread that owns clearing connect_in_progress.
            std::mem::forget(connect_guard);
            let switch_state = Arc::clone(&state);
            thread::spawn(move || {
                perform_disconnect(&switch_state);
                start_connect(switch_state, connect_req, resolved_username, resolved_password);
            });
            return json_response(StatusCode::OK, &json!({"server_switch": true}));
        }
    }

    // Clean up stale state from a previous connect session that crashed/failed
    // without running its cleanup path. The state.json records the helper's PID
    // (std::process::id()), so check_and_recover() inside connect::run() would
    // find our own PID alive and bail with "another instance running" — even
    // though the connect thread is long dead. We know it's safe to recover here
    // because is_connected() returned false above.
    if let Ok(Some(stale)) = recovery::load() {
        if stale.pid == std::process::id() {
            info!("cleaning up stale state from previous connect session (our PID, no active connect thread)");
            if let Err(e) = recovery::force_recover() {
                warn!("stale state cleanup failed: {}", e);
            }
        }
    }

    // Start the connect engine (disconnect_flag is created fresh inside start_connect).
    // Defuse the guard — the connect thread now owns clearing connect_in_progress.
    std::mem::forget(connect_guard);
    start_connect(Arc::clone(&state), connect_req, resolved_username, resolved_password);

    // Subscribe to events and stream them back as chunked NDJSON response
    let (sub_tx, sub_rx) = mpsc::channel::<ipc::HelperEvent>();
    {
        let mut st = state.0.lock().unwrap();
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
        .body(body)
        .unwrap()
}

/// Disconnect the active VPN connection (blocking: joins threads).
/// Returns true if a connection was active and torn down.
fn perform_disconnect(state: &State) -> bool {
    let is_connected = state.0.lock().unwrap().conn.is_connected();
    if !is_connected {
        return false;
    }

    // Signal the connect thread via its per-connection flag.
    // Do NOT call recovery::trigger_shutdown() here — that sets the global
    // flag which also kills the helper's accept loop (the zombie-helper bug).
    state.0.lock().unwrap().conn.disconnect_flag.store(true, Ordering::SeqCst);

    {
        let mut st = state.0.lock().unwrap();
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnecting,
        });
    }

    // Take handles — drop lock before joining threads (they may need the lock)
    let (connect_handle, stats_handle) = {
        let mut st = state.0.lock().unwrap();
        let ch = st.conn.connect_handle.take();
        st.conn.stats_stop.store(true, Ordering::SeqCst);
        let sh = st.conn.stats_handle.take();
        (ch, sh)
    };

    if let Some(h) = connect_handle {
        let _ = h.join();
    }
    if let Some(h) = stats_handle {
        let _ = h.join();
    }

    // The connect thread may have exited without full cleanup (e.g., shutdown
    // caught between reconnection iterations at connect.rs:1071). Force-recover
    // from the state file to clean up DNS, WireGuard, netlock, IPv6, etc.
    // If the connect thread already cleaned up, force_recover finds no state
    // file and is a no-op.
    if let Err(e) = recovery::force_recover() {
        warn!("force_recover after disconnect: {}", e);
    }

    // Clear server info and broadcast disconnected
    {
        let mut st = state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        });
    }

    true
}

/// Start a connect engine in background threads (no HTTP response needed).
/// Used by server-switch path where the HTTP handler returns immediately.
/// Events are broadcast to all /events subscribers.
fn start_connect(state: State, connect_req: ipc::ConnectRequest, username: Zeroizing<String>, password: Zeroizing<String>) {
    let (event_tx, event_rx) = mpsc::channel::<ipc::EngineEvent>();

    let server_info = {
        let st = state.0.lock().unwrap();
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
            if let Ok(mut st) = broadcast_state.0.lock() {
                st.broadcast(&helper_event);
            }
        }
    });

    // Stop any previous stats poller
    {
        let mut st = state.0.lock().unwrap();
        st.conn.stats_stop.store(true, Ordering::SeqCst);
        let prev_stats = st.conn.stats_handle.take();
        drop(st);
        if let Some(h) = prev_stats {
            let _ = h.join();
        }
    }

    let connect_broadcast_state = Arc::clone(&state);
    let (cached_manifest, cached_latency) = {
        let st = lock_state(&state);
        (st.manifest.clone().expect("ready=true implies manifest"), st.latency.clone())
    };

    // Create a fresh per-connection disconnect flag.
    // perform_disconnect() sets this to signal the connect thread to stop,
    // without touching the global shutdown flag (which would kill the accept loop).
    let disconnect_flag = Arc::new(AtomicBool::new(false));
    {
        let mut st = state.0.lock().unwrap();
        st.conn.disconnect_flag = disconnect_flag.clone();
    }

    // Resolve options: defaults -> profile -> per-session overrides
    let profile_options = config::load_profile_options();
    let resolved = options::resolve(&profile_options, &connect_req.overrides);

    let connect_config = connect::ConnectConfig {
        server_name: connect_req.server,
        no_lock: !options::get_bool(&resolved, options::NETLOCK),
        allow_lan: options::get_bool(&resolved, options::NETLOCK_ALLOW_PRIVATE),
        no_reconnect: !options::get_bool(&resolved, options::RECONNECT),
        username,
        password,
        allow_server: options::get_list(&resolved, options::SERVERS_ALLOWLIST),
        deny_server: options::get_list(&resolved, options::SERVERS_DENYLIST),
        allow_country: options::get_list(&resolved, options::AREAS_ALLOWLIST),
        deny_country: options::get_list(&resolved, options::AREAS_DENYLIST),
        no_verify: !options::get_bool(&resolved, options::VERIFY),
        no_lock_last: !options::get_bool(&resolved, options::SERVERS_LOCKLAST),
        no_start_last: !options::get_bool(&resolved, options::SERVERS_STARTLAST),
        cli_ipv6_mode: {
            let v = options::get_str(&resolved, options::NETWORK_IPV6_MODE);
            if v.is_empty() || v == "in-block" { None } else { Some(v.to_string()) }
        },
        cli_dns_servers: options::get_list(&resolved, options::DNS_SERVERS),
        event_tx: event_tx.clone(),
        cached_latency,
        manifest: cached_manifest,
        resolved,
        shutdown: Some(disconnect_flag),
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
            // Clean up state left behind by the failed connect session.
            // Without this, state.json + nftables rules persist and the next
            // connect attempt bails with "another instance running" (the helper
            // finds its own PID alive in state.json).
            if let Err(re) = recovery::force_recover() {
                warn!("post-error recovery failed: {}", re);
            }
            if let Ok(mut st) = connect_broadcast_state.0.lock() {
                st.broadcast(&ipc::HelperEvent::Error {
                    message: format!("{}", e),
                });
            }
        }

        // Signal disconnected and clear the connect_in_progress guard
        if let Ok(mut st) = connect_broadcast_state.0.lock() {
            st.conn.connect_in_progress.store(false, Ordering::SeqCst);
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnected,
            });
        }
    });

    // Spawn stats polling thread
    let stats_state = Arc::clone(&state);
    let stats_stop = Arc::new(AtomicBool::new(false));
    let stats_stop_clone = stats_stop.clone();
    let stats_handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));
            if stats_stop_clone.load(Ordering::SeqCst) {
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
                    if let Ok(mut st) = stats_state.0.lock() {
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
        let mut st = state.0.lock().unwrap();
        st.conn.connect_handle = Some(conn_handle);
        st.conn.stats_stop = stats_stop;
        st.conn.stats_handle = Some(stats_handle);
    }

    // Detach: event_fwd exits when event_rx drops (connect thread finishes)
    thread::spawn(move || {
        let _ = event_fwd.join();
    });
}

/// POST /disconnect — stop VPN connection.
fn handle_disconnect(state: &State) -> Response<HyperBody> {
    let is_connected;
    let has_orphan;

    {
        let st = state.0.lock().unwrap();
        is_connected = st.conn.is_connected();
        has_orphan = !is_connected && matches!(
            recovery::load(),
            Ok(Some(ref rec)) if wireguard::is_connected(&rec.wg_interface)
        );
    }

    if is_connected {
        perform_disconnect(state);
        json_response(StatusCode::OK, &json!({"disconnected": true}))
    } else if has_orphan {
        // Orphaned connection: no connect thread but WireGuard interface is still up.
        info!("no connect thread but orphaned WireGuard interface found, recovering");

        {
            let mut st = state.0.lock().unwrap();
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnecting,
            });
        }

        if let Err(e) = recovery::force_recover() {
            error!("orphaned disconnect recovery failed: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("orphaned disconnect failed: {}", e));
        }

        // Clean up server host routes (force_recover doesn't know server IPs)
        {
            let st = state.0.lock().unwrap();
            if let Some(ref manifest) = st.manifest {
                let server_ips: Vec<String> = manifest.servers
                    .iter()
                    .flat_map(|s| s.ips_entry.iter().cloned())
                    .collect();
                drop(st);
                if let Ok(gw) = wireguard::get_default_gateway_pub() {
                    let _ = wireguard::remove_server_host_routes(&server_ips, &gw);
                }
            }
        }

        // Stop stats poller and clear server info
        {
            let mut st = state.0.lock().unwrap();
            st.conn.stats_stop.store(true, Ordering::SeqCst);
            let sh = st.conn.stats_handle.take();
            drop(st);
            if let Some(h) = sh {
                let _ = h.join();
            }
        }

        {
            let mut st = state.0.lock().unwrap();
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
        let st = state.0.lock().unwrap();
        initial_state = current_connection_state(&st);
    }

    // Create subscriber channel
    let (sub_tx, sub_rx) = mpsc::channel::<ipc::HelperEvent>();
    {
        let mut st = state.0.lock().unwrap();
        st.subscribers.push(sub_tx);
    }

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, Infallible>>(32);

    // Spawn blocking thread that reads from sub_rx and sends to tokio tx
    tokio::task::spawn_blocking(move || {
        // Send initial events
        let _ = send_event_frame(&tx, &ipc::HelperEvent::StateChanged { state: initial_state });
        let _ = send_event_frame(&tx, &ipc::HelperEvent::LockStatus {
            session_active: lock_info.session_active,
            persistent_active: lock_info.persistent_active,
            persistent_installed: lock_info.persistent_installed,
        });

        // Stream events
        loop {
            match sub_rx.recv_timeout(Duration::from_secs(30)) {
                Ok(event) => {
                    if send_event_frame(&tx, &event).is_err() { break; }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if send_event_frame(&tx, &json!({"keepalive": true})).is_err() { break; }
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
        .body(body)
        .unwrap()
}

/// POST /import-eddie — import credentials from Eddie profile.
fn handle_import_eddie(body_bytes: &Bytes, peer_uid: Option<u32>, state: &State) -> Response<HyperBody> {
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
            } else {
                // Wake manifest loop now that creds are available
                state.1.manifest_cv.notify_all();
            }
            json_response(StatusCode::OK, &json!({"imported": true}))
        }
        Err(e) => {
            error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to import Eddie profile: {:#}", e))
        }
    }
}

/// GET /servers — return scored server list from cached manifest.
///
/// Uses cached manifest and latency from background loops.
/// Returns 503 if the helper hasn't fetched a manifest yet.
fn handle_list_servers(state: &State) -> Response<HyperBody> {
    let (manifest, latency) = {
        let st = lock_state(state);
        match &st.manifest {
            Some(m) => (m.clone(), st.latency.clone()),
            None => return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Server list not yet available — helper is warming up.",
            ),
        }
    };

    let profile_options = config::load_profile_options();
    let resolved = options::resolve(&profile_options, &std::collections::HashMap::new());
    let scoring = server::ScoringConfig::from_options(&resolved);

    let servers = dispatch_list_servers(&manifest, &latency, &scoring);
    json_response(StatusCode::OK, &json!({"servers": servers}))
}

/// GET /keys — return cached WireGuard key names.
fn handle_get_keys(state: &State) -> Response<HyperBody> {
    let st = lock_state(state);
    let names = st.key_names.clone();
    drop(st);
    json_response(StatusCode::OK, &json!({"keys": names}))
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
/// Credential keys (login/password) are rejected — credentials must go through
/// `sudo airvpn connect` or the `/import-eddie` endpoint.
fn handle_save_profile(body_bytes: &Bytes, _state: &State) -> Response<HyperBody> {
    let save_req: ipc::SaveProfileRequest = match serde_json::from_slice(body_bytes) {
        Ok(r) => r,
        Err(e) => return error_response(StatusCode::BAD_REQUEST, &format!("invalid SaveProfileRequest JSON: {}", e)),
    };

    if save_req.options.contains_key("login") || save_req.options.contains_key("password") {
        return error_response(
            StatusCode::FORBIDDEN,
            "credential writes not allowed via SaveProfile \
             — use sudo airvpn connect or Eddie import",
        );
    }

    match dispatch_save_profile(&save_req.options) {
        Ok(()) => {
            // Apply log level changes at runtime (no helper restart needed).
            // File path changes still require restart since simplelog doesn't
            // support reconfiguring file handles.
            if let Some(debug_val) = save_req.options.get(options::LOG_LEVEL_DEBUG) {
                let new_level = if debug_val.eq_ignore_ascii_case("true") {
                    log::LevelFilter::Debug
                } else {
                    log::LevelFilter::Info
                };
                log::set_max_level(new_level);
                info!("Log level changed to {:?}", new_level);
            }
            json_response(StatusCode::OK, &json!({"saved": true}))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("Failed to save profile: {:#}", e)),
    }
}

/// POST /lock/enable
fn handle_lock_enable(state: &State) -> Response<HyperBody> {
    if let Err(e) = dispatch_lock_enable() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock enable failed: {}", e));
    }
    repopulate_ping_allow(state);
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
fn handle_lock_install(state: &State) -> Response<HyperBody> {
    match dispatch_lock_install() {
        Ok(msg) => {
            repopulate_ping_allow(state);
            json_response(StatusCode::OK, &json!({"message": msg, "lock": build_lock_status_info()}))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock install failed: {}", e)),
    }
}

/// Re-populate the persistent lock's ping_allow chain from current server IPs.
/// Called after any operation that recreates the persistent table (enable, install).
fn repopulate_ping_allow(state: &State) {
    let ips: Vec<String> = {
        let st = state.0.lock().unwrap();
        st.latency.server_ips().values().cloned().collect()
    };
    if !ips.is_empty() {
        if let Err(e) = netlock::populate_ping_allow(&ips) {
            warn!("Failed to repopulate ping_allow after lock operation: {e}");
        }
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

/// POST /recover — clean up orphaned VPN state.
///
/// Runs force_recover (DNS, locks, WireGuard) and also cleans up stale
/// server host routes that force_recover can't handle (needs manifest IPs).
fn handle_recover(state: &State) -> Response<HyperBody> {
    if let Err(e) = recovery::force_recover() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("recovery failed: {}", e));
    }

    // Best-effort cleanup of server host routes (the ~1000 /32 routes to server IPs).
    // force_recover can't do this because it doesn't know the server IPs.
    // We get them from the cached manifest in SharedState.
    let st = state.0.lock().unwrap();
    if let Some(ref manifest) = st.manifest {
        let server_ips: Vec<String> = manifest.servers
            .iter()
            .flat_map(|s| s.ips_entry.iter().cloned())
            .collect();
        drop(st);
        if let Ok(gw) = wireguard::get_default_gateway_pub() {
            let _ = wireguard::remove_server_host_routes(&server_ips, &gw);
        }
    }

    json_response(StatusCode::OK, &json!({"recovered": true}))
}

/// POST /shutdown — trigger shutdown and exit helper.
fn handle_shutdown(state: &State) -> Response<HyperBody> {
    // Set BOTH: the global flag (to exit accept loop) and the per-connection
    // flag (to stop the connect thread's reconnection loop).
    recovery::trigger_shutdown();

    // Take handles — drop lock before joining
    let (connect_handle, stats_handle) = {
        let mut st = state.0.lock().unwrap();
        st.conn.disconnect_flag.store(true, Ordering::SeqCst);
        st.conn.stats_stop.store(true, Ordering::SeqCst);
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
    let allowlist_ips = options::parse_allowlist_ips(
        options::get_str(&resolved, options::NETLOCK_ALLOWLIST_IPS),
    );
    let local_forward_ifaces: Vec<String> = {
        let v = options::get_str(&resolved, options::NETLOCK_LOCAL_FORWARD_IFACES);
        if v.is_empty() { vec![] } else { v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect() }
    };
    let ruleset = netlock::generate_persistent_ruleset(&bootstrap_ips, iface_name, &allowlist_ips, &local_forward_ifaces);

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

/// Score and sort servers from a cached manifest + latency cache.
/// Always sorts by score (GUI re-sorts client-side as needed).
fn dispatch_list_servers(manifest: &manifest::Manifest, pings: &pinger::LatencyCache, scoring: &server::ScoringConfig) -> Vec<ipc::ServerInfo> {
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
            let score = server::score_with_ping(s, ping_ms_raw, scoring);
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
                bandwidth_cur: 2_i64.saturating_mul(s.bandwidth.saturating_mul(8)) / (1_000 * 1_000),
                bandwidth_max: s.bandwidth_max,
                score,
                ping_ms,
                warning,
                ipv4: s.support_ipv4,
                ipv6: s.support_ipv6,
            }
        })
        .collect();

    servers.sort_by_key(|s| s.score);

    servers
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

}
