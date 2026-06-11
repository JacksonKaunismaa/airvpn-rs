//! HTTP route handlers for the helper daemon.

use std::convert::Infallible;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper::{Response, StatusCode};
use log::{debug, error, info, warn};
use serde_json::json;
use zeroize::Zeroizing;

use crate::{api, config, connect, ipc, netlock, options, pinger, recovery, server, wireguard};
use super::{error_response, json_response, lock_state, HyperBody, SharedState, State};
use super::dispatch;

// ---------------------------------------------------------------------------
// Streaming event helper
// ---------------------------------------------------------------------------

pub(super) fn send_event_frame(tx: &tokio::sync::mpsc::Sender<Result<Frame<Bytes>, Infallible>>, event: &impl serde::Serialize) -> Result<(), ()> {
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
pub(super) fn handle_status(state: &State) -> Response<HyperBody> {
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

/// RAII guard for the connect thread. On drop (including panic unwind), clears
/// the `connect_in_progress` flag and broadcasts the final `Disconnected` event.
///
/// Used at two call sites:
/// - `handle_connect_async`: created before warmup, defused via `mem::forget()`
///   once we're committed to spawning the connect thread. The connect thread
///   creates its own guard and takes over responsibility.
/// - The connect thread closure: created at the top, runs on every exit path
///   (Ok, Err, panic).
struct ConnectGuard {
    in_progress: Arc<AtomicBool>,
    /// `None` when used as the early-exit guard in `handle_connect_async`
    /// (no broadcast needed — connection never started). `Some` inside the
    /// connect thread.
    state: Option<State>,
}

impl Drop for ConnectGuard {
    fn drop(&mut self) {
        self.in_progress.store(false, Ordering::SeqCst);
        if let Some(state) = &self.state {
            if let Ok(mut st) = state.0.lock() {
                st.broadcast(&ipc::HelperEvent::StateChanged {
                    state: ipc::ConnectionState::Disconnected,
                });
            }
        }
    }
}

/// RAII guard that clears `switch_in_progress` on every exit path of the
/// server-switch thread (normal return or panic unwind). Without this, a panic
/// in `perform_disconnect`/`start_connect` would leave the flag stuck `true` and
/// permanently reject all future connect requests.
struct SwitchGuard(State);

impl Drop for SwitchGuard {
    fn drop(&mut self) {
        // Recover from a poisoned mutex so the flag is ALWAYS cleared — a stuck
        // `switch_in_progress` would permanently reject every future connect.
        let st = self.0 .0.lock().unwrap_or_else(|e| e.into_inner());
        st.conn.switch_in_progress.store(false, Ordering::SeqCst);
    }
}

/// Resolve credentials from the saved profile, returning 409 if Eddie import
/// is needed. Returns `Ok((username, password))` on success, or `Err(response)`
/// with the appropriate HTTP error/conflict response on failure.
fn resolve_credentials(
    peer_uid: Option<u32>,
) -> Result<(Zeroizing<String>, Zeroizing<String>), Response<HyperBody>> {
    let profile_options = config::load_profile_options();
    let prof_user = Zeroizing::new(profile_options.get("login").cloned().unwrap_or_default());
    let prof_pass = Zeroizing::new(profile_options.get("password").cloned().unwrap_or_default());

    if !prof_user.is_empty() && !prof_pass.is_empty() {
        Ok((prof_user, prof_pass))
    } else if let Some(eddie_path) = peer_uid.and_then(config::eddie_profile_path_for_uid) {
        Err(json_response(StatusCode::CONFLICT, &ipc::EddieImportNeeded {
            eddie_profile: eddie_path.display().to_string(),
        }))
    } else {
        Err(error_response(StatusCode::BAD_REQUEST, "no credentials available — run `sudo airvpn connect` for first-time setup"))
    }
}

/// Wait for the helper to finish warming up (manifest fetched + first ping
/// cycle complete). Returns `Ok(())` in steady state (already warm) or after
/// the condvar fires within 60 s. Returns `Err(response)` with a 503 if the
/// timeout expires before warmup completes.
fn wait_for_warmup(state: &State) -> Result<(), Response<HyperBody>> {
    let guard = lock_state(state);
    if guard.ready && guard.manifest.is_some() {
        return Ok(());
    }
    info!("Waiting for helper warmup (manifest + first ping cycle)...");
    let result = state.1.ready_cv.wait_timeout_while(
        guard,
        Duration::from_secs(60),
        |st| !st.ready || st.manifest.is_none(),
    ).unwrap_or_else(|e| e.into_inner());
    if !result.0.ready || result.0.manifest.is_none() {
        Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Helper still warming up (waiting for first latency measurement). Try again shortly.",
        ))
    } else {
        Ok(())
    }
}

/// POST /connect — start VPN connection, stream events via chunked response.
pub(super) async fn handle_connect_async(
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
    // Exception: when already connected, allow through — the server_switch path
    // (below) handles the disconnect→reconnect sequence. Without this, the
    // connect_in_progress flag (set while the connect thread is running) would
    // block every server-switch attempt with a silent 409.
    let (connect_guard, claimed_exclusive) = {
        let st = state.0.lock().unwrap();
        // A server-switch in flight owns the whole disconnect→reconnect; reject
        // anything else for its full duration (connect_in_progress alone is
        // insufficient — it flaps to false mid-switch).
        if st.conn.switch_in_progress.load(Ordering::SeqCst) {
            return error_response(StatusCode::CONFLICT, "connect already in progress (server switch)");
        }
        if st.conn.connect_in_progress.load(Ordering::SeqCst) && !st.conn.is_connected() {
            return error_response(StatusCode::CONFLICT, "connect already in progress");
        }
        // Claim the flag with a swap so we know whether WE took it (false→true)
        // or it was already held by a running connect thread (the
        // already-connected exception above). The distinction matters twice:
        // only an exclusive claimant may take the fresh-connect fall-through
        // after the switch block below, and only an exclusive claimant gets an
        // early-exit guard — clearing a flag owned by a still-running connect
        // thread would let a concurrent request slip past this gate.
        let claimed_exclusive = !st.conn.connect_in_progress.swap(true, Ordering::SeqCst);
        // RAII guard: clears the flag if we return early (credential errors,
        // warmup timeout, etc.). The connect thread clears it on normal exit.
        let guard = claimed_exclusive.then(|| ConnectGuard {
            in_progress: st.conn.connect_in_progress.clone(),
            state: None,
        });
        (guard, claimed_exclusive)
    };

    let (resolved_username, resolved_password) = match resolve_credentials(peer_uid) {
        Ok(creds) => creds,
        Err(resp) => return resp,
    };

    if let Err(resp) = wait_for_warmup(&state) {
        return resp;
    }

    // If already connected, do the full disconnect→connect in a detached thread
    // and return immediately. The HTTP connection may die during disconnect
    // (cancelling this handler), so we must not await the disconnect.
    // Events flow through the /events stream.
    {
        let st = state.0.lock().unwrap();
        // Decide switch-vs-fresh and claim the switch under ONE critical section.
        // Checking `switch_in_progress` here — before the `is_connected()`
        // branch AND before the fall-through to a fresh connect — is what
        // actually closes the duplicate-spawn race: `is_connected()` reads false
        // during the switch's perform_disconnect window, so a request that
        // parked in wait_for_warmup and resumes mid-switch would otherwise fall
        // straight through to start_connect and spawn a second connect thread.
        // Because the check and the set below both happen under this lock, no
        // swap/CAS is needed — the mutex serializes the decision.
        if st.conn.switch_in_progress.load(Ordering::SeqCst) {
            drop(st);
            return error_response(StatusCode::CONFLICT, "connect already in progress (server switch)");
        }
        if st.conn.is_connected() {
            st.conn.switch_in_progress.store(true, Ordering::SeqCst);
            drop(st);
            let switch_state = Arc::clone(&state);
            // Use Builder::spawn (returns Result) rather than thread::spawn
            // (panics on failure): the SwitchGuard that clears the flag lives
            // INSIDE the closure, so if thread creation fails we must clear
            // switch_in_progress here or every future connect is rejected.
            let spawn_result = thread::Builder::new()
                .name("airvpn-switch".into())
                .spawn(move || {
                    // Clears switch_in_progress on every exit path (incl. panic),
                    // at which point the new connect thread is running and
                    // is_connected() is true again, so releasing the gate is safe.
                    let _switch_guard = SwitchGuard(Arc::clone(&switch_state));
                    perform_disconnect(&switch_state);
                    // Re-arm the flag: the old connect thread cleared it on exit
                    // (during the join inside perform_disconnect).
                    switch_state.0.lock().unwrap().conn.connect_in_progress.store(true, Ordering::SeqCst);
                    start_connect(switch_state, connect_req, resolved_username, resolved_password);
                });
            match spawn_result {
                Ok(_) => {
                    // Committed: the switch thread now owns both flags. Defuse the
                    // early-exit guard so it doesn't clear connect_in_progress.
                    std::mem::forget(connect_guard);
                    return json_response(StatusCode::OK, &json!({"server_switch": true}));
                }
                Err(e) => {
                    // Thread couldn't be created — undo the switch claim so the
                    // helper isn't permanently wedged. If we claimed
                    // connect_in_progress ourselves, connect_guard clears it on
                    // drop; if we entered via the already-connected exception,
                    // there is no guard and the flag correctly stays with the
                    // still-running connect thread.
                    state.0.lock().unwrap_or_else(|p| p.into_inner())
                        .conn.switch_in_progress.store(false, Ordering::SeqCst);
                    return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("failed to start server switch: {e}"));
                }
            }
        }
    }

    // Falling through to a fresh connect is only safe for the request that
    // claimed `connect_in_progress` itself (false→true). A request that entered
    // through the already-connected exception holds no claim of its own — if
    // the connection dropped while it sat in resolve_credentials/warmup,
    // another request may have since claimed a fresh connect, and proceeding
    // here would spawn a duplicate connect thread (and the stale-state
    // force_recover below could tear down that request's half-built session).
    if !claimed_exclusive {
        return error_response(StatusCode::CONFLICT, "connection dropped during connect request, retry");
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

/// Signal disconnect and spawn async cleanup. Returns immediately.
///
/// Idempotent: if the disconnect flag is already set, returns false without
/// spawning a duplicate cleanup thread. Returns true only for the caller
/// that successfully flipped the flag.
fn signal_disconnect(state: &State) -> bool {
    // Single critical section: check, claim, capture handles, snapshot
    // manifest IPs, broadcast.
    let (connect_handle, stats_handle, route_ips) = {
        let mut st = state.0.lock().unwrap();
        if !st.conn.is_connected() {
            return false;
        }
        if st.conn.disconnect_flag.swap(true, Ordering::SeqCst) {
            // Another caller already signalled — they own cleanup.
            return false;
        }
        st.conn.stats_stop.store(true, Ordering::SeqCst);
        let ch = st.conn.connect_handle.take();
        let sh = st.conn.stats_handle.take();
        // Snapshot manifest IPs so the cleanup thread can remove host routes
        // after force_recover (which doesn't know server IPs).
        let ips: Vec<String> = st.manifest.as_ref()
            .map(|m| m.servers.iter().flat_map(|s| s.ips_entry.iter().cloned()).collect())
            .unwrap_or_default();
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnecting,
        });
        (ch, sh, ips)
    };

    // Spawn detached thread for blocking cleanup
    let cleanup_state = Arc::clone(state);
    thread::spawn(move || {
        if let Some(h) = connect_handle {
            let _ = h.join();
        }
        if let Some(h) = stats_handle {
            let _ = h.join();
        }

        if let Err(e) = recovery::force_recover() {
            warn!("force_recover after disconnect: {}", e);
        }

        // Remove stale /32 server host routes left by the pinger.
        // force_recover doesn't handle these (it doesn't know server IPs).
        if !route_ips.is_empty() {
            if let Ok(gw) = wireguard::get_default_gateway_pub() {
                let _ = wireguard::remove_server_host_routes(&route_ips, &gw);
            }
        }

        // Clear server info. The connect thread's ConnectGuard broadcasts
        // Disconnected on its way out — don't duplicate it here.
        let st = cleanup_state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        };
    });

    true
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

    // Remove stale /32 server host routes left by the pinger.
    // force_recover doesn't handle these (it doesn't know server IPs).
    let route_ips: Vec<String> = {
        let st = state.0.lock().unwrap();
        st.manifest.as_ref()
            .map(|m| m.servers.iter().flat_map(|s| s.ips_entry.iter().cloned()).collect())
            .unwrap_or_default()
    };
    if !route_ips.is_empty() {
        if let Ok(gw) = wireguard::get_default_gateway_pub() {
            let _ = wireguard::remove_server_host_routes(&route_ips, &gw);
        }
    }

    // Clear server info. The connect thread's ConnectGuard broadcasts
    // Disconnected on its way out — don't duplicate it here.
    {
        let st = state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        };
    }

    true
}

/// Spawn the engine-event → helper-event forwarder thread.
///
/// Reads `EngineEvent`s from `event_rx`, maps them to `HelperEvent`s, updates
/// the server info cache, and broadcasts to all `/events` subscribers. The
/// returned `JoinHandle` is detached by the caller (exits when the connect
/// thread drops `event_tx`).
fn spawn_event_forwarder(
    event_rx: mpsc::Receiver<ipc::EngineEvent>,
    state: &State,
    server_info: &Arc<Mutex<(String, String, String)>>,
) -> thread::JoinHandle<()> {
    let broadcast_state = Arc::clone(state);
    let fwd_server_info = server_info.clone();
    thread::spawn(move || {
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
    })
}

/// Spawn the stats polling thread — reads WireGuard transfer stats every 2 s
/// and broadcasts `HelperEvent::Stats` to all subscribers.
///
/// Returns `(JoinHandle, stop_flag)`. Set the stop flag to exit the loop.
fn spawn_stats_poller(state: &State) -> (thread::JoinHandle<()>, Arc<AtomicBool>) {
    let stats_state = Arc::clone(state);
    let stats_stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stats_stop.clone();
    let handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));
            if stop_clone.load(Ordering::SeqCst) {
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
    (handle, stats_stop)
}

/// Build a `ConnectConfig` from the connect request, resolved options, and
/// cached manifest/latency data.
fn build_connect_config(
    connect_req: ipc::ConnectRequest,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    event_tx: mpsc::Sender<ipc::EngineEvent>,
    cached_manifest: crate::manifest::Manifest,
    cached_latency: pinger::LatencyCache,
    disconnect_flag: Arc<AtomicBool>,
) -> connect::ConnectConfig {
    let profile_options = config::load_profile_options();
    let resolved = options::resolve(&profile_options, &connect_req.overrides);

    connect::ConnectConfig {
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
        event_tx,
        cached_latency,
        manifest: cached_manifest,
        resolved,
        shutdown: Some(disconnect_flag),
    }
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

    let event_fwd = spawn_event_forwarder(event_rx, &state, &server_info);

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

    let connect_config = build_connect_config(
        connect_req, username, password,
        event_tx.clone(), cached_manifest, cached_latency,
        disconnect_flag,
    );

    let connect_in_progress_for_guard = {
        let st = state.0.lock().unwrap();
        st.conn.connect_in_progress.clone()
    };
    let conn_handle = thread::spawn(move || {
        // Guard fires on every exit path (Ok, Err, panic) — clears
        // connect_in_progress and broadcasts Disconnected exactly once.
        let _guard = ConnectGuard {
            in_progress: connect_in_progress_for_guard,
            state: Some(Arc::clone(&connect_broadcast_state)),
        };

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
        // No manual store/broadcast — guard handles both on drop.
    });

    let (stats_handle, stats_stop) = spawn_stats_poller(&state);

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
pub(super) fn handle_disconnect(state: &State) -> Response<HyperBody> {
    let is_connected;
    let has_orphan;

    {
        let st = state.0.lock().unwrap();
        // A server-switch owns the whole disconnect→reconnect window; check it
        // FIRST, before is_connected/has_orphan are computed. Mid-switch,
        // is_connected() reads false while the WG interface may still be up, so
        // this request would otherwise take the orphan path and run
        // force_recover() concurrently with the switch thread's own teardown
        // (racing on nft tables, routes, and state.json) — or take the signal
        // path and report success while the switch reconnects anyway. The
        // switch thread owns its teardown/flag via SwitchGuard; report it and
        // let the caller retry once the switch settles.
        if st.conn.switch_in_progress.load(Ordering::SeqCst) {
            return error_response(StatusCode::CONFLICT, "server switch in progress, try again shortly");
        }
        is_connected = st.conn.is_connected();
        has_orphan = !is_connected && matches!(
            recovery::load(),
            Ok(Some(ref rec)) if wireguard::is_connected(&rec.wg_interface)
        );
    }

    if is_connected {
        signal_disconnect(state);
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
        // Known narrow race: this stale-flag clear can't distinguish a genuinely
        // stuck flag from a connect request still in its pre-thread window
        // (resolving credentials/warming up). A disconnect landing in that
        // window "succeeds" while the pending connect proceeds anyway. Fixing
        // it needs a way to cancel an in-flight pre-thread connect, which the
        // flag alone can't express.
        let was_stuck = state.0.lock().unwrap().conn.connect_in_progress.swap(false, Ordering::SeqCst);
        if was_stuck {
            info!("cleared stale connect_in_progress flag");
            json_response(StatusCode::OK, &json!({"disconnected": true}))
        } else {
            error_response(StatusCode::BAD_REQUEST, "no active connection")
        }
    }
}

/// GET /events — long-lived chunked stream of helper events (for GUI).
pub(super) async fn handle_events_async(state: State) -> Response<HyperBody> {
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
pub(super) fn handle_import_eddie(body_bytes: &Bytes, peer_uid: Option<u32>, state: &State) -> Response<HyperBody> {
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
pub(super) fn handle_list_servers(state: &State) -> Response<HyperBody> {
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

    let servers = dispatch::dispatch_list_servers(&manifest, &latency, &scoring);
    json_response(StatusCode::OK, &json!({"servers": servers}))
}

/// GET /keys — return cached WireGuard key names.
pub(super) fn handle_get_keys(state: &State) -> Response<HyperBody> {
    let st = lock_state(state);
    let names = st.key_names.clone();
    drop(st);
    json_response(StatusCode::OK, &json!({"keys": names}))
}

/// GET /profile — return profile options (credentials stripped).
pub(super) fn handle_get_profile() -> Response<HyperBody> {
    match dispatch::dispatch_get_profile() {
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
pub(super) fn handle_save_profile(body_bytes: &Bytes, _state: &State) -> Response<HyperBody> {
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

    // Reject interface names that would be unsafe to interpolate into the nft
    // kill-switch ruleset. These options flow into `nft -f` (run as root), so a
    // value containing `"`/`;` could inject arbitrary rules. Validate at write
    // time too — not just at the activate()/lock-install boundary — so bad
    // values can't persist and silently break (or subvert) lock activation
    // later. Empty is allowed: it means "use the default interface".
    if let Some(iface) = save_req.options.get(options::NETWORK_IFACE_NAME) {
        if !iface.is_empty() && !crate::common::validate_interface_name(iface) {
            return error_response(
                StatusCode::BAD_REQUEST,
                &format!("invalid {}: must be alphanumeric/-/_/. and ≤15 chars", options::NETWORK_IFACE_NAME),
            );
        }
    }
    if let Some(list) = save_req.options.get(options::NETLOCK_LOCAL_FORWARD_IFACES) {
        for entry in list.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            if !crate::common::validate_interface_name(entry) {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid interface {entry:?} in {}: must be alphanumeric/-/_/. and ≤15 chars", options::NETLOCK_LOCAL_FORWARD_IFACES),
                );
            }
        }
    }

    match dispatch::dispatch_save_profile(&save_req.options) {
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
pub(super) fn handle_lock_enable(state: &State) -> Response<HyperBody> {
    if let Err(e) = dispatch::dispatch_lock_enable() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock enable failed: {}", e));
    }
    dispatch::repopulate_ping_allow(state);
    json_response(StatusCode::OK, &build_lock_status_info())
}

/// POST /lock/disable
pub(super) fn handle_lock_disable() -> Response<HyperBody> {
    if let Err(e) = netlock::reclaim_and_delete() {
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock disable failed: {}", e));
    }
    json_response(StatusCode::OK, &build_lock_status_info())
}

/// POST /lock/install
pub(super) fn handle_lock_install(state: &State) -> Response<HyperBody> {
    match dispatch::dispatch_lock_install() {
        Ok(msg) => {
            dispatch::repopulate_ping_allow(state);
            json_response(StatusCode::OK, &json!({"message": msg, "lock": build_lock_status_info()}))
        }
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock install failed: {}", e)),
    }
}

/// POST /lock/uninstall
pub(super) fn handle_lock_uninstall() -> Response<HyperBody> {
    match dispatch::dispatch_lock_uninstall() {
        Ok(msg) => json_response(StatusCode::OK, &json!({"message": msg, "lock": build_lock_status_info()})),
        Err(e) => error_response(StatusCode::INTERNAL_SERVER_ERROR, &format!("lock uninstall failed: {}", e)),
    }
}

/// GET /lock/status
pub(super) fn handle_lock_status() -> Response<HyperBody> {
    json_response(StatusCode::OK, &build_lock_status_info())
}

/// POST /recover — clean up orphaned VPN state.
///
/// Runs force_recover (DNS, locks, WireGuard) and also cleans up stale
/// server host routes that force_recover can't handle (needs manifest IPs).
pub(super) fn handle_recover(state: &State) -> Response<HyperBody> {
    state.0.lock().unwrap().conn.connect_in_progress.store(false, Ordering::SeqCst);

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
pub(super) fn handle_shutdown(state: &State) -> Response<HyperBody> {
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
