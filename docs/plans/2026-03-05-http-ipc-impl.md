# HTTP IPC Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace JSON-lines IPC protocol with HTTP/1.1 over Unix socket so multiple clients (CLI + GUI) can use the helper concurrently.

**Architecture:** Minimal HTTP/1.1 parser (~100 lines) over existing `UnixListener`. Thread-per-connection gives multi-client for free. Shared state via `Arc<Mutex<SharedState>>`. Fan-out event subscribers for streaming (GET /events). Two-phase connect flow for Eddie profile import.

**Tech Stack:** No new dependencies. Minimal HTTP parser over `std::os::unix::net::UnixStream`. Existing `serde_json` for bodies.

**Design doc:** `docs/plans/2026-03-05-http-ipc-design.md`

---

### Task 1: HTTP Parser Module (`src/http.rs`)

New module: minimal HTTP/1.1 request parser and response writer over `UnixStream`.

**Files:**
- Create: `src/http.rs`
- Modify: `src/lib.rs` (add `pub mod http;`)

**Step 1: Write the HTTP parser module**

```rust
// src/http.rs
//! Minimal HTTP/1.1 parser for helper IPC over Unix socket.
//!
//! Only supports what we need: fixed routes, JSON bodies, chunked streaming.
//! Not a general-purpose HTTP server.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

/// Parsed HTTP request.
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
    /// Peer UID from SO_PEERCRED (set by caller after accept).
    pub peer_uid: Option<u32>,
}

/// HTTP response writer. Wraps a stream and writes HTTP/1.1 responses.
pub struct ResponseWriter {
    stream: UnixStream,
    headers_sent: bool,
}

impl ResponseWriter {
    pub fn new(stream: UnixStream) -> Self {
        Self { stream, headers_sent: false }
    }

    /// Send a complete JSON response.
    pub fn json(&mut self, status: u16, body: &impl serde::Serialize) -> Result<()> {
        let json = serde_json::to_vec(body).context("serialize response")?;
        let status_text = status_reason(status);
        write!(
            self.stream,
            "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status, status_text, json.len()
        )?;
        self.stream.write_all(&json)?;
        self.stream.flush()?;
        self.headers_sent = true;
        Ok(())
    }

    /// Begin a chunked streaming response (for /events and /connect).
    pub fn begin_chunked(&mut self, status: u16) -> Result<()> {
        let status_text = status_reason(status);
        write!(
            self.stream,
            "HTTP/1.1 {} {}\r\nContent-Type: application/x-ndjson\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
            status, status_text
        )?;
        self.stream.flush()?;
        self.headers_sent = true;
        Ok(())
    }

    /// Write a single chunk (JSON line). Returns Err if client disconnected.
    pub fn send_chunk(&mut self, event: &impl serde::Serialize) -> Result<()> {
        let mut json = serde_json::to_string(event).context("serialize chunk")?;
        json.push('\n');
        write!(self.stream, "{:x}\r\n{}\r\n", json.len(), json)?;
        self.stream.flush()?;
        Ok(())
    }

    /// End the chunked response.
    pub fn end_chunked(&mut self) -> Result<()> {
        write!(self.stream, "0\r\n\r\n")?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send a plain text error response (fallback for parse errors).
    pub fn error(&mut self, status: u16, message: &str) -> Result<()> {
        let status_text = status_reason(status);
        write!(
            self.stream,
            "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status, status_text, message.len(), message
        )?;
        self.stream.flush()?;
        self.headers_sent = true;
        Ok(())
    }
}

/// Parse an HTTP/1.1 request from a UnixStream.
pub fn parse_request(stream: &UnixStream) -> Result<Request> {
    let mut reader = BufReader::new(stream);

    // Read request line: METHOD /path?query HTTP/1.1
    let mut request_line = String::new();
    reader.read_line(&mut request_line).context("read request line")?;
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 {
        anyhow::bail!("malformed request line");
    }
    let method = parts[0].to_string();
    let raw_path = parts[1];

    // Split path and query string
    let (path, query) = if let Some(idx) = raw_path.find('?') {
        let p = raw_path[..idx].to_string();
        let q = parse_query_string(&raw_path[idx + 1..]);
        (p, q)
    } else {
        (raw_path.to_string(), HashMap::new())
    };

    // Read headers
    let mut content_length: usize = 0;
    loop {
        let mut header_line = String::new();
        reader.read_line(&mut header_line).context("read header")?;
        if header_line.trim().is_empty() {
            break; // End of headers
        }
        if let Some(val) = header_line.strip_prefix("Content-Length:").or_else(|| header_line.strip_prefix("content-length:")) {
            content_length = val.trim().parse().unwrap_or(0);
        }
    }

    // Read body
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).context("read body")?;
    }

    Ok(Request { method, path, query, body, peer_uid: None })
}

fn parse_query_string(qs: &str) -> HashMap<String, String> {
    qs.split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            Some((parts.next()?.to_string(), parts.next().unwrap_or("").to_string()))
        })
        .collect()
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}
```

**Step 2: Register module in lib.rs**

Add `pub mod http;` to `src/lib.rs`.

**Step 3: Write unit tests for HTTP parser**

Add to bottom of `src/http.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    fn make_pair() -> (UnixStream, UnixStream) {
        UnixStream::pair().expect("create socket pair")
    }

    #[test]
    fn test_parse_get_request() {
        let (mut client, server) = make_pair();
        client.write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
        drop(client);
        let req = parse_request(&server).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/status");
        assert!(req.body.is_empty());
    }

    #[test]
    fn test_parse_post_with_body() {
        let (mut client, server) = make_pair();
        let body = r#"{"accept":true}"#;
        write!(
            client,
            "POST /import-eddie HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        ).unwrap();
        drop(client);
        let req = parse_request(&server).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/import-eddie");
        assert_eq!(req.body, body.as_bytes());
    }

    #[test]
    fn test_parse_query_string() {
        let (mut client, server) = make_pair();
        client.write_all(b"GET /servers?skip_ping=true&sort=name HTTP/1.1\r\n\r\n").unwrap();
        drop(client);
        let req = parse_request(&server).unwrap();
        assert_eq!(req.path, "/servers");
        assert_eq!(req.query.get("skip_ping").unwrap(), "true");
        assert_eq!(req.query.get("sort").unwrap(), "name");
    }

    #[test]
    fn test_json_response() {
        let (client, server) = make_pair();
        let mut writer = ResponseWriter::new(server);
        writer.json(200, &serde_json::json!({"status": "ok"})).unwrap();
        drop(writer);

        let mut response = String::new();
        BufReader::new(client).read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Content-Type: application/json"));
        assert!(response.contains(r#"{"status":"ok"}"#));
    }

    #[test]
    fn test_chunked_response() {
        let (client, server) = make_pair();
        let mut writer = ResponseWriter::new(server);
        writer.begin_chunked(200).unwrap();
        writer.send_chunk(&serde_json::json!({"event": "test"})).unwrap();
        writer.end_chunked().unwrap();
        drop(writer);

        let mut response = String::new();
        BufReader::new(client).read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("Transfer-Encoding: chunked"));
        assert!(response.contains(r#"{"event":"test"}"#));
        assert!(response.ends_with("0\r\n\r\n"));
    }
}
```

**Step 4: Run tests**

Run: `cargo test http::tests -p airvpn -- --nocapture`
Expected: All 5 tests pass.

**Step 5: Commit**

```bash
git add src/http.rs src/lib.rs
git commit -m "feat: add minimal HTTP/1.1 parser for IPC over Unix socket"
```

---

### Task 2: Add HTTP-specific IPC Types (`src/ipc.rs`)

Add request/response types for the HTTP routes. Keep existing types unchanged.

**Files:**
- Modify: `src/ipc.rs`

**Step 1: Add new types to ipc.rs**

Add after the existing `HelperEvent` enum (before the `encode_line` functions):

```rust
/// Request body for POST /connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectRequest {
    pub server: Option<String>,
    pub no_lock: bool,
    pub allow_lan: bool,
    pub skip_ping: bool,
    pub allow_country: Vec<String>,
    pub deny_country: Vec<String>,
    pub allow_server: Vec<String>,
    pub deny_server: Vec<String>,
    pub no_reconnect: bool,
    pub no_verify: bool,
    pub no_lock_last: bool,
    pub no_start_last: bool,
    pub ipv6_mode: Option<String>,
    pub dns_servers: Vec<String>,
    pub event_pre: [Option<String>; 3],
    pub event_up: [Option<String>; 3],
    pub event_down: [Option<String>; 3],
}

/// Response for GET /status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub state: ConnectionState,
    pub lock: LockStatusInfo,
}

/// Lock status info (reusable across responses).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockStatusInfo {
    pub session_active: bool,
    pub persistent_active: bool,
    pub persistent_installed: bool,
}

/// Response for POST /import-eddie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportEddieRequest {
    pub accept: bool,
}

/// Response when connect needs Eddie import (409).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EddieImportNeeded {
    pub eddie_profile: String,
}

/// Request body for POST /profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveProfileRequest {
    pub options: std::collections::HashMap<String, String>,
}
```

**Step 2: Build check**

Run: `cargo build 2>&1 | head -5`
Expected: Compiles without errors.

**Step 3: Commit**

```bash
git add src/ipc.rs
git commit -m "feat: add HTTP-specific IPC request/response types"
```

---

### Task 3: Rewrite Helper — Accept Loop and Shared State

Replace the single-client accept loop with a multi-client thread-per-connection HTTP server.

**Files:**
- Modify: `src/helper.rs`

**Step 1: Replace module header, imports, and shared state types**

Replace lines 1-227 (everything before `fn handle_client`) with the new accept loop and shared state. Keep all `dispatch_*` functions (lines 875-1107) unchanged.

The new `run()`:
- Gets systemd listener (same as before)
- Creates `Arc<Mutex<SharedState>>`
- Spawns a thread per accepted connection
- Each thread parses HTTP request, dispatches to route handler
- Shutdown: set flag, join all threads

```rust
//! Root helper daemon — HTTP/1.1 over Unix socket.
//!
//! Runs as root via systemd socket activation. Accepts multiple concurrent
//! clients: CLI commands are short-lived request/response, GUI uses GET /events
//! for streaming. Thread-per-connection.

use std::collections::HashMap;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};

use crate::{api, config, connect, http, ipc, manifest, netlock, pinger, recovery, server, wireguard};

pub const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";
const PID_FILE: &str = "/run/airvpn-rs/helper.pid";
```

SharedState struct:

```rust
/// VPN connection state that persists across client sessions.
struct ConnState {
    connect_handle: Option<thread::JoinHandle<()>>,
    stats_stop: Arc<AtomicBool>,
    stats_handle: Option<thread::JoinHandle<()>>,
    server_info: Arc<Mutex<(String, String, String)>>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            connect_handle: None,
            stats_stop: Arc::new(AtomicBool::new(false)),
            stats_handle: None,
            server_info: Arc::new(Mutex::new((String::new(), String::new(), String::new()))),
        }
    }

    fn is_connected(&self) -> bool {
        self.connect_handle.as_ref().is_some_and(|h| !h.is_finished())
    }
}

/// Shared state across all client handler threads.
struct SharedState {
    conn: ConnState,
    /// Event subscribers for GET /events (fan-out pattern).
    subscribers: Vec<mpsc::Sender<ipc::HelperEvent>>,
}

impl SharedState {
    fn new() -> Self {
        Self {
            conn: ConnState::new(),
            subscribers: Vec::new(),
        }
    }

    /// Broadcast an event to all subscribers. Removes dead subscribers.
    fn broadcast(&mut self, event: &ipc::HelperEvent) {
        self.subscribers.retain(|tx| tx.send(event.clone()).is_ok());
    }
}

type State = Arc<Mutex<SharedState>>;
```

New `run()` function:

```rust
pub fn run() -> Result<()> {
    connect::preflight_checks()?;

    let listener = get_systemd_listener()?;
    write_pid_file()?;
    info!("Helper listening on {} (HTTP, systemd socket activation)", SOCKET_PATH);

    let shutdown = recovery::setup_signal_handler()?;
    let state: State = Arc::new(Mutex::new(SharedState::new()));

    loop {
        if shutdown.load(Ordering::Relaxed) {
            info!("Shutdown signal received, exiting helper");
            break;
        }

        // Poll with 1s timeout
        listener.set_nonblocking(true).ok();
        match listener.accept() {
            Ok((stream, _addr)) => {
                listener.set_nonblocking(false).ok();
                let peer_uid = log_peer_credentials(&stream);
                let state = Arc::clone(&state);

                thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, state, peer_uid) {
                        debug!("Connection handler error: {}", e);
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

    // Graceful shutdown: disconnect active VPN
    {
        let mut s = state.lock().unwrap();
        if s.conn.is_connected() {
            info!("Disconnecting active VPN before shutdown...");
            recovery::trigger_shutdown();
            if let Some(h) = s.conn.connect_handle.take() {
                let _ = h.join();
            }
            s.conn.stats_stop.store(true, Ordering::SeqCst);
            if let Some(h) = s.conn.stats_handle.take() {
                let _ = h.join();
            }
        }
    }

    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}
```

**Step 2: Add connection handler and route dispatcher**

```rust
/// Handle a single HTTP connection: parse request, dispatch to route handler.
fn handle_connection(stream: UnixStream, state: State, peer_uid: Option<u32>) -> Result<()> {
    let mut req = http::parse_request(&stream)?;
    req.peer_uid = peer_uid;

    debug!("HTTP {} {} (uid={:?})", req.method, req.path, peer_uid);

    let mut resp = http::ResponseWriter::new(stream);

    match (req.method.as_str(), req.path.as_str()) {
        ("GET",  "/status")         => handle_status(&state, &mut resp),
        ("POST", "/connect")        => handle_connect(&req, &state, &mut resp),
        ("POST", "/disconnect")     => handle_disconnect(&state, &mut resp),
        ("POST", "/import-eddie")   => handle_import_eddie(&req, &state, &mut resp),
        ("GET",  "/events")         => handle_events(&state, &mut resp),
        ("GET",  "/servers")        => handle_list_servers(&req, &mut resp),
        ("GET",  "/profile")        => handle_get_profile(&mut resp),
        ("POST", "/profile")        => handle_save_profile(&req, &mut resp),
        ("POST", "/lock/enable")    => handle_lock_enable(&mut resp),
        ("POST", "/lock/disable")   => handle_lock_disable(&mut resp),
        ("POST", "/lock/install")   => handle_lock_install(&mut resp),
        ("POST", "/lock/uninstall") => handle_lock_uninstall(&mut resp),
        ("GET",  "/lock/status")    => handle_lock_status(&mut resp),
        ("POST", "/recover")        => handle_recover(&mut resp),
        ("POST", "/shutdown")       => handle_shutdown(&state, &mut resp),
        _ => resp.error(404, "not found"),
    }
}
```

**Step 3: Build check (will fail — route handlers not implemented yet)**

Run: `cargo build 2>&1 | head -20`
Expected: Errors about missing `handle_*` functions. This is expected — Task 4 implements them.

**Step 4: Commit work-in-progress**

Don't commit yet — continue to Task 4.

---

### Task 4: Implement Route Handlers

Port each command handler from the old `handle_client` match arms to standalone HTTP handler functions.

**Files:**
- Modify: `src/helper.rs`

**Step 1: Implement read-only handlers (Status, LockStatus, Profile, Servers)**

```rust
fn handle_status(state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    let s = state.lock().unwrap();
    let conn_state = if s.conn.is_connected() {
        match recovery::load() {
            Ok(Some(rec)) if wireguard::is_connected(&rec.wg_interface) => {
                let (name, country, location) = s.conn.server_info
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
    let lock = build_lock_status_info();
    resp.json(200, &ipc::StatusResponse { state: conn_state, lock })
}

fn handle_lock_status(resp: &mut http::ResponseWriter) -> Result<()> {
    resp.json(200, &build_lock_status_info())
}

fn handle_get_profile(resp: &mut http::ResponseWriter) -> Result<()> {
    match dispatch_get_profile() {
        Ok(mut options) => {
            let credentials_configured = options.get("login").map_or(false, |v| !v.is_empty())
                && options.get("password").map_or(false, |v| !v.is_empty());
            options.remove("login");
            options.remove("password");
            resp.json(200, &ipc::HelperEvent::Profile { options, credentials_configured })
        }
        Err(e) => resp.json(500, &ipc::HelperEvent::Error { message: format!("{:#}", e) }),
    }
}

fn handle_save_profile(req: &http::Request, resp: &mut http::ResponseWriter) -> Result<()> {
    let body: ipc::SaveProfileRequest = serde_json::from_slice(&req.body)
        .context("parse SaveProfile body")?;
    match dispatch_save_profile(&body.options) {
        Ok(()) => resp.json(200, &ipc::HelperEvent::ProfileSaved),
        Err(e) => resp.json(500, &ipc::HelperEvent::Error { message: format!("{:#}", e) }),
    }
}

fn handle_list_servers(req: &http::Request, resp: &mut http::ResponseWriter) -> Result<()> {
    let skip_ping = req.query.get("skip_ping").map_or(false, |v| v == "true");
    let sort = req.query.get("sort").map(|s| s.as_str());

    let profile_options = config::load_profile_options();
    let prof_user = profile_options.get("login").cloned().unwrap_or_default();
    let prof_pass = profile_options.get("password").cloned().unwrap_or_default();

    if prof_user.is_empty() || prof_pass.is_empty() {
        return resp.json(400, &ipc::HelperEvent::Error {
            message: "No credentials configured. Run `sudo airvpn connect` first.".into(),
        });
    }

    match dispatch_list_servers(skip_ping, sort, &prof_user, &prof_pass) {
        Ok(servers) => resp.json(200, &ipc::HelperEvent::ServerList { servers }),
        Err(e) => resp.json(500, &ipc::HelperEvent::Error { message: format!("{:#}", e) }),
    }
}

fn build_lock_status_info() -> ipc::LockStatusInfo {
    ipc::LockStatusInfo {
        session_active: netlock::is_active(),
        persistent_active: netlock::is_persist_active(),
        persistent_installed: std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists(),
    }
}
```

**Step 2: Implement lock operation handlers**

```rust
fn handle_lock_enable(resp: &mut http::ResponseWriter) -> Result<()> {
    if let Err(e) = dispatch_lock_enable() {
        return resp.json(500, &ipc::HelperEvent::Error { message: format!("{}", e) });
    }
    resp.json(200, &build_lock_status_info())
}

fn handle_lock_disable(resp: &mut http::ResponseWriter) -> Result<()> {
    if let Err(e) = netlock::reclaim_and_delete() {
        return resp.json(500, &ipc::HelperEvent::Error { message: format!("{}", e) });
    }
    resp.json(200, &build_lock_status_info())
}

fn handle_lock_install(resp: &mut http::ResponseWriter) -> Result<()> {
    match dispatch_lock_install() {
        Ok(msg) => resp.json(200, &serde_json::json!({
            "message": msg,
            "lock": build_lock_status_info()
        })),
        Err(e) => resp.json(500, &ipc::HelperEvent::Error { message: format!("{}", e) }),
    }
}

fn handle_lock_uninstall(resp: &mut http::ResponseWriter) -> Result<()> {
    match dispatch_lock_uninstall() {
        Ok(msg) => resp.json(200, &serde_json::json!({
            "message": msg,
            "lock": build_lock_status_info()
        })),
        Err(e) => resp.json(500, &ipc::HelperEvent::Error { message: format!("{}", e) }),
    }
}
```

**Step 3: Implement recover and shutdown**

```rust
fn handle_recover(resp: &mut http::ResponseWriter) -> Result<()> {
    match recovery::force_recover() {
        Ok(()) => resp.json(200, &serde_json::json!({"message": "Recovery complete."})),
        Err(e) => resp.json(500, &ipc::HelperEvent::Error { message: format!("{}", e) }),
    }
}

fn handle_shutdown(state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    recovery::trigger_shutdown();
    let mut s = state.lock().unwrap();
    if let Some(h) = s.conn.connect_handle.take() {
        let _ = h.join();
    }
    s.conn.stats_stop.store(true, Ordering::SeqCst);
    if let Some(h) = s.conn.stats_handle.take() {
        let _ = h.join();
    }
    resp.json(200, &serde_json::json!({"event": "Shutdown"}))
}
```

**Step 4: Implement Eddie import handler**

```rust
fn handle_import_eddie(req: &http::Request, state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    let body: ipc::ImportEddieRequest = serde_json::from_slice(&req.body)
        .context("parse import-eddie body")?;

    if !body.accept {
        return resp.json(200, &serde_json::json!({"imported": false}));
    }

    let peer_uid = req.peer_uid;
    let eddie_path = match peer_uid.and_then(config::eddie_profile_path_for_uid) {
        Some(p) => p,
        None => return resp.json(400, &ipc::HelperEvent::Error {
            message: "no Eddie profile found for your user".into(),
        }),
    };

    match config::load_eddie_profile_for_uid(&eddie_path, peer_uid.unwrap()) {
        Ok((opts, _is_v2n)) => {
            let eddie_user = opts.get("login").cloned().unwrap_or_default();
            let eddie_pass = opts.get("password").cloned().unwrap_or_default();
            if eddie_user.is_empty() || eddie_pass.is_empty() {
                return resp.json(400, &ipc::HelperEvent::Error {
                    message: "Eddie profile has no credentials".into(),
                });
            }
            if let Err(e) = config::save_credentials(&eddie_user, &eddie_pass) {
                warn!("Could not save credentials: {:#}", e);
            }
            resp.json(200, &serde_json::json!({"imported": true}))
        }
        Err(e) => resp.json(500, &ipc::HelperEvent::Error {
            message: format!("Failed to import: {:#}", e),
        }),
    }
}
```

**Step 5: Implement Connect handler (streaming)**

This is the most complex handler. It streams engine events over chunked HTTP.

```rust
fn handle_connect(req: &http::Request, state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    let body: ipc::ConnectRequest = serde_json::from_slice(&req.body)
        .context("parse connect body")?;

    let mut s = state.lock().unwrap();

    // Check if already connected
    if s.conn.is_connected() {
        return resp.json(409, &ipc::HelperEvent::Error {
            message: "already connected -- disconnect first".into(),
        });
    }

    // Resolve credentials from profile
    let profile_options = config::load_profile_options();
    let prof_user = profile_options.get("login").cloned().unwrap_or_default();
    let prof_pass = profile_options.get("password").cloned().unwrap_or_default();

    if prof_user.is_empty() || prof_pass.is_empty() {
        // Check for Eddie profile
        if let Some(eddie_path) = req.peer_uid.and_then(config::eddie_profile_path_for_uid) {
            return resp.json(409, &ipc::EddieImportNeeded {
                eddie_profile: eddie_path.display().to_string(),
            });
        }
        return resp.json(400, &ipc::HelperEvent::Error {
            message: "no credentials -- run `sudo airvpn connect` for first-time setup".into(),
        });
    }

    // Reset shutdown flag for the new connection
    recovery::reset_shutdown();

    // Create mpsc channel for engine events
    let (event_tx, event_rx) = mpsc::channel::<ipc::EngineEvent>();

    // Capture server info for status queries
    let server_info = s.conn.server_info.clone();

    // Stop any previous stats poller
    s.conn.stats_stop.store(true, Ordering::SeqCst);
    if let Some(h) = s.conn.stats_handle.take() {
        let _ = h.join();
    }

    // Spawn connect thread
    let connect_event_tx = event_tx.clone();
    let connect_config = connect::ConnectConfig {
        server_name: body.server,
        no_lock: body.no_lock,
        allow_lan: body.allow_lan,
        no_reconnect: body.no_reconnect,
        username: prof_user,
        password: prof_pass,
        allow_server: body.allow_server,
        deny_server: body.deny_server,
        allow_country: body.allow_country,
        deny_country: body.deny_country,
        skip_ping: body.skip_ping,
        no_verify: body.no_verify,
        no_lock_last: body.no_lock_last,
        no_start_last: body.no_start_last,
        cli_ipv6_mode: body.ipv6_mode,
        cli_dns_servers: body.dns_servers,
        cli_event_pre: body.event_pre,
        cli_event_up: body.event_up,
        cli_event_down: body.event_down,
        event_tx: connect_event_tx,
    };

    // Clone state for broadcasting from connect thread
    let broadcast_state = Arc::clone(state);

    let conn_handle = thread::spawn(move || {
        let result = (|| -> Result<()> {
            let mut provider_config = api::load_provider_config()?;
            api::verify_rsa_key_integrity(&provider_config);
            connect::run(&mut provider_config, &connect_config)?;
            Ok(())
        })();

        if let Err(e) = &result {
            error!("Connect thread exited with error: {}", e);
            let err_event = ipc::HelperEvent::Error { message: format!("{}", e) };
            if let Ok(mut s) = broadcast_state.lock() {
                s.broadcast(&err_event);
            }
        }

        // Signal disconnected
        let disc_event = ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        };
        if let Ok(mut s) = broadcast_state.lock() {
            s.broadcast(&disc_event);
        }
    });

    // Spawn stats poller
    s.conn.stats_stop = Arc::new(AtomicBool::new(false));
    let stats_stop = s.conn.stats_stop.clone();
    let stats_state = Arc::clone(state);
    s.conn.stats_handle = Some(thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_secs(2));
            if stats_stop.load(Ordering::SeqCst) { break; }
            let iface = match recovery::load() {
                Ok(Some(s)) => s.wg_interface,
                _ => continue,
            };
            if iface.is_empty() || !wireguard::is_connected(&iface) { continue; }
            match wireguard::get_transfer_stats(&iface) {
                Ok((rx, tx)) => {
                    let evt = ipc::HelperEvent::Stats { rx_bytes: rx, tx_bytes: tx };
                    if let Ok(mut s) = stats_state.lock() {
                        s.broadcast(&evt);
                    }
                }
                Err(_) => {}
            }
        }
    }));

    s.conn.connect_handle = Some(conn_handle);

    // Spawn engine event -> broadcast forwarder
    let fwd_state = Arc::clone(state);
    let fwd_server_info = server_info;
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
            if let Ok(mut s) = fwd_state.lock() {
                s.broadcast(&helper_event);
            }
        }
    });

    // Release lock before streaming
    drop(s);

    // Stream events back to this specific Connect caller
    resp.begin_chunked(200)?;

    // Subscribe for this caller's stream
    let (my_tx, my_rx) = mpsc::channel();
    {
        let mut s = state.lock().unwrap();
        s.subscribers.push(my_tx);
    }

    // Stream until Disconnected or client hangup
    for event in &my_rx {
        if resp.send_chunk(&event).is_err() {
            break; // Client disconnected
        }
        if matches!(event, ipc::HelperEvent::StateChanged { state: ipc::ConnectionState::Disconnected }) {
            break;
        }
    }

    resp.end_chunked().ok();
    Ok(())
}
```

**Step 6: Implement Events handler (long-lived streaming for GUI)**

```rust
fn handle_events(state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    resp.begin_chunked(200)?;

    // Subscribe
    let (tx, rx) = mpsc::channel();
    {
        let mut s = state.lock().unwrap();
        s.subscribers.push(tx);
    }

    // Send initial status
    {
        let s = state.lock().unwrap();
        let conn_state = if s.conn.is_connected() {
            match recovery::load() {
                Ok(Some(rec)) if wireguard::is_connected(&rec.wg_interface) => {
                    let (name, country, location) = s.conn.server_info
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
        let _ = resp.send_chunk(&ipc::HelperEvent::StateChanged { state: conn_state });
        let _ = resp.send_chunk(&ipc::HelperEvent::LockStatus {
            session_active: netlock::is_active(),
            persistent_active: netlock::is_persist_active(),
            persistent_installed: std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists(),
        });
    }

    // Stream events until client disconnects
    for event in &rx {
        if resp.send_chunk(&event).is_err() {
            break;
        }
    }

    resp.end_chunked().ok();
    Ok(())
}
```

**Step 7: Implement Disconnect handler**

```rust
fn handle_disconnect(state: &State, resp: &mut http::ResponseWriter) -> Result<()> {
    let mut s = state.lock().unwrap();

    if s.conn.is_connected() {
        recovery::trigger_shutdown();

        // Broadcast Disconnecting
        s.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnecting,
        });

        if let Some(h) = s.conn.connect_handle.take() {
            drop(s); // Release lock while joining
            let _ = h.join();
            s = state.lock().unwrap();
        }

        s.conn.stats_stop.store(true, Ordering::SeqCst);
        if let Some(h) = s.conn.stats_handle.take() {
            drop(s);
            let _ = h.join();
            s = state.lock().unwrap();
        }

        if let Ok(mut info) = s.conn.server_info.lock() {
            *info = Default::default();
        }

        s.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        });

        return resp.json(200, &ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        });
    }

    // Check for orphaned connection
    if matches!(recovery::load(), Ok(Some(ref rec)) if wireguard::is_connected(&rec.wg_interface)) {
        info!("Orphaned WireGuard interface found, recovering");
        s.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnecting,
        });
        drop(s);

        if let Err(e) = recovery::force_recover() {
            error!("Orphaned disconnect failed: {}", e);
            return resp.json(500, &ipc::HelperEvent::Error {
                message: format!("orphaned disconnect failed: {}", e),
            });
        }

        let mut s = state.lock().unwrap();
        s.conn.stats_stop.store(true, Ordering::SeqCst);
        if let Some(h) = s.conn.stats_handle.take() {
            drop(s);
            let _ = h.join();
        }

        return resp.json(200, &ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        });
    }

    resp.json(400, &ipc::HelperEvent::Error {
        message: "no active connection".into(),
    })
}
```

**Step 8: Keep existing helper functions**

Keep `get_systemd_listener`, `write_pid_file`, `log_peer_credentials`, `dispatch_lock_enable`, `dispatch_lock_install`, `dispatch_lock_uninstall`, `dispatch_get_profile`, `dispatch_save_profile`, `dispatch_list_servers` exactly as they are (lines 33-1107 of existing file, minus `run()`, `handle_client()`, `ConnState`, `build_lock_status`, `send_event`).

Remove:
- Old `run()` function
- Old `handle_client()` function
- Old `ConnState` struct (replaced by new version)
- `build_lock_status()` (replaced by `build_lock_status_info()`)
- `send_event()` (no longer needed — responses are per-handler)

**Step 9: Build check**

Run: `cargo build 2>&1 | head -30`
Expected: Compiles (possibly with warnings about unused old IPC types).

**Step 10: Commit**

```bash
git add src/helper.rs
git commit -m "feat: rewrite helper to HTTP/1.1 — multi-client, thread-per-connection"
```

---

### Task 5: Rewrite CLI Client (`src/cli_client.rs`)

Replace socket JSON-lines protocol with HTTP requests.

**Files:**
- Modify: `src/cli_client.rs`

**Step 1: Rewrite cli_client.rs**

```rust
//! Thin CLI client: HTTP requests to helper socket.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

use crate::helper::SOCKET_PATH;
use crate::ipc;

/// Send an HTTP request to the helper and return the response body.
fn http_request(method: &str, path: &str, body: Option<&[u8]>) -> Result<(u16, String)> {
    let mut stream = UnixStream::connect(SOCKET_PATH).with_context(|| {
        format!(
            "Could not connect to helper at {}.\n\
             Enable the socket unit:\n\n  \
             sudo systemctl enable --now airvpn-helper.socket",
            SOCKET_PATH
        )
    })?;

    // Write request
    if let Some(b) = body {
        write!(
            stream,
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            method, path, b.len()
        )?;
        stream.write_all(b)?;
    } else {
        write!(stream, "{} {} HTTP/1.1\r\nHost: localhost\r\n\r\n", method, path)?;
    }
    stream.flush()?;

    // Read response
    let mut reader = BufReader::new(stream);

    // Status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    // Headers
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() { break; }
        let lower = line.to_lowercase();
        if lower.starts_with("content-length:") {
            content_length = lower.split(':').nth(1).and_then(|v| v.trim().parse().ok());
        }
        if lower.contains("transfer-encoding: chunked") {
            chunked = true;
        }
    }

    // Body
    let body = if chunked {
        // Read chunked — for non-streaming use, just collect all chunks
        let mut body = String::new();
        loop {
            let mut size_line = String::new();
            reader.read_line(&mut size_line)?;
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 { break; }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            body.push_str(&String::from_utf8_lossy(&chunk));
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf); // trailing \r\n
        }
        body
    } else if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        String::from_utf8_lossy(&buf).to_string()
    } else {
        let mut buf = String::new();
        reader.read_to_string(&mut buf)?;
        buf
    };

    Ok((status, body))
}

/// Stream chunked events from a long-lived HTTP response. Calls callback for each JSON line.
fn stream_events(method: &str, path: &str, body: Option<&[u8]>, mut on_event: impl FnMut(&ipc::HelperEvent) -> bool) -> Result<()> {
    let mut stream = UnixStream::connect(SOCKET_PATH).with_context(|| {
        format!("Could not connect to helper at {}", SOCKET_PATH)
    })?;

    if let Some(b) = body {
        write!(
            stream,
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            method, path, b.len()
        )?;
        stream.write_all(b)?;
    } else {
        write!(stream, "{} {} HTTP/1.1\r\nHost: localhost\r\n\r\n", method, path)?;
    }
    stream.flush()?;

    let mut reader = BufReader::new(stream);

    // Read status + headers
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(500);

    // If not 200 chunked, read as normal response and parse as error
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        if line.trim().is_empty() { break; }
    }

    if status != 200 {
        // Read body as error
        let mut body = String::new();
        reader.read_to_string(&mut body)?;
        anyhow::bail!("{}", body);
    }

    // Read chunked events
    loop {
        let mut size_line = String::new();
        reader.read_line(&mut size_line)?;
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        if size == 0 { break; }
        let mut chunk = vec![0u8; size];
        reader.read_exact(&mut chunk)?;
        let mut crlf = [0u8; 2];
        let _ = reader.read_exact(&mut crlf);

        let text = String::from_utf8_lossy(&chunk);
        for line in text.lines() {
            if line.trim().is_empty() { continue; }
            if let Ok(event) = ipc::decode_line::<ipc::HelperEvent>(line) {
                if !on_event(&event) {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

/// Send a connect command and stream events.
pub fn send_connect(req: &ipc::ConnectRequest) -> Result<()> {
    let body = serde_json::to_vec(req).context("serialize connect request")?;
    let (status, resp_body) = http_request("POST", "/connect", Some(&body))?;

    // 409 with eddie_profile = need Eddie import
    if status == 409 {
        if let Ok(needed) = serde_json::from_str::<ipc::EddieImportNeeded>(&resp_body) {
            let accept = prompt_eddie_import(&needed.eddie_profile);
            let import_body = serde_json::to_vec(&ipc::ImportEddieRequest { accept })
                .context("serialize import request")?;
            let (import_status, import_resp) = http_request("POST", "/import-eddie", Some(&import_body))?;
            if import_status != 200 {
                anyhow::bail!("Eddie import failed: {}", import_resp);
            }
            // Retry connect
            return send_connect(req);
        }
        // 409 but not Eddie — already connected
        anyhow::bail!("{}", resp_body);
    }

    if status != 200 {
        anyhow::bail!("{}", resp_body);
    }

    // For streaming connect, re-do as stream_events
    // (The first http_request already consumed the response for non-chunked 409/400 cases.
    //  For the streaming 200 case, we need to re-connect.)
    stream_events("POST", "/connect", Some(&body), |event| {
        match render_event(event) {
            EventAction::Continue => true,
            EventAction::Done => false,
            EventAction::Error(msg) => {
                eprintln!("error: {}", msg);
                false
            }
        }
    })
}

pub fn send_status() -> Result<()> {
    let (status, body) = http_request("GET", "/status", None)?;
    if status != 200 {
        anyhow::bail!("{}", body);
    }
    let resp: ipc::StatusResponse = serde_json::from_str(&body)
        .context("parse status response")?;

    match &resp.state {
        ipc::ConnectionState::Connected { server_name, server_country, server_location } => {
            if server_location.is_empty() && server_country.is_empty() {
                println!("Connected via {}", server_name);
            } else {
                println!("Connected to {} ({}, {})", server_name, server_location, server_country);
            }
        }
        ipc::ConnectionState::Connecting => println!("Connecting..."),
        ipc::ConnectionState::Reconnecting => println!("Reconnecting..."),
        ipc::ConnectionState::Disconnecting => println!("Disconnecting..."),
        ipc::ConnectionState::Disconnected => println!("Not connected."),
    }

    println!("Lock status:");
    println!("  Session lock:    {}", if resp.lock.session_active { "active" } else { "inactive" });
    println!("  Persistent lock: {}", if resp.lock.persistent_active { "active" } else { "inactive" });
    println!("  Installed:       {}", if resp.lock.persistent_installed { "yes" } else { "no" });
    Ok(())
}

/// Send a simple command and print the result.
pub fn send_command(method: &str, path: &str, body: Option<&[u8]>) -> Result<()> {
    let (status, resp_body) = http_request(method, path, body)?;

    // Try to parse as HelperEvent for nice rendering
    if let Ok(event) = serde_json::from_str::<ipc::HelperEvent>(&resp_body) {
        match render_event(&event) {
            EventAction::Error(msg) => anyhow::bail!("{}", msg),
            _ => {}
        }
        return Ok(());
    }

    // Fallback: print raw JSON
    if status >= 400 {
        anyhow::bail!("{}", resp_body);
    }
    if !resp_body.is_empty() {
        println!("{}", resp_body);
    }
    Ok(())
}

fn prompt_eddie_import(path: &str) -> bool {
    use std::io::Write;
    eprint!("Eddie profile detected at {}. Import settings? [Y/n] ", path);
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    match std::io::stdin().read_line(&mut answer) {
        Ok(_) => {
            let trimmed = answer.trim().to_lowercase();
            trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
        }
        Err(_) => false,
    }
}

enum EventAction {
    Continue,
    Done,
    Error(String),
}

fn render_event(event: &ipc::HelperEvent) -> EventAction {
    match event {
        ipc::HelperEvent::StateChanged { state } => match state {
            ipc::ConnectionState::Connecting => { eprintln!(":: Connecting..."); EventAction::Continue }
            ipc::ConnectionState::Connected { server_name, server_location, server_country } => {
                eprintln!(":: Connected to {} ({}, {})", server_name, server_location, server_country);
                EventAction::Continue
            }
            ipc::ConnectionState::Reconnecting => { eprintln!(":: Reconnecting..."); EventAction::Continue }
            ipc::ConnectionState::Disconnecting => { eprintln!(":: Disconnecting..."); EventAction::Continue }
            ipc::ConnectionState::Disconnected => { eprintln!(":: Disconnected."); EventAction::Done }
        },
        ipc::HelperEvent::Log { level, message } => {
            match level.as_str() {
                "error" => eprintln!("error: {}", message),
                "warn" => eprintln!("warning: {}", message),
                _ => eprintln!("{}", message),
            }
            EventAction::Continue
        }
        ipc::HelperEvent::Stats { .. } => EventAction::Continue,
        ipc::HelperEvent::LockStatus { session_active, persistent_active, persistent_installed } => {
            println!("Lock status:");
            println!("  Session lock:    {}", if *session_active { "active" } else { "inactive" });
            println!("  Persistent lock: {}", if *persistent_active { "active" } else { "inactive" });
            println!("  Installed:       {}", if *persistent_installed { "yes" } else { "no" });
            EventAction::Done
        }
        ipc::HelperEvent::ServerList { servers } => {
            println!("{:<20} {:<6} {:<12} {:>6} {:>6} {:>8}", "NAME", "CC", "LOCATION", "USERS", "LOAD%", "SCORE");
            println!("{}", "-".repeat(64));
            for s in servers {
                println!("{:<20} {:<6} {:<12} {:>6} {:>5.0}% {:>8}", s.name, s.country_code, s.location, s.users, s.load_percent, s.score);
            }
            println!("\n{} servers total.", servers.len());
            EventAction::Done
        }
        ipc::HelperEvent::Error { message } => EventAction::Error(message.clone()),
        ipc::HelperEvent::Shutdown => EventAction::Done,
        _ => EventAction::Continue,
    }
}
```

**Step 2: Update main.rs to use new CLI client API**

The `main.rs` command dispatch needs updating. Check how each subcommand currently calls `cli_client::send_command` and update to use the new HTTP-based functions. For example, `Commands::Status` calls `cli_client::send_status()` (unchanged signature). `Commands::Connect` will need to build a `ConnectRequest` and call `cli_client::send_connect()`. `Commands::Disconnect` calls `cli_client::send_command("POST", "/disconnect", None)`.

Read `src/main.rs` fully and update the match arms to use the new API. The `HelperCommand` enum is no longer needed in main.rs — replace with direct HTTP method/path calls.

**Step 3: Build check**

Run: `cargo build 2>&1 | head -30`
Expected: Compiles.

**Step 4: Commit**

```bash
git add src/cli_client.rs src/main.rs
git commit -m "feat: rewrite CLI client for HTTP IPC"
```

---

### Task 6: Rewrite GUI IPC Client (`src/gui/ipc.rs`)

Replace persistent JSON-lines connection with HTTP client + event stream reader.

**Files:**
- Modify: `src/gui/ipc.rs`
- Modify: `src/gui/main.rs` (update HelperClient usage)

**Step 1: Rewrite gui/ipc.rs**

The GUI needs two capabilities:
1. **Send commands** (Connect, Disconnect, etc.) — short-lived HTTP requests
2. **Receive events** (state changes, stats, logs) — long-lived `GET /events` stream

```rust
//! IPC client for communicating with the airvpn helper daemon.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;

use airvpn::ipc::{self, HelperCommand, HelperEvent};

const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";

pub struct HelperClient {
    event_rx: mpsc::Receiver<HelperEvent>,
    _reader_thread: thread::JoinHandle<()>,
}

impl HelperClient {
    /// Connect to helper and start receiving events via GET /events.
    pub fn connect() -> std::io::Result<Self> {
        let stream = Self::connect_with_timeout(SOCKET_PATH, std::time::Duration::from_secs(2))?;
        let (tx, rx) = mpsc::channel();

        let reader_thread = thread::spawn(move || {
            if let Err(e) = Self::event_stream_loop(stream, tx) {
                eprintln!("[GUI] Event stream error: {}", e);
            }
        });

        Ok(Self {
            event_rx: rx,
            _reader_thread: reader_thread,
        })
    }

    /// Open GET /events and read chunked events into the channel.
    fn event_stream_loop(mut stream: UnixStream, tx: mpsc::Sender<HelperEvent>) -> std::io::Result<()> {
        // Send GET /events
        write!(stream, "GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);

        // Skip status line + headers
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() { break; }
        }

        // Read chunked events
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line)? == 0 { break; }
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 { break; }

            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf);

            let text = String::from_utf8_lossy(&chunk);
            for line in text.lines() {
                if line.trim().is_empty() { continue; }
                if let Ok(event) = ipc::decode_line::<HelperEvent>(line) {
                    if tx.send(event).is_err() {
                        return Ok(()); // Receiver dropped
                    }
                }
            }
        }
        Ok(())
    }

    /// Send a command via a separate HTTP request.
    pub fn send_command(&self, method: &str, path: &str, body: Option<&[u8]>) -> std::io::Result<String> {
        let mut stream = Self::connect_with_timeout(SOCKET_PATH, std::time::Duration::from_secs(2))?;

        if let Some(b) = body {
            write!(stream, "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n", method, path, b.len())?;
            stream.write_all(b)?;
        } else {
            write!(stream, "{} {} HTTP/1.1\r\nHost: localhost\r\n\r\n", method, path)?;
        }
        stream.flush()?;

        // Read response
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;

        // Skip headers
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() { break; }
            if line.to_lowercase().starts_with("content-length:") {
                content_length = line.split(':').nth(1).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
            }
        }

        let mut body = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut body)?;
        }
        Ok(String::from_utf8_lossy(&body).to_string())
    }

    pub fn try_recv(&self) -> Option<HelperEvent> {
        self.event_rx.try_recv().ok()
    }

    fn connect_with_timeout(path: &str, timeout: std::time::Duration) -> std::io::Result<UnixStream> {
        let path = path.to_string();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = UnixStream::connect(&path);
            let _ = tx.send(result);
        });
        match rx.recv_timeout(timeout) {
            Ok(result) => result,
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "socket connect timed out (stale socket?)",
            )),
        }
    }
}
```

**Step 2: Update gui/main.rs**

Replace `helper.send(&HelperCommand::...)` calls with `helper.send_command("POST", "/path", body)` calls. Key changes:

- `Message::Connect`: Build `ConnectRequest`, serialize, send `POST /connect` (note: for GUI, connect events come via the `/events` stream, so the POST just needs to succeed)
- `Message::Disconnect`: `helper.send_command("POST", "/disconnect", None)`
- `Message::FetchServers`: `helper.send_command("GET", "/servers?skip_ping=true", None)`, then parse response as `ServerList`
- `Message::HelperConnected`: `HelperClient::connect()` (unchanged — now implicitly opens `/events`)
- Lock operations: `helper.send_command("POST", "/lock/enable", None)` etc.
- Profile operations: `helper.send_command("GET", "/profile", None)` and `POST /profile`

The GUI currently sends commands via the same persistent connection and gets events back on it. With HTTP, commands go via separate short-lived requests, and events come via the persistent `GET /events` stream. This means the GUI's `handle_helper_event` function stays the same — it still processes events from `helper.try_recv()`.

**Step 3: Build both binaries**

Run: `cargo build 2>&1 | head -30`
Expected: Both `airvpn` and `airvpn-gui` compile.

**Step 4: Commit**

```bash
git add src/gui/ipc.rs src/gui/main.rs
git commit -m "feat: rewrite GUI IPC client for HTTP"
```

---

### Task 7: Clean Up Dead Code

Remove `HelperCommand` enum variants and `encode_line`/`decode_line` functions that are no longer needed. The `HelperCommand` enum is no longer sent over the wire — HTTP routes replace it. Keep `HelperEvent` (still used for event serialization), `ConnectionState`, `ServerInfo`, and the new HTTP types.

**Files:**
- Modify: `src/ipc.rs`

**Step 1: Audit ipc.rs usage**

Run `cargo build` and check for dead code warnings. Remove:
- `HelperCommand` enum (no longer serialized — HTTP routes replaced it)
- `encode_line` / `decode_line` (if no longer used)

BUT: check if `decode_line` is still used by the GUI event stream reader. If so, keep it.

**Step 2: Build check**

Run: `cargo build 2>&1`
Expected: Clean compile, no dead code warnings.

**Step 3: Commit**

```bash
git add src/ipc.rs
git commit -m "refactor: remove dead IPC types replaced by HTTP routes"
```

---

### Task 8: Build and Manual Test

**Step 1: Full clean build**

Run: `cargo build && cargo build --release`
Expected: Both debug and release compile cleanly.

**Step 2: Run unit tests**

Run: `cargo test`
Expected: All tests pass (http parser tests + existing ipc roundtrip tests).

**Step 3: Manual integration test (requires root + systemd)**

Test with `systemd-socket-activate`:

```bash
# Terminal 1: Start helper
sudo systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper

# Terminal 2: CLI status
./target/debug/airvpn status

# Terminal 3: GUI (if available)
./target/debug/airvpn-gui

# Terminal 2 again: CLI status while GUI is running
./target/debug/airvpn status
# Should work! This is the whole point of the migration.
```

**Step 4: Test with curl (new capability!)**

```bash
# Status
curl --unix-socket /run/airvpn-rs/helper.sock http://localhost/status

# Lock status
curl --unix-socket /run/airvpn-rs/helper.sock http://localhost/lock/status

# Server list
curl --unix-socket /run/airvpn-rs/helper.sock 'http://localhost/servers?skip_ping=true&sort=name'
```

**Step 5: Commit any fixes and tag**

```bash
git add -A
git commit -m "fix: post-integration-test fixes for HTTP IPC"
```

---

### Task 9: Update Documentation

**Files:**
- Modify: `CLAUDE.md` (update learnings)
- Modify: `docs/security_model.md` (note HTTP transport)
- Modify: `docs/known_divergences.md` (if applicable)

Update CLAUDE.md learnings with:
- Helper uses HTTP/1.1 over Unix socket (not JSON-lines)
- Multiple clients can connect concurrently (CLI + GUI)
- `curl --unix-socket` works for debugging
- Events streamed via GET /events (chunked transfer encoding)

**Step 1: Update docs**

**Step 2: Commit**

```bash
git add CLAUDE.md docs/
git commit -m "docs: update for HTTP IPC migration"
```

---

Plan complete and saved to `docs/plans/2026-03-05-http-ipc-impl.md`. Two execution options:

**1. Subagent-Driven (this session)** — I dispatch a fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** — Open new session with executing-plans, batch execution with checkpoints

Which approach?