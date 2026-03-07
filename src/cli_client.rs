//! Thin CLI client: HTTP requests over Unix socket to the helper daemon.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

use crate::helper::SOCKET_PATH;
use crate::ipc::{self, ConnectionState, HelperEvent, ServerInfo};

// ---------------------------------------------------------------------------
// Low-level HTTP over Unix socket
// ---------------------------------------------------------------------------

/// Connect to the helper socket. If the socket doesn't exist, the error
/// message guides the user to enable the systemd socket unit.
fn connect_to_helper() -> Result<UnixStream> {
    UnixStream::connect(SOCKET_PATH).with_context(|| {
        format!(
            "Could not connect to helper at {}.\n\
             Enable the socket unit:\n\n  \
             sudo systemctl enable --now airvpn-helper.socket",
            SOCKET_PATH
        )
    })
}

/// Parsed HTTP response headers.
struct ResponseHeaders {
    status: u16,
    content_length: Option<usize>,
    chunked: bool,
}

/// Read HTTP response headers from a buffered reader.
/// Returns (status_code, content_length, is_chunked).
fn read_response_headers(reader: &mut BufReader<UnixStream>) -> Result<ResponseHeaders> {
    // Status line: "HTTP/1.1 200 OK\r\n"
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .context("reading HTTP status line")?;
    let status_line = status_line.trim();

    let status: u16 = status_line
        .splitn(3, ' ')
        .nth(1)
        .context("malformed status line")?
        .parse()
        .context("invalid status code")?;

    let mut content_length = None;
    let mut chunked = false;

    // Read headers until empty line
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).context("reading header")?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim();
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = Some(value.parse::<usize>().context("invalid Content-Length")?);
            } else if name.eq_ignore_ascii_case("transfer-encoding")
                && value.eq_ignore_ascii_case("chunked")
            {
                chunked = true;
            }
        }
    }

    Ok(ResponseHeaders {
        status,
        content_length,
        chunked,
    })
}

/// Send an HTTP request and read the full response body.
/// Returns (status_code, body_text). Does NOT handle chunked responses.
fn http_request(method: &str, path: &str, body: Option<&str>) -> Result<(u16, String)> {
    let stream = connect_to_helper()?;
    let mut writer = stream.try_clone().context("clone socket")?;

    // Write request
    let body_bytes = body.unwrap_or("");
    if body_bytes.is_empty() {
        write!(
            writer,
            "{} {} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            method, path
        )
        .context("write request")?;
    } else {
        write!(
            writer,
            "{} {} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            method,
            path,
            body_bytes.len(),
            body_bytes
        )
        .context("write request")?;
    }
    writer.flush().context("flush request")?;

    // Read response
    let mut reader = BufReader::new(stream);
    let headers = read_response_headers(&mut reader)?;

    let body_text = if let Some(len) = headers.content_length {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf).context("reading response body")?;
        String::from_utf8(buf).context("response body is not UTF-8")?
    } else {
        // Read until EOF
        let mut buf = String::new();
        reader.read_to_string(&mut buf).context("reading response")?;
        buf
    };

    Ok((headers.status, body_text))
}

/// Read one HTTP chunk from a chunked stream.
/// Returns the chunk data, or None for the terminal zero-length chunk.
fn read_chunk(reader: &mut BufReader<UnixStream>) -> Result<Option<Vec<u8>>> {
    let mut size_line = String::new();
    reader
        .read_line(&mut size_line)
        .context("reading chunk size")?;
    let size = usize::from_str_radix(size_line.trim(), 16)
        .with_context(|| format!("invalid chunk size: {:?}", size_line.trim()))?;

    if size == 0 {
        // Terminal chunk — consume trailing \r\n
        let mut trailing = String::new();
        let _ = reader.read_line(&mut trailing);
        return Ok(None);
    }

    let mut data = vec![0u8; size];
    reader.read_exact(&mut data).context("reading chunk data")?;

    // Consume trailing \r\n after chunk data
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf).context("reading chunk CRLF")?;

    Ok(Some(data))
}

/// Connect to the helper, send an HTTP request, and stream chunked events
/// back via a callback. Used for POST /connect.
///
/// Returns the HTTP status and, for non-chunked responses, the body text.
/// For chunked responses, invokes `on_event` for each parsed HelperEvent
/// and returns (200, "").
fn http_stream(
    method: &str,
    path: &str,
    body: Option<&str>,
    on_event: impl Fn(&HelperEvent) -> EventAction,
) -> Result<(u16, String)> {
    let stream = connect_to_helper()?;
    let mut writer = stream.try_clone().context("clone socket")?;

    // Write request
    let body_bytes = body.unwrap_or("");
    if body_bytes.is_empty() {
        write!(
            writer,
            "{} {} HTTP/1.1\r\nHost: localhost\r\n\r\n",
            method, path
        )
        .context("write request")?;
    } else {
        write!(
            writer,
            "{} {} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            method,
            path,
            body_bytes.len(),
            body_bytes
        )
        .context("write request")?;
    }
    writer.flush().context("flush request")?;

    let mut reader = BufReader::new(stream);
    let headers = read_response_headers(&mut reader)?;

    if !headers.chunked {
        // Not chunked — read full body and return it for the caller to handle
        let body_text = if let Some(len) = headers.content_length {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).context("reading response body")?;
            String::from_utf8(buf).context("response body is not UTF-8")?
        } else {
            let mut buf = String::new();
            reader.read_to_string(&mut buf).context("reading response")?;
            buf
        };
        return Ok((headers.status, body_text));
    }

    // Chunked response — read events until terminal chunk or Disconnected
    loop {
        match read_chunk(&mut reader)? {
            None => break, // Terminal chunk
            Some(data) => {
                let text = String::from_utf8_lossy(&data);
                for line in text.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // Skip keepalive chunks
                    if line.contains("\"keepalive\"") {
                        continue;
                    }
                    let event: HelperEvent = serde_json::from_str(line)
                        .with_context(|| format!("decode event: {}", line))?;
                    match on_event(&event) {
                        EventAction::Continue => {}
                        EventAction::Done => return Ok((headers.status, String::new())),
                        EventAction::Error(msg) => anyhow::bail!("{}", msg),
                    }
                }
            }
        }
    }

    Ok((headers.status, String::new()))
}

// ---------------------------------------------------------------------------
// Public API — called from main.rs
// ---------------------------------------------------------------------------

/// POST /connect — start VPN connection and stream events.
///
/// Handles:
/// - 409 + EddieImportNeeded → prompt user, POST /import-eddie, retry
/// - 409 + already connected → error
/// - 200 chunked → stream events until Disconnected
pub fn send_connect(req: &ipc::ConnectRequest) -> Result<()> {
    let body = serde_json::to_string(req).context("serialize ConnectRequest")?;

    let (status, resp_body) = http_stream("POST", "/connect", Some(&body), render_event)?;

    match status {
        200 => Ok(()),
        409 => {
            // Try to parse as EddieImportNeeded
            if let Ok(eddie) = serde_json::from_str::<ipc::EddieImportNeeded>(&resp_body) {
                let accept = prompt_eddie_import(&eddie.eddie_profile);
                let import_body = serde_json::to_string(&ipc::ImportEddieRequest { accept })
                    .context("serialize ImportEddieRequest")?;
                let (import_status, import_resp) =
                    http_request("POST", "/import-eddie", Some(&import_body))?;
                if import_status != 200 {
                    anyhow::bail!("Eddie import failed: {}", import_resp);
                }
                if !accept {
                    anyhow::bail!("Eddie import declined — no credentials available");
                }

                // Retry connect after successful import
                let (status2, resp_body2) =
                    http_stream("POST", "/connect", Some(&body), render_event)?;
                match status2 {
                    200 => Ok(()),
                    _ => anyhow::bail!("connect failed after Eddie import: {}", resp_body2),
                }
            } else {
                // Already connected or other 409
                anyhow::bail!("{}", resp_body)
            }
        }
        400 => anyhow::bail!("{}", resp_body),
        _ => anyhow::bail!("connect failed (HTTP {}): {}", status, resp_body),
    }
}

/// GET /status — print connection state and lock status.
pub fn send_status() -> Result<()> {
    let (status, body) = http_request("GET", "/status", None)?;
    if status != 200 {
        anyhow::bail!("status failed (HTTP {}): {}", status, body);
    }

    let resp: ipc::StatusResponse =
        serde_json::from_str(&body).context("parse StatusResponse")?;

    // Print connection state
    match &resp.state {
        ConnectionState::Connected {
            server_name,
            server_country,
            server_location,
        } => {
            if server_location.is_empty() && server_country.is_empty() {
                println!("Connected via {}", server_name);
            } else {
                println!(
                    "Connected to {} ({}, {})",
                    server_name, server_location, server_country
                );
            }
        }
        ConnectionState::Connecting => println!("Connecting..."),
        ConnectionState::Reconnecting => println!("Reconnecting..."),
        ConnectionState::Disconnecting => println!("Disconnecting..."),
        ConnectionState::Disconnected => println!("Not connected."),
    }

    // Print lock status
    println!("Lock status:");
    println!(
        "  Session lock:    {}",
        if resp.lock.session_active {
            "active"
        } else {
            "inactive"
        }
    );
    println!(
        "  Persistent lock: {}",
        if resp.lock.persistent_active {
            "active"
        } else {
            "inactive"
        }
    );
    println!(
        "  Installed:       {}",
        if resp.lock.persistent_installed {
            "yes"
        } else {
            "no"
        }
    );

    Ok(())
}

/// Send a simple request and render the response.
/// Used for disconnect, lock ops, recover, shutdown.
pub fn send_simple(method: &str, path: &str, body: Option<&str>) -> Result<()> {
    let (status, resp_body) = http_request(method, path, body)?;

    if status == 200 {
        // Try to render as a HelperEvent for backward compatibility
        // Most simple responses are JSON objects with message/status fields
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&resp_body) {
            // Lock status response
            if val.get("session_active").is_some() {
                render_lock_status(&val);
                return Ok(());
            }
            // Lock install/uninstall with message + lock
            if let Some(msg) = val.get("message").and_then(|m| m.as_str()) {
                println!("{}", msg);
                if let Some(lock) = val.get("lock") {
                    render_lock_status(lock);
                }
                return Ok(());
            }
            // Disconnect/recover/shutdown — just print the key
            if val.get("disconnected").is_some() {
                eprintln!(":: Disconnected.");
                return Ok(());
            }
            if val.get("recovered").is_some() {
                eprintln!(":: Recovery complete.");
                return Ok(());
            }
            if val.get("shutdown").is_some() {
                eprintln!(":: Helper shutdown.");
                return Ok(());
            }
        }
        // Fallback: print raw response if non-empty
        if !resp_body.is_empty() {
            println!("{}", resp_body);
        }
        Ok(())
    } else {
        anyhow::bail!("{}", resp_body)
    }
}

/// GET /servers — fetch and display server list.
pub fn send_list_servers(sort: &str) -> Result<()> {
    let path = format!("/servers?sort={}", sort);
    let (status, body) = http_request("GET", &path, None)?;

    if status != 200 {
        anyhow::bail!("{}", body);
    }

    // Response is {"servers": [...]}
    let val: serde_json::Value = serde_json::from_str(&body).context("parse server list")?;
    let servers: Vec<ServerInfo> = serde_json::from_value(
        val.get("servers")
            .context("missing 'servers' field")?
            .clone(),
    )
    .context("parse server info")?;

    println!(
        "{:<20} {:<6} {:<12} {:>6} {:>6} {:>8}",
        "NAME", "CC", "LOCATION", "USERS", "LOAD%", "SCORE"
    );
    println!("{}", "-".repeat(64));
    for s in &servers {
        println!(
            "{:<20} {:<6} {:<12} {:>6} {:>5.0}% {:>8}",
            s.name, s.country_code, s.location, s.users, s.load_percent, s.score
        );
    }
    println!("\n{} servers total.", servers.len());

    Ok(())
}

// ---------------------------------------------------------------------------
// Event rendering (shared with streaming connect)
// ---------------------------------------------------------------------------

enum EventAction {
    Continue,
    Done,
    Error(String),
}

/// Render a HelperEvent to stderr/stdout. Returns whether to continue reading.
fn render_event(event: &HelperEvent) -> EventAction {
    match event {
        HelperEvent::StateChanged { state } => match state {
            ConnectionState::Connecting => {
                eprintln!(":: Connecting...");
                EventAction::Continue
            }
            ConnectionState::Connected {
                server_name,
                server_country,
                server_location,
            } => {
                eprintln!(
                    ":: Connected to {} ({}, {})",
                    server_name, server_location, server_country
                );
                EventAction::Continue // keep reading for stats/reconnection
            }
            ConnectionState::Reconnecting => {
                eprintln!(":: Reconnecting...");
                EventAction::Continue
            }
            ConnectionState::Disconnecting => {
                eprintln!(":: Disconnecting...");
                EventAction::Continue
            }
            ConnectionState::Disconnected => {
                eprintln!(":: Disconnected.");
                EventAction::Done
            }
        },
        HelperEvent::Log { level, message } => {
            match level.as_str() {
                "error" => eprintln!("error: {}", message),
                "warn" => eprintln!("warning: {}", message),
                _ => eprintln!("{}", message),
            }
            EventAction::Continue
        }
        HelperEvent::Stats { rx_bytes, tx_bytes } => {
            // Stats are continuous — don't print unless user asked (future --stats flag)
            let _ = (rx_bytes, tx_bytes);
            EventAction::Continue
        }
        HelperEvent::Error { message } => EventAction::Error(message.clone()),
        HelperEvent::Shutdown => EventAction::Done,
        // Events that shouldn't appear in streaming connect but handle gracefully
        HelperEvent::LockStatus { .. }
        | HelperEvent::ServerList { .. }
        | HelperEvent::EddieProfileFound { .. }
        | HelperEvent::Profile { .. }
        | HelperEvent::ProfileSaved => EventAction::Continue,
    }
}

/// Render lock status from a JSON value.
fn render_lock_status(val: &serde_json::Value) {
    let session = val
        .get("session_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let persistent = val
        .get("persistent_active")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let installed = val
        .get("persistent_installed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    println!("Lock status:");
    println!(
        "  Session lock:    {}",
        if session { "active" } else { "inactive" }
    );
    println!(
        "  Persistent lock: {}",
        if persistent { "active" } else { "inactive" }
    );
    println!(
        "  Installed:       {}",
        if installed { "yes" } else { "no" }
    );
}

// ---------------------------------------------------------------------------
// Interactive prompts
// ---------------------------------------------------------------------------

/// Prompt the user whether to import an Eddie profile.
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
