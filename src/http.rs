/// Minimal HTTP/1.1 request parser and response writer for IPC over Unix sockets.
///
/// No external HTTP dependencies — just enough to frame JSON-RPC style
/// request/response and chunked streaming over `UnixStream`.
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::{bail, Context, Result};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// Parsed HTTP/1.1 request from a Unix socket client.
pub struct Request {
    pub method: String,
    pub path: String,
    pub query: HashMap<String, String>,
    pub body: Vec<u8>,
    /// Set by the caller after `accept()` via SO_PEERCRED — not by the parser.
    pub peer_uid: Option<u32>,
}

/// Parse an HTTP/1.1 request from `stream`.
///
/// Reads the request line, headers, and optional body (sized by
/// `Content-Length`). The `peer_uid` field is left as `None` — the caller
/// fills it in from `SO_PEERCRED` after accept.
pub fn parse_request(stream: &UnixStream) -> Result<Request> {
    let mut reader = BufReader::new(stream);

    // -- request line -------------------------------------------------------
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .context("reading request line")?;
    let request_line = request_line.trim_end_matches(|c| c == '\r' || c == '\n');

    let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
    if parts.len() != 3 {
        bail!("malformed request line: {request_line}");
    }
    let method = parts[0].to_string();
    let raw_path = parts[1];
    // parts[2] is "HTTP/1.1" — we don't need to store it.

    let (path, query) = if let Some(idx) = raw_path.find('?') {
        let p = &raw_path[..idx];
        let qs = &raw_path[idx + 1..];
        (p.to_string(), parse_query_string(qs))
    } else {
        (raw_path.to_string(), HashMap::new())
    };

    // -- headers ------------------------------------------------------------
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).context("reading header")?;
        let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n');
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value
                    .trim()
                    .parse::<usize>()
                    .context("invalid Content-Length")?;
            }
        }
    }

    // -- body ---------------------------------------------------------------
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader
            .read_exact(&mut body)
            .context("reading request body")?;
    }

    Ok(Request {
        method,
        path,
        query,
        body,
        peer_uid: None,
    })
}

// ---------------------------------------------------------------------------
// Query string
// ---------------------------------------------------------------------------

/// Parse a `key=value&key2=value2` query string into a map.
///
/// Percent-decoding is intentionally omitted — our keys/values are simple
/// ASCII identifiers.
pub fn parse_query_string(qs: &str) -> HashMap<String, String> {
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
// Response writer
// ---------------------------------------------------------------------------

/// Wraps a `UnixStream` and provides helpers for writing HTTP/1.1 responses.
pub struct ResponseWriter {
    stream: UnixStream,
}

impl ResponseWriter {
    pub fn new(stream: UnixStream) -> Self {
        Self { stream }
    }

    /// Write a complete JSON response with `Content-Length`.
    pub fn json(&mut self, status: u16, body: &impl Serialize) -> Result<()> {
        let payload = serde_json::to_vec(body).context("serializing JSON body")?;
        let header = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            status,
            status_reason(status),
            payload.len(),
        );
        self.stream.write_all(header.as_bytes())?;
        self.stream.write_all(&payload)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Begin a chunked streaming response (Transfer-Encoding: chunked).
    ///
    /// Follow with [`send_chunk`] calls and finish with [`end_chunked`].
    pub fn begin_chunked(&mut self, status: u16) -> Result<()> {
        let header = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: application/x-ndjson\r\n\
             Transfer-Encoding: chunked\r\n\
             Connection: keep-alive\r\n\
             \r\n",
            status,
            status_reason(status),
        );
        self.stream.write_all(header.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send one JSON line as an HTTP chunk.
    pub fn send_chunk(&mut self, event: &impl Serialize) -> Result<()> {
        let mut payload = serde_json::to_vec(event).context("serializing chunk")?;
        payload.push(b'\n');
        let chunk = format!("{:x}\r\n", payload.len());
        self.stream.write_all(chunk.as_bytes())?;
        self.stream.write_all(&payload)?;
        self.stream.write_all(b"\r\n")?;
        self.stream.flush()?;
        Ok(())
    }

    /// Write the terminal zero-length chunk.
    pub fn end_chunked(&mut self) -> Result<()> {
        self.stream.write_all(b"0\r\n\r\n")?;
        self.stream.flush()?;
        Ok(())
    }

    /// Write a plain-text error response.
    pub fn error(&mut self, status: u16, message: &str) -> Result<()> {
        let header = format!(
            "HTTP/1.1 {} {}\r\n\
             Content-Type: text/plain\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n",
            status,
            status_reason(status),
            message.len(),
        );
        self.stream.write_all(header.as_bytes())?;
        self.stream.write_all(message.as_bytes())?;
        self.stream.flush()?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map common HTTP status codes to their reason phrases.
pub fn status_reason(status: u16) -> &'static str {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn test_parse_get_request() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .write_all(b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        // Shut down writes so the reader sees EOF after headers.
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let req = parse_request(&server).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/status");
        assert!(req.query.is_empty());
        assert!(req.body.is_empty());
        assert!(req.peer_uid.is_none());
    }

    #[test]
    fn test_parse_post_with_body() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let body = r#"{"username":"test","password":"secret"}"#;
        let raw = format!(
            "POST /import-eddie HTTP/1.1\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             \r\n\
             {}",
            body.len(),
            body,
        );
        client.write_all(raw.as_bytes()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let req = parse_request(&server).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/import-eddie");
        assert_eq!(req.body, body.as_bytes());
    }

    #[test]
    fn test_parse_query_string() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client
            .write_all(b"GET /servers?skip_ping=true&sort=name HTTP/1.1\r\n\r\n")
            .unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();

        let req = parse_request(&server).unwrap();
        assert_eq!(req.path, "/servers");
        assert_eq!(req.query.get("skip_ping").unwrap(), "true");
        assert_eq!(req.query.get("sort").unwrap(), "name");
    }

    #[test]
    fn test_json_response() {
        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let mut writer = ResponseWriter::new(server_stream);

        #[derive(Serialize)]
        struct Status {
            connected: bool,
        }
        writer
            .json(200, &Status { connected: true })
            .unwrap();

        // Read raw bytes from client side.
        drop(writer);
        let mut buf = Vec::new();
        let mut reader = client_stream;
        reader.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Connection: close\r\n"));
        assert!(text.contains(r#"{"connected":true}"#));
    }

    #[test]
    fn test_chunked_response() {
        let (server_stream, client_stream) = UnixStream::pair().unwrap();
        let mut writer = ResponseWriter::new(server_stream);

        #[derive(Serialize)]
        struct Event {
            kind: String,
        }

        writer.begin_chunked(200).unwrap();
        writer
            .send_chunk(&Event {
                kind: "progress".to_string(),
            })
            .unwrap();
        writer.end_chunked().unwrap();

        drop(writer);
        let mut buf = Vec::new();
        let mut reader = client_stream;
        reader.read_to_end(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Transfer-Encoding: chunked\r\n"));
        assert!(text.contains("Content-Type: application/x-ndjson\r\n"));
        assert!(text.contains("Connection: keep-alive\r\n"));
        // The chunk should contain our JSON event.
        assert!(text.contains(r#"{"kind":"progress"}"#));
        // Must end with the terminal chunk.
        assert!(text.ends_with("0\r\n\r\n"));
    }
}
