//! HTTP IPC client for communicating with the airvpn helper daemon.
//!
//! Uses hyper v1 client over Unix socket. Two mechanisms:
//! 1. GET /events — long-lived streaming response for receiving events
//! 2. Separate HTTP requests for sending commands (each opens a new connection)

use std::io;
use std::sync::mpsc;
use std::time::Duration;

use airvpn::ipc::{self, HelperEvent};
use bytes::{Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http1;
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;

const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

pub struct HelperClient {
    event_rx: mpsc::Receiver<HelperEvent>,
    rt: tokio::runtime::Runtime,
}

impl HelperClient {
    /// Connect to helper — opens GET /events for event streaming.
    /// The event stream automatically delivers initial StatusResponse + LockStatus.
    pub fn connect() -> io::Result<Self> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()?;

        let (tx, rx) = mpsc::channel();

        rt.spawn(async move {
            eprintln!("[GUI-IPC] Event stream starting (hyper client)");
            if let Err(e) = event_stream(tx).await {
                eprintln!("[GUI-IPC] Event stream error: {}", e);
            }
            eprintln!("[GUI-IPC] Event stream ended");
        });

        Ok(Self { event_rx: rx, rt })
    }

    /// Send a command via a separate short-lived HTTP request. Returns (status, body).
    pub fn send_command(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> io::Result<(u16, String)> {
        let method = method.to_string();
        let path = path.to_string();
        let body_owned = body.map(|b| Bytes::copy_from_slice(b));

        let (resp_tx, resp_rx) = mpsc::channel();
        self.rt.spawn(async move {
            let result = send_request(method, path, body_owned).await;
            let _ = resp_tx.send(result);
        });

        resp_rx
            .recv()
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "IPC task died"))?
    }

    pub fn try_recv(&self) -> Option<HelperEvent> {
        self.event_rx.try_recv().ok()
    }
}

/// Open a hyper HTTP/1.1 connection over Unix socket.
async fn open_connection() -> io::Result<http1::SendRequest<Full<Bytes>>> {
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, UnixStream::connect(SOCKET_PATH))
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "socket connect timed out (stale socket?)",
            )
        })??;

    let io = TokioIo::new(stream);
    let (sender, conn) = http1::handshake(io)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    // Drive the HTTP connection in the background
    tokio::spawn(async move {
        let _ = conn.await;
    });

    Ok(sender)
}

/// Send a single HTTP request and return (status, body).
async fn send_request(
    method: String,
    path: String,
    body: Option<Bytes>,
) -> io::Result<(u16, String)> {
    let mut sender = open_connection().await?;

    let has_body = body.is_some();
    let req_body = Full::new(body.unwrap_or_default());

    let mut builder = Request::builder()
        .method(method.as_str())
        .uri(&path)
        .header("host", "localhost");
    if has_body {
        builder = builder.header("content-type", "application/json");
    }

    let req = builder
        .body(req_body)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let resp = tokio::time::timeout(COMMAND_TIMEOUT, sender.send_request(req))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request timed out"))?
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let status = resp.status().as_u16();

    // Only collect body for non-streaming responses (those with Content-Length).
    // Streaming responses (e.g. POST /connect) have no Content-Length — drop the
    // body so the connection closes cleanly.
    if resp.headers().contains_key("content-length") {
        let collected = resp
            .collect()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok((status, String::from_utf8_lossy(&collected.to_bytes()).to_string()))
    } else {
        Ok((status, String::new()))
    }
}

/// Long-lived event stream: GET /events, parse NDJSON body frames.
async fn event_stream(tx: mpsc::Sender<HelperEvent>) -> io::Result<()> {
    let mut sender = open_connection().await?;

    let req = Request::builder()
        .method("GET")
        .uri("/events")
        .header("host", "localhost")
        .body(Full::new(Bytes::new()))
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    eprintln!("[GUI-IPC] Sending GET /events...");
    let resp = sender
        .send_request(req)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    eprintln!("[GUI-IPC] /events response: {} {:?}", resp.status(), resp.headers());
    let mut body = resp.into_body();
    let mut buf = BytesMut::new();

    while let Some(frame_result) = body.frame().await {
        let frame = frame_result.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        if let Ok(data) = frame.into_data() {
            eprintln!("[GUI-IPC] frame ({} bytes): {:?}", data.len(), String::from_utf8_lossy(&data[..data.len().min(200)]));
            buf.extend_from_slice(&data);

            // Process all complete lines in the buffer
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line_bytes = buf.split_to(pos + 1);
                let text = String::from_utf8_lossy(&line_bytes);
                let trimmed = text.trim();
                if trimmed.is_empty() || trimmed.contains("\"keepalive\"") {
                    continue;
                }
                match ipc::decode_line::<HelperEvent>(trimmed) {
                    Ok(event) => {
                        eprintln!("[GUI-IPC] parsed event: {:?}", std::mem::discriminant(&event));
                        if tx.send(event).is_err() {
                            return Ok(()); // GUI closed
                        }
                    }
                    Err(e) => eprintln!("[GUI-IPC] decode error: {} — line: {:?}", e, trimmed),
                }
            }
        }
    }

    Ok(())
}
