//! HTTP IPC client for communicating with the airvpn helper daemon.
//!
//! Two mechanisms:
//! 1. GET /events — long-lived chunked HTTP response for receiving events
//! 2. Separate HTTP requests for sending commands (each opens a new connection)

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use airvpn::ipc::{self, HelperEvent};

const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";

pub struct HelperClient {
    event_rx: mpsc::Receiver<HelperEvent>,
    _reader_thread: thread::JoinHandle<()>,
}

impl HelperClient {
    /// Connect to helper — opens GET /events for event streaming.
    /// The event stream automatically delivers initial StatusResponse + LockStatus.
    pub fn connect() -> std::io::Result<Self> {
        let stream = Self::connect_with_timeout(SOCKET_PATH, Duration::from_secs(2))?;
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

    /// Send GET /events, skip HTTP headers, read chunked events into channel.
    fn event_stream_loop(
        mut stream: UnixStream,
        tx: mpsc::Sender<HelperEvent>,
    ) -> std::io::Result<()> {
        write!(stream, "GET /events HTTP/1.1\r\nHost: localhost\r\n\r\n")?;
        stream.flush()?;

        let mut reader = BufReader::new(stream);

        // Skip status line + headers
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() {
                break;
            }
        }

        // Read chunked events
        loop {
            let mut size_line = String::new();
            if reader.read_line(&mut size_line)? == 0 {
                break;
            }
            let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
            if size == 0 {
                // Terminal chunk — consume trailing CRLF
                let mut trailing = String::new();
                let _ = reader.read_line(&mut trailing);
                break;
            }

            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk)?;
            // Consume trailing CRLF after chunk data
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf);

            let text = String::from_utf8_lossy(&chunk);
            for line in text.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                // Skip keepalive messages
                if line.contains("\"keepalive\"") {
                    continue;
                }
                match ipc::decode_line::<HelperEvent>(line) {
                    Ok(event) => {
                        if tx.send(event).is_err() {
                            return Ok(());
                        }
                    }
                    Err(e) => eprintln!("[GUI] Event decode error: {} — line: {}", e, line),
                }
            }
        }
        Ok(())
    }

    /// Send a command via a separate short-lived HTTP request. Returns (status, body).
    pub fn send_command(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
    ) -> std::io::Result<(u16, String)> {
        let mut stream = Self::connect_with_timeout(SOCKET_PATH, Duration::from_secs(5))?;

        if let Some(b) = body {
            write!(
                stream,
                "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                method, path, b.len()
            )?;
            stream.write_all(b)?;
        } else {
            write!(
                stream,
                "{} {} HTTP/1.1\r\nHost: localhost\r\n\r\n",
                method, path
            )?;
        }
        stream.flush()?;

        let mut reader = BufReader::new(stream);

        // Read status line
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;
        let status: u16 = status_line
            .splitn(3, ' ')
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        // Read headers, extract Content-Length
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line)?;
            if line.trim().is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("content-length") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
        }

        // Read body
        let mut buf = vec![0u8; content_length];
        if content_length > 0 {
            reader.read_exact(&mut buf)?;
        }
        Ok((status, String::from_utf8_lossy(&buf).to_string()))
    }

    pub fn try_recv(&self) -> Option<HelperEvent> {
        self.event_rx.try_recv().ok()
    }

    /// Connect to a Unix socket with a timeout.
    /// Spawns a thread to do the blocking connect and waits with a deadline.
    fn connect_with_timeout(path: &str, timeout: Duration) -> std::io::Result<UnixStream> {
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
