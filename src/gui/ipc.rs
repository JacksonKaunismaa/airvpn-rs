//! IPC client for communicating with the airvpn helper daemon.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;

use airvpn::ipc::{self, HelperCommand, HelperEvent};

const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";

pub struct HelperClient {
    writer: UnixStream,
    event_rx: mpsc::Receiver<HelperEvent>,
    _reader_thread: thread::JoinHandle<()>,
}

impl HelperClient {
    pub fn connect() -> std::io::Result<Self> {
        let stream = UnixStream::connect(SOCKET_PATH)?;
        let reader_stream = stream.try_clone()?;
        let writer = stream;
        let (tx, rx) = mpsc::channel();

        let reader_thread = thread::spawn(move || {
            let reader = BufReader::new(reader_stream);
            for line in reader.lines() {
                match line {
                    Ok(l) if l.trim().is_empty() => continue,
                    Ok(l) => match ipc::decode_line::<HelperEvent>(&l) {
                        Ok(event) => {
                            if tx.send(event).is_err() {
                                break;
                            }
                        }
                        Err(e) => eprintln!("IPC decode error: {}", e),
                    },
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            writer,
            event_rx: rx,
            _reader_thread: reader_thread,
        })
    }

    pub fn send(&mut self, cmd: &HelperCommand) -> std::io::Result<()> {
        let json = ipc::encode_line(cmd)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        self.writer.write_all(json.as_bytes())?;
        self.writer.flush()
    }

    pub fn try_recv(&self) -> Option<HelperEvent> {
        self.event_rx.try_recv().ok()
    }
}

pub fn is_helper_running() -> bool {
    std::path::Path::new(SOCKET_PATH).exists()
}

pub fn launch_helper() -> std::io::Result<std::process::Child> {
    std::process::Command::new("pkexec")
        .args(["airvpn", "helper"])
        .spawn()
}
