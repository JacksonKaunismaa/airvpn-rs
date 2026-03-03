//! Thin CLI client: connect to helper socket, send commands, render events.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

use crate::helper::SOCKET_PATH;
use crate::ipc::{self, ConnectionState, HelperCommand, HelperEvent};

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

/// Send a command and consume the event stream, printing each event.
/// Returns when a terminal event is received (Disconnected, Error, Shutdown).
pub fn send_command(cmd: &HelperCommand) -> Result<()> {
    let stream = connect_to_helper()?;
    let mut writer = stream.try_clone().context("clone socket")?;
    let reader = BufReader::new(stream);

    // Send command
    let line = ipc::encode_line(cmd).context("encode command")?;
    writer.write_all(line.as_bytes()).context("write command")?;
    writer.flush().context("flush command")?;

    // Read and render events
    for line in reader.lines() {
        let line = line.context("read event")?;
        if line.trim().is_empty() {
            continue;
        }
        let event: HelperEvent =
            ipc::decode_line(&line).with_context(|| format!("decode event: {}", line))?;

        match render_event(&event) {
            EventAction::Continue => {}
            EventAction::Done => return Ok(()),
            EventAction::Error(msg) => anyhow::bail!("{}", msg),
        }
    }

    // Socket closed without terminal event
    anyhow::bail!("helper closed connection unexpectedly")
}

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
        HelperEvent::LockStatus {
            session_active,
            persistent_active,
            persistent_installed,
        } => {
            println!("Lock status:");
            println!(
                "  Session lock:    {}",
                if *session_active {
                    "active"
                } else {
                    "inactive"
                }
            );
            println!(
                "  Persistent lock: {}",
                if *persistent_active {
                    "active"
                } else {
                    "inactive"
                }
            );
            println!(
                "  Installed:       {}",
                if *persistent_installed { "yes" } else { "no" }
            );
            EventAction::Done
        }
        HelperEvent::Error { message } => EventAction::Error(message.clone()),
        HelperEvent::Shutdown => EventAction::Done,
    }
}
