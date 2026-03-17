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
/// Handles interactive prompts from the helper (e.g. Eddie profile import).
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

        // Handle interactive prompts from the helper
        if let HelperEvent::EddieProfileFound { ref path } = event {
            let accept = prompt_eddie_import(path);
            let resp = ipc::HelperCommand::ImportEddieProfile { accept };
            let resp_line = ipc::encode_line(&resp).context("encode response")?;
            writer.write_all(resp_line.as_bytes()).context("write response")?;
            writer.flush().context("flush response")?;
            continue;
        }

        match render_event(&event) {
            EventAction::Continue => {}
            EventAction::Done => return Ok(()),
            EventAction::Error(msg) => anyhow::bail!("{}", msg),
        }
    }

    // Socket closed without terminal event
    anyhow::bail!("helper closed connection unexpectedly")
}

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

/// Send a Status command and render both StateChanged + LockStatus events.
/// Unlike send_command, this reads a fixed number of events (Status always
/// returns exactly 2: StateChanged + LockStatus) to avoid Disconnected
/// being treated as terminal before LockStatus is read.
pub fn send_status() -> Result<()> {
    let stream = connect_to_helper()?;
    let mut writer = stream.try_clone().context("clone socket")?;
    let reader = BufReader::new(stream);

    let line = ipc::encode_line(&HelperCommand::Status).context("encode command")?;
    writer.write_all(line.as_bytes()).context("write command")?;
    writer.flush().context("flush command")?;

    let mut events_read = 0;
    for line in reader.lines() {
        let line = line.context("read event")?;
        if line.trim().is_empty() {
            continue;
        }
        let event: HelperEvent =
            ipc::decode_line(&line).with_context(|| format!("decode event: {}", line))?;

        match &event {
            HelperEvent::StateChanged { state } => {
                match state {
                    ConnectionState::Connected { server_name, server_country, server_location } => {
                        if server_location.is_empty() && server_country.is_empty() {
                            println!("Connected via {}", server_name);
                        } else {
                            println!("Connected to {} ({}, {})", server_name, server_location, server_country);
                        }
                    }
                    ConnectionState::Connecting => println!("Connecting..."),
                    ConnectionState::Reconnecting => println!("Reconnecting..."),
                    ConnectionState::Disconnecting => println!("Disconnecting..."),
                    ConnectionState::Disconnected => println!("Not connected."),
                }
                events_read += 1;
            }
            HelperEvent::LockStatus { session_active, persistent_active, persistent_installed } => {
                println!("Lock status:");
                println!("  Session lock:    {}", if *session_active { "active" } else { "inactive" });
                println!("  Persistent lock: {}", if *persistent_active { "active" } else { "inactive" });
                println!("  Installed:       {}", if *persistent_installed { "yes" } else { "no" });
                events_read += 1;
            }
            HelperEvent::Error { message } => anyhow::bail!("{}", message),
            _ => {} // ignore unexpected events
        }

        if events_read >= 2 {
            return Ok(());
        }
    }

    if events_read > 0 {
        return Ok(());
    }
    anyhow::bail!("helper closed connection without response")
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
        HelperEvent::ServerList { table } => {
            println!("{}", table);
            EventAction::Done
        }
        HelperEvent::Error { message } => EventAction::Error(message.clone()),
        HelperEvent::EddieProfileFound { .. } => {
            // Handled in send_command before reaching render_event
            EventAction::Continue
        }
        HelperEvent::Shutdown => EventAction::Done,
        // GUI-only events — CLI ignores these
        HelperEvent::ServerListDetailed { .. }
        | HelperEvent::Profile { .. }
        | HelperEvent::ProfileSaved => EventAction::Continue,
    }
}
