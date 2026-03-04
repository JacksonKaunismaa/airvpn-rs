//! Shared IPC types for helper<->GUI communication.
//!
//! JSON-lines protocol over Unix socket: one JSON object per line,
//! newline-delimited.

use serde::{Deserialize, Serialize};

/// Commands sent from GUI to helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum HelperCommand {
    Connect {
        server: Option<String>,
        no_lock: bool,
        allow_lan: bool,
        skip_ping: bool,
        allow_country: Vec<String>,
        deny_country: Vec<String>,
        allow_server: Vec<String>,
        deny_server: Vec<String>,
        no_reconnect: bool,
        no_verify: bool,
        no_lock_last: bool,
        no_start_last: bool,
        ipv6_mode: Option<String>,
        dns_servers: Vec<String>,
        event_pre: [Option<String>; 3],
        event_up: [Option<String>; 3],
        event_down: [Option<String>; 3],
    },
    Disconnect,
    Status,
    LockInstall,
    LockUninstall,
    LockEnable,
    LockDisable,
    LockStatus,
    Recover,
    /// Response to EddieProfileFound prompt.
    ImportEddieProfile { accept: bool },
    Shutdown,
}

/// Connection state machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected {
        server_name: String,
        server_country: String,
        server_location: String,
    },
    Reconnecting,
    Disconnecting,
}

/// Events sent from helper to GUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event")]
pub enum HelperEvent {
    StateChanged { state: ConnectionState },
    Log { level: String, message: String },
    Stats { rx_bytes: u64, tx_bytes: u64 },
    LockStatus {
        session_active: bool,
        persistent_active: bool,
        persistent_installed: bool,
    },
    Error { message: String },
    /// Helper found an Eddie profile and asks the client whether to import it.
    EddieProfileFound { path: String },
    Shutdown,
}

/// Internal engine events (mpsc channel, not serialized over socket).
/// Helper translates these into HelperEvents for the GUI.
#[derive(Debug, Clone)]
pub enum EngineEvent {
    StateChanged(ConnectionState),
    Log { level: String, message: String },
    ServerSelected { name: String, country: String, location: String },
}

pub fn encode_line<T: Serialize>(value: &T) -> serde_json::Result<String> {
    let mut json = serde_json::to_string(value)?;
    json.push('\n');
    Ok(json)
}

pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_connect_roundtrip() {
        let cmd = HelperCommand::Connect {
            server: Some("Castor".to_string()),
            no_lock: false,
            allow_lan: true,
            skip_ping: false,
            allow_country: vec!["NL".to_string(), "DE".to_string()],
            deny_country: vec!["US".to_string()],
            allow_server: vec!["Castor".to_string()],
            deny_server: vec!["Pollux".to_string()],
            no_reconnect: true,
            no_verify: false,
            no_lock_last: true,
            no_start_last: false,
            ipv6_mode: Some("block".to_string()),
            dns_servers: vec!["10.128.0.1".to_string(), "10.128.0.2".to_string()],
            event_pre: [Some("echo pre".to_string()), None, None],
            event_up: [Some("echo up".to_string()), Some("echo up2".to_string()), None],
            event_down: [None, None, None],
        };

        let encoded = encode_line(&cmd).expect("encode failed");
        assert!(encoded.contains(r#""cmd":"Connect""#));
        assert!(encoded.ends_with('\n'));

        let decoded: HelperCommand = decode_line(&encoded).expect("decode failed");
        match decoded {
            HelperCommand::Connect {
                server,
                no_lock,
                allow_lan,
                skip_ping,
                allow_country,
                deny_country,
                allow_server,
                deny_server,
                no_reconnect,
                no_verify,
                no_lock_last,
                no_start_last,
                ipv6_mode,
                dns_servers,
                event_pre,
                event_up,
                event_down,
            } => {
                assert_eq!(server, Some("Castor".to_string()));
                assert!(!no_lock);
                assert!(allow_lan);
                assert!(!skip_ping);
                assert_eq!(allow_country, vec!["NL", "DE"]);
                assert_eq!(deny_country, vec!["US"]);
                assert_eq!(allow_server, vec!["Castor"]);
                assert_eq!(deny_server, vec!["Pollux"]);
                assert!(no_reconnect);
                assert!(!no_verify);
                assert!(no_lock_last);
                assert!(!no_start_last);
                assert_eq!(ipv6_mode, Some("block".to_string()));
                assert_eq!(dns_servers, vec!["10.128.0.1", "10.128.0.2"]);
                assert_eq!(event_pre, [Some("echo pre".to_string()), None, None]);
                assert_eq!(
                    event_up,
                    [Some("echo up".to_string()), Some("echo up2".to_string()), None]
                );
                assert_eq!(event_down, [None, None, None]);
            }
            other => panic!("expected Connect, got {:?}", other),
        }
    }

    #[test]
    fn test_event_state_changed_roundtrip() {
        let event = HelperEvent::StateChanged {
            state: ConnectionState::Connected {
                server_name: "Castor".to_string(),
                server_country: "NL".to_string(),
                server_location: "Alblasserdam".to_string(),
            },
        };

        let encoded = encode_line(&event).expect("encode failed");
        assert!(encoded.contains(r#""event":"StateChanged""#));
        assert!(encoded.ends_with('\n'));

        let decoded: HelperEvent = decode_line(&encoded).expect("decode failed");
        match decoded {
            HelperEvent::StateChanged { state } => {
                assert_eq!(
                    state,
                    ConnectionState::Connected {
                        server_name: "Castor".to_string(),
                        server_country: "NL".to_string(),
                        server_location: "Alblasserdam".to_string(),
                    }
                );
            }
            other => panic!("expected StateChanged, got {:?}", other),
        }
    }

    #[test]
    fn test_command_disconnect_roundtrip() {
        let cmd = HelperCommand::Disconnect;

        let encoded = encode_line(&cmd).expect("encode failed");
        assert!(encoded.contains(r#""cmd":"Disconnect""#));
        assert!(encoded.ends_with('\n'));

        let decoded: HelperCommand = decode_line(&encoded).expect("decode failed");
        assert!(matches!(decoded, HelperCommand::Disconnect));
    }

    #[test]
    fn test_lock_status_event_roundtrip() {
        let event = HelperEvent::LockStatus {
            session_active: true,
            persistent_active: false,
            persistent_installed: true,
        };

        let encoded = encode_line(&event).expect("encode failed");

        let decoded: HelperEvent = decode_line(&encoded).expect("decode failed");
        match decoded {
            HelperEvent::LockStatus {
                session_active,
                persistent_active,
                persistent_installed,
            } => {
                assert!(session_active);
                assert!(!persistent_active);
                assert!(persistent_installed);
            }
            other => panic!("expected LockStatus, got {:?}", other),
        }
    }
}
