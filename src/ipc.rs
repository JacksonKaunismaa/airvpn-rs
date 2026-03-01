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
    },
    Disconnect,
    Status,
    LockInstall,
    LockUninstall,
    LockEnable,
    LockDisable,
    LockStatus,
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
            } => {
                assert_eq!(server, Some("Castor".to_string()));
                assert!(!no_lock);
                assert!(allow_lan);
                assert!(!skip_ping);
                assert_eq!(allow_country, vec!["NL", "DE"]);
                assert_eq!(deny_country, vec!["US"]);
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
