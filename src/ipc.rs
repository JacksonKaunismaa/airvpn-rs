//! Shared IPC types for helper<->GUI communication.
//!
//! JSON-lines protocol over Unix socket: one JSON object per line,
//! newline-delimited.

use serde::{Deserialize, Serialize};

/// GUI-friendly server info with pre-calculated scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerInfo {
    pub name: String,
    pub country_code: String,
    pub location: String,
    pub users: i64,
    pub users_max: i64,
    pub load_percent: f64,
    pub score: i64,
    pub ping_ms: Option<i64>,
    pub warning: Option<String>,
    pub ipv4: bool,
    pub ipv6: bool,
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
    /// Server list in response to ListServers command.
    ServerList { servers: Vec<ServerInfo> },
    Profile {
        options: std::collections::HashMap<String, String>,
        credentials_configured: bool,
    },
    ProfileSaved,
}

// ---------------------------------------------------------------------------
// HTTP-specific request/response types (Tasks 2–4)
// ---------------------------------------------------------------------------

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

/// Request body for POST /import-eddie.
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

    #[test]
    fn test_event_server_list_roundtrip() {
        let servers = vec![
            ServerInfo {
                name: "Castor".to_string(),
                country_code: "NL".to_string(),
                location: "Alblasserdam".to_string(),
                users: 42,
                users_max: 500,
                load_percent: 8.4,
                score: 150,
                ping_ms: Some(12),
                warning: None,
                ipv4: true,
                ipv6: true,
            },
            ServerInfo {
                name: "Pollux".to_string(),
                country_code: "DE".to_string(),
                location: "Frankfurt".to_string(),
                users: 300,
                users_max: 500,
                load_percent: 60.0,
                score: 900,
                ping_ms: None,
                warning: Some("High load".to_string()),
                ipv4: true,
                ipv6: false,
            },
        ];
        let event = HelperEvent::ServerList { servers };

        let encoded = encode_line(&event).expect("encode failed");
        assert!(encoded.contains(r#""event":"ServerList""#));
        assert!(encoded.ends_with('\n'));

        let decoded: HelperEvent = decode_line(&encoded).expect("decode failed");
        match decoded {
            HelperEvent::ServerList { servers } => {
                assert_eq!(servers.len(), 2);
                assert_eq!(servers[0].name, "Castor");
                assert_eq!(servers[0].ping_ms, Some(12));
                assert!(servers[0].warning.is_none());
                assert_eq!(servers[1].name, "Pollux");
                assert!(servers[1].ping_ms.is_none());
                assert_eq!(servers[1].warning, Some("High load".to_string()));
            }
            other => panic!("expected ServerList, got {:?}", other),
        }
    }

    #[test]
    fn test_event_profile_roundtrip() {
        let mut options = std::collections::HashMap::new();
        options.insert("servers.locklast".to_string(), "false".to_string());
        options.insert("mode.protocol".to_string(), "wireguard".to_string());
        let event = HelperEvent::Profile { options: options.clone(), credentials_configured: true };

        let encoded = encode_line(&event).expect("encode failed");
        assert!(encoded.contains(r#""event":"Profile""#));
        assert!(encoded.ends_with('\n'));

        let decoded: HelperEvent = decode_line(&encoded).expect("decode failed");
        match decoded {
            HelperEvent::Profile { options: decoded_options, credentials_configured } => {
                assert_eq!(decoded_options, options);
                assert!(credentials_configured);
            }
            other => panic!("expected Profile, got {:?}", other),
        }
    }

}
