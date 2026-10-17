use std::collections::HashMap;
use std::time::{Duration, Instant};

use iced::Task;

use airvpn::ipc::{ConnectionState, ConnectRequest, HelperEvent, SaveProfileRequest};
use airvpn::options;

use super::ipc;
use super::views;
use super::{App, Message, MAX_LOG_ENTRIES};
use super::message::LogEntry;

impl App {
    pub(crate) fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                if tab == views::Tab::Servers && self.servers.is_empty() && !self.servers_loading {
                    return Task::done(Message::FetchServers);
                }
                if tab == views::Tab::Settings && !self.settings.loaded {
                    // Profile normally loads eagerly on HelperConnected; this is a
                    // fallback if that initial fetch failed. The device/key list now
                    // lives on the Overview, so Settings no longer fetches keys.
                    return Task::done(Message::FetchProfile);
                }
                Task::none()
            }
            Message::Connect => {
                // Set state immediately to disable the button and prevent
                // rapid-fire connect requests that race in the helper.
                self.connection_state = ConnectionState::Connecting;
                let server = self.selected_server.clone();
                self.send_connect(server);
                Task::none()
            }
            Message::ConnectToServer(server_name) => {
                self.selected_server = Some(server_name.clone());
                self.connection_state = ConnectionState::Connecting;
                // Use send_connect (same as overview Connect button) so errors
                // (409, credential issues, warmup) are shown instead of silently
                // swallowed by fire_command.
                self.send_connect(Some(server_name));
                Task::none()
            }
            Message::Disconnect => {
                self.error_overview = None;
                if let Some(ref helper) = self.helper {
                    if helper.send_command("POST", "/disconnect", None).is_err() {
                        self.enter_reconnection();
                    }
                }
                Task::none()
            }
            Message::Recover => {
                // Break-glass cleanup of orphaned VPN state (kill switch, DNS,
                // tunnel). Resulting state/lock changes arrive via the /events
                // stream. Feedback goes through `activity` (always visible) since
                // the error banner is gated behind show_errors and a silent
                // outcome defeats the whole point of a recover button.
                self.error_overview = None;
                if let Some(ref helper) = self.helper {
                    match helper.send_command("POST", "/recover", None) {
                        Ok((status, body)) => {
                            if status == 200 {
                                self.activity = "Recovery complete".into();
                            } else {
                                self.activity = format!("Recover failed (HTTP {})", status);
                                self.error_overview = Some(format!("Recover failed: {}", body));
                            }
                        }
                        Err(_) => self.enter_reconnection(),
                    }
                }
                Task::none()
            }
            Message::OverviewKeyChanged(key) => {
                // Device picked on the Overview. Persist immediately (focused
                // profile save merges, so other options are untouched) so the
                // choice is remembered and used on the next connect. wg_key is
                // only updated on a confirmed save — otherwise the dropdown would
                // show a device the next connect wouldn't actually use.
                self.error_overview = None;
                if let Some(ref helper) = self.helper {
                    let mut options = std::collections::HashMap::new();
                    options.insert(options::KEY.into(), key.clone());
                    let req = SaveProfileRequest { options };
                    match serde_json::to_vec(&req) {
                        Ok(body) => match helper.send_command("POST", "/profile", Some(&body)) {
                            Ok((status, _body)) => {
                                if status == 200 {
                                    self.settings.wg_key = key;
                                } else {
                                    self.error_overview =
                                        Some(format!("Failed to save device (HTTP {})", status));
                                }
                            }
                            Err(_) => self.enter_reconnection(),
                        },
                        Err(e) => {
                            self.error_overview =
                                Some(format!("Failed to serialize device selection: {}", e));
                        }
                    }
                }
                Task::none()
            }
            Message::Tick => {
                // Attempt reconnection if helper died
                if self.helper_reconnecting && Instant::now() >= self.helper_reconnect_at {
                    eprintln!("[GUI] Attempting helper reconnection...");
                    match ipc::HelperClient::connect() {
                        Ok(client) => {
                            eprintln!("[GUI] Helper reconnected successfully");
                            self.helper = Some(client);
                            self.helper_reconnecting = false;
                            self.activity.clear();
                            self.error_overview = None;
                            // Re-fetch state from the new helper instance. The event
                            // stream delivers the initial StatusResponse + LockStatus,
                            // but profile (connect flags + selected device) and the
                            // device/key list must be pulled explicitly.
                            return Task::batch([
                                Task::done(Message::FetchProfile),
                                Task::done(Message::FetchKeys),
                            ]);
                        }
                        Err(e) => {
                            eprintln!("[GUI] Helper reconnection failed: {}", e);
                            self.helper_reconnect_at =
                                Instant::now() + Duration::from_secs(2);
                        }
                    }
                    return Task::none();
                }

                // Drain events into a vec to avoid borrow conflict
                let events: Vec<_> = self
                    .helper
                    .as_ref()
                    .map(|h| std::iter::from_fn(|| h.try_recv()).collect())
                    .unwrap_or_default();
                for event in events {
                    self.handle_helper_event(event);
                }
                // Advance loading animation tick
                if self.servers_loading {
                    self.loading_tick = self.loading_tick.wrapping_add(1);
                }
                // Auto-refresh server list every 3 minutes
                if self.helper.is_some()
                    && !self.servers_loading
                    && self.last_server_fetch.elapsed() > Duration::from_secs(180)
                {
                    self.last_server_fetch = Instant::now();
                    return Task::done(Message::FetchServers);
                }
                // Retry the device/key list while empty — the helper's background
                // loop populates it a few seconds after startup, so the initial
                // FetchKeys on connect often comes back empty. Gated on
                // credentials_configured so a credential-less profile (which can
                // never have keys) doesn't poll forever.
                if self.helper.is_some()
                    && self.settings.credentials_configured
                    && self.available_keys.is_empty()
                    && self.last_keys_fetch.elapsed() > Duration::from_secs(5)
                {
                    self.last_keys_fetch = Instant::now();
                    return Task::done(Message::FetchKeys);
                }
                Task::none()
            }
            Message::HelperConnected => {
                match ipc::HelperClient::connect() {
                    Ok(client) => {
                        self.helper = Some(client);
                        self.helper_reconnecting = false;
                        self.error_overview = None;
                        self.activity.clear();
                        // Eagerly load profile (connect flags + selected device)
                        // and the device/key list so the Overview is fully
                        // populated without first visiting Settings.
                        Task::batch([
                            Task::done(Message::FetchProfile),
                            Task::done(Message::FetchKeys),
                        ])
                    }
                    Err(e) => {
                        eprintln!("[GUI] HelperClient::connect() failed: {}", e);
                        // Enter reconnection mode — systemd may need a moment to spawn
                        self.helper_reconnecting = true;
                        self.helper_reconnect_at =
                            Instant::now() + Duration::from_secs(2);
                        self.activity = "Reconnecting to helper...".into();
                        Task::none()
                    }
                }
            }
            Message::FetchServers => {
                self.error_servers = None;
                self.last_server_fetch = Instant::now();
                if let Some(ref helper) = self.helper {
                    self.servers_loading = true;
                    match helper.send_command("GET", "/servers", None) {
                        Ok((status, body)) => {
                            if status == 200 {
                                // Parse {"servers": [...]}
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                                    if let Some(arr) = parsed.get("servers") {
                                        if let Ok(servers) = serde_json::from_value::<Vec<airvpn::ipc::ServerInfo>>(arr.clone()) {
                                            self.servers = servers;
                                        }
                                    }
                                }
                            } else {
                                self.error_servers = Some(format!("Server list error: {}", body));
                            }
                            self.servers_loading = false;
                        }
                        Err(_) => {
                            self.servers_loading = false;
                            self.enter_reconnection();
                        }
                    }
                }
                Task::none()
            }
            Message::ServerClicked(idx) => {
                self.selected_server_idx = Some(idx);
                // Map display index to server name for use by Connect
                let filtered = views::servers::filter_and_sort(
                    &self.servers,
                    &self.server_search,
                    self.server_sort,
                    self.server_sort_ascending,
                );
                if let Some(server) = filtered.get(idx) {
                    self.selected_server = Some(server.name.clone());
                }
                Task::none()
            }
            Message::ServerSort(col) => {
                if col == self.server_sort {
                    self.server_sort_ascending = !self.server_sort_ascending;
                } else {
                    self.server_sort = col;
                    // Score: lower is better, so default ascending
                    self.server_sort_ascending = true;
                }
                self.selected_server_idx = None;
                Task::none()
            }
            Message::ServerSearchChanged(query) => {
                self.server_search = query;
                self.selected_server_idx = None;
                Task::none()
            }
            Message::LogFilterToggle(level) => {
                match level.as_str() {
                    "debug" => self.log_filter_debug = !self.log_filter_debug,
                    "info" => self.log_filter_info = !self.log_filter_info,
                    "warn" => self.log_filter_warn = !self.log_filter_warn,
                    "error" => self.log_filter_error = !self.log_filter_error,
                    _ => {}
                }
                Task::none()
            }
            Message::LogClear => {
                self.logs.clear();
                Task::none()
            }
            Message::FetchKeys => {
                if let Some(ref helper) = self.helper {
                    match helper.send_command("GET", "/keys", None) {
                        Ok((status, body)) => {
                            if status == 200 {
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                                    if let Some(arr) = parsed.get("keys") {
                                        if let Ok(keys) = serde_json::from_value::<Vec<String>>(arr.clone()) {
                                            self.available_keys = keys;
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            self.enter_reconnection();
                        }
                    }
                }
                Task::none()
            }
            Message::FetchProfile => {
                self.error_settings = None;
                if let Some(ref helper) = self.helper {
                    match helper.send_command("GET", "/profile", None) {
                        Ok((status, body)) => {
                            if status == 200 {
                                // Parse {"options": {...}, "credentials_configured": bool}
                                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                                    let credentials_configured = parsed.get("credentials_configured")
                                        .and_then(|v| v.as_bool()).unwrap_or(false);
                                    if let Some(opts) = parsed.get("options") {
                                        if let Ok(options) = serde_json::from_value::<std::collections::HashMap<String, String>>(opts.clone()) {
                                            self.handle_helper_event(HelperEvent::Profile { options, credentials_configured });
                                        }
                                    }
                                }
                            } else {
                                self.error_settings = Some(format!("Profile error: {}", body));
                            }
                        }
                        Err(_) => {
                            self.enter_reconnection();
                        }
                    }
                }
                Task::none()
            }
            Message::SaveSettings => {
                if let Some(ref helper) = self.helper {
                    let mut options = std::collections::HashMap::new();
                    options.insert(options::CONNECT.into(), self.settings.connect.to_string());
                    options.insert(options::SERVERS_STARTLAST.into(), self.settings.startlast.to_string());
                    options.insert(options::SERVERS_LOCKLAST.into(), self.settings.locklast.to_string());
                    options.insert(options::NETWORK_IPV6_MODE.into(), self.settings.ipv6_mode.clone());
                    options.insert(options::NETWORK_IPV4_MODE.into(), self.settings.ipv4_mode.clone());
                    options.insert(options::NETWORK_ENTRY_IFACE.into(), self.settings.entry_iface.clone());
                    options.insert(options::DNS_SERVERS.into(), self.settings.dns.clone());
                    // Connection flags (saved as positive option names)
                    options.insert(options::NETLOCK.into(), (!self.connect_no_lock).to_string());
                    options.insert(options::NETLOCK_ALLOW_PRIVATE.into(), self.connect_allow_lan.to_string());
                    options.insert(options::RECONNECT.into(), (!self.connect_no_reconnect).to_string());
                    options.insert(options::VERIFY.into(), (!self.connect_no_verify).to_string());
                    // WireGuard settings
                    options.insert(options::KEY.into(), self.settings.wg_key.clone());
                    options.insert(options::WG_MTU.into(), self.settings.wg_mtu.clone());
                    options.insert(options::WG_KEEPALIVE.into(), self.settings.wg_keepalive.clone());
                    options.insert(options::WG_HANDSHAKE_FIRST.into(), self.settings.wg_handshake_first.clone());
                    options.insert(options::WG_HANDSHAKE_CONNECTED.into(), self.settings.wg_handshake_connected.clone());
                    // Area filter settings
                    options.insert(options::AREAS_ALLOWLIST.into(), self.settings.areas_allowlist.clone());
                    options.insert(options::AREAS_DENYLIST.into(), self.settings.areas_denylist.clone());
                    // Network Lock settings
                    options.insert(options::NETLOCK_INCOMING.into(), self.settings.netlock_incoming.clone());
                    options.insert(options::NETLOCK_ALLOW_PING.into(), self.settings.netlock_allow_ping.to_string());
                    options.insert(options::NETLOCK_ALLOWLIST_IPS.into(), self.settings.netlock_allowlist_ips.clone());
                    options.insert(options::NETLOCK_LOCAL_FORWARD_IFACES.into(), self.settings.netlock_local_forward_ifaces.clone());
                    // Routes
                    options.insert(options::ROUTES_CUSTOM.into(), self.settings.routes_custom.clone());
                    // DNS settings
                    options.insert(options::DNS_MODE.into(), self.settings.dns_mode.clone());
                    options.insert(options::LINUX_DNS_SERVICES.into(), self.settings.dns_services.clone());
                    // UI display settings
                    options.insert(options::UI_UNIT.into(), self.settings.ui_unit.clone());
                    options.insert(options::UI_IEC.into(), self.settings.ui_iec.to_string());
                    // Logging settings
                    options.insert(options::LOG_FILE_ENABLED.into(), self.settings.log_file_enabled.to_string());
                    options.insert(options::LOG_FILE_PATH.into(), self.settings.log_file_path.clone());
                    options.insert(options::LOG_LEVEL_DEBUG.into(), self.settings.log_level_debug.to_string());
                    // Mode settings
                    options.insert(options::MODE_PORT.into(), self.settings.mode_port.clone());
                    // Advanced settings
                    options.insert(options::PINGER_TIMEOUT.into(), self.settings.pinger_timeout.clone());
                    options.insert(options::MANIFEST_REFRESH.into(), self.settings.manifest_refresh.clone());
                    options.insert(options::PENALITY_ON_ERROR.into(), self.settings.penality.clone());
                    options.insert(options::HTTP_TIMEOUT.into(), self.settings.http_timeout.clone());
                    options.insert(options::CHECKING_NTRY.into(), self.settings.checking_ntry.clone());
                    options.insert(options::SERVERS_CAPACITY_FACTOR.into(), self.settings.capacity_factor.clone());
                    options.insert(options::CHECK_ROUTE.into(), self.settings.check_route.to_string());
                    let req = SaveProfileRequest { options };
                    match serde_json::to_vec(&req) {
                        Ok(body) => match helper.send_command("POST", "/profile", Some(&body)) {
                            Ok((status, _body)) => {
                                if status == 200 {
                                    self.settings.dirty = false;
                                } else {
                                    self.error_settings = Some(format!("Failed to save profile (HTTP {})", status));
                                }
                            }
                            Err(_) => {
                                self.enter_reconnection();
                            }
                        },
                        Err(e) => {
                            self.error_settings = Some(format!("Failed to serialize profile: {}", e));
                        }
                    }
                }
                Task::none()
            }
            Message::SettingsConnectToggle(val) => {
                self.settings.connect = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsStartlastToggle(val) => {
                self.settings.startlast = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsLocklastToggle(val) => {
                self.settings.locklast = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsIpv6ModeChanged(val) => {
                self.settings.ipv6_mode = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsIpv4ModeChanged(val) => {
                self.settings.ipv4_mode = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsEntryIfaceChanged(val) => {
                self.settings.entry_iface = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsDnsChanged(val) => {
                self.settings.dns = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::ShowErrorsToggle(val) => {
                self.show_errors = val;
                Task::none()
            }
            Message::SettingsSubTabChanged(tab) => {
                self.settings.sub_tab = tab;
                Task::none()
            }
            Message::SettingsWgMtuChanged(val) => {
                self.settings.wg_mtu = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsWgKeepaliveChanged(val) => {
                self.settings.wg_keepalive = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsWgHandshakeFirstChanged(val) => {
                self.settings.wg_handshake_first = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsWgHandshakeConnectedChanged(val) => {
                self.settings.wg_handshake_connected = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsAreasAllowlistChanged(val) => {
                self.settings.areas_allowlist = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsAreasDenylistChanged(val) => {
                self.settings.areas_denylist = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsNetlockIncomingChanged(val) => {
                self.settings.netlock_incoming = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsNetlockAllowPingToggle(val) => {
                self.settings.netlock_allow_ping = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsNetlockAllowlistIpsChanged(val) => {
                self.settings.netlock_allowlist_ips = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsNetlockLocalForwardIfacesChanged(val) => {
                self.settings.netlock_local_forward_ifaces = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsRoutesCustomChanged(val) => {
                self.settings.routes_custom = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsPingerTimeoutChanged(val) => {
                self.settings.pinger_timeout = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsManifestRefreshChanged(val) => {
                self.settings.manifest_refresh = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsPenalityChanged(val) => {
                self.settings.penality = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsHttpTimeoutChanged(val) => {
                self.settings.http_timeout = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsCheckingNtryChanged(val) => {
                self.settings.checking_ntry = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsCapacityFactorChanged(val) => {
                self.settings.capacity_factor = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsCheckRouteToggle(val) => {
                self.settings.check_route = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsDnsModeChanged(val) => {
                self.settings.dns_mode = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsDnsServicesChanged(val) => {
                self.settings.dns_services = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsUiUnitChanged(val) => {
                self.settings.ui_unit = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsUiIecToggle(val) => {
                self.settings.ui_iec = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsLogFileEnabledToggle(val) => {
                self.settings.log_file_enabled = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsLogFilePathChanged(val) => {
                self.settings.log_file_path = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsLogLevelDebugToggle(val) => {
                self.settings.log_level_debug = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::SettingsModePortChanged(val) => {
                self.settings.mode_port = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::ConnectNoLockToggle(val) => {
                self.connect_no_lock = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::ConnectAllowLanToggle(val) => {
                self.connect_allow_lan = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::ConnectNoReconnectToggle(val) => {
                self.connect_no_reconnect = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::ConnectNoVerifyToggle(val) => {
                self.connect_no_verify = val;
                self.settings.dirty = true;
                Task::none()
            }
            Message::LockInstall => {
                self.error_settings = None;
                self.handle_lock_command("/lock/install");
                Task::none()
            }
            Message::LockUninstall => {
                self.error_settings = None;
                self.handle_lock_command("/lock/uninstall");
                Task::none()
            }
            Message::LockEnable => {
                self.error_settings = None;
                self.handle_lock_command("/lock/enable");
                Task::none()
            }
            Message::LockDisable => {
                self.error_settings = None;
                self.handle_lock_command("/lock/disable");
                Task::none()
            }
            Message::EddieImportAccept => {
                let _path = self.eddie_import_pending.take();
                self.activity = "Importing Eddie profile...".into();
                if let Some(ref helper) = self.helper {
                    let import_body = b"{\"accept\":true}";
                    match helper.send_command("POST", "/import-eddie", Some(import_body)) {
                        Ok((200, _)) => {}
                        Ok((status, resp_body)) => {
                            // Don't retry connect: it would 409 and re-show the dialog.
                            self.error_overview = Some(format!(
                                "Eddie import failed (HTTP {}): {}",
                                status, resp_body
                            ));
                            return Task::none();
                        }
                        Err(_) => {
                            self.enter_reconnection();
                            return Task::none();
                        }
                    }
                    // Retry connect after successful import
                    let server = self.selected_server.clone();
                    self.send_connect(server);
                }
                Task::none()
            }
            Message::EddieImportCancel => {
                self.eddie_import_pending = None;
                self.error_overview = Some(
                    "Credentials required. Run 'sudo airvpn connect' to set up.".into(),
                );
                Task::none()
            }
        }
    }

    pub(crate) fn handle_helper_event(&mut self, event: HelperEvent) {
        match event {
            HelperEvent::StateChanged { state } => {
                // Track connection timing
                if matches!(state, ConnectionState::Connected { .. })
                    && !matches!(self.connection_state, ConnectionState::Connected { .. })
                {
                    self.connected_since = Some(std::time::Instant::now());
                    self.connection_count += 1;
                }
                if matches!(state, ConnectionState::Disconnected) {
                    self.connected_since = None;
                    self.rx_speed = 0.0;
                    self.tx_speed = 0.0;
                }
                // Clear activity text on terminal states
                if matches!(state, ConnectionState::Connected { .. } | ConnectionState::Disconnected) {
                    self.activity.clear();
                }
                self.connection_state = state;
            }
            HelperEvent::Log { level, message } => {
                self.activity = message.clone();
                // UTC time-of-day (no chrono dependency; local time would need chrono)
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let secs = now % 86400;
                let h = secs / 3600;
                let m = (secs % 3600) / 60;
                let s = secs % 60;
                self.logs.push_back(LogEntry {
                    timestamp: format!("{:02}:{:02}:{:02}", h, m, s),
                    level,
                    message,
                });
                if self.logs.len() > MAX_LOG_ENTRIES {
                    self.logs.pop_front();
                }
            }
            HelperEvent::Stats { rx_bytes, tx_bytes } => {
                if self.prev_rx_bytes > 0 {
                    self.rx_speed = (rx_bytes.saturating_sub(self.prev_rx_bytes)) as f64 / 2.0;
                    self.tx_speed = (tx_bytes.saturating_sub(self.prev_tx_bytes)) as f64 / 2.0;
                }
                self.prev_rx_bytes = rx_bytes;
                self.prev_tx_bytes = tx_bytes;
                self.rx_bytes = rx_bytes;
                self.tx_bytes = tx_bytes;
            }
            HelperEvent::LockStatus {
                session_active,
                persistent_active,
                persistent_installed,
            } => {
                self.lock_session = session_active;
                self.lock_persistent = persistent_active;
                self.lock_installed = persistent_installed;
            }
            HelperEvent::Error { message } => {
                self.error_overview = Some(message);
            }
            HelperEvent::EddieProfileFound { path: _ } => {
                // Eddie import is now handled via HTTP 409 response in send_connect().
                // This event should not arrive via /events, but ignore it gracefully.
            }
            HelperEvent::Shutdown => {
                self.helper = None;
                self.connection_state = ConnectionState::Disconnected;
                self.helper_reconnecting = true;
                self.helper_reconnect_at = Instant::now() + Duration::from_secs(1);
                self.activity = "Reconnecting to helper...".into();
            }
            HelperEvent::ServerList { servers } => {
                self.servers = servers;
                self.servers_loading = false;
            }
            HelperEvent::Profile { options, credentials_configured } => {
                self.settings.credentials_configured = credentials_configured;
                self.settings.connect = options.get(options::CONNECT)
                    .map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
                self.settings.startlast = options.get(options::SERVERS_STARTLAST)
                    .map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
                self.settings.locklast = options.get(options::SERVERS_LOCKLAST)
                    .map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
                self.settings.ipv6_mode = options.get(options::NETWORK_IPV6_MODE)
                    .cloned().unwrap_or_else(|| "in-block".into());
                self.settings.ipv4_mode = options.get(options::NETWORK_IPV4_MODE)
                    .cloned().unwrap_or_else(|| "in".into());
                self.settings.entry_iface = options.get(options::NETWORK_ENTRY_IFACE)
                    .cloned().unwrap_or_default();
                self.settings.dns = options.get(options::DNS_SERVERS).cloned().unwrap_or_default();

                // Connection flags (inverted: profile uses positive names)
                self.connect_no_lock = !options.get(options::NETLOCK)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true); // default: lock ON (netlock=true, no_lock=false)
                self.connect_allow_lan = options.get(options::NETLOCK_ALLOW_PRIVATE)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true); // default: allow LAN
                self.connect_no_reconnect = !options.get(options::RECONNECT)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true); // default: reconnect ON
                self.connect_no_verify = !options.get(options::VERIFY)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true); // default: verify ON

                // WireGuard settings
                self.settings.wg_key = options.get(options::KEY)
                    .cloned().unwrap_or_else(|| "Default".into());
                self.settings.wg_mtu = options.get(options::WG_MTU)
                    .cloned().unwrap_or_else(|| "1320".into());
                self.settings.wg_keepalive = options.get(options::WG_KEEPALIVE)
                    .cloned().unwrap_or_else(|| "15".into());
                self.settings.wg_handshake_first = options.get(options::WG_HANDSHAKE_FIRST)
                    .cloned().unwrap_or_else(|| "50".into());
                self.settings.wg_handshake_connected = options.get(options::WG_HANDSHAKE_CONNECTED)
                    .cloned().unwrap_or_else(|| "200".into());

                // Area filter settings
                self.settings.areas_allowlist = options.get(options::AREAS_ALLOWLIST)
                    .cloned().unwrap_or_default();
                self.settings.areas_denylist = options.get(options::AREAS_DENYLIST)
                    .cloned().unwrap_or_default();

                // Network Lock settings
                self.settings.netlock_incoming = options.get(options::NETLOCK_INCOMING)
                    .cloned().unwrap_or_else(|| "block".into());
                self.settings.netlock_allow_ping = options.get(options::NETLOCK_ALLOW_PING)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true);
                self.settings.netlock_allowlist_ips = options.get(options::NETLOCK_ALLOWLIST_IPS)
                    .cloned().unwrap_or_default();
                self.settings.netlock_local_forward_ifaces = options.get(options::NETLOCK_LOCAL_FORWARD_IFACES)
                    .cloned().unwrap_or_default();

                // Routes
                self.settings.routes_custom = options.get(options::ROUTES_CUSTOM)
                    .cloned().unwrap_or_default();

                // DNS settings
                self.settings.dns_mode = options.get(options::DNS_MODE)
                    .cloned().unwrap_or_else(|| "auto".into());
                self.settings.dns_services = options.get(options::LINUX_DNS_SERVICES)
                    .cloned().unwrap_or_else(|| "nscd,dnsmasq,named,bind9".into());

                // UI display settings
                self.settings.ui_unit = options.get(options::UI_UNIT)
                    .cloned().unwrap_or_else(|| "bytes".into());
                self.settings.ui_iec = options.get(options::UI_IEC)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                // Logging settings
                self.settings.log_file_enabled = options.get(options::LOG_FILE_ENABLED)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                self.settings.log_file_path = options.get(options::LOG_FILE_PATH)
                    .cloned().unwrap_or_else(|| "/var/log/airvpn-rs/helper.log".into());
                self.settings.log_level_debug = options.get(options::LOG_LEVEL_DEBUG)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                // Mode settings
                self.settings.mode_port = options.get(options::MODE_PORT)
                    .cloned().unwrap_or_default();

                // Advanced settings
                self.settings.pinger_timeout = options.get(options::PINGER_TIMEOUT)
                    .cloned().unwrap_or_else(|| "3".into());
                self.settings.manifest_refresh = options.get(options::MANIFEST_REFRESH)
                    .cloned().unwrap_or_else(|| "1800".into());
                self.settings.penality = options.get(options::PENALITY_ON_ERROR)
                    .cloned().unwrap_or_else(|| "30".into());
                self.settings.http_timeout = options.get(options::HTTP_TIMEOUT)
                    .cloned().unwrap_or_else(|| "10".into());
                self.settings.checking_ntry = options.get(options::CHECKING_NTRY)
                    .cloned().unwrap_or_else(|| "3".into());
                self.settings.capacity_factor = options.get(options::SERVERS_CAPACITY_FACTOR)
                    .cloned().unwrap_or_else(|| "0".into());
                self.settings.check_route = options.get(options::CHECK_ROUTE)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true);

                self.settings.loaded = true;
                self.settings.dirty = false;
            }
            HelperEvent::ProfileSaved => {
                self.settings.dirty = false;
            }
        }
    }

    /// Enter reconnection mode after a send_command I/O error.
    /// Drops the dead HelperClient so the next attempt creates a fresh connection
    /// (which triggers systemd socket activation to respawn the helper).
    pub(crate) fn enter_reconnection(&mut self) {
        eprintln!("[GUI] Helper connection lost, entering reconnection mode");
        self.helper = None;
        self.helper_reconnecting = true;
        self.helper_reconnect_at = Instant::now() + Duration::from_secs(1);
        self.activity = "Reconnecting to helper...".into();
    }

    /// Send a lock command and update local lock state from the response.
    pub(crate) fn handle_lock_command(&mut self, path: &str) {
        let Some(ref helper) = self.helper else { return };
        match helper.send_command("POST", path, None) {
            Ok((status, body)) => {
                if status != 200 {
                    self.error_settings = Some(format!("Lock command failed: {}", body));
                    return;
                }
                // enable/disable return LockStatusInfo directly.
                // install/uninstall return {"message": ..., "lock": LockStatusInfo}.
                // Try nested first, then direct.
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&body) {
                    let lock_val = parsed.get("lock").unwrap_or(&parsed);
                    if let (Some(sa), Some(pa), Some(pi)) = (
                        lock_val.get("session_active").and_then(|v| v.as_bool()),
                        lock_val.get("persistent_active").and_then(|v| v.as_bool()),
                        lock_val.get("persistent_installed").and_then(|v| v.as_bool()),
                    ) {
                        self.lock_session = sa;
                        self.lock_persistent = pa;
                        self.lock_installed = pi;
                    }
                }
            }
            Err(_) => self.enter_reconnection(),
        }
    }

    /// Build a ConnectRequest from current settings.
    pub(crate) fn build_connect_request(&self, server: Option<String>) -> ConnectRequest {
        let mut overrides = HashMap::new();
        // Always send current GUI state as overrides — resolve() handles layering
        overrides.insert(options::NETLOCK.into(), (!self.connect_no_lock).to_string());
        overrides.insert(options::NETLOCK_ALLOW_PRIVATE.into(), self.connect_allow_lan.to_string());
        overrides.insert(options::RECONNECT.into(), (!self.connect_no_reconnect).to_string());
        overrides.insert(options::VERIFY.into(), (!self.connect_no_verify).to_string());
        if !self.settings.ipv6_mode.is_empty() {
            overrides.insert(options::NETWORK_IPV6_MODE.into(), self.settings.ipv6_mode.clone());
        }
        if !self.settings.ipv4_mode.is_empty() {
            overrides.insert(options::NETWORK_IPV4_MODE.into(), self.settings.ipv4_mode.clone());
        }
        if !self.settings.entry_iface.is_empty() {
            overrides.insert(options::NETWORK_ENTRY_IFACE.into(), self.settings.entry_iface.clone());
        }
        if !self.settings.dns.is_empty() {
            overrides.insert(options::DNS_SERVERS.into(), self.settings.dns.clone());
        }
        ConnectRequest { server, overrides }
    }

    /// Send POST /connect via HTTP. Handles 409 Eddie import by auto-accepting and retrying.
    pub(crate) fn send_connect(&mut self, server: Option<String>) {
        self.error_overview = None;
        let req = self.build_connect_request(server);
        let body = match serde_json::to_vec(&req) {
            Ok(b) => b,
            Err(e) => {
                self.error_overview = Some(format!("Failed to serialize ConnectRequest: {}", e));
                return;
            }
        };

        let helper = match self.helper {
            Some(ref h) => h,
            None => return,
        };

        match helper.send_command("POST", "/connect", Some(&body)) {
            Ok((status, resp_body)) => {
                if status == 409 {
                    // Check if Eddie import needed
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&resp_body) {
                        if let Some(path) = parsed.get("eddie_profile").and_then(|v| v.as_str()) {
                            // Show confirmation dialog instead of auto-accepting
                            self.eddie_import_pending = Some(path.to_string());
                            return;
                        }
                    }
                    // 409 but not Eddie — already connected or other error
                    self.error_overview = Some(format!("Connect failed: {}", resp_body));
                    self.connection_state = ConnectionState::Disconnected;
                } else if status != 200 {
                    self.error_overview = Some(format!("Connect failed (HTTP {}): {}", status, resp_body));
                    self.connection_state = ConnectionState::Disconnected;
                }
                // 200 = connect started, events arrive via /events stream
            }
            Err(_) => {
                self.enter_reconnection();
            }
        }
    }
}
