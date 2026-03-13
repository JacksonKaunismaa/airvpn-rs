mod ipc;
mod theme;
mod views;

use iced::widget::{button, column, container, row, text};
use iced::{Element, Fill, Size, Subscription, Task};
use iced::time;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const MAX_LOG_ENTRIES: usize = 10_000;

use airvpn::ipc::{ConnectionState, ConnectRequest, HelperEvent, SaveProfileRequest, ServerInfo};
use airvpn::options;

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

fn main() -> iced::Result {
    eprintln!("[GUI] Starting airvpn-gui (built {})", env!("CARGO_PKG_VERSION"));
    iced::application(App::boot, App::update, App::view)
        .title("AirVPN")
        .theme(theme::airvpn_theme())
        .subscription(App::subscription)
        .window_size(Size::new(900.0, 600.0))
        .centered()
        .run()
}

struct App {
    active_tab: views::Tab,
    connection_state: ConnectionState,
    lock_session: bool,
    lock_persistent: bool,
    lock_installed: bool,
    rx_bytes: u64,
    tx_bytes: u64,
    prev_rx_bytes: u64,
    prev_tx_bytes: u64,
    rx_speed: f64,
    tx_speed: f64,
    connected_since: Option<std::time::Instant>,
    connection_count: u32,
    selected_server: Option<String>,
    servers: Vec<ServerInfo>,
    servers_loading: bool,
    selected_server_idx: Option<usize>,
    server_sort: views::servers::SortColumn,
    server_sort_ascending: bool,
    server_search: String,
    server_country_filter: String,
    helper: Option<ipc::HelperClient>,
    error_overview: Option<String>,
    error_servers: Option<String>,
    error_settings: Option<String>,
    logs: VecDeque<LogEntry>,
    log_filter_debug: bool,
    log_filter_info: bool,
    log_filter_warn: bool,
    log_filter_error: bool,
    activity: String,

    // Profile-backed settings (loaded via GetProfile, saved via SaveProfile)
    settings_credentials_configured: bool,
    settings_startlast: bool,
    settings_locklast: bool,
    settings_ipv6_mode: String,
    settings_ipv4_mode: String,
    settings_entry_iface: String,
    settings_dns: String,
    settings_loaded: bool,
    settings_dirty: bool,

    // GUI-only toggles (not persisted)
    show_errors: bool,

    // Eddie import confirmation (Some = dialog visible with profile path)
    eddie_import_pending: Option<String>,

    // Connection settings (profile-backed)
    connect_no_lock: bool,
    connect_allow_lan: bool,
    connect_no_reconnect: bool,
    connect_no_verify: bool,

    // Settings sub-tab navigation
    settings_sub_tab: views::settings::SettingsSubTab,

    // WireGuard settings (profile-backed, text for text_input widget)
    settings_wg_key: String,
    settings_wg_mtu: String,
    settings_wg_keepalive: String,
    settings_wg_handshake_first: String,
    settings_wg_handshake_connected: String,

    // Network Lock settings (profile-backed)
    settings_netlock_incoming: String,
    settings_netlock_allow_ping: bool,
    settings_netlock_allowlist_ips: String,

    // Routes (profile-backed)
    settings_routes_custom: String,

    // Area filter settings (profile-backed)
    settings_areas_allowlist: String,
    settings_areas_denylist: String,

    // DNS settings (profile-backed)
    settings_dns_mode: String,
    settings_dns_services: String,

    // UI display settings (profile-backed)
    settings_ui_unit: String,
    settings_ui_iec: bool,

    // Logging settings (profile-backed)
    settings_log_file_enabled: bool,
    settings_log_file_path: String,
    settings_log_level_debug: bool,

    // Mode settings (profile-backed)
    settings_mode_port: String,

    // Advanced settings (profile-backed, text for text_input widget)
    settings_pinger_timeout: String,
    settings_manifest_refresh: String,
    settings_penality: String,
    settings_http_timeout: String,
    settings_checking_ntry: String,
    settings_capacity_factor: String,
    settings_check_route: bool,

    // Auto-refresh timer for server list
    last_server_fetch: Instant,

    // Tick counter for loading animation (wraps on overflow)
    loading_tick: u32,

    // Helper reconnection state
    helper_reconnecting: bool,
    helper_reconnect_at: Instant,
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(views::Tab),
    Connect,
    ConnectToServer(String),
    Disconnect,
    Tick,
    HelperConnected,
    FetchServers,
    ServerClicked(usize),
    ServerSort(views::servers::SortColumn),
    ServerSearchChanged(String),
    ServerCountryFilterChanged(String),
    LogFilterToggle(String),
    LogClear,
    FetchProfile,
    SaveSettings,
    SettingsStartlastToggle(bool),
    SettingsLocklastToggle(bool),
    SettingsIpv6ModeChanged(String),
    SettingsIpv4ModeChanged(String),
    SettingsEntryIfaceChanged(String),
    SettingsDnsChanged(String),
    ShowErrorsToggle(bool),
    ConnectNoLockToggle(bool),
    ConnectAllowLanToggle(bool),
    ConnectNoReconnectToggle(bool),
    ConnectNoVerifyToggle(bool),
    SettingsSubTabChanged(views::settings::SettingsSubTab),
    // WireGuard settings
    SettingsWgKeyChanged(String),
    SettingsWgMtuChanged(String),
    SettingsWgKeepaliveChanged(String),
    SettingsWgHandshakeFirstChanged(String),
    SettingsWgHandshakeConnectedChanged(String),
    // Area filter settings
    SettingsAreasAllowlistChanged(String),
    SettingsAreasDenylistChanged(String),
    // Network Lock settings
    SettingsNetlockIncomingChanged(String),
    SettingsNetlockAllowPingToggle(bool),
    SettingsNetlockAllowlistIpsChanged(String),
    // Routes
    SettingsRoutesCustomChanged(String),
    // DNS settings
    SettingsDnsModeChanged(String),
    SettingsDnsServicesChanged(String),
    // UI display settings
    SettingsUiUnitChanged(String),
    SettingsUiIecToggle(bool),
    // Logging settings
    SettingsLogFileEnabledToggle(bool),
    SettingsLogFilePathChanged(String),
    SettingsLogLevelDebugToggle(bool),
    // Mode settings
    SettingsModePortChanged(String),
    // Advanced settings
    SettingsPingerTimeoutChanged(String),
    SettingsManifestRefreshChanged(String),
    SettingsPenalityChanged(String),
    SettingsHttpTimeoutChanged(String),
    SettingsCheckingNtryChanged(String),
    SettingsCapacityFactorChanged(String),
    SettingsCheckRouteToggle(bool),
    LockInstall,
    LockUninstall,
    LockEnable,
    LockDisable,
    EddieImportAccept,
    EddieImportCancel,
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let app = Self {
            active_tab: views::Tab::Overview,
            connection_state: ConnectionState::Disconnected,
            lock_session: false,
            lock_persistent: false,
            lock_installed: false,
            rx_bytes: 0,
            tx_bytes: 0,
            prev_rx_bytes: 0,
            prev_tx_bytes: 0,
            rx_speed: 0.0,
            tx_speed: 0.0,
            connected_since: None,
            connection_count: 0,
            selected_server: None,
            servers: Vec::new(),
            servers_loading: false,
            selected_server_idx: None,
            server_sort: views::servers::SortColumn::Score,
            server_sort_ascending: true,
            server_search: String::new(),
            server_country_filter: String::new(),
            helper: None,
            error_overview: None,
            error_servers: None,
            error_settings: None,
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            log_filter_debug: false,
            log_filter_info: true,
            log_filter_warn: true,
            log_filter_error: true,
            activity: String::new(),

            settings_credentials_configured: false,
            settings_startlast: false,
            settings_locklast: false,
            settings_ipv6_mode: String::new(),
            settings_ipv4_mode: String::new(),
            settings_entry_iface: String::new(),
            settings_dns: String::new(),
            settings_loaded: false,
            settings_dirty: false,

            show_errors: false,
            eddie_import_pending: None,

            connect_no_lock: false,
            connect_allow_lan: true,
            connect_no_reconnect: false,
            connect_no_verify: false,

            settings_sub_tab: views::settings::SettingsSubTab::General,

            settings_wg_key: String::new(),
            settings_wg_mtu: String::new(),
            settings_wg_keepalive: String::new(),
            settings_wg_handshake_first: String::new(),
            settings_wg_handshake_connected: String::new(),

            settings_netlock_incoming: String::new(),
            settings_netlock_allow_ping: true,
            settings_netlock_allowlist_ips: String::new(),

            settings_routes_custom: String::new(),

            settings_areas_allowlist: String::new(),
            settings_areas_denylist: String::new(),

            settings_dns_mode: String::new(),
            settings_dns_services: String::new(),

            settings_ui_unit: String::new(),
            settings_ui_iec: false,

            settings_log_file_enabled: false,
            settings_log_file_path: String::new(),
            settings_log_level_debug: false,

            settings_mode_port: String::new(),

            settings_pinger_timeout: String::new(),
            settings_manifest_refresh: String::new(),
            settings_penality: String::new(),
            settings_http_timeout: String::new(),
            settings_checking_ntry: String::new(),
            settings_capacity_factor: String::new(),
            settings_check_route: true,

            last_server_fetch: Instant::now(),

            loading_tick: 0,

            helper_reconnecting: false,
            helper_reconnect_at: Instant::now(),
        };

        // With systemd socket activation, the socket always exists.
        // Connecting triggers systemd to start the helper on demand.
        let task = Task::done(Message::HelperConnected);

        (app, task)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                if tab == views::Tab::Servers && self.servers.is_empty() && !self.servers_loading {
                    return Task::done(Message::FetchServers);
                }
                if tab == views::Tab::Settings && !self.settings_loaded {
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
                self.error_overview = None;
                self.connection_state = ConnectionState::Connecting;
                // Fire-and-forget: helper auto-disconnects if needed.
                // Don't block the GUI — state updates arrive via /events stream.
                let req = self.build_connect_request(Some(server_name));
                if let Ok(body) = serde_json::to_vec(&req) {
                    if let Some(ref helper) = self.helper {
                        helper.fire_command("POST", "/connect", Some(&body));
                    }
                }
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
                            // Re-fetch state from the new helper instance
                            // (event stream delivers initial StatusResponse + LockStatus,
                            // but we also need servers/profile if they were loaded)
                            return Task::none();
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
                Task::none()
            }
            Message::HelperConnected => {
                match ipc::HelperClient::connect() {
                    Ok(client) => {
                        self.helper = Some(client);
                        self.helper_reconnecting = false;
                        self.error_overview = None;
                        self.activity.clear();
                        Task::none()
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
                                        if let Ok(servers) = serde_json::from_value::<Vec<ServerInfo>>(arr.clone()) {
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
                    &self.server_country_filter,
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
            Message::ServerCountryFilterChanged(country) => {
                self.server_country_filter = country;
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
                    options.insert(options::SERVERS_STARTLAST.into(), self.settings_startlast.to_string());
                    options.insert(options::SERVERS_LOCKLAST.into(), self.settings_locklast.to_string());
                    options.insert(options::NETWORK_IPV6_MODE.into(), self.settings_ipv6_mode.clone());
                    options.insert(options::NETWORK_IPV4_MODE.into(), self.settings_ipv4_mode.clone());
                    options.insert(options::NETWORK_ENTRY_IFACE.into(), self.settings_entry_iface.clone());
                    options.insert(options::DNS_SERVERS.into(), self.settings_dns.clone());
                    // Connection flags (saved as positive option names)
                    options.insert(options::NETLOCK.into(), (!self.connect_no_lock).to_string());
                    options.insert(options::NETLOCK_ALLOW_PRIVATE.into(), self.connect_allow_lan.to_string());
                    options.insert(options::RECONNECT.into(), (!self.connect_no_reconnect).to_string());
                    options.insert(options::VERIFY.into(), (!self.connect_no_verify).to_string());
                    // WireGuard settings
                    options.insert(options::KEY.into(), self.settings_wg_key.clone());
                    options.insert(options::WG_MTU.into(), self.settings_wg_mtu.clone());
                    options.insert(options::WG_KEEPALIVE.into(), self.settings_wg_keepalive.clone());
                    options.insert(options::WG_HANDSHAKE_FIRST.into(), self.settings_wg_handshake_first.clone());
                    options.insert(options::WG_HANDSHAKE_CONNECTED.into(), self.settings_wg_handshake_connected.clone());
                    // Area filter settings
                    options.insert(options::AREAS_ALLOWLIST.into(), self.settings_areas_allowlist.clone());
                    options.insert(options::AREAS_DENYLIST.into(), self.settings_areas_denylist.clone());
                    // Network Lock settings
                    options.insert(options::NETLOCK_INCOMING.into(), self.settings_netlock_incoming.clone());
                    options.insert(options::NETLOCK_ALLOW_PING.into(), self.settings_netlock_allow_ping.to_string());
                    options.insert(options::NETLOCK_ALLOWLIST_IPS.into(), self.settings_netlock_allowlist_ips.clone());
                    // Routes
                    options.insert(options::ROUTES_CUSTOM.into(), self.settings_routes_custom.clone());
                    // DNS settings
                    options.insert(options::DNS_MODE.into(), self.settings_dns_mode.clone());
                    options.insert(options::LINUX_DNS_SERVICES.into(), self.settings_dns_services.clone());
                    // UI display settings
                    options.insert(options::UI_UNIT.into(), self.settings_ui_unit.clone());
                    options.insert(options::UI_IEC.into(), self.settings_ui_iec.to_string());
                    // Logging settings
                    options.insert(options::LOG_FILE_ENABLED.into(), self.settings_log_file_enabled.to_string());
                    options.insert(options::LOG_FILE_PATH.into(), self.settings_log_file_path.clone());
                    options.insert(options::LOG_LEVEL_DEBUG.into(), self.settings_log_level_debug.to_string());
                    // Mode settings
                    options.insert(options::MODE_PORT.into(), self.settings_mode_port.clone());
                    // Advanced settings
                    options.insert(options::PINGER_TIMEOUT.into(), self.settings_pinger_timeout.clone());
                    options.insert(options::MANIFEST_REFRESH.into(), self.settings_manifest_refresh.clone());
                    options.insert(options::PENALITY_ON_ERROR.into(), self.settings_penality.clone());
                    options.insert(options::HTTP_TIMEOUT.into(), self.settings_http_timeout.clone());
                    options.insert(options::CHECKING_NTRY.into(), self.settings_checking_ntry.clone());
                    options.insert(options::SERVERS_CAPACITY_FACTOR.into(), self.settings_capacity_factor.clone());
                    options.insert(options::CHECK_ROUTE.into(), self.settings_check_route.to_string());
                    let req = SaveProfileRequest { options };
                    match serde_json::to_vec(&req) {
                        Ok(body) => match helper.send_command("POST", "/profile", Some(&body)) {
                            Ok((status, _body)) => {
                                if status == 200 {
                                    self.settings_dirty = false;
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
            Message::SettingsStartlastToggle(val) => {
                self.settings_startlast = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsLocklastToggle(val) => {
                self.settings_locklast = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsIpv6ModeChanged(val) => {
                self.settings_ipv6_mode = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsIpv4ModeChanged(val) => {
                self.settings_ipv4_mode = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsEntryIfaceChanged(val) => {
                self.settings_entry_iface = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsDnsChanged(val) => {
                self.settings_dns = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::ShowErrorsToggle(val) => {
                self.show_errors = val;
                Task::none()
            }
            Message::SettingsSubTabChanged(tab) => {
                self.settings_sub_tab = tab;
                Task::none()
            }
            Message::SettingsWgKeyChanged(val) => {
                self.settings_wg_key = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsWgMtuChanged(val) => {
                self.settings_wg_mtu = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsWgKeepaliveChanged(val) => {
                self.settings_wg_keepalive = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsWgHandshakeFirstChanged(val) => {
                self.settings_wg_handshake_first = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsWgHandshakeConnectedChanged(val) => {
                self.settings_wg_handshake_connected = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsAreasAllowlistChanged(val) => {
                self.settings_areas_allowlist = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsAreasDenylistChanged(val) => {
                self.settings_areas_denylist = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsNetlockIncomingChanged(val) => {
                self.settings_netlock_incoming = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsNetlockAllowPingToggle(val) => {
                self.settings_netlock_allow_ping = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsNetlockAllowlistIpsChanged(val) => {
                self.settings_netlock_allowlist_ips = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsRoutesCustomChanged(val) => {
                self.settings_routes_custom = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsPingerTimeoutChanged(val) => {
                self.settings_pinger_timeout = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsManifestRefreshChanged(val) => {
                self.settings_manifest_refresh = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsPenalityChanged(val) => {
                self.settings_penality = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsHttpTimeoutChanged(val) => {
                self.settings_http_timeout = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsCheckingNtryChanged(val) => {
                self.settings_checking_ntry = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsCapacityFactorChanged(val) => {
                self.settings_capacity_factor = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsCheckRouteToggle(val) => {
                self.settings_check_route = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsDnsModeChanged(val) => {
                self.settings_dns_mode = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsDnsServicesChanged(val) => {
                self.settings_dns_services = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsUiUnitChanged(val) => {
                self.settings_ui_unit = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsUiIecToggle(val) => {
                self.settings_ui_iec = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsLogFileEnabledToggle(val) => {
                self.settings_log_file_enabled = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsLogFilePathChanged(val) => {
                self.settings_log_file_path = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsLogLevelDebugToggle(val) => {
                self.settings_log_level_debug = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsModePortChanged(val) => {
                self.settings_mode_port = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::ConnectNoLockToggle(val) => {
                self.connect_no_lock = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::ConnectAllowLanToggle(val) => {
                self.connect_allow_lan = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::ConnectNoReconnectToggle(val) => {
                self.connect_no_reconnect = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::ConnectNoVerifyToggle(val) => {
                self.connect_no_verify = val;
                self.settings_dirty = true;
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
                    if helper.send_command("POST", "/import-eddie", Some(import_body)).is_err() {
                        self.enter_reconnection();
                        return Task::none();
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

    fn handle_helper_event(&mut self, event: HelperEvent) {
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
                self.settings_credentials_configured = credentials_configured;
                self.settings_startlast = options.get(options::SERVERS_STARTLAST)
                    .map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
                self.settings_locklast = options.get(options::SERVERS_LOCKLAST)
                    .map(|v| v.eq_ignore_ascii_case("true")).unwrap_or(false);
                self.settings_ipv6_mode = options.get(options::NETWORK_IPV6_MODE)
                    .cloned().unwrap_or_else(|| "in-block".into());
                self.settings_ipv4_mode = options.get(options::NETWORK_IPV4_MODE)
                    .cloned().unwrap_or_else(|| "in".into());
                self.settings_entry_iface = options.get(options::NETWORK_ENTRY_IFACE)
                    .cloned().unwrap_or_default();
                self.settings_dns = options.get(options::DNS_SERVERS).cloned().unwrap_or_default();

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
                self.settings_wg_key = options.get(options::KEY)
                    .cloned().unwrap_or_else(|| "Default".into());
                self.settings_wg_mtu = options.get(options::WG_MTU)
                    .cloned().unwrap_or_else(|| "1320".into());
                self.settings_wg_keepalive = options.get(options::WG_KEEPALIVE)
                    .cloned().unwrap_or_else(|| "15".into());
                self.settings_wg_handshake_first = options.get(options::WG_HANDSHAKE_FIRST)
                    .cloned().unwrap_or_else(|| "50".into());
                self.settings_wg_handshake_connected = options.get(options::WG_HANDSHAKE_CONNECTED)
                    .cloned().unwrap_or_else(|| "200".into());

                // Area filter settings
                self.settings_areas_allowlist = options.get(options::AREAS_ALLOWLIST)
                    .cloned().unwrap_or_default();
                self.settings_areas_denylist = options.get(options::AREAS_DENYLIST)
                    .cloned().unwrap_or_default();

                // Network Lock settings
                self.settings_netlock_incoming = options.get(options::NETLOCK_INCOMING)
                    .cloned().unwrap_or_else(|| "block".into());
                self.settings_netlock_allow_ping = options.get(options::NETLOCK_ALLOW_PING)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true);
                self.settings_netlock_allowlist_ips = options.get(options::NETLOCK_ALLOWLIST_IPS)
                    .cloned().unwrap_or_default();

                // Routes
                self.settings_routes_custom = options.get(options::ROUTES_CUSTOM)
                    .cloned().unwrap_or_default();

                // DNS settings
                self.settings_dns_mode = options.get(options::DNS_MODE)
                    .cloned().unwrap_or_else(|| "auto".into());
                self.settings_dns_services = options.get(options::LINUX_DNS_SERVICES)
                    .cloned().unwrap_or_else(|| "nscd,dnsmasq,named,bind9".into());

                // UI display settings
                self.settings_ui_unit = options.get(options::UI_UNIT)
                    .cloned().unwrap_or_else(|| "bytes".into());
                self.settings_ui_iec = options.get(options::UI_IEC)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                // Logging settings
                self.settings_log_file_enabled = options.get(options::LOG_FILE_ENABLED)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                self.settings_log_file_path = options.get(options::LOG_FILE_PATH)
                    .cloned().unwrap_or_else(|| "/var/log/airvpn-rs/helper.log".into());
                self.settings_log_level_debug = options.get(options::LOG_LEVEL_DEBUG)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);

                // Mode settings
                self.settings_mode_port = options.get(options::MODE_PORT)
                    .cloned().unwrap_or_default();

                // Advanced settings
                self.settings_pinger_timeout = options.get(options::PINGER_TIMEOUT)
                    .cloned().unwrap_or_else(|| "3".into());
                self.settings_manifest_refresh = options.get(options::MANIFEST_REFRESH)
                    .cloned().unwrap_or_else(|| "1800".into());
                self.settings_penality = options.get(options::PENALITY_ON_ERROR)
                    .cloned().unwrap_or_else(|| "30".into());
                self.settings_http_timeout = options.get(options::HTTP_TIMEOUT)
                    .cloned().unwrap_or_else(|| "10".into());
                self.settings_checking_ntry = options.get(options::CHECKING_NTRY)
                    .cloned().unwrap_or_else(|| "3".into());
                self.settings_capacity_factor = options.get(options::SERVERS_CAPACITY_FACTOR)
                    .cloned().unwrap_or_else(|| "0".into());
                self.settings_check_route = options.get(options::CHECK_ROUTE)
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(true);

                self.settings_loaded = true;
                self.settings_dirty = false;
            }
            HelperEvent::ProfileSaved => {
                self.settings_dirty = false;
            }
        }
    }

    /// Enter reconnection mode after a send_command I/O error.
    /// Drops the dead HelperClient so the next attempt creates a fresh connection
    /// (which triggers systemd socket activation to respawn the helper).
    fn enter_reconnection(&mut self) {
        eprintln!("[GUI] Helper connection lost, entering reconnection mode");
        self.helper = None;
        self.helper_reconnecting = true;
        self.helper_reconnect_at = Instant::now() + Duration::from_secs(1);
        self.activity = "Reconnecting to helper...".into();
    }

    /// Send a lock command and update local lock state from the response.
    fn handle_lock_command(&mut self, path: &str) {
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
    fn build_connect_request(&self, server: Option<String>) -> ConnectRequest {
        let mut overrides = HashMap::new();
        // Always send current GUI state as overrides — resolve() handles layering
        overrides.insert(options::NETLOCK.into(), (!self.connect_no_lock).to_string());
        overrides.insert(options::NETLOCK_ALLOW_PRIVATE.into(), self.connect_allow_lan.to_string());
        overrides.insert(options::RECONNECT.into(), (!self.connect_no_reconnect).to_string());
        overrides.insert(options::VERIFY.into(), (!self.connect_no_verify).to_string());
        if !self.settings_ipv6_mode.is_empty() {
            overrides.insert(options::NETWORK_IPV6_MODE.into(), self.settings_ipv6_mode.clone());
        }
        if !self.settings_ipv4_mode.is_empty() {
            overrides.insert(options::NETWORK_IPV4_MODE.into(), self.settings_ipv4_mode.clone());
        }
        if !self.settings_entry_iface.is_empty() {
            overrides.insert(options::NETWORK_ENTRY_IFACE.into(), self.settings_entry_iface.clone());
        }
        if !self.settings_dns.is_empty() {
            overrides.insert(options::DNS_SERVERS.into(), self.settings_dns.clone());
        }
        ConnectRequest { server, overrides }
    }

    /// Send POST /connect via HTTP. Handles 409 Eddie import by auto-accepting and retrying.
    fn send_connect(&mut self, server: Option<String>) {
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
                } else if status != 200 {
                    self.error_overview = Some(format!("Connect failed (HTTP {}): {}", status, resp_body));
                }
                // 200 = connect started, events arrive via /events stream
            }
            Err(_) => {
                self.enter_reconnection();
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        // Left sidebar: tab buttons with active accent
        let mut sidebar = column![].spacing(theme::SPACE_SM).width(theme::SIDEBAR_WIDTH);
        for tab in views::Tab::all() {
            let is_active = *tab == self.active_tab;
            let label = text(tab.label()).size(15);
            let mut btn = button(label).width(Fill).padding([10, 16]);
            if is_active {
                btn = btn.style(theme::sidebar_tab_active);
            } else {
                btn = btn.on_press(Message::TabSelected(*tab))
                    .style(theme::sidebar_tab_inactive);
            }
            sidebar = sidebar.push(btn);
        }
        let sidebar = container(sidebar)
            .padding([theme::SPACE_MD, theme::SPACE_SM + 4.0])
            .style(theme::sidebar);

        // Right content area
        let content: Element<Message> = match self.active_tab {
            views::Tab::Overview => views::overview::view(
                &self.connection_state,
                self.lock_session,
                self.lock_persistent,
                self.lock_installed,
                self.rx_bytes,
                self.tx_bytes,
                self.rx_speed,
                self.tx_speed,
                self.connected_since,
                self.connection_count,
                &self.selected_server,
                self.settings_startlast,
                &self.activity,
                &self.eddie_import_pending,
                views::overview::UnitConfig::from_options(&self.settings_ui_unit, &self.settings_ui_iec.to_string()),
            ),
            views::Tab::Servers => views::servers::view(
                &self.servers,
                self.servers_loading,
                self.loading_tick,
                self.selected_server_idx,
                self.server_sort,
                self.server_sort_ascending,
                &self.server_search,
                &self.server_country_filter,
                &self.connection_state,
            ),
            views::Tab::Logs => views::logs::view(
                &self.logs,
                self.log_filter_debug,
                self.log_filter_info,
                self.log_filter_warn,
                self.log_filter_error,
            ),
            views::Tab::Settings => views::settings::view(
                self.settings_credentials_configured,
                self.settings_startlast,
                self.settings_locklast,
                &self.settings_ipv6_mode,
                &self.settings_ipv4_mode,
                &self.settings_entry_iface,
                &self.settings_dns,
                self.settings_loaded,
                self.settings_dirty,
                self.show_errors,
                self.connect_no_lock,
                self.connect_allow_lan,
                self.connect_no_reconnect,
                self.connect_no_verify,
                self.lock_installed,
                self.lock_persistent,
                self.settings_sub_tab,
                // WireGuard
                &self.settings_wg_key,
                &self.settings_wg_mtu,
                &self.settings_wg_keepalive,
                &self.settings_wg_handshake_first,
                &self.settings_wg_handshake_connected,
                // Network Lock
                &self.settings_netlock_incoming,
                self.settings_netlock_allow_ping,
                &self.settings_netlock_allowlist_ips,
                // Routes
                &self.settings_routes_custom,
                // Area filters
                &self.settings_areas_allowlist,
                &self.settings_areas_denylist,
                // DNS settings
                &self.settings_dns_mode,
                &self.settings_dns_services,
                // UI display settings
                &self.settings_ui_unit,
                self.settings_ui_iec,
                // Logging settings
                self.settings_log_file_enabled,
                &self.settings_log_file_path,
                self.settings_log_level_debug,
                // Mode settings
                &self.settings_mode_port,
                // Advanced
                &self.settings_pinger_timeout,
                &self.settings_manifest_refresh,
                &self.settings_penality,
                &self.settings_http_timeout,
                &self.settings_checking_ntry,
                &self.settings_capacity_factor,
                self.settings_check_route,
            ),
        };
        // Per-tab error display (inline at top of content area, only when show_errors is on)
        let tab_error = if self.show_errors {
            match self.active_tab {
                views::Tab::Overview => self.error_overview.as_deref(),
                views::Tab::Servers => self.error_servers.as_deref(),
                views::Tab::Settings => self.error_settings.as_deref(),
                views::Tab::Logs => None,
            }
        } else {
            None
        };

        let content_with_error: Element<Message> = if let Some(err) = tab_error {
            let err_banner = container(
                text(err).size(13).color(theme::DANGER)
            )
            .padding([8, 12])
            .width(Fill)
            .style(|_theme: &iced::Theme| container::Style {
                background: Some(iced::Background::Color(iced::Color { r: 0.35, g: 0.12, b: 0.12, a: 1.0 })),
                border: iced::Border { radius: theme::RADIUS_MD.into(), ..Default::default() },
                ..Default::default()
            });
            column![err_banner, content].spacing(theme::SPACE_MD).into()
        } else {
            content
        };

        let content = container(content_with_error)
            .padding(theme::SPACE_LG)
            .width(Fill);

        row![sidebar, content]
            .height(Fill)
            .spacing(0)
            .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        if self.helper.is_some() || self.helper_reconnecting {
            time::every(Duration::from_millis(100)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }
}
