mod ipc;
mod theme;
mod views;

use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Fill, Size, Subscription, Task};
use iced::time;
use std::time::Duration;

use airvpn::ipc::{ConnectionState, HelperCommand, HelperEvent, ServerInfo};

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

fn main() -> iced::Result {
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
    helper: Option<ipc::HelperClient>,
    helper_error: Option<String>,
    logs: Vec<LogEntry>,
    log_filter_debug: bool,
    log_filter_info: bool,
    log_filter_warn: bool,
    log_filter_error: bool,
    activity: String,

    // Profile-backed settings (loaded via GetProfile, saved via SaveProfile)
    settings_username: String,
    settings_password: String,
    settings_startlast: bool,
    settings_locklast: bool,
    settings_ipv6_mode: String,
    settings_dns: String,
    settings_event_pre_file: String,
    settings_event_pre_args: String,
    settings_event_pre_wait: bool,
    settings_event_up_file: String,
    settings_event_up_args: String,
    settings_event_up_wait: bool,
    settings_event_down_file: String,
    settings_event_down_args: String,
    settings_event_down_wait: bool,
    settings_loaded: bool,
    settings_dirty: bool,

    // Per-connect flags (not profile-backed)
    connect_no_lock: bool,
    connect_allow_lan: bool,
    connect_no_reconnect: bool,
    connect_skip_ping: bool,
    connect_no_verify: bool,
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
    LogFilterToggle(String),
    LogClear,
    FetchProfile,
    SaveSettings,
    SettingsUsernameChanged(String),
    SettingsPasswordChanged(String),
    SettingsStartlastToggle(bool),
    SettingsLocklastToggle(bool),
    SettingsIpv6ModeChanged(String),
    SettingsDnsChanged(String),
    SettingsEventChanged { hook: String, field: String, value: String },
    ConnectNoLockToggle(bool),
    ConnectAllowLanToggle(bool),
    ConnectNoReconnectToggle(bool),
    ConnectSkipPingToggle(bool),
    ConnectNoVerifyToggle(bool),
    LockInstall,
    LockUninstall,
    LockEnable,
    LockDisable,
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
            helper: None,
            helper_error: None,
            logs: Vec::new(),
            log_filter_debug: false,
            log_filter_info: true,
            log_filter_warn: true,
            log_filter_error: true,
            activity: String::new(),

            settings_username: String::new(),
            settings_password: String::new(),
            settings_startlast: false,
            settings_locklast: false,
            settings_ipv6_mode: String::new(),
            settings_dns: String::new(),
            settings_event_pre_file: String::new(),
            settings_event_pre_args: String::new(),
            settings_event_pre_wait: true,
            settings_event_up_file: String::new(),
            settings_event_up_args: String::new(),
            settings_event_up_wait: true,
            settings_event_down_file: String::new(),
            settings_event_down_args: String::new(),
            settings_event_down_wait: true,
            settings_loaded: false,
            settings_dirty: false,

            connect_no_lock: false,
            connect_allow_lan: true,
            connect_no_reconnect: false,
            connect_skip_ping: false,
            connect_no_verify: false,
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
                let ipv6_mode = if self.settings_ipv6_mode.is_empty() { None } else { Some(self.settings_ipv6_mode.clone()) };
                let dns_servers = if self.settings_dns.is_empty() { Vec::new() } else {
                    self.settings_dns.split(',').map(|s| s.trim().to_string()).collect()
                };
                let event_pre = self.build_event_hook(&self.settings_event_pre_file, &self.settings_event_pre_args, self.settings_event_pre_wait);
                let event_up = self.build_event_hook(&self.settings_event_up_file, &self.settings_event_up_args, self.settings_event_up_wait);
                let event_down = self.build_event_hook(&self.settings_event_down_file, &self.settings_event_down_args, self.settings_event_down_wait);
                if let Some(ref mut helper) = self.helper {
                    let cmd = HelperCommand::Connect {
                        server: self.selected_server.clone(),
                        no_lock: self.connect_no_lock,
                        allow_lan: self.connect_allow_lan,
                        skip_ping: self.connect_skip_ping,
                        allow_country: Vec::new(),
                        deny_country: Vec::new(),
                        allow_server: Vec::new(),
                        deny_server: Vec::new(),
                        no_reconnect: self.connect_no_reconnect,
                        no_verify: self.connect_no_verify,
                        no_lock_last: false,
                        no_start_last: false,
                        ipv6_mode,
                        dns_servers,
                        event_pre,
                        event_up,
                        event_down,
                    };
                    if let Err(e) = helper.send(&cmd) {
                        self.helper_error = Some(format!("Failed to send Connect: {}", e));
                    }
                }
                Task::none()
            }
            Message::ConnectToServer(server_name) => {
                self.selected_server = Some(server_name.clone());
                let ipv6_mode = if self.settings_ipv6_mode.is_empty() { None } else { Some(self.settings_ipv6_mode.clone()) };
                let dns_servers = if self.settings_dns.is_empty() { Vec::new() } else {
                    self.settings_dns.split(',').map(|s| s.trim().to_string()).collect()
                };
                let event_pre = self.build_event_hook(&self.settings_event_pre_file, &self.settings_event_pre_args, self.settings_event_pre_wait);
                let event_up = self.build_event_hook(&self.settings_event_up_file, &self.settings_event_up_args, self.settings_event_up_wait);
                let event_down = self.build_event_hook(&self.settings_event_down_file, &self.settings_event_down_args, self.settings_event_down_wait);
                if let Some(ref mut helper) = self.helper {
                    let cmd = HelperCommand::Connect {
                        server: Some(server_name),
                        no_lock: self.connect_no_lock,
                        allow_lan: self.connect_allow_lan,
                        skip_ping: true, // server already chosen
                        allow_country: Vec::new(),
                        deny_country: Vec::new(),
                        allow_server: Vec::new(),
                        deny_server: Vec::new(),
                        no_reconnect: self.connect_no_reconnect,
                        no_verify: self.connect_no_verify,
                        no_lock_last: false,
                        no_start_last: false,
                        ipv6_mode,
                        dns_servers,
                        event_pre,
                        event_up,
                        event_down,
                    };
                    if let Err(e) = helper.send(&cmd) {
                        self.helper_error = Some(format!("Failed to send Connect: {}", e));
                    }
                }
                Task::none()
            }
            Message::Disconnect => {
                if let Some(ref mut helper) = self.helper {
                    if let Err(e) = helper.send(&HelperCommand::Disconnect) {
                        self.helper_error = Some(format!("Failed to send Disconnect: {}", e));
                    }
                }
                Task::none()
            }
            Message::Tick => {
                // Drain events into a vec to avoid borrow conflict
                let events: Vec<_> = self
                    .helper
                    .as_ref()
                    .map(|h| std::iter::from_fn(|| h.try_recv()).collect())
                    .unwrap_or_default();
                for event in events {
                    self.handle_helper_event(event);
                }
                Task::none()
            }
            Message::HelperConnected => {
                match ipc::HelperClient::connect() {
                    Ok(mut client) => {
                        let _ = client.send(&HelperCommand::Status);
                        self.helper = Some(client);
                        self.helper_error = None;
                        self.activity.clear();
                        Task::none()
                    }
                    Err(e) => {
                        eprintln!("[GUI] HelperClient::connect() failed: {}", e);
                        self.helper_error = Some(format!(
                            "Cannot connect to helper: {}\n\
                             Is airvpn-helper.socket enabled?\n\
                             Run: sudo systemctl enable --now airvpn-helper.socket",
                            e
                        ));
                        Task::none()
                    }
                }
            }
            Message::FetchServers => {
                if let Some(ref mut helper) = self.helper {
                    self.servers_loading = true;
                    let cmd = HelperCommand::ListServers { skip_ping: false };
                    if let Err(e) = helper.send(&cmd) {
                        self.servers_loading = false;
                        self.helper_error =
                            Some(format!("Failed to send ListServers: {}", e));
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
            Message::FetchProfile => {
                if let Some(ref mut helper) = self.helper {
                    if let Err(e) = helper.send(&HelperCommand::GetProfile) {
                        self.helper_error = Some(format!("Failed to send GetProfile: {}", e));
                    }
                }
                Task::none()
            }
            Message::SaveSettings => {
                if let Some(ref mut helper) = self.helper {
                    let mut options = std::collections::HashMap::new();
                    options.insert("login".into(), self.settings_username.clone());
                    options.insert("password".into(), self.settings_password.clone());
                    options.insert("servers.startlast".into(), if self.settings_startlast { "True" } else { "False" }.into());
                    options.insert("servers.locklast".into(), if self.settings_locklast { "True" } else { "False" }.into());
                    options.insert("network.ipv6.mode".into(), self.settings_ipv6_mode.clone());
                    options.insert("dns.servers".into(), self.settings_dns.clone());
                    options.insert("event.vpn.pre.filename".into(), self.settings_event_pre_file.clone());
                    options.insert("event.vpn.pre.arguments".into(), self.settings_event_pre_args.clone());
                    options.insert("event.vpn.pre.waitend".into(), if self.settings_event_pre_wait { "True" } else { "False" }.into());
                    options.insert("event.vpn.up.filename".into(), self.settings_event_up_file.clone());
                    options.insert("event.vpn.up.arguments".into(), self.settings_event_up_args.clone());
                    options.insert("event.vpn.up.waitend".into(), if self.settings_event_up_wait { "True" } else { "False" }.into());
                    options.insert("event.vpn.down.filename".into(), self.settings_event_down_file.clone());
                    options.insert("event.vpn.down.arguments".into(), self.settings_event_down_args.clone());
                    options.insert("event.vpn.down.waitend".into(), if self.settings_event_down_wait { "True" } else { "False" }.into());
                    if let Err(e) = helper.send(&HelperCommand::SaveProfile { options }) {
                        self.helper_error = Some(format!("Failed to send SaveProfile: {}", e));
                    }
                }
                Task::none()
            }
            Message::SettingsUsernameChanged(val) => {
                self.settings_username = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsPasswordChanged(val) => {
                self.settings_password = val;
                self.settings_dirty = true;
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
            Message::SettingsDnsChanged(val) => {
                self.settings_dns = val;
                self.settings_dirty = true;
                Task::none()
            }
            Message::SettingsEventChanged { hook, field, value } => {
                match (hook.as_str(), field.as_str()) {
                    ("pre", "file") => self.settings_event_pre_file = value,
                    ("pre", "args") => self.settings_event_pre_args = value,
                    ("pre", "wait") => self.settings_event_pre_wait = value == "true",
                    ("up", "file") => self.settings_event_up_file = value,
                    ("up", "args") => self.settings_event_up_args = value,
                    ("up", "wait") => self.settings_event_up_wait = value == "true",
                    ("down", "file") => self.settings_event_down_file = value,
                    ("down", "args") => self.settings_event_down_args = value,
                    ("down", "wait") => self.settings_event_down_wait = value == "true",
                    _ => {}
                }
                self.settings_dirty = true;
                Task::none()
            }
            Message::ConnectNoLockToggle(val) => {
                self.connect_no_lock = val;
                Task::none()
            }
            Message::ConnectAllowLanToggle(val) => {
                self.connect_allow_lan = val;
                Task::none()
            }
            Message::ConnectNoReconnectToggle(val) => {
                self.connect_no_reconnect = val;
                Task::none()
            }
            Message::ConnectSkipPingToggle(val) => {
                self.connect_skip_ping = val;
                Task::none()
            }
            Message::ConnectNoVerifyToggle(val) => {
                self.connect_no_verify = val;
                Task::none()
            }
            Message::LockInstall => {
                if let Some(ref mut helper) = self.helper {
                    if let Err(e) = helper.send(&HelperCommand::LockInstall) {
                        self.helper_error = Some(format!("Failed to send LockInstall: {}", e));
                    }
                }
                Task::none()
            }
            Message::LockUninstall => {
                if let Some(ref mut helper) = self.helper {
                    if let Err(e) = helper.send(&HelperCommand::LockUninstall) {
                        self.helper_error = Some(format!("Failed to send LockUninstall: {}", e));
                    }
                }
                Task::none()
            }
            Message::LockEnable => {
                if let Some(ref mut helper) = self.helper {
                    if let Err(e) = helper.send(&HelperCommand::LockEnable) {
                        self.helper_error = Some(format!("Failed to send LockEnable: {}", e));
                    }
                }
                Task::none()
            }
            Message::LockDisable => {
                if let Some(ref mut helper) = self.helper {
                    if let Err(e) = helper.send(&HelperCommand::LockDisable) {
                        self.helper_error = Some(format!("Failed to send LockDisable: {}", e));
                    }
                }
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
                self.logs.push(LogEntry {
                    timestamp: format!("{:02}:{:02}:{:02}", h, m, s),
                    level,
                    message,
                });
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
                self.helper_error = Some(message);
            }
            HelperEvent::EddieProfileFound { .. } => {
                // GUI doesn't handle Eddie import yet
            }
            HelperEvent::ServerList { .. } => {
                // CLI text table — GUI ignores this
            }
            HelperEvent::Shutdown => {
                self.helper = None;
                self.connection_state = ConnectionState::Disconnected;
            }
            HelperEvent::ServerListDetailed { servers } => {
                self.servers = servers;
                self.servers_loading = false;
            }
            HelperEvent::Profile { options } => {
                self.settings_username = options.get("login").cloned().unwrap_or_default();
                self.settings_password = options.get("password").cloned().unwrap_or_default();
                self.settings_startlast = options.get("servers.startlast").map(|v| v == "True").unwrap_or(false);
                self.settings_locklast = options.get("servers.locklast").map(|v| v == "True").unwrap_or(false);
                self.settings_ipv6_mode = options.get("network.ipv6.mode").cloned().unwrap_or_else(|| "in-block".into());
                self.settings_dns = options.get("dns.servers").cloned().unwrap_or_default();
                self.settings_event_pre_file = options.get("event.vpn.pre.filename").cloned().unwrap_or_default();
                self.settings_event_pre_args = options.get("event.vpn.pre.arguments").cloned().unwrap_or_default();
                self.settings_event_pre_wait = options.get("event.vpn.pre.waitend").map(|v| v == "True").unwrap_or(true);
                self.settings_event_up_file = options.get("event.vpn.up.filename").cloned().unwrap_or_default();
                self.settings_event_up_args = options.get("event.vpn.up.arguments").cloned().unwrap_or_default();
                self.settings_event_up_wait = options.get("event.vpn.up.waitend").map(|v| v == "True").unwrap_or(true);
                self.settings_event_down_file = options.get("event.vpn.down.filename").cloned().unwrap_or_default();
                self.settings_event_down_args = options.get("event.vpn.down.arguments").cloned().unwrap_or_default();
                self.settings_event_down_wait = options.get("event.vpn.down.waitend").map(|v| v == "True").unwrap_or(true);
                self.settings_loaded = true;
                self.settings_dirty = false;
            }
            HelperEvent::ProfileSaved => {
                self.settings_dirty = false;
            }
        }
    }

    /// Build an event hook array [filename, arguments, waitend] from settings.
    fn build_event_hook(&self, file: &str, args: &str, wait: bool) -> [Option<String>; 3] {
        [
            if file.is_empty() { None } else { Some(file.to_string()) },
            if args.is_empty() { None } else { Some(args.to_string()) },
            if wait { Some("True".into()) } else { None },
        ]
    }

    fn view(&self) -> Element<'_, Message> {
        // Left sidebar: tab buttons
        let mut sidebar = column![].spacing(4).width(180);
        for tab in views::Tab::all() {
            let is_active = *tab == self.active_tab;
            let label = text(tab.label()).size(16);
            let mut btn = button(label).width(Fill);
            if !is_active {
                btn = btn.on_press(Message::TabSelected(*tab));
            }
            sidebar = sidebar.push(btn);
        }
        let sidebar = container(sidebar).padding(8);

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
                &self.activity,
            ),
            views::Tab::Servers => views::servers::view(
                &self.servers,
                self.servers_loading,
                self.selected_server_idx,
                self.server_sort,
                self.server_sort_ascending,
                &self.server_search,
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
                &self.settings_username,
                &self.settings_password,
                self.settings_startlast,
                self.settings_locklast,
                &self.settings_ipv6_mode,
                &self.settings_dns,
                (&self.settings_event_pre_file, &self.settings_event_pre_args, self.settings_event_pre_wait),
                (&self.settings_event_up_file, &self.settings_event_up_args, self.settings_event_up_wait),
                (&self.settings_event_down_file, &self.settings_event_down_args, self.settings_event_down_wait),
                self.settings_loaded,
                self.settings_dirty,
                self.connect_no_lock,
                self.connect_allow_lan,
                self.connect_no_reconnect,
                self.connect_skip_ping,
                self.connect_no_verify,
                self.lock_installed,
                self.lock_persistent,
            ),
        };
        let content = container(content).padding(16).width(Fill);

        // Error banner
        let mut main_col = column![];
        if let Some(ref err) = self.helper_error {
            let banner = container(
                row![
                    text(format!("Error: {}", err)).color(iced::Color::from_rgb(0.91, 0.27, 0.38)),
                    Space::new().width(Fill),
                    button(text("Retry")).on_press(Message::HelperConnected),
                ]
                .spacing(8),
            )
            .padding(8);
            main_col = main_col.push(banner);
        }

        main_col = main_col.push(
            row![sidebar, content]
                .height(Fill)
                .spacing(0),
        );

        container(main_col)
            .width(Fill)
            .height(Fill)
            .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        if self.helper.is_some() {
            time::every(Duration::from_millis(100)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        }
    }
}
