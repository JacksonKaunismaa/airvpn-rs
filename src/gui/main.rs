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
    helper_launched: bool,
    logs: Vec<LogEntry>,
    log_filter_debug: bool,
    log_filter_info: bool,
    log_filter_warn: bool,
    log_filter_error: bool,
    activity: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(views::Tab),
    Connect,
    ConnectToServer(String),
    Disconnect,
    Tick,
    LaunchHelper,
    HelperConnected,
    FetchServers,
    ServerClicked(usize),
    ServerSort(views::servers::SortColumn),
    ServerSearchChanged(String),
    LogFilterToggle(String),
    LogClear,
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
            helper_launched: false,
            logs: Vec::new(),
            log_filter_debug: false,
            log_filter_info: true,
            log_filter_warn: true,
            log_filter_error: true,
            activity: String::new(),
        };

        // Try connecting to an existing helper. If the socket doesn't exist,
        // go straight to launching one (don't waste time on a failed connect).
        let task = if std::path::Path::new("/run/airvpn-rs/helper.sock").exists() {
            Task::done(Message::HelperConnected)
        } else {
            Task::done(Message::LaunchHelper)
        };

        (app, task)
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::TabSelected(tab) => {
                self.active_tab = tab;
                if tab == views::Tab::Servers && self.servers.is_empty() && !self.servers_loading {
                    return Task::done(Message::FetchServers);
                }
                Task::none()
            }
            Message::Connect => {
                if let Some(ref mut helper) = self.helper {
                    let cmd = HelperCommand::Connect {
                        server: None,
                        no_lock: false,
                        allow_lan: true,
                        skip_ping: false,
                        allow_country: Vec::new(),
                        deny_country: Vec::new(),
                    };
                    if let Err(e) = helper.send(&cmd) {
                        self.helper_error = Some(format!("Failed to send Connect: {}", e));
                    }
                }
                Task::none()
            }
            Message::ConnectToServer(server_name) => {
                self.selected_server = Some(server_name.clone());
                if let Some(ref mut helper) = self.helper {
                    let cmd = HelperCommand::Connect {
                        server: Some(server_name),
                        no_lock: false,
                        allow_lan: true,
                        skip_ping: true,
                        allow_country: Vec::new(),
                        deny_country: Vec::new(),
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
            Message::LaunchHelper => {
                self.helper_launched = true;
                self.helper_error = None;
                self.activity = "Launching helper (waiting for authentication)...".into();
                match ipc::launch_helper() {
                    Ok(_child) => {
                        // Poll for the socket to appear. pkexec blocks for password
                        // input, so 500ms is not enough. Poll every 500ms for up to 60s.
                        Task::future(async {
                            let socket = std::path::Path::new("/run/airvpn-rs/helper.sock");
                            for _ in 0..120 {
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                if socket.exists() {
                                    // Give it a moment to start accepting
                                    tokio::time::sleep(Duration::from_millis(200)).await;
                                    return Message::HelperConnected;
                                }
                            }
                            Message::HelperConnected // try anyway after timeout
                        })
                    }
                    Err(e) => {
                        self.activity.clear();
                        self.helper_error =
                            Some(format!("Failed to launch helper: {}", e));
                        Task::none()
                    }
                }
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
                        if !self.helper_launched {
                            // First failure — automatically try launching a helper
                            Task::done(Message::LaunchHelper)
                        } else {
                            // Already tried launching — show error with retry
                            self.helper_error = Some(format!(
                                "Cannot connect to helper: {}. Click Retry.", e
                            ));
                            Task::none()
                        }
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
            HelperEvent::Shutdown => {
                self.helper = None;
                self.connection_state = ConnectionState::Disconnected;
            }
            HelperEvent::ServerList { servers } => {
                self.servers = servers;
                self.servers_loading = false;
            }
            HelperEvent::Profile { .. } | HelperEvent::ProfileSaved => {
                // Handled by Settings tab (M2)
            }
        }
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
            views::Tab::Settings => text("Settings tab — coming soon").into(),
        };
        let content = container(content).padding(16).width(Fill);

        // Error banner
        let mut main_col = column![];
        if let Some(ref err) = self.helper_error {
            let banner = container(
                row![
                    text(format!("Error: {}", err)).color(iced::Color::from_rgb(0.91, 0.27, 0.38)),
                    Space::new().width(Fill),
                    button(text("Retry")).on_press(Message::LaunchHelper),
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
