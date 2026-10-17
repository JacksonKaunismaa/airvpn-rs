mod app_view;
mod icons;
mod ipc;
mod message;
mod theme;
mod update;
mod views;

pub use message::*;

use iced::{Size, Subscription, Task};
use iced::time;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

const MAX_LOG_ENTRIES: usize = 10_000;

use airvpn::ipc::{ConnectionState, ServerInfo};

fn main() -> iced::Result {
    eprintln!("[GUI] Starting airvpn-gui (built {})", env!("CARGO_PKG_VERSION"));
    let mut app = iced::application(App::boot, App::update, App::view)
        .title("AirVPN")
        .theme(App::theme)
        .subscription(App::subscription)
        .window_size(Size::new(900.0, 600.0))
        .centered();
    for font in theme::FONT_FILES {
        app = app.font(font);
    }
    app.default_font(theme::FONT).run()
}

struct App {
    active_tab: views::Tab,
    /// Light/dark variant: follows the system unless `AIRVPN_THEME` pins it.
    theme_mode: iced::theme::Mode,
    theme_pinned: bool,
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
    error_overview: Option<String>,
    error_servers: Option<String>,
    error_settings: Option<String>,
    logs: VecDeque<LogEntry>,
    log_filter_debug: bool,
    log_filter_info: bool,
    log_filter_warn: bool,
    log_filter_error: bool,
    activity: String,

    // Profile-backed settings
    settings: SettingsState,

    // GUI-only toggles (not persisted)
    show_errors: bool,

    // Eddie import confirmation (Some = dialog visible with profile path)
    eddie_import_pending: Option<String>,

    // Connection settings (profile-backed)
    connect_no_lock: bool,
    connect_allow_lan: bool,
    connect_no_reconnect: bool,
    connect_no_verify: bool,

    /// Available WireGuard key names from helper (for device dropdown).
    available_keys: Vec<String>,

    // Auto-refresh timer for server list
    last_server_fetch: Instant,

    // Throttle for re-fetching the device/key list while it's still empty
    // (the helper's background loop populates it a few seconds after startup).
    last_keys_fetch: Instant,

    // Tick counter for loading animation (wraps on overflow)
    loading_tick: u32,

    // Helper reconnection state
    helper_reconnecting: bool,
    helper_reconnect_at: Instant,
}

impl App {
    fn boot() -> (Self, Task<Message>) {
        let pinned = theme::env_override();
        let app = Self {
            active_tab: views::Tab::Overview,
            theme_mode: pinned.unwrap_or(iced::theme::Mode::Dark),
            theme_pinned: pinned.is_some(),
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
            error_overview: None,
            error_servers: None,
            error_settings: None,
            logs: VecDeque::with_capacity(MAX_LOG_ENTRIES),
            log_filter_debug: false,
            log_filter_info: true,
            log_filter_warn: true,
            log_filter_error: true,
            activity: String::new(),

            settings: SettingsState::default(),

            show_errors: false,
            eddie_import_pending: None,

            connect_no_lock: false,
            connect_allow_lan: true,
            connect_no_reconnect: false,
            connect_no_verify: false,

            available_keys: Vec::new(),

            last_server_fetch: Instant::now(),
            last_keys_fetch: Instant::now(),

            loading_tick: 0,

            helper_reconnecting: false,
            helper_reconnect_at: Instant::now(),
        };

        // With systemd socket activation, the socket always exists.
        // Connecting triggers systemd to start the helper on demand.
        let mut task = Task::done(Message::HelperConnected);
        if !app.theme_pinned {
            task = Task::batch([task, iced::system::theme().map(Message::ThemeChanged)]);
        }

        (app, task)
    }

    fn theme(&self) -> iced::Theme {
        theme::theme_for(self.theme_mode)
    }

    fn subscription(&self) -> Subscription<Message> {
        let tick = if self.helper.is_some() || self.helper_reconnecting {
            time::every(Duration::from_millis(100)).map(|_| Message::Tick)
        } else {
            Subscription::none()
        };
        let system_theme = if self.theme_pinned {
            Subscription::none()
        } else {
            iced::system::theme_changes().map(Message::ThemeChanged)
        };
        Subscription::batch([tick, system_theme])
    }
}
