mod ipc;
mod theme;
mod views;

use iced::widget::{button, column, container, row, text, Space};
use iced::{Element, Fill, Size, Subscription, Task};
use iced::time;
use std::time::Duration;

use airvpn::ipc::{ConnectionState, HelperCommand, HelperEvent};

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
    helper: Option<ipc::HelperClient>,
    helper_error: Option<String>,
    logs: Vec<String>,
    activity: String,
}

#[derive(Debug, Clone)]
pub enum Message {
    TabSelected(views::Tab),
    Connect,
    Disconnect,
    Tick,
    LaunchHelper,
    HelperConnected,
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
            helper: None,
            helper_error: None,
            logs: Vec::new(),
            activity: String::new(),
        };

        // Check if helper is already running
        let task = if ipc::is_helper_running() {
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
                match ipc::launch_helper() {
                    Ok(_child) => {
                        // Give the helper time to start and create its socket
                        Task::future(async {
                            tokio::time::sleep(Duration::from_millis(500)).await;
                            Message::HelperConnected
                        })
                    }
                    Err(e) => {
                        self.helper_error =
                            Some(format!("Failed to launch helper: {}", e));
                        Task::none()
                    }
                }
            }
            Message::HelperConnected => {
                match ipc::HelperClient::connect() {
                    Ok(mut client) => {
                        // Request initial status (connection state + lock state)
                        let _ = client.send(&HelperCommand::Status);
                        self.helper = Some(client);
                        self.helper_error = None;
                    }
                    Err(e) => {
                        self.helper_error =
                            Some(format!("Failed to connect to helper: {}", e));
                    }
                }
                Task::none()
            }
        }
    }

    fn handle_helper_event(&mut self, event: HelperEvent) {
        match event {
            HelperEvent::StateChanged { state } => {
                // Clear activity text on terminal states
                if matches!(state, ConnectionState::Connected { .. } | ConnectionState::Disconnected) {
                    self.activity.clear();
                }
                self.connection_state = state;
            }
            HelperEvent::Log { level, message } => {
                self.activity = message.clone();
                self.logs.push(format!("[{}] {}", level, message));
            }
            HelperEvent::Stats { rx_bytes, tx_bytes } => {
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
                self.rx_bytes,
                self.tx_bytes,
                &self.activity,
            ),
            views::Tab::Servers => text("Servers tab — coming soon").into(),
            views::Tab::Speed => text("Speed tab — coming soon").into(),
            views::Tab::Logs => {
                let mut log_col = column![].spacing(4);
                for entry in &self.logs {
                    log_col = log_col.push(text(entry).size(12));
                }
                if self.logs.is_empty() {
                    log_col = log_col.push(text("No log entries yet."));
                }
                log_col.into()
            }
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
