//! Overview tab: connection status, connect/disconnect, stats, lock status.

use iced::widget::{button, column, row, text};
use iced::Element;

use airvpn::ipc::ConnectionState;

use crate::Message;

/// Render the overview tab.
pub fn view<'a>(
    connection_state: &ConnectionState,
    lock_session: bool,
    lock_persistent: bool,
    lock_installed: bool,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_speed: f64,
    tx_speed: f64,
    connected_since: Option<std::time::Instant>,
    connection_count: u32,
    selected_server: &Option<String>,
    activity: &'a str,
) -> Element<'a, Message> {
    let mut content = column![].spacing(12);

    // Status line with color indication
    let (status_text, status_color) = match connection_state {
        ConnectionState::Disconnected => ("Disconnected", iced::Color::from_rgb(0.91, 0.27, 0.38)),
        ConnectionState::Connecting => ("Connecting...", iced::Color::from_rgb(0.95, 0.61, 0.07)),
        ConnectionState::Connected { .. } => ("Connected", iced::Color::from_rgb(0.18, 0.80, 0.44)),
        ConnectionState::Reconnecting => {
            ("Reconnecting...", iced::Color::from_rgb(0.95, 0.61, 0.07))
        }
        ConnectionState::Disconnecting => {
            ("Disconnecting...", iced::Color::from_rgb(0.95, 0.61, 0.07))
        }
    };

    content = content.push(text(status_text).size(24).color(status_color));

    // Server info when connected
    if let ConnectionState::Connected {
        server_name,
        server_country,
        server_location,
    } = connection_state
    {
        content = content.push(text(format!(
            "Server: {} ({}, {})",
            server_name, server_location, server_country
        )));
    }

    // Uptime when connected
    if let Some(since) = connected_since {
        let elapsed = since.elapsed();
        let total_secs = elapsed.as_secs();
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
        content = content.push(text(format!("Uptime: {:02}:{:02}:{:02}", hours, minutes, seconds)));
    }

    // Activity status line (shows what's happening during connect)
    if !activity.is_empty() {
        content = content.push(
            text(activity)
                .size(14)
                .color(iced::Color::from_rgb(0.53, 0.57, 0.63)),
        );
    }

    // Connect / Disconnect button
    let is_transitioning = matches!(
        connection_state,
        ConnectionState::Connecting | ConnectionState::Reconnecting | ConnectionState::Disconnecting
    );

    match connection_state {
        ConnectionState::Connected { .. } => {
            let mut btn = button(text("Disconnect"));
            if !is_transitioning {
                btn = btn.on_press(Message::Disconnect);
            }
            content = content.push(btn);
        }
        _ => {
            let connect_label = match selected_server {
                Some(server) => format!("Connect to {}", server),
                None => "Connect".to_string(),
            };
            let mut btn = button(text(connect_label));
            if !is_transitioning {
                btn = btn.on_press(Message::Connect);
            }
            content = content.push(btn);
        }
    }

    // Transfer stats and speed when connected
    if matches!(connection_state, ConnectionState::Connected { .. }) {
        content = content.push(row![
            text(format!("RX: {}", format_bytes(rx_bytes))),
            text("  "),
            text(format!("TX: {}", format_bytes(tx_bytes))),
        ]);
        content = content.push(row![
            text(format!("\u{2193} {}", format_speed(rx_speed))),
            text("  "),
            text(format!("\u{2191} {}", format_speed(tx_speed))),
        ]);
    }

    // Connection count
    if connection_count > 0 {
        content = content.push(text(format!(
            "Connections this session: {}",
            connection_count
        )));
    }

    // Network lock status
    let lock_text = if lock_persistent {
        if lock_installed {
            "Network Lock: Persistent (installed)"
        } else {
            "Network Lock: Persistent"
        }
    } else if lock_session {
        "Network Lock: Session"
    } else if lock_installed {
        "Network Lock: Persistent (installed, inactive)"
    } else {
        "Network Lock: Inactive"
    };
    content = content.push(text(lock_text));

    content.into()
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_speed(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;

    if bytes_per_sec >= GB {
        format!("{:.2} GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.2} MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2} KB/s", bytes_per_sec / KB)
    } else {
        format!("{:.0} B/s", bytes_per_sec)
    }
}
