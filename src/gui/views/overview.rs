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
    rx_bytes: u64,
    tx_bytes: u64,
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
            let mut btn = button(text("Connect"));
            if !is_transitioning {
                btn = btn.on_press(Message::Connect);
            }
            content = content.push(btn);
        }
    }

    // Transfer stats when connected
    if matches!(connection_state, ConnectionState::Connected { .. }) {
        content = content.push(row![
            text(format!("RX: {}", format_bytes(rx_bytes))),
            text("  "),
            text(format!("TX: {}", format_bytes(tx_bytes))),
        ]);
    }

    // Network lock status
    let lock_text = if lock_persistent {
        "Network Lock: Persistent"
    } else if lock_session {
        "Network Lock: Session"
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
