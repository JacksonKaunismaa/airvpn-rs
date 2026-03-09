//! Overview tab: connection status, connect/disconnect, stats, lock status.

use iced::widget::{button, column, container, row, text};
use iced::{Element, Fill};

use airvpn::ipc::ConnectionState;

use crate::Message;

/// Display unit configuration for speeds and transfer totals.
#[derive(Debug, Clone, Copy)]
pub struct UnitConfig {
    /// "bytes" or "bits"
    pub unit: UnitType,
    /// false = decimal SI (KB/MB), true = binary IEC (KiB/MiB)
    pub iec: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnitType {
    Bytes,
    Bits,
}

impl UnitConfig {
    pub fn from_options(unit_str: &str, iec_str: &str) -> Self {
        Self {
            unit: if unit_str.eq_ignore_ascii_case("bits") { UnitType::Bits } else { UnitType::Bytes },
            iec: iec_str.eq_ignore_ascii_case("true"),
        }
    }
}

/// Render the overview tab.
#[allow(clippy::too_many_arguments)]
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
    startlast: bool,
    activity: &'a str,
    eddie_import_pending: &'a Option<String>,
    unit_config: UnitConfig,
) -> Element<'a, Message> {
    // If Eddie import confirmation is pending, show that dialog instead
    if let Some(path) = eddie_import_pending {
        return eddie_import_dialog(path);
    }

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
                None if startlast => "Connect (last server)".to_string(),
                None => "Connect (best server)".to_string(),
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
            text(format!("RX: {}", format_transfer(rx_bytes, unit_config))),
            text("  "),
            text(format!("TX: {}", format_transfer(tx_bytes, unit_config))),
        ]);
        content = content.push(row![
            text(format!("\u{2193} {}", format_speed_with_unit(rx_speed, unit_config))),
            text("  "),
            text(format!("\u{2191} {}", format_speed_with_unit(tx_speed, unit_config))),
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

/// Confirmation dialog for Eddie profile import.
fn eddie_import_dialog(path: &str) -> Element<'_, Message> {
    let content = column![
        text("Import credentials from Eddie profile?").size(20),
        text(path)
            .size(14)
            .color(iced::Color::from_rgb(0.53, 0.57, 0.63)),
        row![
            button(text("Import")).on_press(Message::EddieImportAccept),
            button(text("Cancel")).on_press(Message::EddieImportCancel),
        ]
        .spacing(12),
    ]
    .spacing(16);

    container(content)
        .width(Fill)
        .padding(24)
        .into()
}

/// Format a byte count for transfer totals, respecting unit and IEC settings.
fn format_transfer(bytes: u64, cfg: UnitConfig) -> String {
    let (value, base_unit) = if cfg.unit == UnitType::Bits {
        (bytes as f64 * 8.0, "b")
    } else {
        (bytes as f64, "B")
    };
    format_value(value, base_unit, cfg.iec)
}

/// Format a bytes-per-second speed, respecting unit and IEC settings.
fn format_speed_with_unit(bytes_per_sec: f64, cfg: UnitConfig) -> String {
    let (value, base_unit) = if cfg.unit == UnitType::Bits {
        (bytes_per_sec * 8.0, "bps")
    } else {
        (bytes_per_sec, "B/s")
    };
    format_value(value, base_unit, cfg.iec)
}

/// Generic value formatter with SI or IEC prefixes.
fn format_value(value: f64, base_unit: &str, iec: bool) -> String {
    let (k, m, g, k_prefix, m_prefix, g_prefix) = if iec {
        (1024.0, 1024.0 * 1024.0, 1024.0 * 1024.0 * 1024.0, "Ki", "Mi", "Gi")
    } else {
        (1000.0, 1000.0 * 1000.0, 1000.0 * 1000.0 * 1000.0, "K", "M", "G")
    };

    if value >= g {
        format!("{:.2} {}{}", value / g, g_prefix, base_unit)
    } else if value >= m {
        format!("{:.2} {}{}", value / m, m_prefix, base_unit)
    } else if value >= k {
        format!("{:.2} {}{}", value / k, k_prefix, base_unit)
    } else {
        format!("{:.0} {}", value, base_unit)
    }
}
