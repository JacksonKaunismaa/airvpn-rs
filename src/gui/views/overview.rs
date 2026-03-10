//! Overview tab: connection status, connect/disconnect, stats, lock status.

use iced::widget::{button, column, container, row, text, Space};
use iced::{Alignment, Element, Fill};

use airvpn::ipc::ConnectionState;

use crate::theme;
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
    connection_state: &'a ConnectionState,
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

    let mut content = column![].spacing(theme::SPACE_MD).width(Fill);

    // ── Status hero ──────────────────────────────────────────────────
    let (status_text, status_color) = match connection_state {
        ConnectionState::Disconnected => ("Disconnected", theme::DANGER),
        ConnectionState::Connecting => ("Connecting...", theme::WARNING),
        ConnectionState::Connected { .. } => ("Connected", theme::SUCCESS),
        ConnectionState::Reconnecting => ("Reconnecting...", theme::WARNING),
        ConnectionState::Disconnecting => ("Disconnecting...", theme::WARNING),
    };

    let status_label = text(status_text).size(32).color(status_color);

    // Activity sub-status (e.g. "Fetching user info...")
    let status_section = if !activity.is_empty() {
        column![
            status_label,
            text(activity).size(14).color(theme::TEXT_SECONDARY),
        ]
        .spacing(4.0)
        .align_x(Alignment::Center)
    } else {
        column![status_label].align_x(Alignment::Center)
    };

    content = content.push(
        container(status_section)
            .width(Fill)
            .center_x(Fill)
            .padding([theme::SPACE_LG, 0.0]),
    );

    // ── Server info card (when connected) ────────────────────────────
    if let ConnectionState::Connected {
        server_name,
        server_country,
        server_location,
    } = connection_state
    {
        let server_card = container(
            column![
                text(server_name.as_str()).size(18).color(theme::TEXT),
                text(format!("{}, {}", server_location, server_country))
                    .size(14)
                    .color(theme::TEXT_SECONDARY),
            ]
            .spacing(4.0),
        )
        .padding(theme::SPACE_MD)
        .width(Fill)
        .style(theme::card);

        content = content.push(server_card);
    }

    // ── Connect / Disconnect button ──────────────────────────────────
    let is_transitioning = matches!(
        connection_state,
        ConnectionState::Connecting | ConnectionState::Reconnecting | ConnectionState::Disconnecting
    );

    match connection_state {
        ConnectionState::Connected { .. } => {
            let mut btn = button(
                container(text("Disconnect").size(16).color(iced::Color::WHITE))
                    .width(Fill)
                    .center_x(Fill),
            )
            .width(Fill)
            .padding([12, 24])
            .style(theme::danger_button);
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
            let mut btn = button(
                container(text(connect_label).size(16).color(iced::Color::WHITE))
                    .width(Fill)
                    .center_x(Fill),
            )
            .width(Fill)
            .padding([12, 24])
            .style(theme::primary_button);
            if !is_transitioning {
                btn = btn.on_press(Message::Connect);
            }
            content = content.push(btn);
        }
    }

    // ── Stats cards (when connected) ─────────────────────────────────
    if matches!(connection_state, ConnectionState::Connected { .. }) {
        let transfer_card = container(
            column![
                text("Transfer").size(12).color(theme::TEXT_SECONDARY),
                row![
                    column![
                        text("\u{2193} RX").size(11).color(theme::TEXT_SECONDARY),
                        text(format_transfer(rx_bytes, unit_config)).size(16).color(theme::TEXT),
                    ]
                    .spacing(2.0)
                    .width(Fill),
                    column![
                        text("\u{2191} TX").size(11).color(theme::TEXT_SECONDARY),
                        text(format_transfer(tx_bytes, unit_config)).size(16).color(theme::TEXT),
                    ]
                    .spacing(2.0)
                    .width(Fill),
                ]
                .spacing(theme::SPACE_MD),
            ]
            .spacing(theme::SPACE_SM),
        )
        .padding(theme::SPACE_MD)
        .width(Fill)
        .style(theme::card);

        let speed_card = container(
            column![
                text("Speed").size(12).color(theme::TEXT_SECONDARY),
                row![
                    column![
                        text("\u{2193} Down").size(11).color(theme::TEXT_SECONDARY),
                        text(format_speed_with_unit(rx_speed, unit_config)).size(16).color(theme::TEXT),
                    ]
                    .spacing(2.0)
                    .width(Fill),
                    column![
                        text("\u{2191} Up").size(11).color(theme::TEXT_SECONDARY),
                        text(format_speed_with_unit(tx_speed, unit_config)).size(16).color(theme::TEXT),
                    ]
                    .spacing(2.0)
                    .width(Fill),
                ]
                .spacing(theme::SPACE_MD),
            ]
            .spacing(theme::SPACE_SM),
        )
        .padding(theme::SPACE_MD)
        .width(Fill)
        .style(theme::card);

        content = content.push(
            row![transfer_card, speed_card].spacing(theme::SPACE_MD),
        );
    }

    // ── Footer info ──────────────────────────────────────────────────
    let mut footer = row![].spacing(theme::SPACE_MD);

    // Uptime
    if let Some(since) = connected_since {
        let elapsed = since.elapsed();
        let total_secs = elapsed.as_secs();
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
        footer = footer.push(
            text(format!("Uptime {:02}:{:02}:{:02}", hours, minutes, seconds))
                .size(13)
                .color(theme::TEXT_SECONDARY),
        );
    }

    // Connection count
    if connection_count > 0 {
        footer = footer.push(
            text(format!("Connections: {}", connection_count))
                .size(13)
                .color(theme::TEXT_SECONDARY),
        );
    }

    // Network lock badge
    let lock_label = if lock_persistent {
        if lock_installed {
            "Lock: Persistent"
        } else {
            "Lock: Persistent"
        }
    } else if lock_session {
        "Lock: Session"
    } else if lock_installed {
        "Lock: Installed (inactive)"
    } else {
        "Lock: Off"
    };

    let lock_color = if lock_persistent || lock_session {
        theme::SUCCESS
    } else {
        theme::TEXT_SECONDARY
    };

    footer = footer.push(Space::new().width(Fill));
    footer = footer.push(text(lock_label).size(13).color(lock_color));

    content = content.push(footer.align_y(Alignment::Center));

    content.into()
}

/// Confirmation dialog for Eddie profile import.
fn eddie_import_dialog(path: &str) -> Element<'_, Message> {
    let content = container(
        column![
            text("Import credentials from Eddie profile?").size(20).color(theme::TEXT),
            text(path).size(14).color(theme::TEXT_SECONDARY),
            Space::new().height(theme::SPACE_SM),
            row![
                button(
                    container(text("Import").size(15).color(iced::Color::WHITE))
                        .center_x(Fill)
                )
                .width(Fill)
                .padding([10, 20])
                .style(theme::primary_button)
                .on_press(Message::EddieImportAccept),

                button(
                    container(text("Cancel").size(15))
                        .center_x(Fill)
                )
                .width(Fill)
                .padding([10, 20])
                .style(theme::secondary_button)
                .on_press(Message::EddieImportCancel),
            ]
            .spacing(theme::SPACE_MD),
        ]
        .spacing(theme::SPACE_MD),
    )
    .padding(theme::SPACE_LG)
    .width(Fill)
    .style(theme::card);

    container(content)
        .width(Fill)
        .center_y(Fill)
        .padding(theme::SPACE_LG)
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
