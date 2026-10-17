//! Overview tab: connection status, connect/disconnect, stats, lock status.

use iced::widget::{button, column, container, pick_list, row, text, tooltip, Space};
use iced::{Alignment, Element, Fill};

use airvpn::ipc::ConnectionState;

use super::Tab;
use crate::icons::{icon, Icon};
use crate::theme::{self, DotKind, Ink};
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
    available_keys: &'a [String],
    wg_key: &'a str,
) -> Element<'a, Message> {
    // If Eddie import confirmation is pending, show that dialog instead
    if let Some(path) = eddie_import_pending {
        return eddie_import_dialog(path);
    }

    let is_connected = matches!(connection_state, ConnectionState::Connected { .. });
    let is_transitioning = matches!(
        connection_state,
        ConnectionState::Connecting | ConnectionState::Reconnecting | ConnectionState::Disconnecting
    );

    let mut content = column![Space::new().height(Fill)].spacing(theme::SPACE_LG).width(Fill);

    // ── Status chip ──────────────────────────────────────────────────
    let (chip_label, dot_kind) = match connection_state {
        ConnectionState::Disconnected => ("Disconnected".to_string(), DotKind::Off),
        ConnectionState::Connecting => ("Connecting\u{2026}".to_string(), DotKind::Busy),
        ConnectionState::Reconnecting => ("Reconnecting\u{2026}".to_string(), DotKind::Busy),
        ConnectionState::Disconnecting => ("Disconnecting\u{2026}".to_string(), DotKind::Busy),
        ConnectionState::Connected { .. } => (
            match connected_since {
                Some(since) => format!("Connected \u{00B7} {}", format_uptime(since.elapsed().as_secs())),
                None => "Connected".to_string(),
            },
            DotKind::On,
        ),
    };
    let chip = container(
        row![
            container(Space::new()).width(8.0).height(8.0).style(theme::dot(dot_kind)),
            text(chip_label).size(theme::TEXT_SM).font(theme::FONT_MEDIUM),
        ]
        .spacing(theme::SPACE_SM)
        .align_y(Alignment::Center),
    )
    .padding([5, 12])
    .style(theme::chip(is_connected));

    // ── Headline: where traffic goes (or will go) ────────────────────
    let headline: Element<'a, Message> = if let ConnectionState::Connected {
        server_name,
        server_country,
        server_location,
    } = connection_state
    {
        column![
            text(server_name.as_str()).size(theme::TEXT_DISPLAY).font(theme::FONT_SEMIBOLD),
            text(format!("{}, {}", server_location, server_country))
                .size(theme::TEXT_LG)
                .style(theme::text_muted),
        ]
        .spacing(2.0)
        .into()
    } else {
        let target = match selected_server {
            Some(server) => server.clone(),
            None if startlast => "Last server".to_string(),
            None => "Best server".to_string(),
        };
        let choose = button(
            row![
                text(if selected_server.is_some() { "Change server" } else { "Choose a server" })
                    .size(theme::TEXT_MD),
                icon(Icon::ChevronRight, 14.0, Ink::Accent),
            ]
            .spacing(2.0)
            .align_y(Alignment::Center),
        )
        .padding(0)
        .style(theme::link_button)
        .on_press(Message::TabSelected(Tab::Servers));
        column![
            text(target).size(theme::TEXT_DISPLAY).font(theme::FONT_SEMIBOLD),
            choose,
        ]
        .spacing(theme::SPACE_XS)
        .into()
    };

    content = content.push(column![chip, headline].spacing(theme::SPACE_MD));

    // ── Device / key selector (pre-connect) ──────────────────────────
    // Shown only when disconnected and more than one device key exists
    // (hidden for a single key, like Eddie's ComboBox). Picking a device
    // persists it immediately and applies on the next connect.
    if matches!(connection_state, ConnectionState::Disconnected) && available_keys.len() > 1 {
        let key_options: Vec<&str> = available_keys.iter().map(|s| s.as_str()).collect();
        let selected: Option<&str> = key_options
            .iter()
            .find(|&&k| k == wg_key)
            .copied()
            .or_else(|| key_options.first().copied());
        content = content.push(
            row![
                text("Device").size(theme::TEXT_MD).style(theme::text_muted),
                Space::new().width(Fill),
                pick_list(key_options, selected, |selected: &str| {
                    Message::OverviewKeyChanged(selected.to_string())
                })
                .width(220)
                .padding([7, 10])
                .text_size(theme::TEXT_MD)
                .style(theme::pick_list_style)
                .menu_style(theme::menu_style),
            ]
            .align_y(Alignment::Center),
        );
    }

    // ── Connect / Disconnect button ──────────────────────────────────
    let action: Element<'a, Message> = if is_connected {
        let mut btn = button(
            container(text("Disconnect").size(theme::TEXT_LG).font(theme::FONT_MEDIUM))
                .center_x(Fill),
        )
        .width(Fill)
        .padding([13, 24])
        .style(theme::secondary_button);
        if !is_transitioning {
            btn = btn.on_press(Message::Disconnect);
        }
        btn.into()
    } else {
        let label = match connection_state {
            ConnectionState::Connecting => "Connecting\u{2026}",
            ConnectionState::Reconnecting => "Reconnecting\u{2026}",
            ConnectionState::Disconnecting => "Disconnecting\u{2026}",
            _ => "Connect",
        };
        let mut btn = button(
            container(
                row![
                    icon(Icon::Power, 18.0, Ink::OnAccent),
                    text(label).size(theme::TEXT_LG).font(theme::FONT_SEMIBOLD),
                ]
                .spacing(10.0)
                .align_y(Alignment::Center),
            )
            .center_x(Fill),
        )
        .width(Fill)
        .padding([13, 24])
        .style(theme::primary_button);
        if !is_transitioning {
            btn = btn.on_press(Message::Connect);
        }
        btn.into()
    };

    let mut action_block = column![action].spacing(theme::SPACE_SM);
    if !activity.is_empty() {
        action_block = action_block.push(
            container(text(activity).size(theme::TEXT_SM).style(theme::text_muted)).center_x(Fill),
        );
    }
    content = content.push(action_block);

    // ── Live stats (when connected) ──────────────────────────────────
    if is_connected {
        let cell = |arrow: Icon, label: &'static str, value: String| -> Element<'a, Message> {
            column![
                row![
                    icon(arrow, 12.0, Ink::Muted),
                    text(label).size(theme::TEXT_XS).style(theme::text_muted),
                ]
                .spacing(theme::SPACE_XS)
                .align_y(Alignment::Center),
                text(value).size(theme::TEXT_LG).font(theme::MONO),
            ]
            .spacing(6.0)
            .width(Fill)
            .into()
        };
        let vrule = || container(Space::new()).width(1.0).height(36.0).style(theme::rule);

        content = content.push(
            container(
                row![
                    cell(Icon::ArrowDown, "Download", format_speed_with_unit(rx_speed, unit_config)),
                    vrule(),
                    cell(Icon::ArrowUp, "Upload", format_speed_with_unit(tx_speed, unit_config)),
                    vrule(),
                    cell(Icon::ArrowDown, "Received", format_transfer(rx_bytes, unit_config)),
                    vrule(),
                    cell(Icon::ArrowUp, "Sent", format_transfer(tx_bytes, unit_config)),
                ]
                .spacing(theme::SPACE_MD)
                .align_y(Alignment::Center),
            )
            .padding([14, 16])
            .width(Fill)
            .style(theme::panel),
        );
    }

    // ── Footer: lock, session count, recover ─────────────────────────
    let lock_label = if lock_persistent {
        "Network lock: persistent"
    } else if lock_session {
        "Network lock: this session"
    } else if lock_installed {
        "Network lock: installed, inactive"
    } else {
        "Network lock: off"
    };
    let lock_on = lock_persistent || lock_session;

    let mut footer = row![
        icon(if lock_on { Icon::Lock } else { Icon::LockOpen }, 14.0, if lock_on { Ink::Text } else { Ink::Muted }),
        text(lock_label)
            .size(theme::TEXT_SM)
            .style(move |t: &iced::Theme| if lock_on { iced::widget::text::Style::default() } else { theme::text_muted(t) }),
    ]
    .spacing(theme::SPACE_SM)
    .align_y(Alignment::Center);

    if connection_count > 0 {
        footer = footer.push(text("\u{00B7}").size(theme::TEXT_SM).style(theme::text_faint));
        footer = footer.push(
            text(format!(
                "{} connection{} this session",
                connection_count,
                if connection_count == 1 { "" } else { "s" }
            ))
            .size(theme::TEXT_SM)
            .style(theme::text_muted),
        );
    }

    // Subtle break-glass control: clears orphaned VPN state. Always enabled
    // (when the helper is reachable) so it can unstick a frozen
    // Connecting/Reconnecting state, not just a clean disconnected one.
    let recover_btn = button(
        row![icon(Icon::Wrench, 14.0, Ink::Muted), text("Recover").size(theme::TEXT_SM)]
            .spacing(6.0)
            .align_y(Alignment::Center),
    )
    .padding([6, 10])
    .style(theme::ghost_button)
    .on_press(Message::Recover);
    let recover = tooltip(
        recover_btn,
        container(
            text("Clean up stuck VPN state (kill switch, DNS, tunnel)").size(theme::TEXT_XS),
        )
        .padding([6, 10])
        .style(theme::panel),
        tooltip::Position::Top,
    );

    footer = footer.push(Space::new().width(Fill));
    footer = footer.push(recover);

    content = content.push(Space::new().height(Fill));
    content = content.push(container(Space::new()).width(Fill).height(1.0).style(theme::rule));
    content = content.push(footer);

    container(content)
        .max_width(theme::CONTENT_MAX_WIDTH)
        .padding(iced::Padding { top: theme::SPACE_MD, ..Default::default() })
        .height(Fill)
        .center_x(Fill)
        .into()
}

fn format_uptime(total_secs: u64) -> String {
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Confirmation dialog for Eddie profile import.
fn eddie_import_dialog(path: &str) -> Element<'_, Message> {
    let content = container(
        column![
            text("Import credentials from Eddie?").size(theme::TEXT_XL).font(theme::FONT_SEMIBOLD),
            text("Found an Eddie profile. Its saved login will be copied into airvpn-rs.")
                .size(theme::TEXT_MD)
                .style(theme::text_muted),
            text(path).size(theme::TEXT_SM).font(theme::MONO).style(theme::text_muted),
            Space::new().height(theme::SPACE_XS),
            row![
                button(container(text("Cancel").size(theme::TEXT_MD)).center_x(Fill))
                    .width(Fill)
                    .padding([10, 20])
                    .style(theme::secondary_button)
                    .on_press(Message::EddieImportCancel),
                button(
                    container(text("Import").size(theme::TEXT_MD).font(theme::FONT_MEDIUM))
                        .center_x(Fill)
                )
                .width(Fill)
                .padding([10, 20])
                .style(theme::primary_button)
                .on_press(Message::EddieImportAccept),
            ]
            .spacing(theme::SPACE_SM),
        ]
        .spacing(theme::SPACE_SM),
    )
    .padding(theme::SPACE_LG)
    .max_width(theme::CONTENT_MAX_WIDTH)
    .style(theme::panel);

    container(content).center(Fill).into()
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
