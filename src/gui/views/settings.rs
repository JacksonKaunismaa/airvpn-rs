//! Settings tab: profile options, per-connect flags, persistent lock controls.
//! Organized into sub-tabs: General, Network, WireGuard, Network Lock, Advanced.

use iced::widget::{button, checkbox, column, container, pick_list, row, scrollable, text, text_input, Space};
use iced::{Element, Fill};

use crate::Message;

/// Sub-tab within the Settings view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsSubTab {
    General,
    Network,
    WireGuard,
    NetworkLock,
    Advanced,
}

impl SettingsSubTab {
    pub fn all() -> &'static [SettingsSubTab] {
        &[
            SettingsSubTab::General,
            SettingsSubTab::Network,
            SettingsSubTab::WireGuard,
            SettingsSubTab::NetworkLock,
            SettingsSubTab::Advanced,
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            SettingsSubTab::General => "General",
            SettingsSubTab::Network => "Network",
            SettingsSubTab::WireGuard => "WireGuard",
            SettingsSubTab::NetworkLock => "Network Lock",
            SettingsSubTab::Advanced => "Advanced",
        }
    }
}

/// Section header styled text.
fn section_header(label: &str) -> iced::widget::Text<'_> {
    text(label).size(18)
}

/// Label text for form fields.
fn label(s: &str) -> iced::widget::Text<'_> {
    text(s).size(14)
}

/// A single sub-tab button in the tab bar.
fn tab_button(tab: SettingsSubTab, active: bool) -> Element<'static, Message> {
    let btn = button(text(tab.label()).size(13))
        .on_press(Message::SettingsSubTabChanged(tab));
    if active {
        btn.style(iced::widget::button::primary)
    } else {
        btn.style(iced::widget::button::secondary)
    }
    .into()
}

/// A labeled text input row.
fn text_field<'a>(
    field_label: &'a str,
    placeholder: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
) -> Element<'a, Message> {
    row![
        label(field_label).width(220),
        text_input(placeholder, value)
            .on_input(on_input)
            .width(Fill),
    ]
    .spacing(8)
    .align_y(iced::Alignment::Center)
    .into()
}

/// Save button (always at the bottom).
fn save_button(dirty: bool, loaded: bool) -> Element<'static, Message> {
    let mut content = column![].spacing(8);
    content = content.push(Space::new().height(8));
    let mut save_btn = button(text("Save Settings").size(16));
    if dirty && loaded {
        save_btn = save_btn.on_press(Message::SaveSettings);
    }
    content = content.push(save_btn);
    content.into()
}

/// Render the settings tab.
#[allow(clippy::too_many_arguments)]
pub fn view<'a>(
    credentials_configured: bool,
    startlast: bool,
    locklast: bool,
    ipv6_mode: &'a str,
    dns: &'a str,
    loaded: bool,
    dirty: bool,
    show_errors: bool,
    no_lock: bool,
    allow_lan: bool,
    no_reconnect: bool,
    no_verify: bool,
    lock_installed: bool,
    lock_persistent: bool,
    sub_tab: SettingsSubTab,
    // WireGuard settings
    wg_mtu: &'a str,
    wg_keepalive: &'a str,
    wg_handshake_first: &'a str,
    wg_handshake_connected: &'a str,
    // Network Lock settings
    netlock_incoming: &'a str,
    netlock_allow_ping: bool,
    // Advanced settings
    pinger_timeout: &'a str,
    manifest_refresh: &'a str,
    penality: &'a str,
    http_timeout: &'a str,
    checking_ntry: &'a str,
) -> Element<'a, Message> {
    if !loaded {
        return container(text("Loading settings...").size(16))
            .padding(16)
            .into();
    }

    // Sub-tab bar
    let mut tab_bar = row![].spacing(4);
    for &tab in SettingsSubTab::all() {
        tab_bar = tab_bar.push(tab_button(tab, tab == sub_tab));
    }

    // Content for the selected sub-tab
    let tab_content: Element<'a, Message> = match sub_tab {
        SettingsSubTab::General => view_general(
            credentials_configured,
            startlast,
            locklast,
            show_errors,
        ),
        SettingsSubTab::Network => view_network(ipv6_mode, dns),
        SettingsSubTab::WireGuard => view_wireguard(
            wg_mtu,
            wg_keepalive,
            wg_handshake_first,
            wg_handshake_connected,
        ),
        SettingsSubTab::NetworkLock => view_network_lock(
            no_lock,
            allow_lan,
            no_reconnect,
            no_verify,
            lock_installed,
            lock_persistent,
            netlock_incoming,
            netlock_allow_ping,
        ),
        SettingsSubTab::Advanced => view_advanced(
            pinger_timeout,
            manifest_refresh,
            penality,
            http_timeout,
            checking_ntry,
        ),
    };

    let content = column![
        tab_bar,
        Space::new().height(8),
        tab_content,
        save_button(dirty, loaded),
    ]
    .spacing(4);

    scrollable(container(content).padding(4))
        .height(Fill)
        .into()
}

// ── General sub-tab ────────────────────────────────────────────────────

fn view_general<'a>(
    credentials_configured: bool,
    startlast: bool,
    locklast: bool,
    show_errors: bool,
) -> Element<'a, Message> {
    let mut content = column![].spacing(16);

    // Credentials
    content = content.push(section_header("Credentials"));
    if credentials_configured {
        content = content.push(
            text("Credentials: Configured")
                .size(14)
                .color(iced::Color::from_rgb(0.3, 0.75, 0.4)),
        );
    } else {
        content = content.push(
            column![
                text("Credentials: Not configured")
                    .size(14)
                    .color(iced::Color::from_rgb(0.91, 0.65, 0.2)),
                text("Run `sudo airvpn connect` to set up credentials, or import from Eddie profile.")
                    .size(12),
            ]
            .spacing(4),
        );
    }

    // Server Preferences
    content = content.push(section_header("Server Preferences"));
    content = content.push(
        column![
            checkbox(startlast)
                .label("Start with last server")
                .on_toggle(Message::SettingsStartlastToggle),
            checkbox(locklast)
                .label("Lock to server during session")
                .on_toggle(Message::SettingsLocklastToggle),
        ]
        .spacing(6),
    );

    // GUI
    content = content.push(section_header("GUI"));
    content = content.push(
        checkbox(show_errors)
            .label("Show error messages")
            .on_toggle(Message::ShowErrorsToggle),
    );

    content.into()
}

// ── Network sub-tab ────────────────────────────────────────────────────

fn view_network<'a>(ipv6_mode: &'a str, dns: &'a str) -> Element<'a, Message> {
    let mut content = column![].spacing(16);

    content = content.push(section_header("Network"));

    let ipv6_options: Vec<&str> = vec!["in", "in-block", "block"];
    let ipv6_selected: Option<&str> = ipv6_options.iter().find(|&&o| o == ipv6_mode).copied();

    content = content.push(
        column![
            row![
                label("IPv6 Mode").width(220),
                pick_list(ipv6_options, ipv6_selected, |selected: &str| {
                    Message::SettingsIpv6ModeChanged(selected.to_string())
                })
                .width(160),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            row![
                label("Custom DNS").width(220),
                text_input("8.8.8.8, 1.1.1.1", dns)
                    .on_input(Message::SettingsDnsChanged)
                    .width(Fill),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
        ]
        .spacing(8),
    );

    content.into()
}

// ── WireGuard sub-tab ──────────────────────────────────────────────────

fn view_wireguard<'a>(
    wg_mtu: &'a str,
    wg_keepalive: &'a str,
    wg_handshake_first: &'a str,
    wg_handshake_connected: &'a str,
) -> Element<'a, Message> {
    let mut content = column![].spacing(16);

    content = content.push(section_header("WireGuard"));

    content = content.push(
        column![
            text_field("Interface MTU", "1320", wg_mtu, Message::SettingsWgMtuChanged),
            text_field(
                "Persistent Keepalive (s)",
                "15",
                wg_keepalive,
                Message::SettingsWgKeepaliveChanged,
            ),
            text_field(
                "Handshake Timeout — First (s)",
                "50",
                wg_handshake_first,
                Message::SettingsWgHandshakeFirstChanged,
            ),
            text_field(
                "Handshake Timeout — Connected (s)",
                "200",
                wg_handshake_connected,
                Message::SettingsWgHandshakeConnectedChanged,
            ),
        ]
        .spacing(8),
    );

    content.into()
}

// ── Network Lock sub-tab ───────────────────────────────────────────────

fn view_network_lock<'a>(
    no_lock: bool,
    allow_lan: bool,
    no_reconnect: bool,
    no_verify: bool,
    lock_installed: bool,
    lock_persistent: bool,
    netlock_incoming: &'a str,
    netlock_allow_ping: bool,
) -> Element<'a, Message> {
    let mut content = column![].spacing(16);

    // Connection settings
    content = content.push(section_header("Connection"));
    content = content.push(
        column![
            // Inverted: checked = lock ON = no_lock is false
            checkbox(!no_lock)
                .label("Network lock (kill switch)")
                .on_toggle(|checked| Message::ConnectNoLockToggle(!checked)),
            checkbox(allow_lan)
                .label("Allow LAN traffic")
                .on_toggle(Message::ConnectAllowLanToggle),
            // Inverted: checked = reconnect ON = no_reconnect is false
            checkbox(!no_reconnect)
                .label("Auto-reconnect")
                .on_toggle(|checked| Message::ConnectNoReconnectToggle(!checked)),
            checkbox(no_verify)
                .label("Skip tunnel verification")
                .on_toggle(Message::ConnectNoVerifyToggle),
        ]
        .spacing(6),
    );

    // Policy settings
    content = content.push(section_header("Lock Policy"));

    let incoming_options: Vec<&str> = vec!["block", "allow"];
    let incoming_selected: Option<&str> = incoming_options
        .iter()
        .find(|&&o| o == netlock_incoming)
        .copied();

    content = content.push(
        column![
            row![
                label("Incoming Policy").width(220),
                pick_list(incoming_options, incoming_selected, |selected: &str| {
                    Message::SettingsNetlockIncomingChanged(selected.to_string())
                })
                .width(160),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            checkbox(netlock_allow_ping)
                .label("Allow ICMP ping")
                .on_toggle(Message::SettingsNetlockAllowPingToggle),
        ]
        .spacing(6),
    );

    // Persistent Lock controls
    content = content.push(section_header("Persistent Lock"));

    let lock_status = if lock_installed && lock_persistent {
        "Installed and active"
    } else if lock_installed {
        "Installed but inactive"
    } else {
        "Not installed"
    };
    content = content.push(text(lock_status).size(14));

    let mut lock_row = row![].spacing(8);

    // Install: enabled when NOT installed
    let mut install_btn = button(text("Install").size(14));
    if !lock_installed {
        install_btn = install_btn.on_press(Message::LockInstall);
    }
    lock_row = lock_row.push(install_btn);

    // Uninstall: enabled when installed
    let mut uninstall_btn = button(text("Uninstall").size(14));
    if lock_installed {
        uninstall_btn = uninstall_btn.on_press(Message::LockUninstall);
    }
    lock_row = lock_row.push(uninstall_btn);

    // Enable: enabled when installed and NOT active
    let mut enable_btn = button(text("Enable").size(14));
    if lock_installed && !lock_persistent {
        enable_btn = enable_btn.on_press(Message::LockEnable);
    }
    lock_row = lock_row.push(enable_btn);

    // Disable: enabled when installed and active
    let mut disable_btn = button(text("Disable").size(14));
    if lock_installed && lock_persistent {
        disable_btn = disable_btn.on_press(Message::LockDisable);
    }
    lock_row = lock_row.push(disable_btn);

    content = content.push(lock_row);

    content.into()
}

// ── Advanced sub-tab ───────────────────────────────────────────────────

fn view_advanced<'a>(
    pinger_timeout: &'a str,
    manifest_refresh: &'a str,
    penality: &'a str,
    http_timeout: &'a str,
    checking_ntry: &'a str,
) -> Element<'a, Message> {
    let mut content = column![].spacing(16);

    content = content.push(section_header("Advanced"));

    content = content.push(
        column![
            text_field(
                "Pinger Timeout (s)",
                "3",
                pinger_timeout,
                Message::SettingsPingerTimeoutChanged,
            ),
            text_field(
                "Manifest Refresh Interval (s)",
                "1800",
                manifest_refresh,
                Message::SettingsManifestRefreshChanged,
            ),
            text_field(
                "Penalty on Error",
                "30",
                penality,
                Message::SettingsPenalityChanged,
            ),
            text_field(
                "HTTP Timeout (s)",
                "10",
                http_timeout,
                Message::SettingsHttpTimeoutChanged,
            ),
            text_field(
                "Verification Retries",
                "3",
                checking_ntry,
                Message::SettingsCheckingNtryChanged,
            ),
        ]
        .spacing(8),
    );

    content.into()
}
