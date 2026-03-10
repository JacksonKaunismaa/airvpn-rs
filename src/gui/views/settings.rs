//! Settings tab: profile options, per-connect flags, persistent lock controls.
//! Organized into sub-tabs: General, Network, WireGuard, Network Lock, Advanced.

use iced::widget::{button, checkbox, column, container, pick_list, row, scrollable, text, text_input};
use iced::{Element, Fill};

use crate::theme;
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
    text(label).size(16).color(theme::TEXT)
}

/// Hint text below a field.
fn hint(s: &str) -> iced::widget::Text<'_> {
    text(s).size(12).color(theme::TEXT_SECONDARY)
}

/// A single sub-tab button in the pill bar.
fn tab_button(tab: SettingsSubTab, active: bool) -> Element<'static, Message> {
    let btn = button(text(tab.label()).size(13))
        .on_press(Message::SettingsSubTabChanged(tab))
        .padding([6, 16]);
    if active {
        btn.style(theme::pill_active)
    } else {
        btn.style(theme::pill_inactive)
    }
    .into()
}

/// A labeled text input row (label above).
fn text_field<'a>(
    field_label: &'a str,
    placeholder: &'a str,
    value: &'a str,
    on_input: fn(String) -> Message,
) -> Element<'a, Message> {
    column![
        text(field_label).size(13).color(theme::TEXT_SECONDARY),
        text_input(placeholder, value)
            .on_input(on_input)
            .style(theme::text_input_style)
            .width(Fill),
    ]
    .spacing(4.0)
    .into()
}

/// A labeled dropdown row.
fn dropdown_field<'a>(
    field_label: &'a str,
    options: Vec<&'a str>,
    selected: Option<&'a str>,
    on_select: impl Fn(&'a str) -> Message + 'a,
) -> Element<'a, Message> {
    column![
        text(field_label).size(13).color(theme::TEXT_SECONDARY),
        pick_list(options, selected, on_select).width(200),
    ]
    .spacing(4.0)
    .into()
}

/// Wrap content in a card.
fn section_card<'a>(content: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(content)
        .padding(theme::SPACE_MD)
        .width(Fill)
        .style(theme::card)
        .into()
}

/// Save button (always at the bottom).
fn save_button(dirty: bool, loaded: bool) -> Element<'static, Message> {
    let mut btn = button(
        container(text("Save Settings").size(15).color(iced::Color::WHITE))
            .width(Fill)
            .center_x(Fill),
    )
    .width(Fill)
    .padding([10, 20])
    .style(theme::primary_button);
    if dirty && loaded {
        btn = btn.on_press(Message::SaveSettings);
    }
    btn.into()
}

/// Render the settings tab.
#[allow(clippy::too_many_arguments)]
pub fn view<'a>(
    credentials_configured: bool,
    startlast: bool,
    locklast: bool,
    ipv6_mode: &'a str,
    ipv4_mode: &'a str,
    entry_iface: &'a str,
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
    wg_key: &'a str,
    wg_mtu: &'a str,
    wg_keepalive: &'a str,
    wg_handshake_first: &'a str,
    wg_handshake_connected: &'a str,
    // Network Lock settings
    netlock_incoming: &'a str,
    netlock_allow_ping: bool,
    netlock_allowlist_ips: &'a str,
    // Routes
    routes_custom: &'a str,
    // Area filters
    areas_allowlist: &'a str,
    areas_denylist: &'a str,
    // DNS settings
    dns_mode: &'a str,
    dns_services: &'a str,
    // UI display settings
    ui_unit: &'a str,
    ui_iec: bool,
    // Logging settings
    log_file_enabled: bool,
    log_file_path: &'a str,
    log_level_debug: bool,
    // Mode settings
    mode_port: &'a str,
    // Advanced settings
    pinger_timeout: &'a str,
    manifest_refresh: &'a str,
    penality: &'a str,
    http_timeout: &'a str,
    checking_ntry: &'a str,
    capacity_factor: &'a str,
    check_route: bool,
) -> Element<'a, Message> {
    if !loaded {
        return container(text("Loading settings...").size(16).color(theme::TEXT_SECONDARY))
            .padding(theme::SPACE_MD)
            .into();
    }

    // Sub-tab pill bar
    let mut tab_bar = row![].spacing(4.0);
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
            ui_unit,
            ui_iec,
        ),
        SettingsSubTab::Network => view_network(ipv6_mode, ipv4_mode, entry_iface, dns, dns_mode, dns_services, routes_custom, areas_allowlist, areas_denylist),
        SettingsSubTab::WireGuard => view_wireguard(
            wg_key,
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
            netlock_allowlist_ips,
        ),
        SettingsSubTab::Advanced => view_advanced(
            pinger_timeout,
            manifest_refresh,
            penality,
            http_timeout,
            checking_ntry,
            capacity_factor,
            log_file_enabled,
            log_file_path,
            log_level_debug,
            mode_port,
            check_route,
        ),
    };

    let content = column![
        tab_bar,
        tab_content,
        save_button(dirty, loaded),
    ]
    .spacing(theme::SPACE_MD);

    scrollable(container(content).padding([0.0, 4.0]))
        .height(Fill)
        .into()
}

// ── General sub-tab ────────────────────────────────────────────────────

fn view_general<'a>(
    credentials_configured: bool,
    startlast: bool,
    locklast: bool,
    show_errors: bool,
    ui_unit: &'a str,
    ui_iec: bool,
) -> Element<'a, Message> {
    let mut sections = column![].spacing(theme::SPACE_MD);

    // Credentials
    let cred_content = if credentials_configured {
        text("Credentials configured")
            .size(14)
            .color(theme::SUCCESS)
    } else {
        text("Credentials not configured — run `sudo airvpn connect` or import from Eddie")
            .size(14)
            .color(theme::WARNING)
    };
    sections = sections.push(section_card(
        column![section_header("Credentials"), cred_content].spacing(theme::SPACE_SM),
    ));

    // Server Preferences
    sections = sections.push(section_card(
        column![
            section_header("Server Preferences"),
            checkbox(startlast)
                .label("Start with last server")
                .on_toggle(Message::SettingsStartlastToggle),
            checkbox(locklast)
                .label("Lock to server during session")
                .on_toggle(Message::SettingsLocklastToggle),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // GUI
    sections = sections.push(section_card(
        column![
            section_header("GUI"),
            checkbox(show_errors)
                .label("Show error messages")
                .on_toggle(Message::ShowErrorsToggle),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Display Units
    let unit_options: Vec<&str> = vec!["bytes", "bits"];
    let unit_selected: Option<&str> = unit_options.iter().find(|&&o| o == ui_unit).copied();

    sections = sections.push(section_card(
        column![
            section_header("Display Units"),
            dropdown_field("Speed / Transfer Unit", unit_options, unit_selected, |selected: &str| {
                Message::SettingsUiUnitChanged(selected.to_string())
            }),
            checkbox(ui_iec)
                .label("Use binary IEC units (KiB/MiB instead of KB/MB)")
                .on_toggle(Message::SettingsUiIecToggle),
        ]
        .spacing(theme::SPACE_SM),
    ));

    sections.into()
}

// ── Network sub-tab ────────────────────────────────────────────────────

fn view_network<'a>(
    ipv6_mode: &'a str,
    ipv4_mode: &'a str,
    entry_iface: &'a str,
    dns: &'a str,
    dns_mode: &'a str,
    dns_services: &'a str,
    routes_custom: &'a str,
    areas_allowlist: &'a str,
    areas_denylist: &'a str,
) -> Element<'a, Message> {
    let mut sections = column![].spacing(theme::SPACE_MD);

    // IP modes
    let ipv6_options: Vec<&str> = vec!["in", "in-block", "block"];
    let ipv6_selected: Option<&str> = ipv6_options.iter().find(|&&o| o == ipv6_mode).copied();
    let ipv4_options: Vec<&str> = vec!["in", "block"];
    let ipv4_selected: Option<&str> = ipv4_options.iter().find(|&&o| o == ipv4_mode).copied();

    sections = sections.push(section_card(
        column![
            section_header("Network"),
            dropdown_field("IPv6 Mode", ipv6_options, ipv6_selected, |selected: &str| {
                Message::SettingsIpv6ModeChanged(selected.to_string())
            }),
            dropdown_field("IPv4 Mode", ipv4_options, ipv4_selected, |selected: &str| {
                Message::SettingsIpv4ModeChanged(selected.to_string())
            }),
            text_field(
                "Entry Interface",
                "empty = auto (e.g. eth0, wlan0)",
                entry_iface,
                Message::SettingsEntryIfaceChanged,
            ),
            text_field(
                "Custom DNS",
                "8.8.8.8, 1.1.1.1",
                dns,
                Message::SettingsDnsChanged,
            ),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // DNS Configuration
    let dns_mode_options: Vec<&str> = vec!["auto", "resolvconf", "systemd-resolved"];
    let dns_mode_selected: Option<&str> = dns_mode_options.iter().find(|&&o| o == dns_mode).copied();

    sections = sections.push(section_card(
        column![
            section_header("DNS Configuration"),
            dropdown_field("DNS Mode", dns_mode_options, dns_mode_selected, |selected: &str| {
                Message::SettingsDnsModeChanged(selected.to_string())
            }),
            hint("auto = detect systemd-resolved; resolvconf = force /etc/resolv.conf swap"),
            text_field(
                "DNS Cache Services",
                "nscd,dnsmasq,named,bind9",
                dns_services,
                Message::SettingsDnsServicesChanged,
            ),
            hint("Services restarted on DNS flush (comma-separated)"),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Custom routes
    sections = sections.push(section_card(
        column![
            section_header("Custom Routes"),
            hint("Routes with 'out' bypass the VPN. Routes with 'in' force through tunnel."),
            text_field(
                "Custom Routes",
                "192.168.1.0/24,out; 10.0.0.0/8,in",
                routes_custom,
                Message::SettingsRoutesCustomChanged,
            ),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Country filters
    sections = sections.push(section_card(
        column![
            section_header("Country Filters"),
            hint("Restrict which countries are used for server selection."),
            text_field(
                "Allowed Countries",
                "US, NL, DE (empty = all)",
                areas_allowlist,
                Message::SettingsAreasAllowlistChanged,
            ),
            text_field(
                "Denied Countries",
                "CN, RU (empty = none)",
                areas_denylist,
                Message::SettingsAreasDenylistChanged,
            ),
        ]
        .spacing(theme::SPACE_SM),
    ));

    sections.into()
}

// ── WireGuard sub-tab ──────────────────────────────────────────────────

fn view_wireguard<'a>(
    wg_key: &'a str,
    wg_mtu: &'a str,
    wg_keepalive: &'a str,
    wg_handshake_first: &'a str,
    wg_handshake_connected: &'a str,
) -> Element<'a, Message> {
    section_card(
        column![
            section_header("WireGuard"),
            text_field("Device / Key Name", "Default", wg_key, Message::SettingsWgKeyChanged),
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
        .spacing(theme::SPACE_SM),
    )
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
    netlock_allowlist_ips: &'a str,
) -> Element<'a, Message> {
    let mut sections = column![].spacing(theme::SPACE_MD);

    // Connection settings
    sections = sections.push(section_card(
        column![
            section_header("Connection"),
            checkbox(!no_lock)
                .label("Network lock (kill switch)")
                .on_toggle(|checked| Message::ConnectNoLockToggle(!checked)),
            checkbox(allow_lan)
                .label("Allow LAN traffic")
                .on_toggle(Message::ConnectAllowLanToggle),
            checkbox(!no_reconnect)
                .label("Auto-reconnect")
                .on_toggle(|checked| Message::ConnectNoReconnectToggle(!checked)),
            checkbox(no_verify)
                .label("Skip tunnel verification")
                .on_toggle(Message::ConnectNoVerifyToggle),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Policy settings
    let incoming_options: Vec<&str> = vec!["block", "allow"];
    let incoming_selected: Option<&str> = incoming_options
        .iter()
        .find(|&&o| o == netlock_incoming)
        .copied();

    sections = sections.push(section_card(
        column![
            section_header("Lock Policy"),
            dropdown_field("Incoming Policy", incoming_options, incoming_selected, |selected: &str| {
                Message::SettingsNetlockIncomingChanged(selected.to_string())
            }),
            checkbox(netlock_allow_ping)
                .label("Allow ICMP ping")
                .on_toggle(Message::SettingsNetlockAllowPingToggle),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Allowlist IPs
    sections = sections.push(section_card(
        column![
            section_header("Allowlist"),
            hint("CIDRs that pass through the kill switch (no routing change)."),
            text_field(
                "Allowlist IPs",
                "1.2.3.4, 5.6.7.0/24",
                netlock_allowlist_ips,
                Message::SettingsNetlockAllowlistIpsChanged,
            ),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Persistent Lock controls
    let lock_status = if lock_installed && lock_persistent {
        "Installed and active"
    } else if lock_installed {
        "Installed but inactive"
    } else {
        "Not installed"
    };
    let lock_status_color = if lock_installed && lock_persistent {
        theme::SUCCESS
    } else if lock_installed {
        theme::WARNING
    } else {
        theme::TEXT_SECONDARY
    };

    let mut lock_buttons = row![].spacing(theme::SPACE_SM);

    let mut install_btn = button(text("Install").size(14))
        .padding([8, 16])
        .style(theme::secondary_button);
    if !lock_installed {
        install_btn = install_btn.on_press(Message::LockInstall);
    }
    lock_buttons = lock_buttons.push(install_btn);

    let mut uninstall_btn = button(text("Uninstall").size(14))
        .padding([8, 16])
        .style(theme::secondary_button);
    if lock_installed {
        uninstall_btn = uninstall_btn.on_press(Message::LockUninstall);
    }
    lock_buttons = lock_buttons.push(uninstall_btn);

    let mut enable_btn = button(text("Enable").size(14))
        .padding([8, 16])
        .style(theme::secondary_button);
    if lock_installed && !lock_persistent {
        enable_btn = enable_btn.on_press(Message::LockEnable);
    }
    lock_buttons = lock_buttons.push(enable_btn);

    let mut disable_btn = button(text("Disable").size(14))
        .padding([8, 16])
        .style(theme::secondary_button);
    if lock_installed && lock_persistent {
        disable_btn = disable_btn.on_press(Message::LockDisable);
    }
    lock_buttons = lock_buttons.push(disable_btn);

    sections = sections.push(section_card(
        column![
            section_header("Persistent Lock"),
            text(lock_status).size(14).color(lock_status_color),
            lock_buttons,
        ]
        .spacing(theme::SPACE_SM),
    ));

    sections.into()
}

// ── Advanced sub-tab ───────────────────────────────────────────────────

fn view_advanced<'a>(
    pinger_timeout: &'a str,
    manifest_refresh: &'a str,
    penality: &'a str,
    http_timeout: &'a str,
    checking_ntry: &'a str,
    capacity_factor: &'a str,
    log_file_enabled: bool,
    log_file_path: &'a str,
    log_level_debug: bool,
    mode_port: &'a str,
    check_route: bool,
) -> Element<'a, Message> {
    let mut sections = column![].spacing(theme::SPACE_MD);

    // Tuning
    sections = sections.push(section_card(
        column![
            section_header("Tuning"),
            text_field("Pinger Timeout (s)", "3", pinger_timeout, Message::SettingsPingerTimeoutChanged),
            text_field("Manifest Refresh Interval (s)", "1800", manifest_refresh, Message::SettingsManifestRefreshChanged),
            text_field("Penalty on Error", "30", penality, Message::SettingsPenalityChanged),
            text_field("HTTP Timeout (s)", "10", http_timeout, Message::SettingsHttpTimeoutChanged),
            text_field("Verification Retries", "3", checking_ntry, Message::SettingsCheckingNtryChanged),
            text_field("Capacity Factor (0 = off)", "0", capacity_factor, Message::SettingsCapacityFactorChanged),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // WireGuard Mode
    sections = sections.push(section_card(
        column![
            section_header("WireGuard Mode"),
            text_field("Force Port", "empty = auto", mode_port, Message::SettingsModePortChanged),
            hint("Force a specific WireGuard port (e.g. 1637). Empty = auto-select."),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Logging
    sections = sections.push(section_card(
        column![
            section_header("Logging"),
            checkbox(log_file_enabled)
                .label("Enable file logging")
                .on_toggle(Message::SettingsLogFileEnabledToggle),
            text_field("Log File Path", "/var/log/airvpn-rs/helper.log", log_file_path, Message::SettingsLogFilePathChanged),
            checkbox(log_level_debug)
                .label("Enable debug logging")
                .on_toggle(Message::SettingsLogLevelDebugToggle),
            hint("Debug level applies immediately. File path changes require helper restart."),
        ]
        .spacing(theme::SPACE_SM),
    ));

    // Verification
    sections = sections.push(section_card(
        column![
            section_header("Verification"),
            checkbox(check_route)
                .label("Verify routes after connect")
                .on_toggle(Message::SettingsCheckRouteToggle),
            hint("Check routing table is correctly configured post-connection."),
        ]
        .spacing(theme::SPACE_SM),
    ));

    sections.into()
}
