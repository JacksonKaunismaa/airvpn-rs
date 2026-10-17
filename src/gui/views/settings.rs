//! Settings tab: profile options, per-connect flags, persistent lock controls.
//! Organized into sub-tabs: General, Network, WireGuard, Network Lock, Advanced.

use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input, toggler, Space};
use iced::{Alignment, Element, Fill, Length};

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

// ── Building blocks ────────────────────────────────────────────────────

const INPUT_WIDTH: f32 = 240.0;
const NUMBER_WIDTH: f32 = 120.0;

/// A titled group of rows inside one bordered panel, separated by hairlines.
fn group<'a>(
    title: &'a str,
    description: Option<&'a str>,
    rows: Vec<Element<'a, Message>>,
) -> Element<'a, Message> {
    let mut heading = column![text(title).size(theme::TEXT_MD).font(theme::FONT_SEMIBOLD)].spacing(2.0);
    if let Some(desc) = description {
        heading = heading.push(text(desc).size(theme::TEXT_SM).style(theme::text_muted));
    }

    let mut list = column![].spacing(0);
    let count = rows.len();
    for (i, r) in rows.into_iter().enumerate() {
        list = list.push(r);
        if i + 1 < count {
            list = list.push(container(Space::new()).width(Fill).height(1.0).style(theme::rule));
        }
    }

    column![
        container(heading).padding([0.0, 4.0]),
        container(list).width(Fill).style(theme::panel),
    ]
    .spacing(theme::SPACE_SM)
    .into()
}

/// Label (+ optional hint) on the left, control on the right.
fn setting_row<'a>(
    label: &'a str,
    hint: Option<&'a str>,
    control: impl Into<Element<'a, Message>>,
) -> Element<'a, Message> {
    let mut left = column![text(label).size(theme::TEXT_MD)].spacing(2.0).width(Fill);
    if let Some(h) = hint {
        left = left.push(text(h).size(theme::TEXT_XS).style(theme::text_muted));
    }
    row![left, control.into()]
        .spacing(theme::SPACE_MD)
        .padding([11, 16])
        .align_y(Alignment::Center)
        .into()
}

fn toggle_row<'a>(
    label: &'a str,
    hint: Option<&'a str>,
    value: bool,
    on_toggle: impl Fn(bool) -> Message + 'a,
) -> Element<'a, Message> {
    setting_row(
        label,
        hint,
        toggler(value).on_toggle(on_toggle).size(20).style(theme::toggler_style),
    )
}

fn input_row<'a>(
    label: &'a str,
    hint: Option<&'a str>,
    placeholder: &'a str,
    value: &'a str,
    width: f32,
    on_input: fn(String) -> Message,
) -> Element<'a, Message> {
    setting_row(
        label,
        hint,
        text_input(placeholder, value)
            .on_input(on_input)
            .padding([7, 10])
            .size(theme::TEXT_MD)
            .style(theme::text_input_style)
            .width(width),
    )
}

fn select_row<'a>(
    label: &'a str,
    hint: Option<&'a str>,
    options: Vec<&'a str>,
    current: &'a str,
    on_select: impl Fn(&'a str) -> Message + 'a,
) -> Element<'a, Message> {
    let selected = options.iter().find(|&&o| o == current).copied();
    setting_row(
        label,
        hint,
        pick_list(options, selected, on_select)
            .padding([7, 10])
            .text_size(theme::TEXT_MD)
            .width(Length::Fixed(NUMBER_WIDTH + 40.0))
            .style(theme::pick_list_style)
            .menu_style(theme::menu_style),
    )
}

/// One option in the sub-tab segmented control.
fn tab_button(tab: SettingsSubTab, active: bool) -> Element<'static, Message> {
    button(text(tab.label()).size(theme::TEXT_SM))
        .on_press(Message::SettingsSubTabChanged(tab))
        .padding([6, 14])
        .style(theme::segment(active))
        .into()
}

/// Bottom bar: change state + Save.
fn save_bar(dirty: bool, loaded: bool) -> Element<'static, Message> {
    let status = if dirty {
        text("Unsaved changes").size(theme::TEXT_SM)
    } else {
        text("All changes saved").size(theme::TEXT_SM).style(theme::text_muted)
    };
    let mut btn = button(text("Save").size(theme::TEXT_MD).font(theme::FONT_MEDIUM))
        .padding([8, 20])
        .style(theme::primary_button);
    if dirty && loaded {
        btn = btn.on_press(Message::SaveSettings);
    }
    column![
        container(Space::new()).width(Fill).height(1.0).style(theme::rule),
        row![status, Space::new().width(Fill), btn]
            .align_y(Alignment::Center)
            .padding(iced::Padding { top: 12.0, ..Default::default() }),
    ]
    .into()
}

/// Render the settings tab.
#[allow(clippy::too_many_arguments)]
pub fn view<'a>(
    credentials_configured: bool,
    connect: bool,
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
    wg_mtu: &'a str,
    wg_keepalive: &'a str,
    wg_handshake_first: &'a str,
    wg_handshake_connected: &'a str,
    // Network Lock settings
    netlock_incoming: &'a str,
    netlock_allow_ping: bool,
    netlock_allowlist_ips: &'a str,
    netlock_local_forward_ifaces: &'a str,
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
        return container(text("Loading settings\u{2026}").size(theme::TEXT_MD).style(theme::text_muted))
            .padding(theme::SPACE_MD)
            .into();
    }

    // Sub-tab segmented control
    let mut tabs = row![].spacing(2.0);
    for &tab in SettingsSubTab::all() {
        tabs = tabs.push(tab_button(tab, tab == sub_tab));
    }
    let tab_bar = container(tabs).padding(3).style(theme::segment_track);

    // Content for the selected sub-tab
    let tab_content: Element<'a, Message> = match sub_tab {
        SettingsSubTab::General => view_general(
            credentials_configured,
            connect,
            startlast,
            locklast,
            show_errors,
            ui_unit,
            ui_iec,
        ),
        SettingsSubTab::Network => view_network(ipv6_mode, ipv4_mode, entry_iface, dns, dns_mode, dns_services, routes_custom, areas_allowlist, areas_denylist),
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
            netlock_allowlist_ips,
            netlock_local_forward_ifaces,
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

    let body = scrollable(
        container(tab_content)
            .max_width(680)
            .padding(iced::Padding { top: 0.0, right: 14.0, bottom: theme::SPACE_MD, left: 0.0 }),
    )
    .style(theme::scrollable_style)
    .height(Fill);

    column![tab_bar, body, save_bar(dirty, loaded)]
        .spacing(theme::SPACE_LG)
        .into()
}

// ── General sub-tab ────────────────────────────────────────────────────

fn view_general<'a>(
    credentials_configured: bool,
    connect: bool,
    startlast: bool,
    locklast: bool,
    show_errors: bool,
    ui_unit: &'a str,
    ui_iec: bool,
) -> Element<'a, Message> {
    let credentials: Element<'a, Message> = if credentials_configured {
        text("Configured").size(theme::TEXT_MD).style(theme::text_accent).into()
    } else {
        text("Not configured").size(theme::TEXT_MD).style(theme::text_warning).into()
    };
    let credentials_hint = if credentials_configured {
        None
    } else {
        Some("Run `sudo airvpn connect` or import from Eddie")
    };

    column![
        group("Account", None, vec![setting_row("Credentials", credentials_hint, credentials)]),
        group(
            "Server preferences",
            None,
            vec![
                toggle_row(
                    "Connect at startup",
                    Some("Connect to the best server at boot (airvpn-autoconnect.service)"),
                    connect,
                    Message::SettingsConnectToggle,
                ),
                toggle_row("Start with last server", None, startlast, Message::SettingsStartlastToggle),
                toggle_row("Lock to server during session", None, locklast, Message::SettingsLocklastToggle),
            ],
        ),
        group(
            "Display",
            None,
            vec![
                toggle_row("Show error messages", None, show_errors, Message::ShowErrorsToggle),
                select_row(
                    "Speed and transfer unit",
                    None,
                    vec!["bytes", "bits"],
                    ui_unit,
                    |selected: &str| Message::SettingsUiUnitChanged(selected.to_string()),
                ),
                toggle_row(
                    "Binary units",
                    Some("KiB/MiB instead of KB/MB"),
                    ui_iec,
                    Message::SettingsUiIecToggle,
                ),
            ],
        ),
    ]
    .spacing(theme::SPACE_LG)
    .into()
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
    column![
        group(
            "Network",
            None,
            vec![
                select_row("IPv6 mode", None, vec!["in", "in-block", "block"], ipv6_mode, |selected: &str| {
                    Message::SettingsIpv6ModeChanged(selected.to_string())
                }),
                select_row("IPv4 mode", None, vec!["in", "block"], ipv4_mode, |selected: &str| {
                    Message::SettingsIpv4ModeChanged(selected.to_string())
                }),
                input_row(
                    "Entry interface",
                    Some("Empty = auto"),
                    "eth0, wlan0",
                    entry_iface,
                    INPUT_WIDTH,
                    Message::SettingsEntryIfaceChanged,
                ),
                input_row("Custom DNS", None, "8.8.8.8, 1.1.1.1", dns, INPUT_WIDTH, Message::SettingsDnsChanged),
            ],
        ),
        group(
            "DNS configuration",
            None,
            vec![
                select_row(
                    "DNS mode",
                    Some("auto detects systemd-resolved; resolvconf swaps /etc/resolv.conf"),
                    vec!["auto", "resolvconf", "systemd-resolved"],
                    dns_mode,
                    |selected: &str| Message::SettingsDnsModeChanged(selected.to_string()),
                ),
                input_row(
                    "DNS cache services",
                    Some("Restarted on DNS flush, comma-separated"),
                    "nscd,dnsmasq,named,bind9",
                    dns_services,
                    INPUT_WIDTH,
                    Message::SettingsDnsServicesChanged,
                ),
            ],
        ),
        group(
            "Custom routes",
            Some("Routes marked 'out' bypass the VPN; 'in' forces them through the tunnel."),
            vec![input_row(
                "Routes",
                None,
                "192.168.1.0/24,out; 10.0.0.0/8,in",
                routes_custom,
                INPUT_WIDTH,
                Message::SettingsRoutesCustomChanged,
            )],
        ),
        group(
            "Country filters",
            Some("Restrict which countries are used for server selection."),
            vec![
                input_row(
                    "Allowed countries",
                    Some("Empty = all"),
                    "US, NL, DE",
                    areas_allowlist,
                    INPUT_WIDTH,
                    Message::SettingsAreasAllowlistChanged,
                ),
                input_row(
                    "Denied countries",
                    Some("Empty = none"),
                    "CN, RU",
                    areas_denylist,
                    INPUT_WIDTH,
                    Message::SettingsAreasDenylistChanged,
                ),
            ],
        ),
    ]
    .spacing(theme::SPACE_LG)
    .into()
}

// ── WireGuard sub-tab ──────────────────────────────────────────────────

fn view_wireguard<'a>(
    wg_mtu: &'a str,
    wg_keepalive: &'a str,
    wg_handshake_first: &'a str,
    wg_handshake_connected: &'a str,
) -> Element<'a, Message> {
    // Device/key selection now lives on the Overview, not here.
    group(
        "WireGuard",
        None,
        vec![
            input_row("Interface MTU", None, "1320", wg_mtu, NUMBER_WIDTH, Message::SettingsWgMtuChanged),
            input_row(
                "Persistent keepalive",
                Some("Seconds"),
                "15",
                wg_keepalive,
                NUMBER_WIDTH,
                Message::SettingsWgKeepaliveChanged,
            ),
            input_row(
                "Handshake timeout, first",
                Some("Seconds"),
                "50",
                wg_handshake_first,
                NUMBER_WIDTH,
                Message::SettingsWgHandshakeFirstChanged,
            ),
            input_row(
                "Handshake timeout, connected",
                Some("Seconds"),
                "200",
                wg_handshake_connected,
                NUMBER_WIDTH,
                Message::SettingsWgHandshakeConnectedChanged,
            ),
        ],
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
    netlock_local_forward_ifaces: &'a str,
) -> Element<'a, Message> {
    // Persistent lock status + controls
    let (lock_status, lock_style): (&str, fn(&iced::Theme) -> iced::widget::text::Style) =
        if lock_installed && lock_persistent {
            ("Installed and active", theme::text_accent)
        } else if lock_installed {
            ("Installed, inactive", theme::text_warning)
        } else {
            ("Not installed", theme::text_muted)
        };

    let lock_button = |label: &'a str, enabled: bool, msg: Message| -> Element<'a, Message> {
        let mut btn = button(text(label).size(theme::TEXT_SM))
            .padding([6, 12])
            .style(theme::secondary_button);
        if enabled {
            btn = btn.on_press(msg);
        }
        btn.into()
    };
    let lock_buttons = row![
        lock_button("Install", !lock_installed, Message::LockInstall),
        lock_button("Uninstall", lock_installed, Message::LockUninstall),
        lock_button("Enable", lock_installed && !lock_persistent, Message::LockEnable),
        lock_button("Disable", lock_installed && lock_persistent, Message::LockDisable),
    ]
    .spacing(theme::SPACE_SM);

    column![
        group(
            "Connection",
            None,
            vec![
                toggle_row(
                    "Network lock",
                    Some("Kill switch: block traffic outside the tunnel"),
                    !no_lock,
                    |checked| Message::ConnectNoLockToggle(!checked),
                ),
                toggle_row("Allow LAN traffic", None, allow_lan, Message::ConnectAllowLanToggle),
                toggle_row("Auto-reconnect", None, !no_reconnect, |checked| {
                    Message::ConnectNoReconnectToggle(!checked)
                }),
                toggle_row("Skip tunnel verification", None, no_verify, Message::ConnectNoVerifyToggle),
            ],
        ),
        group(
            "Persistent lock",
            Some("Keeps the kill switch in place across reboots and disconnects."),
            vec![
                setting_row("Status", None, text(lock_status).size(theme::TEXT_MD).style(lock_style)),
                container(lock_buttons).padding([11, 16]).into(),
            ],
        ),
        group(
            "Lock policy",
            None,
            vec![
                select_row("Incoming policy", None, vec!["block", "allow"], netlock_incoming, |selected: &str| {
                    Message::SettingsNetlockIncomingChanged(selected.to_string())
                }),
                toggle_row("Allow ICMP ping", None, netlock_allow_ping, Message::SettingsNetlockAllowPingToggle),
            ],
        ),
        group(
            "Allowlist",
            Some("CIDRs that pass through the kill switch (no routing change)."),
            vec![input_row(
                "Allowlist IPs",
                None,
                "1.2.3.4, 5.6.7.0/24",
                netlock_allowlist_ips,
                INPUT_WIDTH,
                Message::SettingsNetlockAllowlistIpsChanged,
            )],
        ),
        group(
            "Local forward",
            Some("Local interfaces forwarded through the tunnel with masquerade (e.g. phone-relay)."),
            vec![
                input_row(
                    "Forward interfaces",
                    Some("Comma-separated; adds FORWARD + NAT rules"),
                    "phone-relay",
                    netlock_local_forward_ifaces,
                    INPUT_WIDTH,
                    Message::SettingsNetlockLocalForwardIfacesChanged,
                ),
                container(
                    text("Requires persistent lock reinstall + reconnect to take effect.")
                        .size(theme::TEXT_XS)
                        .style(theme::text_warning),
                )
                .padding([10, 16])
                .into(),
            ],
        ),
    ]
    .spacing(theme::SPACE_LG)
    .into()
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
    column![
        group(
            "Tuning",
            None,
            vec![
                input_row("Pinger timeout", Some("Seconds"), "3", pinger_timeout, NUMBER_WIDTH, Message::SettingsPingerTimeoutChanged),
                input_row("Manifest refresh interval", Some("Seconds"), "1800", manifest_refresh, NUMBER_WIDTH, Message::SettingsManifestRefreshChanged),
                input_row("Penalty on error", None, "30", penality, NUMBER_WIDTH, Message::SettingsPenalityChanged),
                input_row("HTTP timeout", Some("Seconds"), "10", http_timeout, NUMBER_WIDTH, Message::SettingsHttpTimeoutChanged),
                input_row("Verification retries", None, "3", checking_ntry, NUMBER_WIDTH, Message::SettingsCheckingNtryChanged),
                input_row("Capacity factor", Some("0 = off"), "0", capacity_factor, NUMBER_WIDTH, Message::SettingsCapacityFactorChanged),
            ],
        ),
        group(
            "WireGuard mode",
            None,
            vec![input_row(
                "Force port",
                Some("e.g. 1637; empty = auto-select"),
                "auto",
                mode_port,
                NUMBER_WIDTH,
                Message::SettingsModePortChanged,
            )],
        ),
        group(
            "Logging",
            Some("Debug level applies immediately. File path changes require a helper restart."),
            vec![
                toggle_row("File logging", None, log_file_enabled, Message::SettingsLogFileEnabledToggle),
                input_row(
                    "Log file path",
                    None,
                    "/var/log/airvpn-rs/helper.log",
                    log_file_path,
                    INPUT_WIDTH,
                    Message::SettingsLogFilePathChanged,
                ),
                toggle_row("Debug logging", None, log_level_debug, Message::SettingsLogLevelDebugToggle),
            ],
        ),
        group(
            "Verification",
            None,
            vec![toggle_row(
                "Verify routes after connect",
                Some("Check the routing table is correct once connected"),
                check_route,
                Message::SettingsCheckRouteToggle,
            )],
        ),
    ]
    .spacing(theme::SPACE_LG)
    .into()
}
