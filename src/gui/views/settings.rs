//! Settings tab: profile options, per-connect flags, persistent lock controls, event hooks.

use iced::widget::{button, checkbox, column, container, pick_list, row, scrollable, text, text_input, Space};
use iced::{Element, Fill};

use crate::Message;

/// Section header styled text.
fn section_header(label: &str) -> iced::widget::Text<'_> {
    text(label).size(18)
}

/// Label text for form fields.
fn label(s: &str) -> iced::widget::Text<'_> {
    text(s).size(14)
}

/// Render a single event-hook group (pre/up/down).
fn event_hook_group<'a>(
    title: &'a str,
    hook: &str,
    file: &str,
    args: &str,
    wait: bool,
) -> iced::widget::Column<'a, Message> {
    let hook_str = hook.to_string();
    let hook_str2 = hook.to_string();
    let hook_str3 = hook.to_string();
    column![
        label(title),
        row![
            text("Script path").size(12).width(90),
            text_input("Path to script...", file)
                .on_input(move |s| Message::SettingsEventChanged {
                    hook: hook_str.clone(),
                    field: "file".into(),
                    value: s,
                })
                .width(Fill),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center),
        row![
            text("Arguments").size(12).width(90),
            text_input("Script arguments...", args)
                .on_input(move |s| Message::SettingsEventChanged {
                    hook: hook_str2.clone(),
                    field: "args".into(),
                    value: s,
                })
                .width(Fill),
        ]
        .spacing(8)
        .align_y(iced::Alignment::Center),
        checkbox(wait)
            .label("Wait for completion")
            .on_toggle({
                let hook_str = hook_str3;
                move |v| Message::SettingsEventChanged {
                    hook: hook_str.clone(),
                    field: "wait".into(),
                    value: v.to_string(),
                }
            }),
    ]
    .spacing(4)
}

/// Render the settings tab.
#[allow(clippy::too_many_arguments)]
pub fn view<'a>(
    credentials_configured: bool,
    startlast: bool,
    locklast: bool,
    ipv6_mode: &str,
    dns: &str,
    event_pre: (&str, &str, bool),
    event_up: (&str, &str, bool),
    event_down: (&str, &str, bool),
    loaded: bool,
    dirty: bool,
    no_lock: bool,
    allow_lan: bool,
    no_reconnect: bool,
    skip_ping: bool,
    no_verify: bool,
    lock_installed: bool,
    lock_persistent: bool,
) -> Element<'a, Message> {
    if !loaded {
        return container(text("Loading settings...").size(16))
            .padding(16)
            .into();
    }

    let mut content = column![].spacing(16);

    // ── Credentials ──────────────────────────────────────
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

    // ── Server Preferences ───────────────────────────────
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

    // ── Connection (per-connect flags) ───────────────────
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
            checkbox(skip_ping)
                .label("Skip ping measurement")
                .on_toggle(Message::ConnectSkipPingToggle),
            checkbox(no_verify)
                .label("Skip tunnel verification")
                .on_toggle(Message::ConnectNoVerifyToggle),
        ]
        .spacing(6),
    );

    // ── Network ──────────────────────────────────────────
    content = content.push(section_header("Network"));

    let ipv6_options: Vec<&str> = vec!["in", "in-block", "block"];
    let ipv6_selected: Option<&str> = ipv6_options.iter().find(|&&o| o == ipv6_mode).copied();

    content = content.push(
        column![
            row![
                label("IPv6 Mode").width(120),
                pick_list(ipv6_options, ipv6_selected, |selected: &str| {
                    Message::SettingsIpv6ModeChanged(selected.to_string())
                })
                .width(160),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
            row![
                label("Custom DNS").width(120),
                text_input("8.8.8.8, 1.1.1.1", dns)
                    .on_input(Message::SettingsDnsChanged)
                    .width(Fill),
            ]
            .spacing(8)
            .align_y(iced::Alignment::Center),
        ]
        .spacing(8),
    );

    // ── Persistent Lock ──────────────────────────────────
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

    // ── Event Hooks ──────────────────────────────────────
    content = content.push(section_header("Event Hooks"));
    content = content.push(event_hook_group(
        "Pre-connect",
        "pre",
        event_pre.0,
        event_pre.1,
        event_pre.2,
    ));
    content = content.push(event_hook_group(
        "Post-connect",
        "up",
        event_up.0,
        event_up.1,
        event_up.2,
    ));
    content = content.push(event_hook_group(
        "Post-disconnect",
        "down",
        event_down.0,
        event_down.1,
        event_down.2,
    ));

    // ── Save button ──────────────────────────────────────
    content = content.push(Space::new().height(8));
    let mut save_btn = button(text("Save Settings").size(16));
    if dirty && loaded {
        save_btn = save_btn.on_press(Message::SaveSettings);
    }
    content = content.push(save_btn);

    scrollable(container(content).padding(4))
        .height(Fill)
        .into()
}
