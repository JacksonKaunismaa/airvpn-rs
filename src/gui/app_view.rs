use iced::widget::{button, column, container, row, text, Space};
use iced::{Alignment, Element, Fill};

use airvpn::ipc::ConnectionState;

use super::icons::{icon, Icon};
use super::theme::{self, DotKind, Ink};
use super::views;
use super::{App, Message};

impl App {
    pub(crate) fn view(&self) -> Element<'_, Message> {
        // Left sidebar: wordmark, tab buttons, connection status pinned to the bottom
        let mut nav = column![].spacing(2.0);
        for tab in views::Tab::all() {
            let is_active = *tab == self.active_tab;
            let label = row![
                icon(tab.icon(), 16.0, if is_active { Ink::Text } else { Ink::Muted }),
                text(tab.label()).size(theme::TEXT_MD).font(theme::FONT_MEDIUM),
            ]
            .spacing(10.0)
            .align_y(Alignment::Center);
            let mut btn = button(label)
                .width(Fill)
                .padding([8, 10])
                .style(theme::nav_item(is_active));
            if !is_active {
                btn = btn.on_press(Message::TabSelected(*tab));
            }
            nav = nav.push(btn);
        }

        let wordmark = row![
            text("airvpn").size(15).font(theme::FONT_SEMIBOLD),
            text("-rs").size(15).font(theme::FONT_SEMIBOLD).style(theme::text_faint),
        ];

        let sidebar = container(
            column![
                container(wordmark).padding([4.0, 10.0]),
                Space::new().height(theme::SPACE_MD),
                nav,
                Space::new().height(Fill),
                self.sidebar_status(),
            ]
            .height(Fill),
        )
        .width(theme::SIDEBAR_WIDTH)
        .height(Fill)
        .padding([theme::SPACE_MD, theme::SPACE_SM + 2.0])
        .style(theme::sidebar);

        let divider = container(Space::new()).width(1.0).height(Fill).style(theme::rule);

        // Right content area
        let content: Element<Message> = match self.active_tab {
            views::Tab::Overview => views::overview::view(
                &self.connection_state,
                self.rx_bytes,
                self.tx_bytes,
                self.rx_speed,
                self.tx_speed,
                self.connected_since,
                self.connection_count,
                &self.selected_server,
                self.settings.startlast,
                &self.activity,
                &self.eddie_import_pending,
                views::overview::UnitConfig::from_options(&self.settings.ui_unit, &self.settings.ui_iec.to_string()),
                &self.available_keys,
                &self.settings.wg_key,
            ),
            views::Tab::Servers => views::servers::view(
                &self.servers,
                self.servers_loading,
                self.loading_tick,
                self.selected_server_idx,
                self.server_sort,
                self.server_sort_ascending,
                &self.server_search,
                &self.connection_state,
            ),
            views::Tab::Logs => views::logs::view(
                &self.logs,
                self.log_filter_debug,
                self.log_filter_info,
                self.log_filter_warn,
                self.log_filter_error,
            ),
            views::Tab::Settings => views::settings::view(
                self.settings.credentials_configured,
                self.settings.connect,
                self.settings.startlast,
                self.settings.locklast,
                &self.settings.ipv6_mode,
                &self.settings.ipv4_mode,
                &self.settings.entry_iface,
                &self.settings.dns,
                self.settings.loaded,
                self.settings.dirty,
                self.show_errors,
                self.connect_no_lock,
                self.connect_allow_lan,
                self.connect_no_reconnect,
                self.connect_no_verify,
                self.lock_installed,
                self.lock_persistent,
                self.settings.sub_tab,
                // WireGuard
                &self.settings.wg_mtu,
                &self.settings.wg_keepalive,
                &self.settings.wg_handshake_first,
                &self.settings.wg_handshake_connected,
                // Network Lock
                &self.settings.netlock_incoming,
                self.settings.netlock_allow_ping,
                &self.settings.netlock_allowlist_ips,
                &self.settings.netlock_local_forward_ifaces,
                // Routes
                &self.settings.routes_custom,
                // Area filters
                &self.settings.areas_allowlist,
                &self.settings.areas_denylist,
                // DNS settings
                &self.settings.dns_mode,
                &self.settings.dns_services,
                // UI display settings
                &self.settings.ui_unit,
                self.settings.ui_iec,
                // Logging settings
                self.settings.log_file_enabled,
                &self.settings.log_file_path,
                self.settings.log_level_debug,
                // Mode settings
                &self.settings.mode_port,
                // Advanced
                &self.settings.pinger_timeout,
                &self.settings.manifest_refresh,
                &self.settings.penality,
                &self.settings.http_timeout,
                &self.settings.checking_ntry,
                &self.settings.capacity_factor,
                self.settings.check_route,
            ),
        };
        // Per-tab error display (inline at top of content area, only when show_errors is on)
        let tab_error = if self.show_errors {
            match self.active_tab {
                views::Tab::Overview => self.error_overview.as_deref(),
                views::Tab::Servers => self.error_servers.as_deref(),
                views::Tab::Settings => self.error_settings.as_deref(),
                views::Tab::Logs => None,
            }
        } else {
            None
        };

        let content_with_error: Element<Message> = if let Some(err) = tab_error {
            let err_banner = container(
                row![
                    icon(Icon::Alert, 16.0, Ink::Text),
                    text(err).size(theme::TEXT_SM).style(theme::text_danger),
                ]
                .spacing(theme::SPACE_SM)
                .align_y(Alignment::Center),
            )
            .padding([10, 12])
            .width(Fill)
            .style(theme::error_banner);
            column![err_banner, content].spacing(theme::SPACE_MD).into()
        } else {
            content
        };

        let content = container(content_with_error)
            .padding(theme::SPACE_LG)
            .width(Fill)
            .height(Fill);

        row![sidebar, divider, content]
            .height(Fill)
            .into()
    }

    /// Compact always-visible connection status at the bottom of the sidebar.
    fn sidebar_status(&self) -> Element<'_, Message> {
        let (kind, label, detail) = match &self.connection_state {
            ConnectionState::Connected { server_name, .. } => {
                (DotKind::On, "Connected", Some(server_name.clone()))
            }
            ConnectionState::Connecting => (DotKind::Busy, "Connecting", None),
            ConnectionState::Reconnecting => (DotKind::Busy, "Reconnecting", None),
            ConnectionState::Disconnecting => (DotKind::Busy, "Disconnecting", None),
            ConnectionState::Disconnected => (DotKind::Off, "Disconnected", None),
        };
        let lock_on = self.lock_session || self.lock_persistent;

        let mut lines = column![
            row![
                container(Space::new()).width(8.0).height(8.0).style(theme::dot(kind)),
                text(label).size(theme::TEXT_SM).font(theme::FONT_MEDIUM),
            ]
            .spacing(theme::SPACE_SM)
            .padding(iced::Padding { left: 6.0, ..Default::default() })
            .align_y(Alignment::Center),
        ]
        .spacing(2.0);
        if let Some(name) = detail {
            lines = lines.push(
                container(text(name).size(theme::TEXT_XS).style(theme::text_muted))
                    .padding(iced::Padding { left: 22.0, ..Default::default() }),
            );
        }
        let lock_link = button(
            row![
                icon(if lock_on { Icon::Lock } else { Icon::LockOpen }, 12.0, Ink::Muted),
                text(if lock_on { "Network lock on" } else { "Network lock off" }).size(theme::TEXT_XS),
                icon(Icon::ChevronRight, 12.0, Ink::Muted),
            ]
            .spacing(theme::SPACE_XS + 2.0)
            .align_y(Alignment::Center),
        )
        .padding([4, 6])
        .style(theme::ghost_button)
        .on_press(Message::OpenLockSettings);
        lines = lines.push(lock_link);

        container(lines).padding([theme::SPACE_SM, 4.0]).width(Fill).into()
    }
}
