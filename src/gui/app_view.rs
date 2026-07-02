use iced::widget::{button, column, container, row, text};
use iced::{Element, Fill};

use super::views;
use super::theme;
use super::{App, Message};

impl App {
    pub(crate) fn view(&self) -> Element<'_, Message> {
        // Left sidebar: tab buttons with active accent
        let mut sidebar = column![].spacing(theme::SPACE_SM).width(theme::SIDEBAR_WIDTH);
        for tab in views::Tab::all() {
            let is_active = *tab == self.active_tab;
            let label = text(tab.label()).size(15);
            let mut btn = button(label).width(Fill).padding([10, 16]);
            if is_active {
                btn = btn.style(theme::sidebar_tab_active);
            } else {
                btn = btn.on_press(Message::TabSelected(*tab))
                    .style(theme::sidebar_tab_inactive);
            }
            sidebar = sidebar.push(btn);
        }
        let sidebar = container(sidebar)
            .padding([theme::SPACE_MD, theme::SPACE_SM + 4.0])
            .style(theme::sidebar);

        // Right content area
        let content: Element<Message> = match self.active_tab {
            views::Tab::Overview => views::overview::view(
                &self.connection_state,
                self.lock_session,
                self.lock_persistent,
                self.lock_installed,
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
                text(err).size(13).color(theme::DANGER)
            )
            .padding([8, 12])
            .width(Fill)
            .style(|_theme: &iced::Theme| container::Style {
                background: Some(iced::Background::Color(iced::Color { r: 0.35, g: 0.12, b: 0.12, a: 1.0 })),
                border: iced::Border { radius: theme::RADIUS_MD.into(), ..Default::default() },
                ..Default::default()
            });
            column![err_banner, content].spacing(theme::SPACE_MD).into()
        } else {
            content
        };

        let content = container(content_with_error)
            .padding(theme::SPACE_LG)
            .width(Fill);

        row![sidebar, content]
            .height(Fill)
            .spacing(0)
            .into()
    }
}
