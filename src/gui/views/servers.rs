//! Servers tab: sortable, searchable table of VPN servers.

use iced::widget::{button, column, container, row, scrollable, text, text_input, tooltip, Space};
use iced::{Alignment, Element, Fill, FillPortion};

use airvpn::ipc::{ConnectionState, ServerInfo};

use crate::icons::{icon, Icon};
use crate::theme::{self, DotKind, Ink};
use crate::Message;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortColumn {
    Name,
    Country,
    Users,
    Load,
    Score,
    Ping,
}

// Fixed widths for the numeric columns; the server column takes the rest.
const W_LOAD: f32 = 132.0;
const W_USERS: f32 = 56.0;
const W_PING: f32 = 64.0;
const W_SCORE: f32 = 56.0;
const COL_GAP: f32 = 12.0;
const ROW_PAD_X: f32 = 10.0;

/// Render the servers tab.
pub fn view<'a>(
    servers: &[ServerInfo],
    loading: bool,
    loading_tick: u32,
    selected_idx: Option<usize>,
    sort_column: SortColumn,
    sort_ascending: bool,
    search: &str,
    connection_state: &ConnectionState,
) -> Element<'a, Message> {
    let mut content = column![].spacing(theme::SPACE_MD);

    // Filter and sort
    let displayed = filter_and_sort(servers, search, sort_column, sort_ascending);

    // Top bar: search, refresh, count, connect-to-selection
    let search_input = text_input("Search servers, countries, cities", search)
        .on_input(Message::ServerSearchChanged)
        .padding([8, 12])
        .size(theme::TEXT_MD)
        .style(theme::text_input_style)
        .width(280);

    let refresh_btn = tooltip(
        button(icon(Icon::Refresh, 16.0, Ink::Muted))
            .on_press(Message::FetchServers)
            .padding(9)
            .style(theme::ghost_button),
        container(text("Refresh server list").size(theme::TEXT_XS))
            .padding([6, 10])
            .style(theme::panel),
        tooltip::Position::Bottom,
    );

    let mut top_bar = row![search_input, refresh_btn]
        .spacing(theme::SPACE_SM)
        .align_y(Alignment::Center);

    if !servers.is_empty() {
        let count = if search.is_empty() {
            format!("{} servers", servers.len())
        } else {
            format!("{} of {}", displayed.len(), servers.len())
        };
        top_bar = top_bar.push(text(count).size(theme::TEXT_SM).style(theme::text_muted));
    }
    top_bar = top_bar.push(Space::new().width(Fill));

    // "Connect to {server}" button when one is selected
    if let Some(server) = selected_idx.and_then(|idx| displayed.get(idx)) {
        top_bar = top_bar.push(
            button(
                row![
                    icon(Icon::Power, 14.0, Ink::OnAccent),
                    text(format!("Connect to {}", server.name)).size(theme::TEXT_MD).font(theme::FONT_MEDIUM),
                ]
                .spacing(theme::SPACE_SM)
                .align_y(Alignment::Center),
            )
            .padding([8, 14])
            .style(theme::primary_button)
            .on_press(Message::ConnectToServer(server.name.clone())),
        );
    }

    content = content.push(top_bar);

    // Loading indicator
    if loading {
        let dots = ".".repeat((loading_tick / 5 % 4) as usize);
        content = content.push(
            text(format!("Loading servers{dots}"))
                .size(theme::TEXT_MD)
                .style(theme::text_muted),
        );
        return content.into();
    }

    if servers.is_empty() {
        content = content.push(
            column![
                text("No servers loaded").size(theme::TEXT_LG).font(theme::FONT_MEDIUM),
                text("The helper hasn't sent a server list yet.")
                    .size(theme::TEXT_MD)
                    .style(theme::text_muted),
                button(text("Fetch server list").size(theme::TEXT_MD))
                    .padding([8, 14])
                    .style(theme::secondary_button)
                    .on_press(Message::FetchServers),
            ]
            .spacing(theme::SPACE_SM)
            .padding([theme::SPACE_XL, 0.0]),
        );
        return content.into();
    }

    // Connected server name for highlighting
    let connected_name = match connection_state {
        ConnectionState::Connected { server_name, .. } => Some(server_name.as_str()),
        _ => None,
    };

    // Server rows in a scrollable container
    let mut rows = column![].spacing(2.0);
    for (display_idx, server) in displayed.iter().enumerate() {
        let is_selected = selected_idx == Some(display_idx);
        let is_connected = connected_name == Some(server.name.as_str());
        let is_warning = server.score >= 99998;

        rows = rows.push(
            button(build_row(server, is_connected, is_warning))
                .on_press(Message::ServerClicked(display_idx))
                .width(Fill)
                .padding([7.0, ROW_PAD_X])
                .style(theme::server_row(is_selected)),
        );
    }

    if displayed.is_empty() {
        rows = rows.push(
            container(
                text(format!("No servers match \u{201C}{}\u{201D}.", search))
                    .size(theme::TEXT_MD)
                    .style(theme::text_muted),
            )
            .padding([theme::SPACE_LG, ROW_PAD_X]),
        );
    }

    let table = column![
        build_header(sort_column, sort_ascending),
        container(Space::new()).width(Fill).height(1.0).style(theme::rule),
        scrollable(container(rows).padding(iced::Padding { top: 4.0, right: 12.0, ..Default::default() }))
            .style(theme::scrollable_style)
            .height(Fill),
    ]
    .spacing(0);

    content = content.push(table);

    content.into()
}

/// Build clickable column header row.
fn build_header<'a>(sort_column: SortColumn, sort_ascending: bool) -> Element<'a, Message> {
    let header = |col: SortColumn, label: &'static str, right: bool| -> Element<'a, Message> {
        let active = col == sort_column;
        let mut label_row = row![text(label).size(theme::TEXT_XS).font(theme::FONT_MEDIUM)]
            .spacing(2.0)
            .align_y(Alignment::Center);
        if active {
            label_row = label_row.push(icon(
                if sort_ascending { Icon::ChevronUp } else { Icon::ChevronDown },
                12.0,
                Ink::Text,
            ));
        }
        let inner = container(label_row).width(Fill);
        let inner = if right { inner.align_right(Fill) } else { inner };
        button(inner)
            .on_press(Message::ServerSort(col))
            .width(Fill)
            .padding([8, 0])
            .style(theme::table_header)
            .into()
    };

    row![
        container(header(SortColumn::Name, "Server", false)).width(FillPortion(5)),
        container(header(SortColumn::Country, "Location", false)).width(FillPortion(4)),
        container(header(SortColumn::Load, "Load", false)).width(W_LOAD),
        container(header(SortColumn::Users, "Users", true)).width(W_USERS),
        container(header(SortColumn::Ping, "Ping", true)).width(W_PING),
        container(header(SortColumn::Score, "Score", true)).width(W_SCORE),
    ]
    .spacing(COL_GAP)
    .padding(iced::Padding { left: ROW_PAD_X, right: ROW_PAD_X + 12.0, ..Default::default() })
    .into()
}

/// Build a single server row.
fn build_row<'a>(server: &ServerInfo, is_connected: bool, is_warning: bool) -> Element<'a, Message> {
    let dim = move |t: &iced::Theme| {
        if is_warning { theme::text_faint(t) } else { iced::widget::text::Style::default() }
    };

    // Server name, with a dot when it carries the current tunnel
    let mut name_cell = row![].spacing(theme::SPACE_SM).align_y(Alignment::Center);
    if is_connected {
        name_cell = name_cell.push(
            container(Space::new()).width(7.0).height(7.0).style(theme::dot(DotKind::On)),
        );
    }
    name_cell = name_cell.push(
        text(server.name.clone()).size(theme::TEXT_MD).font(theme::FONT_MEDIUM).style(dim),
    );
    if is_warning {
        let note = server.warning.clone().unwrap_or_else(|| "Unavailable".to_string());
        name_cell = name_cell.push(text(note).size(theme::TEXT_XS).style(theme::text_warning));
    }

    let location = format!("{}, {}", server.location, server.country_code.to_uppercase());

    // Load: neutral bar, full-strength above 80%
    let load_pct = server.load_percent;
    let bar_w = 56.0;
    let fill_w = (load_pct as f32 / 100.0 * bar_w).clamp(0.0, bar_w);
    let load_cell = row![
        container(
            container(Space::new())
                .width(fill_w)
                .height(4.0)
                .style(theme::bar_fill(load_pct > 80.0)),
        )
        .width(bar_w)
        .height(4.0)
        .style(theme::bar_track),
        text(format!("{:.0}%", load_pct)).size(theme::TEXT_SM).font(theme::MONO).style(dim),
    ]
    .spacing(theme::SPACE_SM)
    .align_y(Alignment::Center);

    let ping: Element<'a, Message> = match server.ping_ms {
        Some(ms) => text(format!("{} ms", ms))
            .size(theme::TEXT_SM)
            .font(theme::MONO)
            .style(move |t: &iced::Theme| {
                if ms >= 150 || is_warning { theme::text_muted(t) } else { iced::widget::text::Style::default() }
            })
            .into(),
        None => text("\u{2014}").size(theme::TEXT_SM).style(theme::text_faint).into(),
    };

    let num = |s: String| text(s).size(theme::TEXT_SM).font(theme::MONO).style(theme::text_muted);

    row![
        container(name_cell).width(FillPortion(5)),
        container(text(location).size(theme::TEXT_SM).style(theme::text_muted).wrapping(iced::widget::text::Wrapping::None)).width(FillPortion(4)).clip(true),
        container(load_cell).width(W_LOAD),
        container(num(server.users.to_string())).width(W_USERS).align_right(W_USERS),
        container(ping).width(W_PING).align_right(W_PING),
        container(num(if is_warning { "\u{2014}".into() } else { server.score.to_string() }))
            .width(W_SCORE)
            .align_right(W_SCORE),
    ]
    .spacing(COL_GAP)
    .align_y(Alignment::Center)
    .into()
}

/// Filter servers by search query (case-insensitive on name, country code, country name, location)
/// then sort by the given column.
pub fn filter_and_sort<'a>(
    servers: &'a [ServerInfo],
    search: &str,
    sort_column: SortColumn,
    ascending: bool,
) -> Vec<&'a ServerInfo> {
    let query = search.to_lowercase();
    let mut filtered: Vec<&ServerInfo> = servers
        .iter()
        .filter(|s| {
            if query.is_empty() {
                return true;
            }
            s.name.to_lowercase().contains(&query)
                || s.country_code.to_lowercase().contains(&query)
                || airvpn::countries::country_name(&s.country_code).to_lowercase().contains(&query)
                || s.location.to_lowercase().contains(&query)
        })
        .collect();

    filtered.sort_by(|a, b| {
        let ord = match sort_column {
            SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortColumn::Country => a
                .country_code
                .to_lowercase()
                .cmp(&b.country_code.to_lowercase())
                .then_with(|| a.location.to_lowercase().cmp(&b.location.to_lowercase())),
            SortColumn::Users => a.users.cmp(&b.users),
            SortColumn::Load => a
                .load_percent
                .partial_cmp(&b.load_percent)
                .unwrap_or(std::cmp::Ordering::Equal),
            SortColumn::Score => a.score.cmp(&b.score),
            SortColumn::Ping => {
                match (a.ping_ms, b.ping_ms) {
                    (Some(pa), Some(pb)) => pa.cmp(&pb),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            }
        };
        if ascending { ord } else { ord.reverse() }
    });

    filtered
}
