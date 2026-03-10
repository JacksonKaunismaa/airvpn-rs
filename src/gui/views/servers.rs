//! Servers tab: sortable, searchable table of VPN servers.

use iced::widget::{button, column, container, pick_list, row, scrollable, text, text_input, Space};
use iced::{Element, Fill};

use airvpn::ipc::{ConnectionState, ServerInfo};

use crate::theme;
use crate::Message;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SortColumn {
    Name,
    Country,
    Location,
    Users,
    Load,
    Score,
    Ping,
}

/// Render the servers tab.
pub fn view<'a>(
    servers: &[ServerInfo],
    loading: bool,
    loading_tick: u32,
    selected_idx: Option<usize>,
    sort_column: SortColumn,
    sort_ascending: bool,
    search: &str,
    country_filter: &str,
    connection_state: &ConnectionState,
) -> Element<'a, Message> {
    let mut content = column![].spacing(theme::SPACE_SM);

    // Build sorted unique country list for the dropdown
    let mut countries: Vec<String> = servers
        .iter()
        .map(|s| s.country_code.clone())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    countries.insert(0, "All Countries".to_string());

    let selected_country: Option<String> = if country_filter.is_empty() {
        Some("All Countries".to_string())
    } else {
        Some(country_filter.to_string())
    };

    // Top bar: search + country filter + refresh + connect button
    let search_input = text_input("Search servers...", search)
        .on_input(Message::ServerSearchChanged)
        .style(theme::text_input_style)
        .width(250);

    let country_picker = pick_list(countries, selected_country, |selected: String| {
        if selected == "All Countries" {
            Message::ServerCountryFilterChanged(String::new())
        } else {
            Message::ServerCountryFilterChanged(selected)
        }
    })
    .width(140);

    let refresh_btn = button(text("Refresh").size(14))
        .on_press(Message::FetchServers)
        .padding([8, 16])
        .style(theme::secondary_button);

    let mut top_bar = row![search_input, country_picker, refresh_btn]
        .spacing(theme::SPACE_SM)
        .align_y(iced::Alignment::Center);

    // "Connect to {server}" button when one is selected
    if let Some(idx) = selected_idx {
        let filtered = filter_and_sort(servers, search, country_filter, sort_column, sort_ascending);
        if let Some(server) = filtered.get(idx) {
            let label = format!("Connect to {}", server.name);
            top_bar = top_bar.push(Space::new().width(Fill));
            top_bar = top_bar.push(
                button(text(label).size(14).color(iced::Color::WHITE))
                    .padding([8, 16])
                    .style(theme::primary_button)
                    .on_press(Message::ConnectToServer(server.name.clone())),
            );
        }
    }

    content = content.push(top_bar);

    // Loading indicator
    if loading {
        let dots = ".".repeat((loading_tick / 5 % 4) as usize);
        content = content.push(
            text(format!("Loading servers{dots}"))
                .size(14)
                .color(theme::TEXT_SECONDARY),
        );
        return content.into();
    }

    if servers.is_empty() {
        content = content.push(
            text("No servers loaded. Click Refresh to fetch server list.")
                .size(14)
                .color(theme::TEXT_SECONDARY),
        );
        return content.into();
    }

    // Column headers
    let header = build_header(sort_column, sort_ascending);
    content = content.push(header);

    // Filter and sort
    let displayed = filter_and_sort(servers, search, country_filter, sort_column, sort_ascending);

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

        let row_content = build_row(server, is_warning);

        let styled_btn = button(row_content)
            .on_press(Message::ServerClicked(display_idx))
            .width(Fill)
            .padding([6, 8])
            .style(theme::server_row(is_connected, is_selected));

        rows = rows.push(styled_btn);
    }

    if displayed.is_empty() {
        rows = rows.push(
            text("No servers match the search.")
                .size(14)
                .color(theme::TEXT_SECONDARY),
        );
    }

    content = content.push(scrollable(rows).height(Fill));

    content.into()
}

/// Build clickable column header row.
fn build_header<'a>(sort_column: SortColumn, sort_ascending: bool) -> Element<'a, Message> {
    let arrow = if sort_ascending { " \u{25B2}" } else { " \u{25BC}" };

    let cols: &[(SortColumn, &str, f32)] = &[
        (SortColumn::Name, "Name", 140.0),
        (SortColumn::Country, "CC", 50.0),
        (SortColumn::Location, "Location", 100.0),
        (SortColumn::Users, "Users", 70.0),
        (SortColumn::Load, "Load", 190.0),
        (SortColumn::Score, "Score", 60.0),
        (SortColumn::Ping, "Ping", 65.0),
    ];

    let mut header_row = row![].spacing(4.0);
    for &(col, label, width) in cols {
        let display = if col == sort_column {
            format!("{}{}", label, arrow)
        } else {
            label.to_string()
        };
        let btn = button(text(display).size(12))
            .on_press(Message::ServerSort(col))
            .width(width)
            .padding([6, 8])
            .style(theme::table_header);
        header_row = header_row.push(btn);
    }
    header_row.into()
}

/// Build a single server row.
fn build_row<'a>(server: &ServerInfo, is_warning: bool) -> Element<'a, Message> {
    let text_color = if is_warning {
        theme::TEXT_SECONDARY
    } else {
        theme::TEXT
    };

    let ping_str = match server.ping_ms {
        Some(ms) => format!("{}ms", ms),
        None => "\u{2014}".to_string(),
    };
    let ping_color = match server.ping_ms {
        Some(ms) if ms < 50 => theme::PING_GOOD,
        Some(ms) if ms < 100 => theme::PING_OK,
        Some(_) => theme::PING_BAD,
        None => theme::TEXT_SECONDARY,
    };

    let users_str = format!("{}/{}", server.users, server.users_max);
    let load_pct = server.load_percent;

    // Load bar: a row with a colored fill portion
    let load_bar_width = 60.0;
    let fill_width = (load_pct as f32 / 100.0 * load_bar_width).clamp(0.0, load_bar_width);
    let load_color = if load_pct > 80.0 {
        theme::DANGER
    } else if load_pct > 50.0 {
        theme::WARNING
    } else {
        theme::SUCCESS
    };

    let load_fill = container(Space::new())
        .width(fill_width)
        .height(4.0)
        .style(move |_theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(load_color)),
            border: iced::Border { radius: 2.0.into(), ..Default::default() },
            ..Default::default()
        });
    let load_bg = container(load_fill)
        .width(load_bar_width)
        .height(4.0)
        .style(|_theme: &iced::Theme| container::Style {
            background: Some(iced::Background::Color(iced::Color { r: 1.0, g: 1.0, b: 1.0, a: 0.1 })),
            border: iced::Border { radius: 2.0.into(), ..Default::default() },
            ..Default::default()
        });

    let load_cell = row![
        text(format!("{:.0}%", load_pct)).size(12).color(text_color).width(35.0),
        load_bg,
        text(format!("{}/{}", server.bandwidth_cur, server.bandwidth_max))
            .size(11)
            .color(theme::TEXT_SECONDARY)
            .width(80.0),
    ]
    .spacing(4.0)
    .align_y(iced::Alignment::Center);

    row![
        text(server.name.clone()).size(13).color(text_color).width(140.0),
        text(server.country_code.clone()).size(13).color(text_color).width(50.0),
        text(server.location.clone()).size(13).color(text_color).width(100.0),
        text(users_str).size(13).color(text_color).width(70.0),
        container(load_cell).width(190.0),
        text(server.score.to_string()).size(13).color(text_color).width(60.0),
        text(ping_str).size(13).color(ping_color).width(65.0),
    ]
    .spacing(4.0)
    .align_y(iced::Alignment::Center)
    .into()
}

/// Filter servers by country and search query (case-insensitive on name, country, location)
/// then sort by the given column.
pub fn filter_and_sort<'a>(
    servers: &'a [ServerInfo],
    search: &str,
    country_filter: &str,
    sort_column: SortColumn,
    ascending: bool,
) -> Vec<&'a ServerInfo> {
    let query = search.to_lowercase();
    let mut filtered: Vec<&ServerInfo> = servers
        .iter()
        .filter(|s| {
            if !country_filter.is_empty() && s.country_code != country_filter {
                return false;
            }
            if query.is_empty() {
                return true;
            }
            s.name.to_lowercase().contains(&query)
                || s.country_code.to_lowercase().contains(&query)
                || s.location.to_lowercase().contains(&query)
        })
        .collect();

    filtered.sort_by(|a, b| {
        let ord = match sort_column {
            SortColumn::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            SortColumn::Country => a
                .country_code
                .to_lowercase()
                .cmp(&b.country_code.to_lowercase()),
            SortColumn::Location => a.location.to_lowercase().cmp(&b.location.to_lowercase()),
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
