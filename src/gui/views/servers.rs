//! Servers tab: sortable, searchable table of VPN servers.

use iced::widget::{button, column, row, scrollable, text, text_input, Space};
use iced::{Element, Fill};

use airvpn::ipc::{ConnectionState, ServerInfo};

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
    connection_state: &ConnectionState,
) -> Element<'a, Message> {
    let mut content = column![].spacing(8);

    // Top bar: search + refresh + connect button
    let search_input = text_input("Search servers...", search)
        .on_input(Message::ServerSearchChanged)
        .width(300);

    let refresh_btn = button(text("Refresh")).on_press(Message::FetchServers);

    let mut top_bar = row![search_input, refresh_btn].spacing(8);

    // "Connect to {server}" button when one is selected
    if let Some(idx) = selected_idx {
        let filtered = filter_and_sort(servers, search, sort_column, sort_ascending);
        if let Some(server) = filtered.get(idx) {
            let label = format!("Connect to {}", server.name);
            top_bar = top_bar.push(Space::new().width(Fill));
            top_bar = top_bar.push(
                button(text(label))
                    .on_press(Message::ConnectToServer(server.name.clone())),
            );
        }
    }

    content = content.push(top_bar);

    // Loading indicator with animated dots (cycles every ~2s at 100ms ticks)
    if loading {
        let dots = ".".repeat((loading_tick / 5 % 4) as usize);
        content = content.push(text(format!("Loading servers{dots}")).size(14));
        return content.into();
    }

    if servers.is_empty() {
        content = content.push(text("No servers loaded. Click Refresh to fetch server list."));
        return content.into();
    }

    // Column headers
    let header = build_header(sort_column, sort_ascending);
    content = content.push(header);

    // Filter and sort
    let displayed = filter_and_sort(servers, search, sort_column, sort_ascending);

    // Connected server name for highlighting
    let connected_name = match connection_state {
        ConnectionState::Connected { server_name, .. } => Some(server_name.as_str()),
        _ => None,
    };

    // Server rows in a scrollable container
    let mut rows = column![].spacing(2);
    for (display_idx, server) in displayed.iter().enumerate() {
        let is_selected = selected_idx == Some(display_idx);
        let is_connected = connected_name == Some(server.name.as_str());
        let is_warning = server.score >= 99998;

        let row_content = build_row(server, is_warning);

        let row_bg = if is_connected {
            iced::Color::from_rgb(0.1, 0.35, 0.2) // green tint for connected
        } else if is_selected {
            iced::Color::from_rgb(0.15, 0.25, 0.45) // blue tint for selected
        } else {
            iced::Color::TRANSPARENT
        };

        let styled_btn = button(row_content)
            .on_press(Message::ServerClicked(display_idx))
            .width(Fill)
            .style(move |_theme, status| {
                let bg = match status {
                    button::Status::Hovered => {
                        if is_connected {
                            iced::Color::from_rgb(0.12, 0.40, 0.25)
                        } else {
                            iced::Color::from_rgb(0.18, 0.28, 0.48)
                        }
                    }
                    _ => row_bg,
                };
                button::Style {
                    background: Some(iced::Background::Color(bg)),
                    text_color: iced::Color::from_rgb(0.88, 0.88, 0.88),
                    border: iced::Border {
                        radius: 2.0.into(),
                        ..Default::default()
                    },
                    ..Default::default()
                }
            });

        rows = rows.push(styled_btn);
    }

    if displayed.is_empty() {
        rows = rows.push(text("No servers match the search.").size(14));
    }

    content = content.push(scrollable(rows).height(Fill));

    content.into()
}

/// Build clickable column header row.
fn build_header<'a>(sort_column: SortColumn, sort_ascending: bool) -> Element<'a, Message> {
    let arrow = if sort_ascending { " \u{25B2}" } else { " \u{25BC}" };

    let cols: &[(SortColumn, &str, f32)] = &[
        (SortColumn::Name, "Name", 140.0),
        (SortColumn::Country, "Country", 60.0),
        (SortColumn::Location, "Location", 100.0),
        (SortColumn::Users, "Users", 70.0),
        (SortColumn::Load, "Load", 190.0),
        (SortColumn::Score, "Score", 60.0),
        (SortColumn::Ping, "Ping", 60.0),
    ];

    let mut header_row = row![].spacing(4);
    for &(col, label, width) in cols {
        let display = if col == sort_column {
            format!("{}{}", label, arrow)
        } else {
            label.to_string()
        };
        let btn = button(text(display).size(13))
            .on_press(Message::ServerSort(col))
            .width(width)
            .style(|_theme, _status| button::Style {
                background: Some(iced::Background::Color(iced::Color::from_rgb(
                    0.12, 0.18, 0.30,
                ))),
                text_color: iced::Color::from_rgb(0.7, 0.75, 0.82),
                border: iced::Border {
                    radius: 2.0.into(),
                    width: 1.0,
                    color: iced::Color::from_rgb(0.2, 0.3, 0.5),
                },
                ..Default::default()
            });
        header_row = header_row.push(btn);
    }
    header_row.into()
}

/// Build a single server row.
fn build_row<'a>(server: &ServerInfo, is_warning: bool) -> Element<'a, Message> {
    let dim = if is_warning {
        iced::Color::from_rgb(0.45, 0.48, 0.52)
    } else {
        iced::Color::from_rgb(0.88, 0.88, 0.88)
    };

    let ping_str = match server.ping_ms {
        Some(ms) => format!("{}ms", ms),
        None => "\u{2014}".to_string(), // em dash
    };

    let users_str = format!("{}/{}", server.users, server.users_max);

    let load_str = format!(
        "{:.0}%, {}/{} Mbit/s",
        server.load_percent, server.bandwidth_cur, server.bandwidth_max
    );

    row![
        text(server.name.clone()).size(13).color(dim).width(140.0),
        text(server.country_code.clone()).size(13).color(dim).width(60.0),
        text(server.location.clone()).size(13).color(dim).width(100.0),
        text(users_str).size(13).color(dim).width(70.0),
        text(load_str).size(13).color(dim).width(190.0),
        text(server.score.to_string()).size(13).color(dim).width(60.0),
        text(ping_str).size(13).color(dim).width(60.0),
    ]
    .spacing(4)
    .into()
}

/// Filter servers by search query (case-insensitive on name, country, location)
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
                // None (no ping) sorts last
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
