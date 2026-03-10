//! Logs tab: filterable, color-coded log viewer.

use std::collections::VecDeque;

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Element, Fill};

use crate::theme;
use crate::{LogEntry, Message};

/// Render the logs tab.
pub fn view<'a>(
    logs: &VecDeque<LogEntry>,
    filter_debug: bool,
    filter_info: bool,
    filter_warn: bool,
    filter_error: bool,
) -> Element<'a, Message> {
    // Top bar: pill filter toggles + clear button
    let top_bar = row![
        filter_pill("Debug", filter_debug, "debug"),
        filter_pill("Info", filter_info, "info"),
        filter_pill("Warn", filter_warn, "warn"),
        filter_pill("Error", filter_error, "error"),
        Space::new().width(Fill),
        button(text("Clear").size(13))
            .padding([6, 14])
            .style(theme::secondary_button)
            .on_press(Message::LogClear),
    ]
    .spacing(theme::SPACE_SM)
    .align_y(iced::Alignment::Center);

    // Filter and render log entries
    let mut log_col = column![].spacing(1.0);
    let mut count = 0;
    let mut even = false;

    for entry in logs {
        if !is_visible(&entry.level, filter_debug, filter_info, filter_warn, filter_error) {
            continue;
        }
        let color = level_color(&entry.level);
        let line = text(format!(
            "[{}] [{}] {}",
            entry.timestamp, entry.level, entry.message
        ))
        .size(12)
        .color(color);

        // Alternating row backgrounds for readability
        let bg = if even {
            iced::Color { r: 1.0, g: 1.0, b: 1.0, a: 0.03 }
        } else {
            iced::Color::TRANSPARENT
        };

        let row_container = container(line)
            .width(Fill)
            .padding([3, 8])
            .style(move |_theme: &iced::Theme| container::Style {
                background: Some(iced::Background::Color(bg)),
                ..Default::default()
            });

        log_col = log_col.push(row_container);
        count += 1;
        even = !even;
    }

    if count == 0 {
        log_col = log_col.push(
            text("No log entries.").size(14).color(theme::TEXT_SECONDARY),
        );
    }

    let log_area = scrollable(container(log_col).padding([4.0, 0.0]))
        .anchor_bottom()
        .height(Fill);

    column![top_bar, log_area].spacing(theme::SPACE_SM).into()
}

/// A pill toggle button for log level filtering.
fn filter_pill<'a>(label: &'a str, active: bool, level: &'a str) -> Element<'a, Message> {
    let btn = button(text(label).size(13))
        .padding([5, 14])
        .on_press(Message::LogFilterToggle(level.into()));
    if active {
        btn.style(theme::pill_active)
    } else {
        btn.style(theme::pill_inactive)
    }
    .into()
}

/// Check whether a log level should be displayed given the current filters.
fn is_visible(
    level: &str,
    filter_debug: bool,
    filter_info: bool,
    filter_warn: bool,
    filter_error: bool,
) -> bool {
    match level.to_lowercase().as_str() {
        "debug" => filter_debug,
        "info" => filter_info,
        "warn" | "warning" => filter_warn,
        "error" => filter_error,
        _ => true,
    }
}

/// Map log level to a display color.
fn level_color(level: &str) -> iced::Color {
    match level.to_lowercase().as_str() {
        "debug" => iced::Color::from_rgb(0.55, 0.55, 0.55),
        "info" => theme::TEXT,
        "warn" | "warning" => theme::WARNING,
        "error" => theme::DANGER,
        _ => iced::Color::WHITE,
    }
}
