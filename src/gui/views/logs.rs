//! Logs tab: filterable, color-coded log viewer.

use std::collections::VecDeque;

use iced::widget::{button, checkbox, column, container, row, scrollable, text, Space};
use iced::{Element, Fill};

use crate::{LogEntry, Message};

/// Render the logs tab.
pub fn view<'a>(
    logs: &VecDeque<LogEntry>,
    filter_debug: bool,
    filter_info: bool,
    filter_warn: bool,
    filter_error: bool,
) -> Element<'a, Message> {
    // Top bar: filter checkboxes + clear button
    let top_bar = row![
        checkbox(filter_debug)
            .label("Debug")
            .on_toggle(|_| Message::LogFilterToggle("debug".into())),
        checkbox(filter_info)
            .label("Info")
            .on_toggle(|_| Message::LogFilterToggle("info".into())),
        checkbox(filter_warn)
            .label("Warn")
            .on_toggle(|_| Message::LogFilterToggle("warn".into())),
        checkbox(filter_error)
            .label("Error")
            .on_toggle(|_| Message::LogFilterToggle("error".into())),
        Space::new().width(Fill),
        button(text("Clear").size(14)).on_press(Message::LogClear),
    ]
    .spacing(16)
    .align_y(iced::Alignment::Center);

    // Filter and render log entries
    let mut log_col = column![].spacing(2);
    let mut count = 0;

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
        log_col = log_col.push(line);
        count += 1;
    }

    if count == 0 {
        log_col = log_col.push(text("No log entries.").size(14));
    }

    let log_area = scrollable(container(log_col).padding(4))
        .anchor_bottom()
        .height(Fill);

    column![top_bar, log_area].spacing(8).into()
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
        _ => true, // unknown levels always shown
    }
}

/// Map log level to a display color.
fn level_color(level: &str) -> iced::Color {
    match level.to_lowercase().as_str() {
        "debug" => iced::Color::from_rgb(0.6, 0.6, 0.6),        // grey
        "info" => iced::Color::from_rgb(0.85, 0.85, 0.85),       // light grey / default
        "warn" | "warning" => iced::Color::from_rgb(1.0, 0.76, 0.03), // amber
        "error" => iced::Color::from_rgb(0.91, 0.27, 0.38),      // red (matches error banner)
        _ => iced::Color::WHITE,
    }
}
