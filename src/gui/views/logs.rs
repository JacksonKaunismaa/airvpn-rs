//! Logs tab: filterable, color-coded log viewer.

use std::collections::VecDeque;

use iced::widget::{button, column, container, row, scrollable, text, Space};
use iced::{Alignment, Element, Fill};

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
    // Top bar: level filter toggles + clear button
    let filters = container(
        row![
            filter_toggle("Debug", filter_debug, "debug"),
            filter_toggle("Info", filter_info, "info"),
            filter_toggle("Warn", filter_warn, "warn"),
            filter_toggle("Error", filter_error, "error"),
        ]
        .spacing(2.0),
    )
    .padding(3)
    .style(theme::segment_track);

    let top_bar = row![
        filters,
        Space::new().width(Fill),
        button(text("Clear").size(theme::TEXT_SM))
            .padding([6, 12])
            .style(theme::ghost_button)
            .on_press(Message::LogClear),
    ]
    .spacing(theme::SPACE_SM)
    .align_y(Alignment::Center);

    // Filter and render log entries
    let mut log_col = column![].spacing(0);
    let mut count = 0;

    for entry in logs {
        if !is_visible(&entry.level, filter_debug, filter_info, filter_warn, filter_error) {
            continue;
        }
        let level = entry.level.to_lowercase();
        let level_style: fn(&iced::Theme) -> iced::widget::text::Style = match level.as_str() {
            "warn" | "warning" => theme::text_warning,
            "error" => theme::text_danger,
            _ => theme::text_faint,
        };
        let message_style: fn(&iced::Theme) -> iced::widget::text::Style = match level.as_str() {
            "debug" => theme::text_muted,
            "error" => theme::text_danger,
            _ => |_: &iced::Theme| iced::widget::text::Style::default(),
        };

        let line = row![
            text(entry.timestamp.clone()).size(theme::TEXT_XS).font(theme::MONO).style(theme::text_faint).width(64.0),
            text(level.to_uppercase()).size(theme::TEXT_XS).font(theme::MONO).style(level_style).width(48.0),
            text(entry.message.clone()).size(theme::TEXT_XS).font(theme::MONO).style(message_style).width(Fill),
        ]
        .spacing(theme::SPACE_SM);

        log_col = log_col.push(container(line).width(Fill).padding([4, 12]));
        count += 1;
    }

    let log_area: Element<'a, Message> = if count == 0 {
        let any_hidden = !logs.is_empty();
        container(
            column![
                text("No log entries").size(theme::TEXT_MD).font(theme::FONT_MEDIUM),
                text(if any_hidden {
                    "Entries exist but are hidden by the level filters."
                } else {
                    "Helper messages will appear here as they arrive."
                })
                .size(theme::TEXT_SM)
                .style(theme::text_muted),
            ]
            .spacing(theme::SPACE_XS)
            .align_x(Alignment::Center),
        )
        .center(Fill)
        .style(theme::panel)
        .into()
    } else {
        container(
            scrollable(container(log_col).width(Fill).padding([8.0, 0.0]))
                .anchor_bottom()
                .style(theme::scrollable_style)
                .width(Fill)
                .height(Fill),
        )
        .width(Fill)
        .height(Fill)
        .style(theme::panel)
        .into()
    };

    column![top_bar, log_area].spacing(theme::SPACE_MD).into()
}

/// A toggle inside the level filter segmented control.
fn filter_toggle<'a>(label: &'a str, active: bool, level: &'a str) -> Element<'a, Message> {
    button(text(label).size(theme::TEXT_SM))
        .padding([5, 12])
        .style(theme::segment(active))
        .on_press(Message::LogFilterToggle(level.into()))
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
