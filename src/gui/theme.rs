//! Warm dark-blue theme for airvpn-gui.

use iced::widget::{button, container, text_input};
use iced::{Border, Color, Shadow, Theme, Vector};
use iced::theme::Palette;

// ── Palette ──────────────────────────────────────────────────────────────

pub const BACKGROUND: Color = color(0x19, 0x2E, 0x45);
pub const SURFACE: Color = color(0x1E, 0x3A, 0x5C);
pub const SURFACE_HOVER: Color = color(0x24, 0x44, 0x68);
pub const SURFACE_BRIGHT: Color = color(0x29, 0x4D, 0x73);
pub const PRIMARY: Color = color(0x3B, 0x8E, 0xED);
pub const PRIMARY_HOVER: Color = color(0x2D, 0x7A, 0xD4);
pub const TEXT: Color = color(0xF0, 0xEF, 0xE9);
pub const TEXT_SECONDARY: Color = Color { r: 1.0, g: 1.0, b: 1.0, a: 0.55 };
pub const SUCCESS: Color = color(0x44, 0xAD, 0x4D);
pub const DANGER: Color = color(0xE3, 0x40, 0x39);
pub const WARNING: Color = color(0xFF, 0xD5, 0x24);
pub const BORDER: Color = color(0x29, 0x4D, 0x73);

// Row colors for connected/selected server
pub const ROW_CONNECTED: Color = Color { r: 0.15, g: 0.35, b: 0.22, a: 1.0 };
pub const ROW_CONNECTED_HOVER: Color = Color { r: 0.18, g: 0.40, b: 0.27, a: 1.0 };
pub const ROW_SELECTED: Color = Color { r: 0.15, g: 0.28, b: 0.48, a: 1.0 };
pub const ROW_SELECTED_HOVER: Color = Color { r: 0.18, g: 0.32, b: 0.52, a: 1.0 };
pub const ROW_HOVER: Color = Color { r: 0.12, g: 0.22, b: 0.38, a: 1.0 };

// Ping colors
pub const PING_GOOD: Color = SUCCESS;
pub const PING_OK: Color = WARNING;
pub const PING_BAD: Color = DANGER;

// ── Spacing ──────────────────────────────────────────────────────────────

pub const RADIUS_SM: f32 = 6.0;
pub const RADIUS_MD: f32 = 8.0;
pub const RADIUS_LG: f32 = 12.0;

pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 16.0;
pub const SPACE_LG: f32 = 24.0;

pub const SIDEBAR_WIDTH: f32 = 180.0;
pub const SIDEBAR_ACCENT_WIDTH: f32 = 3.0;

// ── Theme constructor ────────────────────────────────────────────────────

pub fn airvpn_theme() -> Theme {
    Theme::custom(
        "AirVPN Dark".to_string(),
        Palette {
            background: BACKGROUND,
            text: TEXT,
            primary: PRIMARY,
            success: SUCCESS,
            warning: WARNING,
            danger: DANGER,
        },
    )
}

// ── Reusable style helpers ───────────────────────────────────────────────

/// A card container: rounded surface background with subtle border.
pub fn card(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(SURFACE)),
        border: Border {
            radius: RADIUS_LG.into(),
            width: 1.0,
            color: BORDER,
        },
        shadow: Shadow {
            color: Color { r: 0.0, g: 0.0, b: 0.0, a: 0.25 },
            offset: Vector::new(0.0, 2.0),
            blur_radius: 8.0,
        },
        ..Default::default()
    }
}

/// Same as card but no border (for inner grouping).
pub fn card_flat(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(SURFACE)),
        border: Border {
            radius: RADIUS_LG.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Sidebar container background.
pub fn sidebar(_theme: &Theme) -> container::Style {
    container::Style {
        background: Some(iced::Background::Color(color(0x14, 0x27, 0x3D))),
        ..Default::default()
    }
}

/// Active sidebar tab: accent bar on left, surface background.
pub fn sidebar_tab_active(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => SURFACE_HOVER,
        _ => SURFACE,
    };
    button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: TEXT,
        border: Border {
            radius: RADIUS_MD.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Inactive sidebar tab: transparent, muted text.
pub fn sidebar_tab_inactive(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => Color { r: SURFACE.r, g: SURFACE.g, b: SURFACE.b, a: 0.5 },
        _ => Color::TRANSPARENT,
    };
    button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: TEXT_SECONDARY,
        border: Border {
            radius: RADIUS_MD.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Big primary action button (Connect, Save, etc).
pub fn primary_button(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => PRIMARY_HOVER,
        button::Status::Disabled => Color { r: PRIMARY.r, g: PRIMARY.g, b: PRIMARY.b, a: 0.4 },
        _ => PRIMARY,
    };
    button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: Color::WHITE,
        border: Border {
            radius: RADIUS_MD.into(),
            ..Default::default()
        },
        shadow: Shadow {
            color: Color { r: 0.0, g: 0.0, b: 0.0, a: 0.3 },
            offset: Vector::new(0.0, 2.0),
            blur_radius: 6.0,
        },
        ..Default::default()
    }
}

/// Danger button (Disconnect).
pub fn danger_button(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => color(0xC4, 0x36, 0x30),
        button::Status::Disabled => Color { r: DANGER.r, g: DANGER.g, b: DANGER.b, a: 0.4 },
        _ => DANGER,
    };
    button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: Color::WHITE,
        border: Border {
            radius: RADIUS_MD.into(),
            ..Default::default()
        },
        shadow: Shadow {
            color: Color { r: 0.0, g: 0.0, b: 0.0, a: 0.3 },
            offset: Vector::new(0.0, 2.0),
            blur_radius: 6.0,
        },
        ..Default::default()
    }
}

/// Small secondary button (Refresh, Clear, etc).
pub fn secondary_button(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => SURFACE_HOVER,
        button::Status::Disabled => Color { r: SURFACE.r, g: SURFACE.g, b: SURFACE.b, a: 0.4 },
        _ => SURFACE,
    };
    button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: TEXT,
        border: Border {
            radius: RADIUS_MD.into(),
            width: 1.0,
            color: BORDER,
        },
        ..Default::default()
    }
}

/// Pill-shaped toggle button (active state).
pub fn pill_active(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => PRIMARY_HOVER,
        _ => PRIMARY,
    };
    button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: Color::WHITE,
        border: Border {
            radius: 20.0.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Pill-shaped toggle button (inactive state).
pub fn pill_inactive(_theme: &Theme, status: button::Status) -> button::Style {
    let bg = match status {
        button::Status::Hovered => SURFACE_HOVER,
        _ => SURFACE,
    };
    button::Style {
        background: Some(iced::Background::Color(bg)),
        text_color: TEXT_SECONDARY,
        border: Border {
            radius: 20.0.into(),
            width: 1.0,
            color: BORDER,
        },
        ..Default::default()
    }
}

/// Styled text input.
pub fn text_input_style(_theme: &Theme, status: text_input::Status) -> text_input::Style {
    let border_color = match status {
        text_input::Status::Focused { .. } => PRIMARY,
        text_input::Status::Hovered => SURFACE_BRIGHT,
        _ => BORDER,
    };
    text_input::Style {
        background: iced::Background::Color(color(0x14, 0x27, 0x3D)),
        border: Border {
            radius: RADIUS_MD.into(),
            width: 1.0,
            color: border_color,
        },
        icon: TEXT_SECONDARY,
        placeholder: TEXT_SECONDARY,
        value: TEXT,
        selection: Color { r: PRIMARY.r, g: PRIMARY.g, b: PRIMARY.b, a: 0.3 },
    }
}

/// Table header button style.
pub fn table_header(_theme: &Theme, _status: button::Status) -> button::Style {
    button::Style {
        background: Some(iced::Background::Color(color(0x14, 0x27, 0x3D))),
        text_color: TEXT_SECONDARY,
        border: Border {
            radius: RADIUS_SM.into(),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Server row button style.
pub fn server_row(is_connected: bool, is_selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |_theme: &Theme, status: button::Status| {
        let bg = match (status, is_connected, is_selected) {
            (button::Status::Hovered, true, _) => ROW_CONNECTED_HOVER,
            (_, true, _) => ROW_CONNECTED,
            (button::Status::Hovered, _, true) => ROW_SELECTED_HOVER,
            (_, _, true) => ROW_SELECTED,
            (button::Status::Hovered, _, _) => ROW_HOVER,
            _ => Color::TRANSPARENT,
        };
        button::Style {
            background: Some(iced::Background::Color(bg)),
            text_color: TEXT,
            border: Border {
                radius: RADIUS_SM.into(),
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

// ── Color helper ─────────────────────────────────────────────────────────

const fn color(r: u8, g: u8, b: u8) -> Color {
    Color {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        a: 1.0,
    }
}
