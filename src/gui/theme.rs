//! Dark minimal theme for airvpn-gui.

use iced::Color;
use iced::Theme;
use iced::theme::Palette;

/// Create the custom dark theme.
pub fn airvpn_theme() -> Theme {
    Theme::custom(
        "AirVPN Dark".to_string(),
        Palette {
            background: color(0x1a, 0x1a, 0x2e),
            text: color(0xe0, 0xe0, 0xe0),
            primary: color(0x4a, 0x9e, 0xff),
            success: color(0x2e, 0xcc, 0x71),
            warning: color(0xf3, 0x9c, 0x12),
            danger: color(0xe9, 0x45, 0x60),
        },
    )
}

pub const SURFACE: Color = color(0x16, 0x21, 0x3e);
pub const SURFACE_HOVER: Color = color(0x1a, 0x27, 0x44);
pub const ACCENT: Color = color(0x0f, 0x34, 0x60);
pub const WARNING: Color = color(0xf3, 0x9c, 0x12);
pub const TEXT_SECONDARY: Color = color(0x88, 0x92, 0xa0);
pub const BORDER: Color = color(0x2a, 0x3a, 0x5c);

const fn color(r: u8, g: u8, b: u8) -> Color {
    Color {
        r: r as f32 / 255.0,
        g: g as f32 / 255.0,
        b: b as f32 / 255.0,
        a: 1.0,
    }
}
