//! Monochrome theme with one electric-blue accent, in dark and light variants.
//!
//! Every style helper reads its colors from [`tokens`], so widgets follow the
//! active variant (system light/dark, or `AIRVPN_THEME=light|dark`).

use iced::border::Radius;
use iced::font::Weight;
use iced::theme::{Mode, Palette};
use iced::widget::{button, container, pick_list, scrollable, svg, text, text_input, toggler};
use iced::{Background, Border, Color, Font, Shadow, Theme};

// ── Fonts ────────────────────────────────────────────────────────────────

pub const FONT: Font = Font::with_name("Geist");
pub const FONT_MEDIUM: Font = Font { weight: Weight::Medium, ..FONT };
pub const FONT_SEMIBOLD: Font = Font { weight: Weight::Semibold, ..FONT };
pub const MONO: Font = Font::with_name("Geist Mono");

pub const FONT_FILES: [&[u8]; 5] = [
    include_bytes!("../../resources/fonts/Geist-Regular.ttf"),
    include_bytes!("../../resources/fonts/Geist-Medium.ttf"),
    include_bytes!("../../resources/fonts/Geist-SemiBold.ttf"),
    include_bytes!("../../resources/fonts/GeistMono-Regular.ttf"),
    include_bytes!("../../resources/fonts/GeistMono-Medium.ttf"),
];

// ── Type scale ───────────────────────────────────────────────────────────

pub const TEXT_XS: f32 = 12.0;
pub const TEXT_SM: f32 = 13.0;
pub const TEXT_MD: f32 = 14.0;
pub const TEXT_LG: f32 = 16.0;
pub const TEXT_XL: f32 = 20.0;
pub const TEXT_DISPLAY: f32 = 34.0;

// ── Spacing & shape ──────────────────────────────────────────────────────

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 16.0;
pub const SPACE_LG: f32 = 24.0;
pub const SPACE_XL: f32 = 32.0;

pub const RADIUS_SM: f32 = 6.0;
pub const RADIUS_MD: f32 = 8.0;
pub const RADIUS_LG: f32 = 12.0;
pub const RADIUS_FULL: f32 = 999.0;

pub const SIDEBAR_WIDTH: f32 = 196.0;
pub const CONTENT_MAX_WIDTH: f32 = 560.0;

// ── Color tokens ─────────────────────────────────────────────────────────

pub struct Tokens {
    pub bg: Color,
    pub sidebar: Color,
    pub surface: Color,
    pub hover: Color,
    pub pressed: Color,
    pub border: Color,
    pub border_strong: Color,
    pub text: Color,
    pub muted: Color,
    pub faint: Color,
    pub accent: Color,
    pub accent_hover: Color,
    pub on_accent: Color,
    /// Accent used as a text/icon color on the page background.
    pub accent_fg: Color,
    pub accent_soft: Color,
    pub danger: Color,
    pub danger_soft: Color,
    pub warning: Color,
}

pub const DARK: Tokens = Tokens {
    bg: rgb(0x0A, 0x0A, 0x0A),
    sidebar: rgb(0x11, 0x11, 0x11),
    surface: rgb(0x14, 0x14, 0x14),
    hover: rgb(0x1C, 0x1C, 0x1C),
    pressed: rgb(0x24, 0x24, 0x24),
    border: rgb(0x26, 0x26, 0x26),
    border_strong: rgb(0x3A, 0x3A, 0x3A),
    text: rgb(0xED, 0xED, 0xED),
    muted: rgb(0xA1, 0xA1, 0xA1),
    faint: rgb(0x6B, 0x6B, 0x6B),
    accent: rgb(0x2F, 0x6B, 0xFF),
    accent_hover: rgb(0x4A, 0x7F, 0xFF),
    on_accent: rgb(0xFF, 0xFF, 0xFF),
    accent_fg: rgb(0x6E, 0x9B, 0xFF),
    accent_soft: rgba(0x2F, 0x6B, 0xFF, 0.16),
    danger: rgb(0xFF, 0x5C, 0x5C),
    danger_soft: rgba(0xFF, 0x5C, 0x5C, 0.10),
    warning: rgb(0xF5, 0xA5, 0x24),
};

pub const LIGHT: Tokens = Tokens {
    bg: rgb(0xFF, 0xFF, 0xFF),
    sidebar: rgb(0xF7, 0xF7, 0xF7),
    surface: rgb(0xFA, 0xFA, 0xFA),
    hover: rgb(0xF0, 0xF0, 0xF0),
    pressed: rgb(0xE8, 0xE8, 0xE8),
    border: rgb(0xE6, 0xE6, 0xE6),
    border_strong: rgb(0xD0, 0xD0, 0xD0),
    text: rgb(0x0A, 0x0A, 0x0A),
    muted: rgb(0x5F, 0x5F, 0x5F),
    faint: rgb(0xA3, 0xA3, 0xA3),
    accent: rgb(0x2F, 0x6B, 0xFF),
    accent_hover: rgb(0x1F, 0x57, 0xE6),
    on_accent: rgb(0xFF, 0xFF, 0xFF),
    accent_fg: rgb(0x1F, 0x57, 0xE6),
    accent_soft: rgba(0x2F, 0x6B, 0xFF, 0.10),
    danger: rgb(0xD9, 0x2D, 0x20),
    danger_soft: rgba(0xD9, 0x2D, 0x20, 0.08),
    warning: rgb(0xB4, 0x53, 0x09),
};

/// Tokens for the active theme variant.
pub fn tokens(theme: &Theme) -> &'static Tokens {
    if theme.extended_palette().is_dark { &DARK } else { &LIGHT }
}

/// Build the iced theme for a light/dark mode (`Mode::None` falls back to dark).
pub fn theme_for(mode: Mode) -> Theme {
    let (name, t) = match mode {
        Mode::Light => ("AirVPN Light", &LIGHT),
        _ => ("AirVPN Dark", &DARK),
    };
    Theme::custom(
        name.to_string(),
        Palette {
            background: t.bg,
            text: t.text,
            primary: t.accent,
            success: t.accent,
            warning: t.warning,
            danger: t.danger,
        },
    )
}

/// `AIRVPN_THEME=light|dark` pins the variant instead of following the system.
pub fn env_override() -> Option<Mode> {
    match std::env::var("AIRVPN_THEME").ok()?.to_ascii_lowercase().as_str() {
        "light" => Some(Mode::Light),
        "dark" => Some(Mode::Dark),
        _ => None,
    }
}

// ── Text ─────────────────────────────────────────────────────────────────

pub fn text_muted(theme: &Theme) -> text::Style {
    text::Style { color: Some(tokens(theme).muted) }
}

pub fn text_faint(theme: &Theme) -> text::Style {
    text::Style { color: Some(tokens(theme).faint) }
}

pub fn text_accent(theme: &Theme) -> text::Style {
    text::Style { color: Some(tokens(theme).accent_fg) }
}

pub fn text_danger(theme: &Theme) -> text::Style {
    text::Style { color: Some(tokens(theme).danger) }
}

pub fn text_warning(theme: &Theme) -> text::Style {
    text::Style { color: Some(tokens(theme).warning) }
}

// ── Containers ───────────────────────────────────────────────────────────

pub fn sidebar(theme: &Theme) -> container::Style {
    let t = tokens(theme);
    container::Style {
        background: Some(Background::Color(t.sidebar)),
        border: Border { width: 0.0, ..Default::default() },
        ..Default::default()
    }
}

/// 1px vertical rule between sidebar and content.
pub fn rule(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(tokens(theme).border)),
        ..Default::default()
    }
}

/// Bordered panel grouping related content (stats strip, settings list).
pub fn panel(theme: &Theme) -> container::Style {
    let t = tokens(theme);
    container::Style {
        background: Some(Background::Color(t.surface)),
        border: Border { radius: RADIUS_LG.into(), width: 1.0, color: t.border },
        ..Default::default()
    }
}

pub fn error_banner(theme: &Theme) -> container::Style {
    let t = tokens(theme);
    container::Style {
        text_color: Some(t.danger),
        background: Some(Background::Color(t.danger_soft)),
        border: Border { radius: RADIUS_MD.into(), width: 1.0, color: with_alpha(t.danger, 0.35) },
        ..Default::default()
    }
}

/// Status chip outline (connected chip gets the soft accent fill).
pub fn chip(active: bool) -> impl Fn(&Theme) -> container::Style {
    move |theme| {
        let t = tokens(theme);
        container::Style {
            text_color: Some(if active { t.accent_fg } else { t.muted }),
            background: Some(Background::Color(if active { t.accent_soft } else { Color::TRANSPARENT })),
            border: Border {
                radius: RADIUS_FULL.into(),
                width: 1.0,
                color: if active { Color::TRANSPARENT } else { t.border_strong },
            },
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DotKind {
    On,
    Busy,
    Off,
}

/// Small round status dot.
pub fn dot(kind: DotKind) -> impl Fn(&Theme) -> container::Style {
    move |theme| {
        let t = tokens(theme);
        let (fill, ring) = match kind {
            DotKind::On => (t.accent, Color::TRANSPARENT),
            DotKind::Busy => (Color::TRANSPARENT, t.accent_fg),
            DotKind::Off => (t.faint, Color::TRANSPARENT),
        };
        container::Style {
            background: Some(Background::Color(fill)),
            border: Border { radius: RADIUS_FULL.into(), width: 1.5, color: ring },
            ..Default::default()
        }
    }
}

pub fn bar_track(theme: &Theme) -> container::Style {
    container::Style {
        background: Some(Background::Color(tokens(theme).border)),
        border: Border { radius: 2.0.into(), ..Default::default() },
        ..Default::default()
    }
}

/// Load bar fill: neutral, turning to full-strength text color when hot.
pub fn bar_fill(hot: bool) -> impl Fn(&Theme) -> container::Style {
    move |theme| {
        let t = tokens(theme);
        container::Style {
            background: Some(Background::Color(if hot { t.text } else { t.muted })),
            border: Border { radius: 2.0.into(), ..Default::default() },
            ..Default::default()
        }
    }
}

// ── Buttons ──────────────────────────────────────────────────────────────

fn base_button(bg: Color, fg: Color, border: Border) -> button::Style {
    button::Style {
        background: Some(Background::Color(bg)),
        text_color: fg,
        border,
        shadow: Shadow::default(),
        snap: true,
    }
}

/// Filled accent button: the one primary action on a screen.
pub fn primary_button(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    let (bg, fg) = match status {
        button::Status::Hovered => (t.accent_hover, t.on_accent),
        button::Status::Pressed => (t.accent, t.on_accent),
        button::Status::Disabled => (with_alpha(t.accent, 0.35), with_alpha(t.on_accent, 0.7)),
        button::Status::Active => (t.accent, t.on_accent),
    };
    base_button(bg, fg, Border { radius: RADIUS_MD.into(), ..Default::default() })
}

/// Outlined neutral button.
pub fn secondary_button(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    let (bg, fg, border) = match status {
        button::Status::Hovered => (t.hover, t.text, t.border_strong),
        button::Status::Pressed => (t.pressed, t.text, t.border_strong),
        button::Status::Disabled => (Color::TRANSPARENT, t.faint, t.border),
        button::Status::Active => (Color::TRANSPARENT, t.text, t.border_strong),
    };
    base_button(bg, fg, Border { radius: RADIUS_MD.into(), width: 1.0, color: border })
}

/// Borderless low-emphasis button (Recover, Clear, icon buttons).
pub fn ghost_button(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    let (bg, fg) = match status {
        button::Status::Hovered => (t.hover, t.text),
        button::Status::Pressed => (t.pressed, t.text),
        button::Status::Disabled => (Color::TRANSPARENT, t.faint),
        button::Status::Active => (Color::TRANSPARENT, t.muted),
    };
    base_button(bg, fg, Border { radius: RADIUS_MD.into(), ..Default::default() })
}

/// Inline text link (no chrome, accent text).
pub fn link_button(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    let fg = match status {
        button::Status::Hovered | button::Status::Pressed => t.text,
        button::Status::Disabled => t.faint,
        button::Status::Active => t.accent_fg,
    };
    base_button(Color::TRANSPARENT, fg, Border::default())
}

pub fn nav_item(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let t = tokens(theme);
        let (bg, fg) = match (active, status) {
            (true, _) => (t.pressed, t.text),
            (false, button::Status::Hovered | button::Status::Pressed) => (t.hover, t.text),
            (false, _) => (Color::TRANSPARENT, t.muted),
        };
        base_button(bg, fg, Border { radius: RADIUS_MD.into(), ..Default::default() })
    }
}

/// One option inside a segmented control (settings sections, log levels).
pub fn segment(active: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let t = tokens(theme);
        let (bg, fg, border) = match (active, status) {
            (true, _) => (t.bg, t.text, t.border_strong),
            (false, button::Status::Hovered | button::Status::Pressed) => {
                (Color::TRANSPARENT, t.text, Color::TRANSPARENT)
            }
            (false, _) => (Color::TRANSPARENT, t.muted, Color::TRANSPARENT),
        };
        base_button(bg, fg, Border { radius: RADIUS_SM.into(), width: 1.0, color: border })
    }
}

/// Track behind a row of [`segment`] buttons.
pub fn segment_track(theme: &Theme) -> container::Style {
    let t = tokens(theme);
    container::Style {
        background: Some(Background::Color(t.hover)),
        border: Border { radius: RADIUS_MD.into(), width: 1.0, color: t.border },
        ..Default::default()
    }
}

pub fn table_header(theme: &Theme, status: button::Status) -> button::Style {
    let t = tokens(theme);
    let fg = match status {
        button::Status::Hovered | button::Status::Pressed => t.text,
        _ => t.muted,
    };
    base_button(Color::TRANSPARENT, fg, Border::default())
}

pub fn server_row(is_selected: bool) -> impl Fn(&Theme, button::Status) -> button::Style {
    move |theme, status| {
        let t = tokens(theme);
        let (bg, border) = match (is_selected, status) {
            (true, _) => (t.accent_soft, with_alpha(t.accent, 0.55)),
            (false, button::Status::Hovered | button::Status::Pressed) => (t.hover, Color::TRANSPARENT),
            (false, _) => (Color::TRANSPARENT, Color::TRANSPARENT),
        };
        base_button(bg, t.text, Border { radius: RADIUS_MD.into(), width: 1.0, color: border })
    }
}

// ── Inputs ───────────────────────────────────────────────────────────────

pub fn text_input_style(theme: &Theme, status: text_input::Status) -> text_input::Style {
    let t = tokens(theme);
    let border = match status {
        text_input::Status::Focused { .. } => t.accent,
        text_input::Status::Hovered => t.border_strong,
        _ => t.border,
    };
    text_input::Style {
        background: Background::Color(if matches!(status, text_input::Status::Disabled) { t.surface } else { t.bg }),
        border: Border { radius: RADIUS_MD.into(), width: 1.0, color: border },
        icon: t.muted,
        placeholder: t.faint,
        value: t.text,
        selection: with_alpha(t.accent, 0.3),
    }
}

pub fn pick_list_style(theme: &Theme, status: pick_list::Status) -> pick_list::Style {
    let t = tokens(theme);
    let border = match status {
        pick_list::Status::Opened { .. } => t.accent,
        pick_list::Status::Hovered => t.border_strong,
        pick_list::Status::Active => t.border,
    };
    pick_list::Style {
        text_color: t.text,
        placeholder_color: t.faint,
        handle_color: t.muted,
        background: Background::Color(t.bg),
        border: Border { radius: RADIUS_MD.into(), width: 1.0, color: border },
    }
}

pub fn menu_style(theme: &Theme) -> iced::overlay::menu::Style {
    let t = tokens(theme);
    iced::overlay::menu::Style {
        background: Background::Color(t.surface),
        border: Border { radius: RADIUS_MD.into(), width: 1.0, color: t.border_strong },
        text_color: t.text,
        selected_text_color: t.text,
        selected_background: Background::Color(t.pressed),
        shadow: Shadow {
            color: Color { a: 0.25, ..Color::BLACK },
            offset: iced::Vector::new(0.0, 6.0),
            blur_radius: 18.0,
        },
    }
}

pub fn toggler_style(theme: &Theme, status: toggler::Status) -> toggler::Style {
    let t = tokens(theme);
    let (on, hovered, disabled) = match status {
        toggler::Status::Active { is_toggled } => (is_toggled, false, false),
        toggler::Status::Hovered { is_toggled } => (is_toggled, true, false),
        toggler::Status::Disabled { is_toggled } => (is_toggled, false, true),
    };
    let track = match (on, hovered) {
        (true, true) => t.accent_hover,
        (true, false) => t.accent,
        (false, true) => t.faint,
        (false, false) => t.border_strong,
    };
    toggler::Style {
        background: Background::Color(if disabled { with_alpha(track, 0.4) } else { track }),
        background_border_width: 0.0,
        background_border_color: Color::TRANSPARENT,
        foreground: Background::Color(Color::WHITE),
        foreground_border_width: 0.0,
        foreground_border_color: Color::TRANSPARENT,
        text_color: Some(t.text),
        border_radius: Some(Radius::from(RADIUS_FULL)),
        padding_ratio: 0.12,
    }
}

pub fn scrollable_style(theme: &Theme, status: scrollable::Status) -> scrollable::Style {
    let t = tokens(theme);
    let active = matches!(
        status,
        scrollable::Status::Hovered { is_vertical_scrollbar_hovered: true, .. }
            | scrollable::Status::Dragged { is_vertical_scrollbar_dragged: true, .. }
    );
    let rail = scrollable::Rail {
        background: None,
        border: Border::default(),
        scroller: scrollable::Scroller {
            background: Background::Color(if active { t.faint } else { t.border_strong }),
            border: Border { radius: RADIUS_FULL.into(), ..Default::default() },
        },
    };
    let mut style = scrollable::default(theme, status);
    style.vertical_rail = rail;
    style.horizontal_rail = rail;
    style
}

// ── Icons ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Ink {
    Text,
    Muted,
    Accent,
    OnAccent,
}

pub fn ink(role: Ink) -> impl Fn(&Theme, svg::Status) -> svg::Style {
    move |theme, _| {
        let t = tokens(theme);
        svg::Style {
            color: Some(match role {
                Ink::Text => t.text,
                Ink::Muted => t.muted,
                Ink::Accent => t.accent_fg,
                Ink::OnAccent => t.on_accent,
            }),
        }
    }
}

// ── Color helpers ────────────────────────────────────────────────────────

const fn rgb(r: u8, g: u8, b: u8) -> Color {
    rgba(r, g, b, 1.0)
}

const fn rgba(r: u8, g: u8, b: u8, a: f32) -> Color {
    Color { r: r as f32 / 255.0, g: g as f32 / 255.0, b: b as f32 / 255.0, a }
}

pub fn with_alpha(c: Color, a: f32) -> Color {
    Color { a, ..c }
}
