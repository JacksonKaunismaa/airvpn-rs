# UI Overhaul Design

## Goal
Make the GUI genuinely beautiful. Warm dark blue palette, card-based layout,
generous spacing, proper visual hierarchy. Stay with Iced 0.14 — it supports
gradients, shadows, animations, and full custom styling.

## Color Palette

| Role | Hex | Notes |
|------|-----|-------|
| Background | `#192E45` | Warm dark blue |
| Surface (cards) | `#1E3A5C` | Lifted from bg |
| Surface hover | `#244468` | |
| Primary | `#3B8EED` | Buttons, accents |
| Primary hover | `#2D7AD4` | Slightly darker |
| Text | `#F0EFE9` | Warm off-white |
| Text secondary | `white @ 60%` | Opacity-based |
| Success | `#44AD4D` | Connected |
| Danger | `#E34039` | Errors, disconnect |
| Warning | `#FFD524` | Connecting, caution |
| Border | `#294D73` | Subtle card borders |

## Spacing & Radius

- Radius: 8px buttons, 12px cards/panels
- Spacing: 8/16/24/32 scale
- Content padding: 24px
- Card internal padding: 16px
- Sidebar: 180px, 12px padding

## Layout Changes

### Sidebar
- Active tab: left 3px accent bar (primary color) + surface bg
- Inactive: transparent, text secondary color
- 8px spacing between items

### Overview
- Status text: 32px, color-coded, centered
- Server info: card with server name, location, country
- Connect button: full-width, 48px, primary bg, 8px radius, shadow
- Stats: 2-column row of cards (transfer + speed)
- Uptime, connection count, lock status in secondary text below

### Servers
- Search: rounded input (8px radius)
- Load column: colored progress bar fill
- Ping: color-coded text (green/yellow/red/grey)
- Rows: 8px radius hover, selected = left accent bar
- Connected row: green tint

### Settings
- Sub-tabs: pill-style toggle bar
- Each section: card wrapper (surface bg, 12px radius, 16px pad)
- Labels above inputs (not side-by-side)
- Save button: full-width primary at bottom

### Logs
- Filter: pill toggle buttons instead of checkboxes
- Alternating subtle row backgrounds
- System monospace for entries

## Not Doing
- Custom fonts (system default is fine)
- Backdrop blur (not available in Iced)
- Animations on state changes (nice-to-have, defer)
- Map/globe visualization
