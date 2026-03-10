# UI Overhaul Implementation Plan

## Step 1: Theme foundation (`theme.rs`)
- New color palette constants
- Helper functions for card styles, button styles
- Reusable style closures: `card()`, `primary_button()`, `sidebar_button(active)`

## Step 2: Main layout (`gui/main.rs` view function)
- Sidebar: active tab accent bar, better spacing, surface bg on active
- Content area: 24px padding

## Step 3: Overview tab (`views/overview.rs`)
- Hero status text (32px centered)
- Card-wrapped sections (server info, stats)
- Full-width styled connect/disconnect button
- Secondary text for uptime/lock status

## Step 4: Servers tab (`views/servers.rs`)
- Styled search input
- Load progress bars
- Color-coded ping
- Better row styling (radius, hover, accent on selected)

## Step 5: Settings tab (`views/settings.rs`)
- Card wrappers per section
- Pill-style sub-tab bar
- Full-width save button with primary style

## Step 6: Logs tab (`views/logs.rs`)
- Pill toggle filters
- Alternating row backgrounds

## Step 7: Build + visual check

## Files touched
- `src/gui/theme.rs` (rewrite)
- `src/gui/main.rs` (view function ~30 lines)
- `src/gui/views/overview.rs` (rewrite view fn)
- `src/gui/views/servers.rs` (restyle)
- `src/gui/views/settings.rs` (card wrappers + pill tabs)
- `src/gui/views/logs.rs` (restyle)
