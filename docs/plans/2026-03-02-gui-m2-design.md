# GUI Milestone 2 Design — Feature-Complete GUI

**Date:** 2026-03-02
**Status:** Approved
**Approach:** Protocol-first (extend helper IPC, then build tabs)

## Summary

M1 delivered: helper daemon, iced GUI, connect/disconnect, overview with status/stats/lock.

M2 delivers: server browsing + selection, full settings panel, proper logs, enhanced overview.
Four tabs total: **Overview | Servers | Logs | Settings** (Speed/Stats/Countries folded in or eliminated).

## Architecture: Protocol-First

The root privilege boundary is the hard constraint. GUI runs as user, profile lives at
`/etc/airvpn-rs/default.profile` (root-owned), and the API manifest needs credentials from
the profile. Every new feature depends on the helper having the right IPC commands.

**Build order:** extend protocol → implement helper handlers → build GUI tabs.

## Protocol Extension

### New Commands (GUI → Helper)

```
ListServers { skip_ping: bool }
GetProfile
SaveProfile { options: HashMap<String, String> }
LockInstall   (existing enum variant, implement handler)
LockUninstall  (existing enum variant, implement handler)
```

### New Events (Helper → GUI)

```
ServerList { servers: Vec<ServerInfo> }
Profile { options: HashMap<String, String> }
ProfileSaved
```

### ServerInfo struct (GUI-friendly, pre-calculated)

```rust
ServerInfo {
    name: String,
    country_code: String,
    location: String,
    users: i64,
    users_max: i64,
    load_percent: f64,      // pre-calculated by helper
    score: i64,             // with ping if measured
    ping_ms: Option<i64>,   // None if skip_ping or unmeasured
    warning: Option<String>, // warning_open or warning_closed
    ipv4: bool,
    ipv6: bool,
}
```

Scoring happens helper-side. GUI just displays and sorts.

The existing `Connect` command already accepts `server: Option<String>`, country filters, etc.
GUI populates those fields from UI state instead of hardcoding defaults.

## Tab 1: Overview (Enhanced)

Existing M1 features (status display, connect/disconnect, RX/TX totals, lock status, activity
line, logs) plus:

- **Current speed** — download/upload MB/s from byte deltas between 2s stats ticks
- **Session uptime** — HH:MM:SS timer since Connected, ticks with 100ms subscription
- **Connection count** — incremented each Connected transition, session-scoped
- **Smart connect button** — if a server is selected on Servers tab, targets that server
  ("Connect to Castor" vs "Connect")

## Tab 2: Servers

**Table columns:** Name | Country | Location | Users | Load% | Score | Ping

- Sortable by clicking column headers (default: Score ascending, lower = better)
- Search/filter text input — substring match on name, country code, location (case-insensitive)
- Country filter dropdown — multi-select checkboxes for country codes, populates
  allow_country/deny_country on Connect
- Single-click highlights row, double-click connects to that server
- Connected server row gets green accent
- warning_closed servers greyed out, warning_open shows amber indicator
- "Refresh" button re-sends ListServers

**Data flow:**
1. Tab switch to Servers → `ListServers { skip_ping }` (or use cached list)
2. Helper fetches manifest, scores, returns `ServerList`
3. GUI stores `Vec<ServerInfo>`, renders table
4. Sorting/filtering is client-side on cached list

**Countries tab eliminated** — country filtering lives in the Servers tab dropdown.

## Tab 3: Logs

- Scrollable list, newest at bottom, auto-scroll
- Format: `[HH:MM:SS] [LEVEL] message`
- Severity filter: checkboxes for Debug / Info / Warn / Error (Debug off by default)
- "Clear" button resets log buffer
- No new protocol commands — logs already accumulate in App.logs

## Tab 4: Settings

Collapsible sections. "Save" button sends `SaveProfile`. On tab load, sends `GetProfile`.

**Credentials**
- Username (text input)
- Password (masked input)

**Server Preferences**
- Start last server (checkbox) — `servers.startlast`
- Lock to server during session (checkbox) — `servers.locklast`

**Connection** (per-connect flags, stored in App state, not profile)
- Network lock / kill switch (checkbox, default on) → `no_lock`
- Allow LAN traffic (checkbox, default on) → `allow_lan`
- Auto-reconnect (checkbox, default on) → `no_reconnect`
- Skip ping measurement (checkbox) → `skip_ping`
- Skip tunnel verification (checkbox) → `no_verify`

**Network** (profile-backed)
- IPv6 mode (dropdown: "in" / "in-block" / "block") → `network.ipv6.mode`
- Custom DNS servers (text input, comma-separated) → `dns.servers`

**Persistent Lock**
- Status line: "Installed" / "Not installed"
- Install / Uninstall buttons → `LockInstall` / `LockUninstall`
- Enable / Disable buttons (when installed) → `LockEnable` / `LockDisable`

**Event Hooks** (3 groups: Pre-connect, Post-connect, Post-disconnect)
- Script path (text input)
- Arguments (text input)
- Wait for completion (checkbox)

## Non-Goals (M3+)

- System tray / minimize-to-tray
- Desktop notifications
- Splash screen
- Keyboard shortcuts
- Theme/appearance settings
- Refined lock UX (toggle buttons matching Eddie)
- Closer Eddie settings parity
