# GUI Design: airvpn-rs

**Date:** 2026-02-28 (updated 2026-03-01)
**Status:** Approved

## Decisions

- **Toolkit:** iced (pure Rust, Elm architecture, wgpu with software fallback)
- **Scope:** Full Eddie parity (all 7 tabs, settings, tray, splash)
- **Aesthetic:** Dark, minimal, modern (Tailscale/Mullvad vibes)
- **Architecture:** Single crate, dual binaries (`airvpn` CLI + `airvpn-gui`)
- **Privilege model:** Split process — GUI as user, `airvpn helper` subcommand as root via pkexec

## Architecture

Single crate with library + two binaries. No workspace needed — lib.rs already
exports all 15 modules as pub.

```
airvpn-rs/
├─ Cargo.toml                   (lib + 2 binaries)
├─ src/
│  ├─ lib.rs                    (pub mod declarations)
│  ├─ main.rs                   (CLI binary: airvpn)
│  ├─ api.rs
│  ├─ common.rs
│  ├─ config.rs
│  ├─ connect.rs                (connection engine, extracted from main.rs)
│  ├─ crypto.rs
│  ├─ dns.rs
│  ├─ ipv6.rs
│  ├─ manifest.rs
│  ├─ netlock.rs                (two-table: session + persistent lock)
│  ├─ pinger.rs
│  ├─ profile.rs
│  ├─ recovery.rs
│  ├─ server.rs
│  ├─ verify.rs
│  ├─ wireguard.rs
│  ├─ helper.rs                 (NEW — root helper daemon, socket IPC)
│  └─ gui/
│     ├─ main.rs                (GUI binary: airvpn-gui, iced Application)
│     ├─ theme.rs               (dark minimal palette)
│     ├─ ipc.rs                 (client side of helper socket)
│     ├─ widgets/               (custom: speed chart, server table)
│     └─ views/                 (one module per tab/screen)
```

```toml
# Cargo.toml
[lib]
name = "airvpn"
path = "src/lib.rs"

[[bin]]
name = "airvpn"
path = "src/main.rs"

[[bin]]
name = "airvpn-gui"
path = "src/gui/main.rs"
```

## Privilege Model: Split Process

The GUI runs as the user. Privileged operations go through a root helper.
This matches Eddie's architecture (`eddie-ui` + `eddie-cli-elevated`).

```
airvpn-gui (user)              airvpn helper (root)
    |                               |
    |--- pkexec airvpn helper ----->| (launched once, password prompt)
    |                               |
    |===== Unix socket IPC =========|
    |                               |
    |--- Connect(filters) --------->|
    |                               | connect::run() internally
    |<-- StateChanged(Connecting) --|
    |<-- Log("Fetching manifest") --|
    |<-- StateChanged(Connected) ---|
    |<-- Stats(rx, tx) ------------|  (periodic)
    |                               |
    |--- Disconnect --------------->|
    |<-- StateChanged(Disconnected)-|
    |                               |
    |--- LockInstall -------------->|
    |<-- LockStatus(installed) -----|
```

### How it works

1. User launches `airvpn-gui` (no sudo)
2. GUI spawns `pkexec airvpn helper` — polkit shows password dialog once
3. Helper runs as root, listens on Unix socket (`/run/airvpn-rs/helper.sock`)
4. GUI connects to socket, sends commands, receives events
5. Helper can outlive GUI — close GUI, VPN stays up, reopen GUI reconnects to helper

### CLI unchanged

`sudo airvpn connect` still works exactly as today — direct call to `connect::run()`,
no IPC involved. The helper/socket path only exists for the GUI.

### IPC Protocol

Commands (GUI → Helper) and Events (Helper → GUI) are serde-serialized over the
Unix socket. Same `EngineCommand`/`EngineEvent` types used by both CLI and GUI,
just different transports (direct call vs socket).

```rust
// Shared types in helper.rs (or ipc.rs in lib)
pub enum HelperCommand {
    Connect { filters: ServerFilters, credentials: Credentials },
    Disconnect,
    SwitchServer,
    RefreshManifest,
    LockInstall { bootstrap_ips: Vec<String> },
    LockUninstall,
    LockEnable,
    LockDisable,
    Status,
    Shutdown,
}

pub enum HelperEvent {
    StateChanged(ConnectionState),
    Log { level: LogLevel, message: String },
    Stats { rx_bytes: u64, tx_bytes: u64, rx_rate: f64, tx_rate: f64 },
    ServersUpdated(Vec<ServerInfo>),
    LockStatus { session_active: bool, persistent_active: bool },
    Error(String),
}
```

## Screens

7 tabs in a **left sidebar navigator** (not top tabs):

| Tab | Content | Key Widgets |
|-----|---------|-------------|
| **Overview** | Connection status card, connect/disconnect, server name, IP, uptime, mini bandwidth. **Persistent lock status card** (independent of VPN state). | Color-coded status card (green/amber/red). Lock indicator always visible. |
| **Servers** | Sortable table: name, score, country, load bar, latency. Click to connect. Allow/deny | Virtual-scrolled table (~200 rows), search, column sort |
| **Countries** | Grouped by region, server count per country, allow/deny toggles | Collapsible grouped list |
| **Speed** | Real-time bandwidth chart (download blue, upload coral) | Custom iced Canvas widget, resolution selector |
| **Stats** | Session data: connection count, total bandwidth, uptime | Key-value list |
| **Logs** | Timestamped log entries with severity icons, filterable | Virtual-scrolled list, severity filter chips |
| **Settings** | Credentials, Connection, Network, WireGuard, Persistent Lock, UI, Storage | Sectioned form with toggles/inputs/dropdowns |

### Persistent Lock in the GUI

The two-table netlock architecture needs dedicated UI:

**Overview tab** — always-visible status card:
- "Network locked" (persistent active, green shield icon) vs "Network open" (red)
- Independent of VPN connection state — shows even when disconnected
- "Your traffic is blocked unless routed through VPN"

**Settings > Persistent Lock section:**
- Install / Uninstall toggle (maps to `cmd_lock install` / `cmd_lock uninstall`)
- Enable / Disable toggle (maps to `cmd_lock enable` / `cmd_lock disable`)
- Status display (active/inactive, table exists, systemd service state)

### Additional UI

- Splash/loading screen during initial manifest fetch + auth
- System tray via `tray-icon` crate (minimize-to-tray, connect/disconnect menu)
- Desktop notifications via `notify-rust`
- Reconnection to running helper on GUI restart (helper outlives GUI)

## Theme: Dark Minimal

```
Background:     #1a1a2e
Surface:        #16213e  (panels, cards)
Surface hover:  #1a2744
Accent:         #0f3460  (buttons, active tab)
Accent bright:  #4a9eff  (links, highlights)
Success:        #2ecc71  (connected)
Warning:        #f39c12  (connecting/degraded)
Error:          #e94560  (disconnected/error)
Text primary:   #e0e0e0
Text secondary: #8892a0
Border:         #2a3a5c

Font:           Inter (bundled) or system sans
Mono font:      JetBrains Mono (logs, IPs)
Border radius:  8px
Spacing:        16px grid
```

## Implementation Sequence

### Prerequisites — DONE

Refactoring pass completed:
- [x] Decompose cmd_connect → extracted to connect.rs (1430 lines, clean public API)
- [x] Dedup interface name validation → common::validate_interface_name
- [x] Dedup password-stdin reading → common::read_stdin_password
- [x] Dedup MAX_RULE_DELETIONS → common::MAX_RULE_DELETIONS
- [x] Dedup backoff formula → common::backoff_secs
- [x] Dead code cleanup
- [x] Clippy fixes
- [x] Two-table netlock (session + persistent, fully independent)

### GUI Implementation

1. **Add `airvpn helper` subcommand** — socket server wrapping connect::run() + lock commands. Test with CLI client first (no GUI needed).
2. **Add `[[bin]]` for airvpn-gui** — iced dependency, scaffold app with theme, sidebar nav, placeholder tabs.
3. **Wire IPC client** — GUI connects to helper socket, Overview tab works (connect/disconnect/status).
4. **Build tabs** — Servers → Speed → Logs → Countries → Stats → Settings.
5. **Persistent lock UI** — Overview status card + Settings controls.
6. **System tray + polish** — tray, notifications, splash, keyboard shortcuts, helper auto-launch via pkexec.

## Technical Risks

| Risk | Mitigation |
|------|------------|
| iced server table (200+ rows) | Virtual scrolling via iced_lazy or custom widget |
| Real-time speed chart | iced Canvas with ring buffer |
| System tray | `tray-icon` crate, mature on Linux |
| pkexec UX | Password prompt once per session; helper outlives GUI |
| Helper crash recovery | GUI detects dead socket, offers to relaunch helper |
| IPC serialization | serde + bincode or JSON over Unix socket, well-trodden |
| Engine extraction for IPC | connect::run() already has clean API; wrap blocking loop in thread, inject event callbacks |
