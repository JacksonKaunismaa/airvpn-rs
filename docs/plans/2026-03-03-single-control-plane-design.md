# Single Control Plane: CLI as Thin Client

**Date:** 2026-03-03
**Status:** Completed (2026-03-04)

## Problem

CLI and helper are independent VPN managers. Both call `connect::run()` directly.
This creates complexity: `refuse_if_helper_running()`, recovery state conflicts,
two disconnect paths, duplicate credential resolution.

## Solution

One daemon (helper), two clients (CLI + GUI). The helper is the single VPN control
plane. Both clients send commands over the Unix socket and render events.

## Architecture

```
  airvpn (CLI)          airvpn-gui (GUI)
       |                      |
       |   HelperCommand      |   HelperCommand
       v                      v
  /run/airvpn-rs/helper.sock (0660, root:wheel)
              |
              v
    airvpn helper (root, systemd socket-activated)
              |
              v
    connect::run() / netlock / recovery / wireguard
```

## Protocol Changes

### HelperCommand::Connect expansion

Currently:
```rust
Connect { server, no_lock, allow_lan, skip_ping, allow_country, deny_country }
```

Needs to include all CLI flags:
- Credentials: `username`, `password` (collected by CLI, sent in command)
- Server filtering: `allow_server`, `deny_server` (already has country filters)
- Networking: `no_verify`, `no_reconnect`, `no_lock_last`, `no_start_last`
- IPv6/DNS: `ipv6_mode`, `dns_servers`
- Event hooks: `event_pre`, `event_up`, `event_down`

### No new event types needed

GUI already receives the full event stream: `Log`, `StateChanged`, `Stats`,
`Error`, `LockStatus`, `Shutdown`. CLI renders the same events as text.

## File Changes

### main.rs (shrinks)
- Remove: provider loading, `connect::run()` calls, `refuse_if_helper_running()`,
  recovery state handling, direct lock/disconnect operations
- Keep: arg parsing, credential collection (interactive prompt, --password-stdin)
- Add: socket client calls for all commands

### connect.rs (moderate)
- `event_tx: Option<Sender<EngineEvent>>` becomes `event_tx: Sender<EngineEvent>`
- All `eprintln!`/`println!` become `event_tx.send()` calls
- Credentials arrive as parameters (no more resolution inside connect::run)

### helper.rs (expands)
- Implement `LockInstall`/`LockUninstall` (currently stubbed)
- Accept expanded Connect command with all flags + credentials
- Remains single source of truth for VPN state

### New: src/cli_client.rs (~100-150 lines)
- Connect to Unix socket
- Send HelperCommand as JSON line
- Read HelperEvent stream, format as text
- Shared by all CLI subcommands

## What Doesn't Change

- connect.rs core logic (reconnection loop, server selection, WireGuard)
- recovery.rs, netlock.rs, wireguard.rs, dns.rs (called by helper, not CLI)
- Socket activation (systemd unit unchanged)
- GUI code (already a thin client)

## Sudo

Not required for CLI. Socket is root:wheel 0660 — any wheel user can connect.
Helper runs as root via systemd. Security boundary is the socket permissions.

## Removed Complexity

- `refuse_if_helper_running()` — gone (single control plane)
- Two disconnect paths (SIGTERM vs socket command) — one path (socket command)
- CLI recovery state handling — helper handles all recovery
- Duplicate credential resolution — CLI collects, helper receives
