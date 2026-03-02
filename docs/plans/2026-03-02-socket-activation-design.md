# systemd Socket Activation for Helper Daemon

## Context

Race condition on GUI startup: the helper calls `bind()` (socket file appears), then `set_permissions()`, then `chown_socket_to_caller_group()` (NSS lookup). The GUI detects the socket via `Path::exists()`, waits a hardcoded 200ms, then tries to connect — but if the chown hasn't finished, the GUI gets `EACCES` and shows an error requiring manual retry (which spawns a second pkexec prompt).

The standard Linux solution is **systemd socket activation** — systemd creates the socket with correct permissions before the helper process starts. Zero race window by construction. This is what Tailscale, Mullvad, Docker, and other daemon-based tools use.

## Design Decisions

- **All-in on systemd** — no standalone/pkexec fallback. Dev testing uses `systemd-socket-activate`.
- **`sd-notify` crate** for socket activation detection (wraps `LISTEN_PID`/`LISTEN_FDS` protocol).
- **`SocketMode=0660, SocketGroup=wheel`** for now (works on Arch, zero setup). Migrate to dedicated `airvpn` group when packaging for AUR (one-line unit file change).
- **`SO_PEERCRED`** on every accepted connection — log connecting UID, framework for future access policy. Prevents rogue service accounts (non-wheel UIDs like `http`, `dnsmasq`, `anki-sync-server`) from controlling the VPN.
- **PID file** for CLI guard — `refuse_if_helper_running()` can't connect to the socket (would trigger activation). Checks `/run/airvpn-rs/helper.pid` instead.
- **No install/uninstall subcommand** — ship unit files as static files in `resources/`. Package manager handles installation.
- **GUI simplified** — remove pkexec, polling loop, 200ms hack, `LaunchHelper` message. GUI just connects; on failure shows "helper not available" error.

## Changes

### 1. `Cargo.toml`

- Add `sd-notify` crate (socket activation detection + readiness notification)
- No other new deps. `nix` already present; may add `"socket"` feature for `SO_PEERCRED`.

### 2. `src/helper.rs` — require socket activation

**Remove entirely:**
- Stale socket removal
- `UnixListener::bind(SOCKET_PATH)`
- `set_permissions()` on socket
- `chown_socket_to_caller_group()` (the whole function)
- `fs::remove_file(SOCKET_PATH)` on exit (systemd owns the socket)
- mkdir + set_permissions on `/run/airvpn-rs/` (systemd's `DirectoryMode=` handles it)

**Add:**
- Socket activation detection via `sd-notify` crate's `listen_fds()`. If not socket-activated → bail with helpful error message.
- `SO_PEERCRED` check on every `accept()` — get connecting UID via `getsockopt(SOL_SOCKET, SO_PEERCRED)`, log it. (No rejection policy yet — just logging + framework.)
- PID file write (`/run/airvpn-rs/helper.pid`) on startup, cleanup on exit.
- `pub fn read_pid_file() -> Option<u32>` (pub for main.rs).

**`run()` becomes:**
```
preflight_checks()
listener = get_socket_from_systemd()  // bail if not activated
write_pid_file()
setup_signal_handler()
check_for_conflicting_cli_connection()
accept_loop:
    accept() → SO_PEERCRED log → handle_client()
cleanup:
    remove PID file
```

### 3. `src/main.rs` — PID-file-based CLI guard

Replace `refuse_if_helper_running()`: read PID file, check `is_pid_alive()`. No socket connection.

`Commands::Helper` stays as bare variant (no subcommands).

### 4. `src/gui/main.rs` — simplify startup

- `boot()` → always fire `Message::HelperConnected` (no socket existence check — it's always there).
- Remove `Message::LaunchHelper` variant entirely.
- Remove `helper_launched` field.
- `HelperConnected` failure → show "helper not available — is airvpn-helper.socket enabled?" (no auto-launch, no retry loop).

### 5. `src/gui/ipc.rs` — remove pkexec

- Remove `launch_helper()`.
- Remove `is_helper_running()` (dead code).
- `HelperClient` and `connect_with_timeout()` unchanged.

### 6. New: `resources/airvpn-helper.socket`

```ini
[Unit]
Description=AirVPN helper daemon socket

[Socket]
ListenStream=/run/airvpn-rs/helper.sock
SocketMode=0660
SocketGroup=wheel
DirectoryMode=0755
RemoveOnStop=yes

[Install]
WantedBy=sockets.target
```

### 7. New: `resources/airvpn-helper.service`

```ini
[Unit]
Description=AirVPN helper daemon
Requires=airvpn-helper.socket
After=airvpn-helper.socket

[Service]
Type=simple
ExecStart=/usr/bin/airvpn helper
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
```

### 8. Remove: `resources/org.airvpn.helper.policy`

Polkit policy for pkexec — no longer needed.

## Files

| File | Change |
|------|--------|
| `src/helper.rs` | Require socket activation, add SO_PEERCRED + PID file, remove bind/chmod/chown |
| `src/main.rs` | PID-file CLI guard |
| `src/gui/main.rs` | Remove LaunchHelper, simplify boot |
| `src/gui/ipc.rs` | Remove `launch_helper()`, `is_helper_running()` |
| `Cargo.toml` | Add `sd-notify` |
| `resources/airvpn-helper.socket` | **New** |
| `resources/airvpn-helper.service` | **New** |
| `resources/org.airvpn.helper.policy` | **Delete** |

## Verification

1. `cargo build && cargo build --release`
2. Install units: copy to `/etc/systemd/system/`, `systemctl daemon-reload`, `systemctl enable --now airvpn-helper.socket`
3. Verify socket: `ls -la /run/airvpn-rs/helper.sock` → mode 0660, group wheel
4. Test socket activation: `systemd-socket-activate -l /tmp/test.sock -- ./target/debug/airvpn helper`
5. GUI connects without pkexec: launch GUI → immediate connection, no password prompt
6. CLI guard: `sudo airvpn connect` while helper running → refused (PID file check)
7. CLI guard no false positive: stop helper → `sudo airvpn connect` → proceeds
8. Restart on crash: `kill -9 $(cat /run/airvpn-rs/helper.pid)` → systemd restarts within 1s
9. Clean shutdown: GUI Shutdown → exit 0 → no restart → next connect reactivates
10. SO_PEERCRED: check helper logs show connecting UID on each GUI connection
