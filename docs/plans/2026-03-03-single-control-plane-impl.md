# Single Control Plane Implementation Plan

> **Status:** Completed (2026-03-04)

**Goal:** Make the CLI a thin socket client — all VPN operations go through the helper daemon.

**Architecture:** Helper is the single control plane. CLI parses args, resolves credentials (interactive prompt can't happen in daemon), connects to Unix socket, sends HelperCommand, reads/prints HelperEvents. GUI is unchanged (already a thin client).

**Tech Stack:** Rust, serde_json (JSON-lines IPC), Unix sockets, systemd socket activation.

**Design doc:** `docs/plans/2026-03-03-single-control-plane-design.md`

---

### Task 1: Expand HelperCommand::Connect with all CLI flags

The current Connect variant only has 6 fields (server, no_lock, allow_lan, skip_ping, allow_country, deny_country). The CLI has ~20 more flags. Add them all so the helper can fully drive `connect::run()`.

**Files:**
- Modify: `src/ipc.rs:11-28` (HelperCommand::Connect)
- Test: `src/ipc.rs` (existing roundtrip test)

**Step 1: Add fields to HelperCommand::Connect**

In `src/ipc.rs`, expand the Connect variant to include all fields from ConnectConfig that the CLI currently passes. Credentials (username/password) are included because the CLI resolves them before sending.

```rust
Connect {
    server: Option<String>,
    no_lock: bool,
    allow_lan: bool,
    skip_ping: bool,
    allow_country: Vec<String>,
    deny_country: Vec<String>,
    // --- new fields ---
    username: String,
    password: String,
    allow_server: Vec<String>,
    deny_server: Vec<String>,
    no_reconnect: bool,
    no_verify: bool,
    no_lock_last: bool,
    no_start_last: bool,
    ipv6_mode: Option<String>,
    dns_servers: Vec<String>,
    event_pre: [Option<String>; 3],
    event_up: [Option<String>; 3],
    event_down: [Option<String>; 3],
},
```

**Step 2: Update the roundtrip test**

Update `test_command_connect_roundtrip` to include the new fields. Verify they survive encode→decode.

**Step 3: Run tests**

Run: `cargo test --lib ipc`
Expected: all ipc tests pass.

**Step 4: Commit**

```bash
git add src/ipc.rs
git commit -m "feat(ipc): expand Connect command with all CLI flags + credentials"
```

---

### Task 2: Add credentials to ConnectConfig, remove interactive resolution from connect::run

Currently `connect::run()` calls `resolve_credentials()` internally (which can prompt on stdin). Move credential resolution OUT of `connect::run()` so credentials arrive pre-resolved. This is needed because the helper daemon can't do interactive prompts.

**Files:**
- Modify: `src/connect.rs:20-48` (ConnectConfig struct + resolve_session)
- Modify: `src/connect.rs:384-411` (resolve_session credential handling)
- Modify: `src/helper.rs:317-339` (ConnectConfig construction in helper)
- Modify: `src/main.rs:313-339` (ConnectConfig construction in CLI)

**Step 1: Add pre-resolved credential fields to ConnectConfig**

Replace `cli_username: Option<String>` and `password_stdin: bool` with:

```rust
pub username: String,
pub password: String,
```

These are always pre-resolved by the caller (CLI or helper).

**Step 2: Update resolve_session to use pre-resolved credentials**

In `resolve_session()`, remove the `read_stdin_password()` and `resolve_credentials()` calls. Use `config.username` and `config.password` directly:

```rust
let username = Zeroizing::new(config.username.clone());
let password = Zeroizing::new(config.password.clone());
```

**Step 3: Update main.rs to resolve credentials before building ConnectConfig**

In the `Commands::Connect` match arm, resolve credentials BEFORE constructing ConnectConfig:

```rust
Commands::Connect { ... } => {
    let stdin_password = common::read_stdin_password(password_stdin)?;
    let profile_options = config::load_profile_options();
    let (username, password) = config::resolve_credentials(
        cli_username.as_deref(),
        stdin_password.as_deref().map(|s| s.as_str()),
        &profile_options,
    )?;
    let connect_config = connect::ConnectConfig {
        username,
        password,
        // ... rest of fields ...
    };
    // This will change to socket call in Task 5, but for now keep direct call
    // so we can verify the credential move works in isolation.
    let mut provider_config = load_provider()?;
    connect::run(&mut provider_config, &connect_config)
}
```

**Step 4: Update helper.rs ConnectConfig construction**

The helper currently passes `cli_username: None, password_stdin: false`. Update to use the credentials from the HelperCommand (once Task 1 fields exist):

```rust
let connect_config = connect::ConnectConfig {
    username: username,
    password: password,
    // ... rest ...
};
```

Note: For now, the helper still uses profile-resolved credentials (no interactive prompt in daemon). The `username`/`password` fields in HelperCommand will be populated by the CLI thin client in Task 5.

**Step 5: Build and test**

Run: `cargo build && cargo build --release`
Run: `cargo test`
Expected: compiles, tests pass. The connect flow works identically — credentials are just resolved earlier.

**Step 6: Commit**

```bash
git add src/connect.rs src/main.rs src/helper.rs
git commit -m "refactor: move credential resolution out of connect::run into callers"
```

---

### Task 3: Make event_tx non-optional in connect::run

Currently `event_tx: Option<Sender<EngineEvent>>` — `None` for CLI, `Some` for helper. Make it always `Some`. The CLI will create its own channel (discarding events for now — Task 6 adds the renderer). This enables a single code path.

**Files:**
- Modify: `src/connect.rs:20-48` (ConnectConfig, emit())
- Modify: `src/main.rs:313-339` (create channel for CLI)
- Modify: `src/helper.rs:317-339` (already passes Some)

**Step 1: Change event_tx to non-optional**

In ConnectConfig:
```rust
pub event_tx: std::sync::mpsc::Sender<crate::ipc::EngineEvent>,
```

**Step 2: Simplify emit()**

```rust
fn emit(config: &ConnectConfig, event: crate::ipc::EngineEvent) {
    let _ = config.event_tx.send(event);
}
```

**Step 3: Update main.rs to create a channel (drain receiver)**

```rust
let (event_tx, _event_rx) = std::sync::mpsc::channel();
let connect_config = connect::ConnectConfig {
    event_tx,
    // ...
};
```

The `_event_rx` is dropped, which means `event_tx.send()` will return `Err` (receiver dropped), but `emit()` already ignores errors with `let _`. So log output still goes through the `log` crate TermLogger.

**Step 4: Update helper.rs**

Already passes `Some(connect_event_tx)` — just unwrap it to pass directly.

**Step 5: Build and test**

Run: `cargo build && cargo build --release`
Run: `cargo test`

**Step 6: Commit**

```bash
git add src/connect.rs src/main.rs src/helper.rs
git commit -m "refactor: make event_tx non-optional in ConnectConfig"
```

---

### Task 4: Create cli_client module (socket communication + event rendering)

New module that handles all CLI→helper communication. Small (~100-150 lines): connect to socket, send command, read events, print them.

**Files:**
- Create: `src/cli_client.rs`
- Modify: `src/lib.rs` (add module)

**Step 1: Write cli_client.rs**

```rust
//! Thin CLI client: connect to helper socket, send commands, render events.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use anyhow::{Context, Result};

use crate::ipc::{self, HelperCommand, HelperEvent, ConnectionState};
use crate::helper::SOCKET_PATH;

/// Connect to the helper socket. If the socket doesn't exist, the error
/// message guides the user to enable the systemd socket unit.
fn connect_to_helper() -> Result<UnixStream> {
    UnixStream::connect(SOCKET_PATH).with_context(|| {
        format!(
            "Could not connect to helper at {}.\n\
             Enable the socket unit:\n\n  \
             sudo systemctl enable --now airvpn-helper.socket",
            SOCKET_PATH
        )
    })
}

/// Send a command and consume the event stream, printing each event.
/// Returns when a terminal event is received (Disconnected, Error, Shutdown).
pub fn send_command(cmd: &HelperCommand) -> Result<()> {
    let stream = connect_to_helper()?;
    let mut writer = stream.try_clone().context("clone socket")?;
    let reader = BufReader::new(stream);

    // Send command
    let line = ipc::encode_line(cmd).context("encode command")?;
    writer.write_all(line.as_bytes()).context("write command")?;
    writer.flush().context("flush command")?;

    // Read and render events
    for line in reader.lines() {
        let line = line.context("read event")?;
        if line.trim().is_empty() {
            continue;
        }
        let event: HelperEvent = ipc::decode_line(&line)
            .with_context(|| format!("decode event: {}", line))?;

        match render_event(&event) {
            EventAction::Continue => {}
            EventAction::Done => return Ok(()),
            EventAction::Error(msg) => anyhow::bail!("{}", msg),
        }
    }

    // Socket closed without terminal event
    anyhow::bail!("helper closed connection unexpectedly")
}

/// Send a command that expects a single response, not a stream.
/// Returns the first event received.
pub fn send_oneshot(cmd: &HelperCommand) -> Result<HelperEvent> {
    let stream = connect_to_helper()?;
    let mut writer = stream.try_clone().context("clone socket")?;
    let reader = BufReader::new(stream);

    let line = ipc::encode_line(cmd).context("encode command")?;
    writer.write_all(line.as_bytes()).context("write command")?;
    writer.flush().context("flush command")?;

    // Read first non-empty line
    for line in reader.lines() {
        let line = line.context("read response")?;
        if line.trim().is_empty() {
            continue;
        }
        return ipc::decode_line(&line).context("decode response");
    }
    anyhow::bail!("helper closed connection without response")
}

enum EventAction {
    Continue,
    Done,
    Error(String),
}

/// Render a HelperEvent to stderr/stdout. Returns whether to continue reading.
fn render_event(event: &HelperEvent) -> EventAction {
    match event {
        HelperEvent::StateChanged { state } => {
            match state {
                ConnectionState::Connecting => {
                    eprintln!(":: Connecting...");
                    EventAction::Continue
                }
                ConnectionState::Connected { server_name, server_country, server_location } => {
                    eprintln!(":: Connected to {} ({}, {})", server_name, server_location, server_country);
                    EventAction::Continue  // keep reading for stats/reconnection
                }
                ConnectionState::Reconnecting => {
                    eprintln!(":: Reconnecting...");
                    EventAction::Continue
                }
                ConnectionState::Disconnecting => {
                    eprintln!(":: Disconnecting...");
                    EventAction::Continue
                }
                ConnectionState::Disconnected => {
                    eprintln!(":: Disconnected.");
                    EventAction::Done
                }
            }
        }
        HelperEvent::Log { level, message } => {
            match level.as_str() {
                "error" => eprintln!("error: {}", message),
                "warn" => eprintln!("warning: {}", message),
                _ => eprintln!("{}", message),
            }
            EventAction::Continue
        }
        HelperEvent::Stats { rx_bytes, tx_bytes } => {
            // Stats are continuous — don't print unless user asked (future --stats flag)
            let _ = (rx_bytes, tx_bytes);
            EventAction::Continue
        }
        HelperEvent::LockStatus { session_active, persistent_active, persistent_installed } => {
            println!("Lock status:");
            println!("  Session lock:    {}", if *session_active { "active" } else { "inactive" });
            println!("  Persistent lock: {}", if *persistent_active { "active" } else { "inactive" });
            println!("  Installed:       {}", if *persistent_installed { "yes" } else { "no" });
            EventAction::Done
        }
        HelperEvent::Error { message } => {
            EventAction::Error(message.clone())
        }
        HelperEvent::Shutdown => {
            EventAction::Done
        }
    }
}
```

**Step 2: Add module to lib.rs**

Add `pub mod cli_client;` to `src/lib.rs`.

**Step 3: Build**

Run: `cargo build`
Expected: compiles (module not called yet).

**Step 4: Commit**

```bash
git add src/cli_client.rs src/lib.rs
git commit -m "feat: add cli_client module for thin socket communication"
```

---

### Task 5: Rewire main.rs Connect/Disconnect/Status through cli_client

The big switchover. CLI commands stop calling `connect::run()` directly and instead send commands to the helper via `cli_client`.

**Files:**
- Modify: `src/main.rs` (Connect, Disconnect, Status match arms)

**Step 1: Rewrite Commands::Connect**

```rust
Commands::Connect { server, username, password_stdin, ... } => {
    let stdin_password = common::read_stdin_password(password_stdin)?;
    let profile_options = config::load_profile_options();
    let (username, password) = config::resolve_credentials(
        username.as_deref(),
        stdin_password.as_deref().map(|s| s.as_str()),
        &profile_options,
    )?;

    let cmd = ipc::HelperCommand::Connect {
        server,
        no_lock,
        allow_lan,
        skip_ping,
        allow_country,
        deny_country,
        username,
        password,
        allow_server,
        deny_server,
        no_reconnect,
        no_verify,
        no_lock_last,
        no_start_last,
        ipv6_mode,
        dns_servers,
        event_pre: [event_vpn_pre_filename, event_vpn_pre_arguments, event_vpn_pre_waitend],
        event_up: [event_vpn_up_filename, event_vpn_up_arguments, event_vpn_up_waitend],
        event_down: [event_vpn_down_filename, event_vpn_down_arguments, event_vpn_down_waitend],
    };
    cli_client::send_command(&cmd)
}
```

**Step 2: Rewrite Commands::Disconnect**

```rust
Commands::Disconnect => {
    cli_client::send_command(&ipc::HelperCommand::Disconnect)
}
```

**Step 3: Rewrite Commands::Status**

```rust
Commands::Status => {
    let event = cli_client::send_oneshot(&ipc::HelperCommand::Status)?;
    // render_event already handles StateChanged + LockStatus
    // But Status returns two events (StateChanged + LockStatus).
    // Use send_command which reads until terminal event.
    // Actually: send_command, with Status rendering Done on LockStatus.
    cli_client::send_command(&ipc::HelperCommand::Status)
}
```

Note: The Status handler in `helper.rs` sends two events (StateChanged + LockStatus). `cli_client::send_command` reads until `LockStatus` which returns `EventAction::Done`. This works because `render_event` for `LockStatus` returns Done.

**Step 4: Remove dead code from main.rs**

- Delete `refuse_if_helper_running()` (no longer needed)
- Delete `cmd_disconnect()` (replaced by socket call)
- Delete `cmd_status()` (replaced by socket call)
- Delete `load_provider()` (no longer used by connect — only by `cmd_servers`)
- Remove unused imports

**Step 5: Build and test**

Run: `cargo build && cargo build --release`
Run: `cargo test`

**Step 6: Commit**

```bash
git add src/main.rs
git commit -m "feat: rewire CLI connect/disconnect/status through helper socket"
```

---

### Task 6: Rewire Lock commands through cli_client

Move all lock subcommands to use the helper socket.

**Files:**
- Modify: `src/main.rs` (cmd_lock and all Lock subcommands)
- Modify: `src/helper.rs:526-533` (implement LockInstall/LockUninstall)

**Step 1: Implement LockInstall in helper.rs**

Move the logic from `main.rs::cmd_lock_install()` into a helper function and call it from the LockInstall command handler. The helper already runs as root, so the `nft` and `systemctl` calls work.

```rust
ipc::HelperCommand::LockInstall => {
    match dispatch_lock_install() {
        Ok(msg) => {
            send_event(&mut writer, &ipc::HelperEvent::Log {
                level: "info".to_string(),
                message: msg,
            });
        }
        Err(e) => {
            send_event(&mut writer, &ipc::HelperEvent::Error {
                message: format!("lock install failed: {}", e),
            });
        }
    }
    send_event(&mut writer, &build_lock_status());
}
```

Write `dispatch_lock_install()` in helper.rs — copy the logic from `main.rs::cmd_lock_install()`.

**Step 2: Implement LockUninstall similarly**

Same pattern — move `cmd_lock_uninstall()` logic into `dispatch_lock_uninstall()` in helper.rs.

**Step 3: Rewrite CLI lock commands**

```rust
Commands::Lock { action } => {
    let cmd = match action {
        LockAction::Install => ipc::HelperCommand::LockInstall,
        LockAction::Uninstall => ipc::HelperCommand::LockUninstall,
        LockAction::Enable => ipc::HelperCommand::LockEnable,
        LockAction::Disable => ipc::HelperCommand::LockDisable,
        LockAction::Status => ipc::HelperCommand::LockStatus,
    };
    cli_client::send_command(&cmd)
}
```

**Step 4: Remove dead lock code from main.rs**

Delete `cmd_lock_install()`, `cmd_lock_uninstall()`, `cmd_lock_enable()`, `cmd_lock_disable()`, `cmd_lock_status()`. Remove the root check (`nix::unistd::geteuid().is_root()`) — the helper is already root.

**Step 5: Build and test**

Run: `cargo build && cargo build --release`
Run: `cargo test`

**Step 6: Commit**

```bash
git add src/main.rs src/helper.rs
git commit -m "feat: rewire lock commands through helper socket"
```

---

### Task 7: Update helper.rs Connect handler to use expanded fields

The helper's Connect handler currently hardcodes defaults for the fields that weren't in the old protocol (no_reconnect: false, no_verify: false, etc.). Update it to use the fields from the expanded HelperCommand.

**Files:**
- Modify: `src/helper.rs:248-339` (Connect command handler)

**Step 1: Destructure all new fields in the match arm**

```rust
ipc::HelperCommand::Connect {
    server, no_lock, allow_lan, skip_ping,
    allow_country, deny_country,
    username, password,
    allow_server, deny_server,
    no_reconnect, no_verify, no_lock_last, no_start_last,
    ipv6_mode, dns_servers,
    event_pre, event_up, event_down,
} => {
```

**Step 2: Build ConnectConfig from all fields**

```rust
let connect_config = connect::ConnectConfig {
    server_name: server,
    no_lock,
    allow_lan,
    no_reconnect,
    username,
    password,
    allow_server,
    deny_server,
    allow_country,
    deny_country,
    skip_ping,
    no_verify,
    no_lock_last,
    no_start_last,
    cli_ipv6_mode: ipv6_mode,
    cli_dns_servers: dns_servers,
    cli_event_pre: event_pre,
    cli_event_up: event_up,
    cli_event_down: event_down,
    event_tx: connect_event_tx,
};
```

**Step 3: Build and test**

Run: `cargo build && cargo build --release`
Run: `cargo test`

**Step 4: Commit**

```bash
git add src/helper.rs
git commit -m "feat: helper Connect handler uses all expanded protocol fields"
```

---

### Task 8: Handle Recover and Servers commands

Two remaining CLI commands that need consideration.

**Files:**
- Modify: `src/main.rs`

**Step 1: Recover command**

Recovery is a cleanup operation that should go through the helper (helper runs recovery on startup already). But if the helper is dead AND the socket unit isn't active, recovery needs to work standalone. Keep `Recover` as a direct operation — it's a safety valve.

No change needed. Keep: `Commands::Recover => cmd_recover()`.

**Step 2: Servers command**

`cmd_servers` fetches the manifest and displays a server table. It needs credentials and API access but doesn't need root. This is a read-only query.

Options:
- a) Keep as direct CLI operation (needs `load_provider()` — keep that function for this)
- b) Add a `ListServers` command to the helper protocol

Keep as direct for now (option a). It's read-only, doesn't need root, and adding it to the helper protocol adds complexity for no benefit. The CLI just needs the provider config.

No change needed. Keep: `Commands::Servers { ... } => { ... }`.

**Step 3: Commit (if any changes)**

If we cleaned up imports or minor adjustments:
```bash
git add src/main.rs
git commit -m "chore: keep Recover and Servers as direct CLI operations"
```

---

### Task 9: Remove helper conflict guard from helper.rs

The helper currently refuses to start if a CLI connection is running (lines 109-118). With the single control plane, the CLI never manages connections directly, so this guard is dead code.

**Files:**
- Modify: `src/helper.rs:109-118`

**Step 1: Remove the CLI conflict check**

Delete:
```rust
if let Ok(Some(state)) = recovery::load() {
    if recovery::is_pid_alive(state.pid) {
        anyhow::bail!(
            "A CLI connection is already running (PID {}). \
             Disconnect it first with `sudo airvpn disconnect`.",
            state.pid
        );
    }
}
```

**Step 2: Build and test**

Run: `cargo build && cargo build --release`
Run: `cargo test`

**Step 3: Commit**

```bash
git add src/helper.rs
git commit -m "cleanup: remove CLI conflict guard from helper (single control plane)"
```

---

### Task 10: Update documentation

**Files:**
- Modify: `docs/known_divergences.md` (add socket activation + single control plane divergence)
- Modify: `CLAUDE.md` (update learnings, remove outdated notes about independent control paths)

**Step 1: Add divergence documentation**

Add entry to `docs/known_divergences.md`:
- Eddie: CLI connects directly (pkexec for root). GUI uses TCP localhost.
- airvpn-rs: Single daemon (systemd socket-activated). Both CLI and GUI are thin clients over Unix socket.

**Step 2: Update CLAUDE.md learnings**

- Remove: "CLI and GUI are independent control paths" note
- Add: "CLI is thin socket client — all VPN ops go through helper daemon"
- Update: helper-related learnings to reflect single control plane

**Step 3: Commit**

```bash
git add docs/known_divergences.md CLAUDE.md
git commit -m "docs: document single control plane architecture"
```

---

### Task 11: End-to-end manual test

Not automatable (needs real AirVPN credentials + network), but document the test plan:

1. `sudo systemctl enable --now airvpn-helper.socket`
2. `airvpn connect` (no sudo) — should connect via helper
3. `airvpn status` — should show connected server
4. `airvpn disconnect` — should disconnect cleanly
5. `airvpn lock install` — should install persistent lock
6. `airvpn lock status` — should show installed
7. `airvpn lock disable` / `airvpn lock enable` — toggle
8. `airvpn lock uninstall` — clean removal
9. Kill helper (`sudo systemctl stop airvpn-helper`), then `airvpn connect` — socket activation should restart it
10. GUI connect while CLI status shows connected — should show same connection

---

## Task Dependency Graph

```
Task 1 (expand protocol)
    |
Task 2 (credentials out of connect::run)  ← depends on Task 1 (new fields exist)
    |
Task 3 (event_tx non-optional)
    |
Task 4 (cli_client module)  ← independent of 1-3, but conceptually after
    |
Task 5 (rewire Connect/Disconnect/Status)  ← depends on 1, 2, 3, 4
    |
Task 6 (rewire Lock commands)  ← depends on 4, 5
    |
Task 7 (helper uses expanded fields)  ← depends on 1, 2
    |
Task 8 (Recover/Servers decisions)  ← after 5
    |
Task 9 (remove conflict guards)  ← after 5
    |
Task 10 (docs)  ← after all code tasks
    |
Task 11 (manual test)  ← after everything
```

Tasks 1-3 are sequential (each builds on prior).
Task 4 can be done in parallel with 1-3.
Tasks 5-7 depend on 1-4 being done.
Tasks 8-9 are cleanup after the main switchover.
