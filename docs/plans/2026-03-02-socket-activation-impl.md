# Socket Activation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate the GUI/helper startup race by migrating to systemd socket activation.

**Architecture:** systemd creates and owns the socket (`/run/airvpn-rs/helper.sock`) with correct permissions at boot. The helper receives the pre-bound fd via the `sd-notify` crate's `listen_fds()` API. The GUI connects directly — systemd starts the helper on demand. No pkexec, no polling, no race.

**Tech Stack:** Rust, systemd socket activation, `sd-notify` crate, `nix` crate (`SO_PEERCRED`), iced GUI

**Design doc:** `docs/plans/2026-03-02-socket-activation-design.md`

---

### Task 1: Add `sd-notify` dependency and nix `socket` feature

**Files:**
- Modify: `Cargo.toml`

**Step 1: Add dependencies**

Add `sd-notify` after the existing `nix` line, and add `"socket"` to nix features (for `SO_PEERCRED`):

```toml
nix = { version = "0.29", features = ["signal", "process", "fs", "user", "socket"] }

# systemd socket activation
sd-notify = "0.4"
```

**Step 2: Verify it compiles**

Run: `cargo check`
Expected: compiles with no errors

**Step 3: Commit**

```bash
git add Cargo.toml Cargo.lock
git commit -m "deps: add sd-notify for socket activation, nix socket feature for SO_PEERCRED"
```

---

### Task 2: Create systemd unit files

**Files:**
- Create: `resources/airvpn-helper.socket`
- Create: `resources/airvpn-helper.service`

**Step 1: Write the socket unit**

`resources/airvpn-helper.socket`:
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

**Step 2: Write the service unit**

`resources/airvpn-helper.service`:
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

**Step 3: Commit**

```bash
git add resources/airvpn-helper.socket resources/airvpn-helper.service
git commit -m "feat: add systemd socket activation unit files"
```

---

### Task 3: Rewrite `helper::run()` for socket activation

This is the core change. Replace manual bind/chmod/chown with systemd fd inheritance.

**Files:**
- Modify: `src/helper.rs`

**Step 1: Replace the socket setup in `run()`**

Remove lines 22-59 (everything from `SOCKET_PATH` constant through `chown_socket_to_caller_group()` call) and lines 118-119 (socket cleanup on exit). Replace with socket activation detection, PID file, and SO_PEERCRED logging.

The new `run()` structure:

```rust
use std::os::unix::io::FromRawFd;

pub const SOCKET_PATH: &str = "/run/airvpn-rs/helper.sock";
pub const PID_FILE: &str = "/run/airvpn-rs/helper.pid";

/// Get the listener from systemd socket activation.
/// Bails if LISTEN_FDS is not set (not socket-activated).
fn get_systemd_listener() -> Result<UnixListener> {
    // sd-notify's listen_fds() checks LISTEN_PID matches getpid()
    // and returns an iterator of passed fds.
    let fds: Vec<_> = sd_notify::listen_fds()
        .context("failed to query systemd listen fds")?
        .collect();

    if fds.is_empty() {
        anyhow::bail!(
            "not socket-activated (LISTEN_FDS not set).\n\
             Enable the systemd socket unit:\n  \
             sudo cp resources/airvpn-helper.{{socket,service}} /etc/systemd/system/\n  \
             sudo systemctl daemon-reload\n  \
             sudo systemctl enable --now airvpn-helper.socket\n\
             Or for development:\n  \
             systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper"
        );
    }

    // SD_LISTEN_FDS_START = 3; first fd is always 3
    let fd = fds[0];
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    Ok(listener)
}

fn write_pid_file() -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(PID_FILE)
        .context("failed to create PID file")?;
    writeln!(f, "{}", std::process::id()).context("failed to write PID file")?;
    Ok(())
}

pub fn read_pid_file() -> Option<u32> {
    std::fs::read_to_string(PID_FILE)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
}

/// Log the connecting client's UID via SO_PEERCRED.
fn log_peer_credentials(stream: &UnixStream) {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::unix::io::AsRawFd;

    // SAFETY: the fd is valid for the lifetime of stream
    let raw_fd = stream.as_raw_fd();
    match getsockopt(raw_fd, PeerCredentials) {
        Ok(cred) => {
            info!("Client connected: uid={}, gid={}, pid={}", cred.uid(), cred.gid(), cred.pid());
        }
        Err(e) => {
            warn!("Failed to get peer credentials: {}", e);
        }
    }
}
```

The new `run()`:
```rust
pub fn run() -> Result<()> {
    connect::preflight_checks()?;

    let listener = get_systemd_listener()?;

    write_pid_file()?;

    info!("Helper listening on {}", SOCKET_PATH);

    let shutdown = recovery::setup_signal_handler()?;

    // Refuse to start if a CLI connection is already running
    if let Ok(Some(state)) = recovery::load() {
        if recovery::is_pid_alive(state.pid) {
            anyhow::bail!(
                "A CLI connection is already running (PID {}). \
                 Disconnect it first with `sudo airvpn disconnect`.",
                state.pid
            );
        }
    }

    let mut conn_state = ConnState::new();

    listener
        .set_nonblocking(false)
        .context("failed to set listener blocking")?;

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            info!("Shutdown signal received, exiting helper");
            break;
        }

        listener.set_nonblocking(true).ok();
        match listener.accept() {
            Ok((stream, _addr)) => {
                listener.set_nonblocking(false).ok();
                log_peer_credentials(&stream);
                if let Err(e) = handle_client(stream, &mut conn_state) {
                    warn!("Client session ended with error: {}", e);
                }
                info!("Client disconnected");
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                listener.set_nonblocking(false).ok();
                thread::sleep(Duration::from_secs(1));
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                thread::sleep(Duration::from_secs(1));
            }
        }
    }

    // Clean up PID file. Don't remove the socket — systemd owns it.
    let _ = std::fs::remove_file(PID_FILE);
    Ok(())
}
```

Remove the entire `chown_socket_to_caller_group()` function (lines 123-167).

**Step 2: Update module doc comment**

Replace lines 1-9 (the module doc comment) with:
```rust
//! Root helper daemon for GUI IPC over Unix socket.
//!
//! Started by systemd via socket activation (airvpn-helper.socket).
//! Receives the pre-bound socket fd from systemd, accepts GUI connections,
//! and bridges commands to the connect engine.
//!
//! Designed for single-client use (one GUI at a time). If the client
//! disconnects, handle_client returns and the accept loop waits for a new
//! connection.
```

**Step 3: Verify it compiles**

Run: `cargo check`
Expected: compiles (may need to adjust imports — check `sd_notify::listen_fds` API)

Note: if `sd_notify::listen_fds()` has a different API than expected, check docs.rs for the actual signature and adapt. The key is: get the passed fd (fd 3) and wrap it as `UnixListener::from_raw_fd(3)`. If the crate doesn't provide `listen_fds`, implement it manually:
```rust
fn get_systemd_listener() -> Result<UnixListener> {
    let pid: u32 = std::env::var("LISTEN_PID")
        .context("LISTEN_PID not set — not socket-activated")?
        .parse()
        .context("LISTEN_PID is not a valid integer")?;
    if pid != std::process::id() {
        anyhow::bail!("LISTEN_PID ({}) doesn't match our PID ({})", pid, std::process::id());
    }
    let n: u32 = std::env::var("LISTEN_FDS")
        .context("LISTEN_FDS not set")?
        .parse()
        .context("LISTEN_FDS is not a valid integer")?;
    if n < 1 {
        anyhow::bail!("LISTEN_FDS is 0 — no sockets passed");
    }
    // SD_LISTEN_FDS_START = 3
    let listener = unsafe { UnixListener::from_raw_fd(3) };
    // Unset env vars so children don't inherit
    std::env::remove_var("LISTEN_PID");
    std::env::remove_var("LISTEN_FDS");
    std::env::remove_var("LISTEN_FDNAMES");
    Ok(listener)
}
```

Also check the `nix` crate's `PeerCredentials` API — it may be `nix::sys::socket::sockopt::PeerCredentials` or require a different import path in nix 0.29. Consult docs.rs.

**Step 4: Commit**

```bash
git add src/helper.rs
git commit -m "feat: require systemd socket activation in helper daemon

Replace manual bind/chmod/chown with sd-notify listen_fds().
Add SO_PEERCRED logging on accept. Add PID file for CLI guard.
Remove chown_socket_to_caller_group() entirely."
```

---

### Task 4: Update CLI guard in `main.rs`

**Files:**
- Modify: `src/main.rs:370-382`

**Step 1: Replace `refuse_if_helper_running()`**

Current code (lines 370-382) connects to the socket to check liveness. Replace with:

```rust
/// Refuse CLI connect/disconnect when the GUI helper is running.
/// Uses PID file instead of socket connect (socket connect would
/// trigger systemd socket activation and start the helper).
fn refuse_if_helper_running() -> anyhow::Result<()> {
    if let Some(pid) = airvpn::helper::read_pid_file() {
        if recovery::is_pid_alive(pid) {
            anyhow::bail!(
                "The GUI helper is running (PID {}). Use the GUI to connect/disconnect, \
                 or stop the helper first:\n  sudo systemctl stop airvpn-helper.service",
                pid
            );
        }
    }
    Ok(())
}
```

Remove the `use std::os::unix::net::UnixStream;` import if it was only used here (check if anything else in main.rs uses it).

**Step 2: Verify it compiles**

Run: `cargo check`

**Step 3: Commit**

```bash
git add src/main.rs
git commit -m "fix: use PID file for helper guard instead of socket connect

Socket connect would trigger systemd socket activation, accidentally
starting the helper when we just want to check if it's running."
```

---

### Task 5: Simplify GUI — remove pkexec and polling

**Files:**
- Modify: `src/gui/main.rs`
- Modify: `src/gui/ipc.rs`

**Step 1: Clean up `gui/ipc.rs`**

Remove `is_helper_running()` (lines 86-88) and `launch_helper()` (lines 90-94). Keep everything else.

**Step 2: Simplify `gui/main.rs`**

Remove from `App` struct (line 32):
```rust
    helper_launched: bool,
```

Remove from `boot()` (line 59):
```rust
            helper_launched: false,
```

Simplify `boot()` task (lines 64-70) — always try connecting:
```rust
        let task = Task::done(Message::HelperConnected);
```

Remove `Message::LaunchHelper` from the enum (line 43).

Remove the entire `Message::LaunchHelper` handler (lines 117-145).

Simplify `Message::HelperConnected` error handling (lines 155-167):
```rust
                Err(e) => {
                    eprintln!("[GUI] HelperClient::connect() failed: {}", e);
                    self.helper_error = Some(format!(
                        "Cannot connect to helper: {}.\n\
                         Is airvpn-helper.socket enabled?\n\
                         Run: sudo systemctl enable --now airvpn-helper.socket",
                        e
                    ));
                    Task::none()
                }
```

Update the error banner retry button (line 256) — change from `Message::LaunchHelper` to `Message::HelperConnected`:
```rust
                    button(text("Retry")).on_press(Message::HelperConnected),
```

Remove unused imports: `tokio::time::sleep` may no longer be needed if `LaunchHelper` was the only user of the `Task::future(async { ... })` pattern. Check and clean up.

**Step 3: Verify it compiles**

Run: `cargo check`

**Step 4: Commit**

```bash
git add src/gui/main.rs src/gui/ipc.rs
git commit -m "feat: simplify GUI startup — remove pkexec and polling

With systemd socket activation, the socket always exists. GUI just
connects directly. No pkexec prompt, no 60s polling loop, no 200ms
sleep hack. On failure, show error with instructions to enable the
socket unit."
```

---

### Task 6: Delete polkit policy

**Files:**
- Delete: `resources/org.airvpn.helper.policy`

**Step 1: Remove the file**

```bash
git rm resources/org.airvpn.helper.policy
```

**Step 2: Commit**

```bash
git commit -m "chore: remove polkit policy (pkexec no longer used for helper)"
```

---

### Task 7: Build and verify

**Step 1: Full build**

Run: `cargo build && cargo build --release`
Expected: both succeed with no errors

**Step 2: Run existing tests**

Run: `cargo test`
Expected: all pass (the helper tests are mostly in recovery.rs and don't depend on bind/chown)

**Step 3: Test socket activation manually**

```bash
# Create the socket directory (systemd would normally do this)
sudo mkdir -p /run/airvpn-rs
sudo chmod 755 /run/airvpn-rs

# Test with systemd-socket-activate
sudo systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper
```

Expected: helper starts, logs "Helper listening on /run/airvpn-rs/helper.sock"

**Step 4: Install units and test end-to-end**

```bash
sudo cp resources/airvpn-helper.socket resources/airvpn-helper.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now airvpn-helper.socket

# Verify socket exists with correct permissions
ls -la /run/airvpn-rs/helper.sock
# Expected: srw-rw---- root wheel ...

# Launch GUI
./target/debug/airvpn-gui
# Expected: connects immediately, no pkexec prompt
```

**Step 5: Test CLI guard**

```bash
# While helper is running (check PID file):
cat /run/airvpn-rs/helper.pid

# CLI should refuse:
sudo ./target/debug/airvpn connect
# Expected: "The GUI helper is running (PID N). ..."

# Stop helper, CLI should proceed:
sudo systemctl stop airvpn-helper.service
sudo ./target/debug/airvpn connect
# Expected: normal connect flow (will fail at credential prompt if no profile, but that's fine)
```

**Step 6: Test crash restart**

```bash
sudo systemctl start airvpn-helper.service
sudo kill -9 $(cat /run/airvpn-rs/helper.pid)
sleep 2
systemctl is-active airvpn-helper.service
# Expected: active (restarted by systemd)
```

**Step 7: Commit any fixes from testing**

```bash
git add -A
git commit -m "fix: address issues found during socket activation testing"
```

---

### Task 8: Update CLAUDE.md learnings

**Files:**
- Modify: `CLAUDE.md`

Add to Learnings section:
```
- Helper uses systemd socket activation — no manual bind/chown. Dev testing: `systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper`. Unit files in resources/ (2026-03-02)
- SO_PEERCRED logs connecting UID on every accept(). Socket is 0660/wheel — migrate to dedicated airvpn group for AUR packaging (2026-03-02)
- refuse_if_helper_running() checks PID file, not socket connect (socket connect triggers activation) (2026-03-02)
```

Remove outdated learnings that reference pkexec or the old chown race.

**Commit:**
```bash
git add CLAUDE.md
git commit -m "docs: update learnings for socket activation migration"
```
