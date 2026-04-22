# Fix Helper Daemon GUI Blocking — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the helper daemon from blocking GUI requests during connection/reconnection loops.

**Architecture:** Three independent changes: (1) persist manifest to disk so `/servers` works on cold start, (2) make disconnect non-blocking so the handler returns immediately, (3) thread the shutdown flag into `wait_for_handshake` so disconnect actually interrupts the 50s handshake poll.

**Tech Stack:** Rust, serde_json, std::sync::atomic, std::thread

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/manifest.rs` | Add `Serialize`/`Deserialize` derives + `save`/`load` fns |
| `src/helper/mod.rs` | Load cached manifest in `SharedState::new()` |
| `src/helper/background.rs` | Save manifest after each successful API fetch |
| `src/helper/handlers.rs` | Add `signal_disconnect()`, use it in `handle_disconnect()` |
| `src/wireguard.rs` | Add `shutdown` param to `wait_for_handshake` |
| `src/connect.rs` | Pass `params.shutdown` to `wait_for_handshake` |

---

### Task 1: Add Serialize/Deserialize to manifest types + save/load

**Files:**
- Modify: `src/manifest.rs:10-63` (derives on `Message`, `Manifest`, `Server`, `Mode`)
- Modify: `src/manifest.rs` (add `save`/`load` functions after struct definitions, before `parse_manifest`)

- [ ] **Step 1: Write the roundtrip test**

Add to the existing `#[cfg(test)] mod tests` block in `src/manifest.rs` (after the last test ~line 607):

```rust
#[test]
fn test_manifest_persistence_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    let path_str = path.to_str().unwrap();

    let manifest = parse_manifest(FULL_MANIFEST).unwrap();
    save_manifest(&manifest, path_str).unwrap();

    let loaded = load_manifest(path_str).unwrap();
    assert_eq!(loaded.servers.len(), 1);
    assert_eq!(loaded.servers[0].name, "Alchiba");
    assert_eq!(loaded.servers[0].ips_entry, vec!["185.32.12.1", "185.32.12.2"]);
    assert_eq!(loaded.servers[0].country_code, "IT");
    assert_eq!(loaded.modes.len(), 1);
    assert_eq!(loaded.modes[0].title, "WireGuard UDP 1637");
    assert_eq!(loaded.check_domain, "airvpn.org");
    assert_eq!(loaded.check_dns_query, "{hash}.airvpn.org");
    assert_eq!(loaded.bootstrap_urls, vec!["https://api.airvpn.org/api/"]);
}

#[test]
fn test_load_manifest_missing_file() {
    assert!(load_manifest("/nonexistent/manifest.json").is_none());
}

#[test]
fn test_load_manifest_corrupt_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    std::fs::write(&path, "not json").unwrap();
    assert!(load_manifest(path.to_str().unwrap()).is_none());
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib manifest::tests::test_manifest_persistence_roundtrip -- --nocapture 2>&1 | tail -20`
Expected: compile error — `save_manifest` and `load_manifest` don't exist, derives missing.

- [ ] **Step 3: Add Serialize/Deserialize derives**

In `src/manifest.rs`, add the serde import and derives to the four structs that compose `Manifest`:

At the top of the file, add after the existing imports:
```rust
use serde::{Deserialize, Serialize};
```

Change the derives:
- `Message`: `#[derive(Debug, Clone)]` → `#[derive(Debug, Clone, Serialize, Deserialize)]`
- `Manifest`: `#[derive(Debug, Clone)]` → `#[derive(Debug, Clone, Serialize, Deserialize)]`
- `Server`: `#[derive(Debug, Clone)]` → `#[derive(Debug, Clone, Serialize, Deserialize)]`
- `Mode`: `#[derive(Debug, Clone)]` → `#[derive(Debug, Clone, Serialize, Deserialize)]`

Do NOT touch `UserInfo` or `WireGuardKey` — they contain `Zeroizing<String>` fields and are not part of the cached manifest.

- [ ] **Step 4: Add save/load functions**

Add these after the struct definitions, before `parse_manifest` (around line 98). Mirror the `LatencyCache` pattern from `src/pinger.rs:117-148`:

```rust
/// Filesystem path for the persisted manifest cache.
pub const MANIFEST_CACHE_PATH: &str = "/var/lib/airvpn-rs/manifest.json";

/// Persist the manifest to a JSON file (0600 root:root).
pub fn save_manifest(manifest: &Manifest, path: &str) -> anyhow::Result<()> {
    let parent = std::path::Path::new(path).parent();
    if let Some(dir) = parent {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_string_pretty(manifest)?;
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

/// Load the manifest from a JSON file. Returns `None` on any error
/// (missing file, corrupt JSON) — stale cache is optional, not critical.
pub fn load_manifest(path: &str) -> Option<Manifest> {
    match std::fs::read_to_string(path) {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(manifest) => Some(manifest),
            Err(e) => {
                warn!("Corrupt manifest cache at {path}: {e}");
                None
            }
        },
        Err(_) => None,
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib manifest::tests -- --nocapture 2>&1 | tail -20`
Expected: all manifest tests pass (including the 3 new ones).

- [ ] **Step 6: Commit**

```bash
git add src/manifest.rs
git commit -m "feat(manifest): add serde derives and save/load for disk persistence"
```

---

### Task 2: Load cached manifest on startup, save after fetch

**Files:**
- Modify: `src/helper/mod.rs:117-137` (`SharedState::new()`)
- Modify: `src/helper/background.rs:188-231` (after successful manifest parse)

- [ ] **Step 1: Load cached manifest in SharedState::new()**

In `src/helper/mod.rs`, in `SharedState::new()` (line 118), load the manifest after loading latency. Change the `manifest: None` field to load from disk:

```rust
fn new() -> Self {
    let latency = pinger::LatencyCache::load(pinger::LATENCY_CACHE_PATH);
    // Populate persistent lock's ping_allow from cached server IPs so the
    // background pinger can reach servers immediately on startup.
    if !latency.server_ips().is_empty() {
        let ips: Vec<String> = latency.server_ips().values().cloned().collect();
        if let Err(e) = netlock::populate_ping_allow(&ips) {
            log::warn!("Failed to populate ping_allow from cached IPs: {e}");
        }
    }
    let cached_manifest = manifest::load_manifest(manifest::MANIFEST_CACHE_PATH);
    if cached_manifest.is_some() {
        log::info!("Loaded cached manifest from disk ({} servers)",
            cached_manifest.as_ref().unwrap().servers.len());
    }
    let ready = latency.has_data(); // warm start = ready immediately
    Self {
        conn: ConnState::new(),
        subscribers: Vec::new(),
        latency,
        manifest: cached_manifest,
        ready,
        key_names: Vec::new(),
    }
}
```

- [ ] **Step 2: Save manifest after successful fetch in background_manifest_loop**

In `src/helper/background.rs`, inside the `Ok(new_manifest)` arm (around line 188, after `info!("Background manifest refresh: ...")`), add a save call before updating shared state:

```rust
Ok(new_manifest) => {
    info!("Background manifest refresh: {} servers", new_manifest.servers.len());

    if let Err(e) = manifest::save_manifest(&new_manifest, manifest::MANIFEST_CACHE_PATH) {
        warn!("Failed to persist manifest cache: {e}");
    }

    // Extract (name, preferred_entry_ip) pairs, ...
```

Insert the `save_manifest` call right after the `info!` line and before the `let prefer_ipv6 = ...` line.

- [ ] **Step 3: Build and verify**

Run: `cargo build 2>&1 | tail -20`
Expected: compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add src/helper/mod.rs src/helper/background.rs
git commit -m "feat(helper): load manifest from disk on startup, persist after fetch"
```

---

### Task 3: Non-blocking disconnect

**Files:**
- Modify: `src/helper/handlers.rs:292-349` (split `perform_disconnect`)
- Modify: `src/helper/handlers.rs:567-645` (`handle_disconnect` uses new function)

- [ ] **Step 1: Add signal_disconnect function**

In `src/helper/handlers.rs`, add `signal_disconnect` right before the existing `perform_disconnect` (before line 292). This is the non-blocking variant used by `handle_disconnect()`:

```rust
/// Signal disconnect and spawn async cleanup. Returns immediately.
/// Returns true if a connection was active and signalled.
fn signal_disconnect(state: &State) -> bool {
    let is_connected = state.0.lock().unwrap().conn.is_connected();
    if !is_connected {
        return false;
    }

    state.0.lock().unwrap().conn.disconnect_flag.store(true, Ordering::SeqCst);

    {
        let mut st = state.0.lock().unwrap();
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnecting,
        });
    }

    // Take handles — cleanup thread will join them
    let (connect_handle, stats_handle) = {
        let mut st = state.0.lock().unwrap();
        let ch = st.conn.connect_handle.take();
        st.conn.stats_stop.store(true, Ordering::SeqCst);
        let sh = st.conn.stats_handle.take();
        (ch, sh)
    };

    // Spawn detached thread for blocking cleanup
    let cleanup_state = Arc::clone(state);
    thread::spawn(move || {
        if let Some(h) = connect_handle {
            let _ = h.join();
        }
        if let Some(h) = stats_handle {
            let _ = h.join();
        }

        if let Err(e) = recovery::force_recover() {
            warn!("force_recover after disconnect: {}", e);
        }

        // Clear server info and broadcast disconnected
        let mut st = cleanup_state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        });
    });

    true
}
```

- [ ] **Step 2: Update handle_disconnect to use signal_disconnect**

In `handle_disconnect()` (line 581), change the `is_connected` branch from:

```rust
    if is_connected {
        perform_disconnect(state);
        json_response(StatusCode::OK, &json!({"disconnected": true}))
```

to:

```rust
    if is_connected {
        signal_disconnect(state);
        json_response(StatusCode::OK, &json!({"disconnected": true}))
```

Only this one call site changes. The server-switch path in `handle_connect_async` (line 214) keeps calling `perform_disconnect` — it runs in a detached thread and needs the blocking guarantee.

- [ ] **Step 3: Build and verify**

Run: `cargo build 2>&1 | tail -20`
Expected: compiles without errors or warnings.

- [ ] **Step 4: Commit**

```bash
git add src/helper/handlers.rs
git commit -m "fix(helper): non-blocking disconnect — signal and return, cleanup async"
```

---

### Task 4: Thread shutdown flag through wait_for_handshake

**Files:**
- Modify: `src/wireguard.rs:882-902` (`wait_for_handshake` signature + body)
- Modify: `src/connect.rs:1578` (call site)

- [ ] **Step 1: Write the test for early-exit on shutdown**

Add to the existing `#[cfg(test)] mod tests` block in `src/wireguard.rs`:

```rust
#[test]
fn test_wait_for_handshake_respects_shutdown() {
    let shutdown = Arc::new(std::sync::atomic::AtomicBool::new(true));
    // "lo" is always a valid interface but will never have a WG handshake.
    // With shutdown=true, should bail immediately instead of blocking 10s.
    let start = std::time::Instant::now();
    let result = wait_for_handshake("lo", 10, &shutdown);
    let elapsed = start.elapsed();
    assert!(result.is_err());
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "wait_for_handshake took {:?} with shutdown=true, expected <2s",
        elapsed
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib wireguard::tests::test_wait_for_handshake_respects_shutdown -- --nocapture 2>&1 | tail -20`
Expected: compile error — `wait_for_handshake` doesn't accept 3 args.

- [ ] **Step 3: Update wait_for_handshake signature and body**

In `src/wireguard.rs`, change `wait_for_handshake` (line 882):

```rust
pub fn wait_for_handshake(
    iface: &str,
    timeout_secs: u64,
    shutdown: &Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    validate_interface_name(iface)?;

    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    loop {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            anyhow::bail!("handshake wait interrupted by disconnect");
        }

        if start.elapsed() > timeout {
            anyhow::bail!(
                "no WireGuard handshake within {}s — server may be unreachable or key may be wrong",
                timeout_secs
            );
        }

        if latest_handshake(iface).is_some() {
            return Ok(());
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
```

- [ ] **Step 4: Update call site in connect.rs**

In `src/connect.rs` line 1578, change:

```rust
    if let Err(e) = wireguard::wait_for_handshake(iface, handshake_timeout_first) {
```

to:

```rust
    if let Err(e) = wireguard::wait_for_handshake(iface, handshake_timeout_first, &params.shutdown) {
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib wireguard::tests -- --nocapture 2>&1 | tail -20`
Expected: all wireguard tests pass, including the new shutdown test.

- [ ] **Step 6: Build everything**

Run: `cargo build && cargo build --release 2>&1 | tail -10`
Expected: both debug and release compile cleanly.

- [ ] **Step 7: Run full test suite**

Run: `cargo test 2>&1 | tail -20`
Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/wireguard.rs src/connect.rs
git commit -m "fix(wireguard): wait_for_handshake bails early on disconnect signal"
```
