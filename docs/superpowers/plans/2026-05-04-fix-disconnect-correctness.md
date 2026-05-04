# Fix Disconnect Correctness Issues — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 4 pre-existing correctness issues in the helper daemon's disconnect path: double `Disconnected` broadcast, `connect_in_progress` stuck on panic, missing host route cleanup, and TOCTOU on concurrent disconnect.

**Architecture:** Three commits, each a focused fix:
1. RAII guard makes the connect thread the single source of truth for `Disconnected` events and `connect_in_progress` clearing — fires even on panic. Removes duplicate broadcasts from `signal_disconnect` and `perform_disconnect`.
2. Refactor `signal_disconnect` into a single atomic critical section, idempotent on concurrent calls.
3. Snapshot manifest IPs in both disconnect paths and remove stale `/32` server host routes after `force_recover`.

**Tech Stack:** Rust, std::sync::atomic, RAII Drop pattern

---

## File Structure

| File | Responsibility |
|------|----------------|
| `src/helper/handlers.rs` | All three commits live here — guard struct, function refactors, route cleanup |

No new files. No new modules. Pure refactoring of existing functions.

---

### Task 1: RAII guard — single source for Disconnected broadcast and in_progress clearing

**Files:**
- Modify: `src/helper/handlers.rs:109-116` (extend `ConnectGuard` to also broadcast)
- Modify: `src/helper/handlers.rs:550-602` (use guard inside connect thread, remove manual store/broadcast)
- Modify: `src/helper/handlers.rs:332-339` (remove duplicate broadcast in `signal_disconnect` cleanup)
- Modify: `src/helper/handlers.rs:391-399` (remove duplicate broadcast in `perform_disconnect`)

**Why:** The connect thread currently clears `connect_in_progress` and broadcasts `Disconnected` at lines 595-601 — but only if it reaches that code. Panics inside `connect::run` skip it. Meanwhile, `signal_disconnect` and `perform_disconnect` both also broadcast `Disconnected` after joining, producing duplicate events on every normal disconnect. Making the guard the single source of truth fixes both.

- [ ] **Step 1: Replace `ConnectGuard` with a guard that owns both responsibilities**

In `src/helper/handlers.rs`, replace lines 109-116 (the existing `ConnectGuard` struct + `Drop`):

```rust
/// RAII guard for the connect thread. On drop (including panic unwind), clears
/// the `connect_in_progress` flag and broadcasts the final `Disconnected` event.
///
/// Used at two call sites:
/// - `handle_connect_async`: created before warmup, defused via `mem::forget()`
///   once we're committed to spawning the connect thread. The connect thread
///   creates its own guard and takes over responsibility.
/// - The connect thread closure: created at the top, runs on every exit path
///   (Ok, Err, panic).
struct ConnectGuard {
    in_progress: Arc<AtomicBool>,
    /// `None` when used as the early-exit guard in `handle_connect_async`
    /// (no broadcast needed — connection never started). `Some` inside the
    /// connect thread.
    state: Option<State>,
}

impl Drop for ConnectGuard {
    fn drop(&mut self) {
        self.in_progress.store(false, Ordering::SeqCst);
        if let Some(state) = &self.state {
            if let Ok(mut st) = state.0.lock() {
                st.broadcast(&ipc::HelperEvent::StateChanged {
                    state: ipc::ConnectionState::Disconnected,
                });
            }
        }
    }
}
```

- [ ] **Step 2: Update the early-exit guard in `handle_connect_async`**

In `src/helper/handlers.rs` around line 190, change the guard construction. Find the existing line:

```rust
        ConnectGuard(st.conn.connect_in_progress.clone())
```

Change to:

```rust
        ConnectGuard {
            in_progress: st.conn.connect_in_progress.clone(),
            state: None,
        }
```

This guard runs only on early-exit paths (warmup timeout, credential errors). It clears `connect_in_progress` but does NOT broadcast `Disconnected` — the connection never started, so there's nothing to disconnect from. The existing `mem::forget()` calls at lines 211 and 243 still defuse it correctly.

- [ ] **Step 3: Add a guard to the connect thread closure**

In `src/helper/handlers.rs`, in `start_connect`, modify the connect thread spawn (around line 571) to create a guard at the top of the closure that takes over responsibility:

Find the existing block starting at line 571:

```rust
    let conn_handle = thread::spawn(move || {
        let result = (|| -> Result<()> {
            let mut provider_config = api::load_provider_config()?;
            api::verify_rsa_key_integrity(&provider_config);
            connect::run(&mut provider_config, &connect_config)?;
            Ok(())
        })();

        if let Err(e) = &result {
            error!("Connect thread exited with error: {}", e);
            // Clean up state left behind by the failed connect session.
            // Without this, state.json + nftables rules persist and the next
            // connect attempt bails with "another instance running" (the helper
            // finds its own PID alive in state.json).
            if let Err(re) = recovery::force_recover() {
                warn!("post-error recovery failed: {}", re);
            }
            if let Ok(mut st) = connect_broadcast_state.0.lock() {
                st.broadcast(&ipc::HelperEvent::Error {
                    message: format!("{}", e),
                });
            }
        }

        // Signal disconnected and clear the connect_in_progress guard
        if let Ok(mut st) = connect_broadcast_state.0.lock() {
            st.conn.connect_in_progress.store(false, Ordering::SeqCst);
            st.broadcast(&ipc::HelperEvent::StateChanged {
                state: ipc::ConnectionState::Disconnected,
            });
        }
    });
```

Replace with:

```rust
    let connect_in_progress_for_guard = {
        let st = state.0.lock().unwrap();
        st.conn.connect_in_progress.clone()
    };
    let conn_handle = thread::spawn(move || {
        // Guard fires on every exit path (Ok, Err, panic) — clears
        // connect_in_progress and broadcasts Disconnected exactly once.
        let _guard = ConnectGuard {
            in_progress: connect_in_progress_for_guard,
            state: Some(Arc::clone(&connect_broadcast_state)),
        };

        let result = (|| -> Result<()> {
            let mut provider_config = api::load_provider_config()?;
            api::verify_rsa_key_integrity(&provider_config);
            connect::run(&mut provider_config, &connect_config)?;
            Ok(())
        })();

        if let Err(e) = &result {
            error!("Connect thread exited with error: {}", e);
            // Clean up state left behind by the failed connect session.
            // Without this, state.json + nftables rules persist and the next
            // connect attempt bails with "another instance running" (the helper
            // finds its own PID alive in state.json).
            if let Err(re) = recovery::force_recover() {
                warn!("post-error recovery failed: {}", re);
            }
            if let Ok(mut st) = connect_broadcast_state.0.lock() {
                st.broadcast(&ipc::HelperEvent::Error {
                    message: format!("{}", e),
                });
            }
        }
        // No manual store/broadcast — guard handles both on drop.
    });
```

The `connect_in_progress_for_guard` clone is needed because `connect_broadcast_state` is moved into the closure.

- [ ] **Step 4: Remove duplicate broadcast in `signal_disconnect`**

In `src/helper/handlers.rs`, in `signal_disconnect`'s detached cleanup thread (around line 320-340), remove the trailing `Disconnected` broadcast. Find this block:

```rust
        // Clear server info and broadcast disconnected
        let mut st = cleanup_state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        });
    });
```

Replace with:

```rust
        // Clear server info. The connect thread's ConnectGuard broadcasts
        // Disconnected on its way out — don't duplicate it here.
        let mut st = cleanup_state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
    });
```

- [ ] **Step 5: Remove duplicate broadcast in `perform_disconnect`**

In `src/helper/handlers.rs`, in `perform_disconnect` (around line 391-399), remove the trailing broadcast. Find:

```rust
    // Clear server info and broadcast disconnected
    {
        let mut st = state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnected,
        });
    }

    true
}
```

Replace with:

```rust
    // Clear server info. The connect thread's ConnectGuard broadcasts
    // Disconnected on its way out — don't duplicate it here.
    {
        let mut st = state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
    }

    true
}
```

- [ ] **Step 6: Build and verify**

Run: `cargo build 2>&1 | tail -10`
Expected: compiles cleanly. The previously-private `ConnectGuard` is still private; only its definition changed.

- [ ] **Step 7: Run full test suite**

Run: `cargo test --lib 2>&1 | tail -10`
Expected: all tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/helper/handlers.rs
git commit -m "fix(helper): single-source Disconnected broadcast via RAII guard

The connect thread is now the only place that clears connect_in_progress
and broadcasts the final Disconnected event. ConnectGuard's Drop runs
even on panic unwind, fixing the case where a panicking connect thread
left connect_in_progress=true and blocked all subsequent connects.

signal_disconnect and perform_disconnect no longer broadcast Disconnected
themselves — the connect thread's guard fires when its handle is joined."
```

---

### Task 2: Atomic single-lock signal_disconnect, idempotent on concurrent calls

**Files:**
- Modify: `src/helper/handlers.rs:292-343` (rewrite `signal_disconnect` body)

**Why:** `signal_disconnect` currently acquires the mutex 4 separate times. Two concurrent `/disconnect` calls can race — both pass the `is_connected` check, both spawn cleanup threads, second cleanup thread joins nothing and runs `force_recover` redundantly. Collapsing into one critical section + using `disconnect_flag.swap(true, ...)` for idempotency makes the function safe under concurrency.

- [ ] **Step 1: Rewrite signal_disconnect**

In `src/helper/handlers.rs`, replace the entire `signal_disconnect` function (lines 292-343) with:

```rust
/// Signal disconnect and spawn async cleanup. Returns immediately.
///
/// Idempotent: if the disconnect flag is already set, returns false without
/// spawning a duplicate cleanup thread. Returns true only for the caller
/// that successfully flipped the flag.
fn signal_disconnect(state: &State) -> bool {
    // Single critical section: check, claim, capture handles, broadcast.
    // Using swap on disconnect_flag makes this idempotent under concurrent
    // /disconnect calls — only the first caller (which sees the old value
    // false) proceeds to spawn cleanup.
    let (connect_handle, stats_handle) = {
        let mut st = state.0.lock().unwrap();
        if !st.conn.is_connected() {
            return false;
        }
        if st.conn.disconnect_flag.swap(true, Ordering::SeqCst) {
            // Another caller already signalled — they own cleanup.
            return false;
        }
        st.conn.stats_stop.store(true, Ordering::SeqCst);
        let ch = st.conn.connect_handle.take();
        let sh = st.conn.stats_handle.take();
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnecting,
        });
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

        // Clear server info. The connect thread's ConnectGuard broadcasts
        // Disconnected on its way out — don't duplicate it here.
        let mut st = cleanup_state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
    });

    true
}
```

- [ ] **Step 2: Build and verify**

Run: `cargo build 2>&1 | tail -5`
Expected: compiles cleanly.

- [ ] **Step 3: Run tests**

Run: `cargo test --lib 2>&1 | tail -10`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add src/helper/handlers.rs
git commit -m "fix(helper): atomic signal_disconnect, idempotent on concurrent calls

Collapse four separate mutex acquisitions into a single critical section
that checks is_connected, claims the disconnect flag via swap, captures
thread handles, and broadcasts Disconnecting atomically. A second
concurrent /disconnect now sees disconnect_flag already true and returns
false without spawning a duplicate cleanup thread."
```

---

### Task 3: Clean stale server host routes on disconnect

**Files:**
- Modify: `src/helper/handlers.rs:294-?` (`signal_disconnect` — snapshot IPs, clean in cleanup thread)
- Modify: `src/helper/handlers.rs:347-?` (`perform_disconnect` — snapshot IPs, clean after force_recover)

**Why:** The pinger adds ~1000 `/32` host routes for server entry IPs. `force_recover()` doesn't clean these (it doesn't know the IPs). Currently only `handle_recover` and the orphan path of `handle_disconnect` remove them. After a normal GUI-initiated disconnect, ~1000 stale routes pollute the routing table until reboot or `/recover`.

- [ ] **Step 1: Add route cleanup to signal_disconnect**

In `src/helper/handlers.rs`, modify the rewritten `signal_disconnect` from Task 2. Add `route_ips` to the captured tuple in the critical section, and call `remove_server_host_routes` in the cleanup thread after `force_recover`.

Replace the entire `signal_disconnect` function body with:

```rust
fn signal_disconnect(state: &State) -> bool {
    let (connect_handle, stats_handle, route_ips) = {
        let mut st = state.0.lock().unwrap();
        if !st.conn.is_connected() {
            return false;
        }
        if st.conn.disconnect_flag.swap(true, Ordering::SeqCst) {
            return false;
        }
        st.conn.stats_stop.store(true, Ordering::SeqCst);
        let ch = st.conn.connect_handle.take();
        let sh = st.conn.stats_handle.take();
        // Snapshot manifest IPs so the cleanup thread can remove host routes
        // after force_recover (which doesn't know server IPs).
        let ips: Vec<String> = st.manifest.as_ref()
            .map(|m| m.servers.iter().flat_map(|s| s.ips_entry.iter().cloned()).collect())
            .unwrap_or_default();
        st.broadcast(&ipc::HelperEvent::StateChanged {
            state: ipc::ConnectionState::Disconnecting,
        });
        (ch, sh, ips)
    };

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

        // Remove stale /32 server host routes left by the pinger.
        // force_recover doesn't handle these (it doesn't know server IPs).
        if !route_ips.is_empty() {
            if let Ok(gw) = wireguard::get_default_gateway_pub() {
                let _ = wireguard::remove_server_host_routes(&route_ips, &gw);
            }
        }

        let mut st = cleanup_state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
    });

    true
}
```

- [ ] **Step 2: Add route cleanup to perform_disconnect**

In `src/helper/handlers.rs`, modify `perform_disconnect`. Find the block starting at the line with `if let Err(e) = recovery::force_recover()` (around line 386):

```rust
    if let Err(e) = recovery::force_recover() {
        warn!("force_recover after disconnect: {}", e);
    }

    // Clear server info. The connect thread's ConnectGuard broadcasts
    // Disconnected on its way out — don't duplicate it here.
    {
        let mut st = state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
    }

    true
}
```

Replace with:

```rust
    if let Err(e) = recovery::force_recover() {
        warn!("force_recover after disconnect: {}", e);
    }

    // Remove stale /32 server host routes left by the pinger.
    // force_recover doesn't handle these (it doesn't know server IPs).
    let route_ips: Vec<String> = {
        let st = state.0.lock().unwrap();
        st.manifest.as_ref()
            .map(|m| m.servers.iter().flat_map(|s| s.ips_entry.iter().cloned()).collect())
            .unwrap_or_default()
    };
    if !route_ips.is_empty() {
        if let Ok(gw) = wireguard::get_default_gateway_pub() {
            let _ = wireguard::remove_server_host_routes(&route_ips, &gw);
        }
    }

    // Clear server info. The connect thread's ConnectGuard broadcasts
    // Disconnected on its way out — don't duplicate it here.
    {
        let mut st = state.0.lock().unwrap();
        if let Ok(mut info) = st.conn.server_info.lock() {
            *info = Default::default();
        }
    }

    true
}
```

- [ ] **Step 3: Build and verify**

Run: `cargo build && cargo build --release 2>&1 | tail -10`
Expected: both debug and release compile cleanly.

- [ ] **Step 4: Run tests**

Run: `cargo test --lib 2>&1 | tail -10`
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/helper/handlers.rs
git commit -m "fix(helper): clean stale server host routes on disconnect

The pinger adds ~1000 /32 host routes via the physical gateway so it can
ping all servers directly. force_recover() doesn't know about these
routes, so a normal GUI disconnect previously left them in the routing
table until the next /recover or reboot.

signal_disconnect and perform_disconnect now snapshot manifest IPs from
SharedState before triggering cleanup, then call remove_server_host_routes
after force_recover. Mirrors the existing logic in handle_recover and the
orphan path of handle_disconnect."
```
