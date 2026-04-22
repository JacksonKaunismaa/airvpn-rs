# Fix Helper Daemon GUI Blocking

The helper daemon blocks GUI requests during connection/reconnection loops.
Read-only endpoints (`/servers`, `/keys`, `/status`, `/profile`) should always
respond promptly regardless of connection state.

## Root Causes

1. **No persistent manifest cache.** `/servers` returns 503 until the background
   manifest loop completes its first API fetch (~10-20s on startup, indefinitely
   without network). Eddie caches the manifest in `Storage.xml`.

2. **`perform_disconnect()` joins the connect thread.** The connect thread may be
   mid-handshake (up to 50s), mid-verification (up to 20s), or sleeping a
   reconnection backoff (up to 300s). The handler thread blocks the entire time,
   and since all sync handlers share tokio's blocking thread pool, this can
   starve other requests.

3. **`wait_for_handshake()` ignores the disconnect flag.** It polls for up to 50s
   with no way to bail early. Same for verify functions (10s each) and API
   fetches (10s each). After disconnect is signalled, the connect thread can't
   respond for over a minute.

## Changes

### 1. Persist manifest to disk

**File:** `src/helper/background.rs`, `src/helper/mod.rs`, `src/manifest.rs`

Save the parsed `Manifest` to `/var/lib/airvpn-rs/manifest.json` (0600 root:root)
after every successful fetch in `background_manifest_loop`. On helper startup,
`SharedState::new()` loads it alongside the latency cache.

`Manifest` already derives `Serialize`/`Deserialize`. Persistence is
`serde_json::to_string_pretty` / `from_str`, same pattern as `LatencyCache`.

The `/servers` endpoint keeps its existing 503 for `manifest == None` — with
persistence this only happens on truly first-ever run (no creds configured).

### 2. Non-blocking disconnect

**File:** `src/helper/handlers.rs`

Split `perform_disconnect()` into two:

- **`signal_disconnect(state) -> bool`** — sets disconnect flag, broadcasts
  `Disconnecting`, takes thread handles, spawns a detached cleanup thread that
  joins handles + `force_recover()` + broadcasts `Disconnected`. Returns
  immediately. Used by `handle_disconnect()`.

- **`perform_disconnect(state) -> bool`** — existing blocking version. Only used
  by the server-switch path in `handle_connect_async`, which already runs in a
  detached thread and needs disconnect to complete before starting a new
  connection.

### 3. Thread shutdown flag through `wait_for_handshake`

**File:** `src/wireguard.rs`, `src/connect.rs`

Change signature:
```rust
pub fn wait_for_handshake(
    iface: &str,
    timeout_secs: u64,
    shutdown: &Arc<AtomicBool>,
) -> Result<()>
```

The 1-second poll loop checks `shutdown.load(Ordering::Relaxed)` each iteration
and returns `Err` immediately if set.

The verify functions (`check_tunnel`, `check_dns`) and API fetches already have
hard 10-second timeouts. With non-blocking disconnect, 10s is tolerable — the
handler returns immediately and the connect thread exits within one timeout
window.

## Files Touched

| File | Change |
|------|--------|
| `src/helper/background.rs` | Save manifest after fetch |
| `src/helper/mod.rs` | Load manifest in `SharedState::new()` |
| `src/manifest.rs` | Add `save`/`load` functions (mirror `LatencyCache` pattern) |
| `src/helper/handlers.rs` | Split `perform_disconnect` into blocking + non-blocking |
| `src/wireguard.rs` | Add `shutdown` param to `wait_for_handshake` |
| `src/connect.rs` | Pass `shutdown` to `wait_for_handshake` call |

## Not Changed

- `/servers` still returns 503 when manifest is `None` (correct for first-ever run).
- Verify functions and API fetches keep their existing 10s hard timeouts.
- `wait_for_warmup()` is fine — `Condvar::wait_timeout_while` releases the mutex
  while sleeping.
