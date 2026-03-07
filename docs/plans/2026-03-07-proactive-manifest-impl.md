# Proactive Manifest Fetch Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Helper proactively fetches the manifest on startup and keeps it warm, so connect never blocks on manifest fetch and the pinger always has IPs.

**Architecture:** Two independent background loops (manifest refresh + pinger) coordinated by condvars. SharedState gains `manifest` and `ready` fields. Connect reads cached manifest/latency; stalls with 503 if helper is still warming up.

**Tech Stack:** Rust std `Condvar`, existing `Arc<Mutex<SharedState>>` pattern.

**Design doc:** `docs/plans/2026-03-07-proactive-manifest-design.md`

---

### Task 1: Add condvar infrastructure to SharedState

**Files:**
- Modify: `src/helper.rs:111-144` (SharedState, State type alias)

**Step 1: Add fields and condvars**

Replace the `SharedState` struct and `State` type:

```rust
/// State shared across all client connection threads.
struct SharedState {
    conn: ConnState,
    /// Event subscribers (long-lived `/events` connections).
    subscribers: Vec<mpsc::Sender<ipc::HelperEvent>>,
    /// EWMA-smoothed latency cache, updated by background pinger.
    latency: pinger::LatencyCache,
    /// Cached manifest from last background refresh.
    manifest: Option<manifest::Manifest>,
    /// True once the background pinger has completed at least one cycle.
    ready: bool,
}
```

Add a `Notify` struct alongside SharedState to hold the condvars (condvars work with `Mutex`, not inside the guarded data):

```rust
/// Condvars for cold-start coordination between background loops and connect.
struct Notify {
    /// Signaled when credentials become available (eddie import, profile save).
    manifest_cv: Condvar,
    /// Signaled when manifest loop populates server IPs.
    pinger_cv: Condvar,
    /// Signaled when pinger completes its first cycle.
    ready_cv: Condvar,
}

type State = Arc<(Mutex<SharedState>, Notify)>;
```

Update `SharedState::new()` to initialize `manifest: None, ready: false`.

**Step 2: Update all `state.lock().unwrap()` call sites**

Every `state.lock().unwrap()` becomes `state.0.lock().unwrap()`. Every reference to the condvars uses `state.1.manifest_cv`, etc. This is a mechanical find-and-replace.

`lock_state` helper becomes:
```rust
fn lock_state(state: &State) -> std::sync::MutexGuard<'_, SharedState> {
    state.0.lock().unwrap_or_else(|e| {
        warn!("SharedState mutex was poisoned, recovering");
        e.into_inner()
    })
}
```

**Step 3: Build and verify it compiles**

Run: `cargo build 2>&1`
Expected: compiles with no new errors (existing warnings OK)

**Step 4: Commit**

```
feat: add condvar infrastructure to SharedState

manifest_cv/pinger_cv/ready_cv for cold-start coordination.
SharedState gains manifest and ready fields.
```

---

### Task 2: Background manifest refresh loop

**Files:**
- Modify: `src/helper.rs` (new function + spawn in async_run)

**Step 1: Write the manifest refresh loop**

Add after `background_pinger_loop`:

```rust
/// Background manifest refresh loop — fetches manifest every 30 minutes.
///
/// On startup, waits for credentials (via manifest_cv) if none available.
/// After each successful fetch, populates server IPs and signals pinger_cv.
fn background_manifest_loop(state: State, shutdown: Arc<AtomicBool>) {
    const REFRESH_INTERVAL_SECS: u64 = 1800; // 30 minutes (Eddie: next_update=30)

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Load credentials from profile
        let profile_options = config::load_profile_options();
        let username = profile_options.get("login").cloned().unwrap_or_default();
        let password = profile_options.get("password").cloned().unwrap_or_default();

        if username.is_empty() || password.is_empty() {
            // No creds yet — wait for manifest_cv signal
            info!("No credentials available, waiting for profile setup...");
            let guard = lock_state(&state);
            let _guard = state.1.manifest_cv.wait_while(guard, |_| {
                if shutdown.load(Ordering::Relaxed) {
                    return false; // unblock on shutdown
                }
                let opts = config::load_profile_options();
                let u = opts.get("login").cloned().unwrap_or_default();
                let p = opts.get("password").cloned().unwrap_or_default();
                u.is_empty() || p.is_empty()
            }).unwrap_or_else(|e| e.into_inner());
            continue; // re-check creds at top of loop
        }

        // Fetch manifest
        match api::load_provider_config() {
            Ok(mut provider_config) => {
                match api::fetch_manifest(&provider_config, &username, &password) {
                    Ok(manifest_xml) => {
                        match manifest::parse_manifest(&manifest_xml) {
                            Ok(manifest) => {
                                info!("Background manifest refresh: {} servers", manifest.servers.len());

                                // Update RSA key if manifest provides one
                                // (provider_config is local, doesn't affect other threads)

                                // Extract (name, ip) pairs
                                let server_ip_pairs: Vec<(String, String)> = manifest.servers
                                    .iter()
                                    .filter_map(|s| {
                                        let ip = s.ips_entry.iter()
                                            .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                                            .or_else(|| s.ips_entry.first());
                                        ip.map(|ip| (s.name.clone(), ip.clone()))
                                    })
                                    .collect();

                                // Update shared state
                                {
                                    let mut st = lock_state(&state);
                                    st.manifest = Some(manifest);
                                    if !server_ip_pairs.is_empty() {
                                        let ips: Vec<String> = server_ip_pairs.iter()
                                            .map(|(_, ip)| ip.clone()).collect();
                                        st.latency.set_server_ips(server_ip_pairs);
                                        drop(st);
                                        if let Err(e) = netlock::populate_ping_allow(&ips) {
                                            warn!("Failed to update ping_allow: {e}");
                                        }
                                    }
                                }

                                // Signal pinger that IPs are available
                                state.1.pinger_cv.notify_all();
                            }
                            Err(e) => warn!("Failed to parse manifest: {:#}", e),
                        }
                    }
                    Err(e) => warn!("Failed to fetch manifest: {:#}", e),
                }
            }
            Err(e) => warn!("Failed to load provider config: {:#}", e),
        }

        interruptible_sleep_secs(&shutdown, REFRESH_INTERVAL_SECS);
    }
}
```

**Step 2: Spawn the manifest loop in async_run**

In `async_run`, after the pinger spawn block (line ~232), add:

```rust
// Spawn background manifest refresh task (runs every 30 minutes)
{
    let state_for_manifest = Arc::clone(&state);
    let shutdown_for_manifest = Arc::clone(&shutdown);
    tokio::task::spawn_blocking(move || {
        background_manifest_loop(state_for_manifest, shutdown_for_manifest);
    });
}
```

**Step 3: Build and verify**

Run: `cargo build 2>&1`

**Step 4: Commit**

```
feat: add background manifest refresh loop

Fetches manifest every 30 min, populates server IPs for pinger.
Waits on manifest_cv if no credentials available yet.
```

---

### Task 3: Modify pinger loop to use condvar instead of polling

**Files:**
- Modify: `src/helper.rs:312-369` (background_pinger_loop)

**Step 1: Replace polling with condvar wait**

Replace the `has_ips` check + `interruptible_sleep_secs(&shutdown, 10)` polling pattern with a condvar wait on `pinger_cv`:

```rust
fn background_pinger_loop(state: State, shutdown: Arc<AtomicBool>) {
    const CYCLE_INTERVAL_SECS: u64 = 180; // 3 minutes

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Wait until server IPs are available (manifest loop signals pinger_cv)
        {
            let guard = lock_state(&state);
            let _guard = state.1.pinger_cv.wait_while(guard, |st| {
                if shutdown.load(Ordering::Relaxed) {
                    return false; // unblock on shutdown
                }
                st.latency.server_ips().is_empty()
            }).unwrap_or_else(|e| e.into_inner());
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Copy IPs out of shared state (quick lock)
        let ips: Vec<(String, String)> = {
            let st = lock_state(&state);
            st.latency.server_ips()
                .iter()
                .map(|(n, ip)| (n.clone(), ip.clone()))
                .collect()
        };

        if ips.is_empty() {
            continue; // spurious wakeup
        }

        info!("Starting ping cycle ({} servers)", ips.len());
        let results = pinger::measure_all_from_ips(&ips);

        // Merge results back + mark ready after first cycle
        {
            let mut st = lock_state(&state);
            for (name, latency) in &results {
                if *latency >= 0 {
                    st.latency.update(name, *latency);
                } else {
                    st.latency.update_failed(name);
                }
            }
            if !st.ready {
                st.ready = true;
                // Signal ready_cv so any waiting connect requests proceed
                state.1.ready_cv.notify_all();
            }
            if let Err(e) = st.latency.save(pinger::LATENCY_CACHE_PATH) {
                warn!("Failed to persist latency cache: {e}");
            }
        }

        let measured = results.iter().filter(|(_, l)| *l >= 0).count();
        info!("Ping cycle complete ({}/{} servers measured)", measured, results.len());

        interruptible_sleep_secs(&shutdown, CYCLE_INTERVAL_SECS);
    }
}
```

**Step 2: Build and verify**

Run: `cargo build 2>&1`

**Step 3: Commit**

```
feat: pinger uses condvar instead of polling for IPs

Waits on pinger_cv instead of polling every 10s.
Signals ready_cv after first ping cycle completes.
```

---

### Task 4: Signal manifest_cv from cred-arrival paths

**Files:**
- Modify: `src/helper.rs:895-927` (handle_import_eddie)
- Modify: `src/helper.rs:414` (router dispatch for import-eddie)
- Modify: `src/helper.rs:496-528` (handle_connect_async, the cred-save path)

**Step 1: Give handle_import_eddie access to state**

Change the router dispatch to pass `state`:
```rust
("POST", "/import-eddie") => handle_import_eddie(&body_bytes, peer_uid, &state),
```

Update the function signature:
```rust
fn handle_import_eddie(body_bytes: &Bytes, peer_uid: Option<u32>, state: &State) -> Response<HyperBody> {
```

After `config::save_credentials` succeeds, signal the condvar:
```rust
if let Err(e) = config::save_credentials(&eddie_user, &eddie_pass) {
    warn!("Could not save credentials to profile: {:#}", e);
} else {
    // Wake manifest loop now that creds are available
    state.1.manifest_cv.notify_all();
}
```

**Step 2: Signal from connect's cred-save path**

In `handle_connect_async`, the connect flow currently returns 409 for eddie import or errors for no creds. The actual cred save happens via `/import-eddie` (handled in step 1). But if there's a stdin cred path that saves to profile, it should also signal. Check if there is one — if the connect handler itself saves creds anywhere, add the signal there too. Currently it doesn't save creds, so this step may be a no-op.

**Step 3: Build and verify**

Run: `cargo build 2>&1`

**Step 4: Commit**

```
feat: signal manifest_cv when credentials are saved

Eddie import handler wakes the manifest refresh loop.
```

---

### Task 5: Connect flow reads cached manifest, waits for ready

**Files:**
- Modify: `src/helper.rs:496-647` (handle_connect_async)
- Modify: `src/connect.rs:20-46` (ConnectConfig)
- Modify: `src/connect.rs:554-652` (fetch_initial_data)

**Step 1: Add ready wait to handle_connect_async**

After the cred resolution block (line ~528), before spawning the connect thread, add:

```rust
// Wait for background pinger to complete first cycle (cold start only)
{
    let st = state.0.lock().unwrap();
    if !st.ready {
        info!("Waiting for background pinger to complete first cycle...");
        drop(st);
        let guard = lock_state(&state);
        let result = state.1.ready_cv.wait_timeout_while(
            guard,
            Duration::from_secs(60),
            |st| !st.ready,
        ).unwrap_or_else(|e| e.into_inner());
        if !result.0.ready {
            return error_response(
                StatusCode::SERVICE_UNAVAILABLE,
                "Helper still warming up (waiting for first latency measurement). Try again shortly.",
            );
        }
    }
}
```

**Step 2: Pass cached manifest to connect flow**

Replace the manifest-fetch-inside-connect pattern. In `handle_connect_async`, after the ready check, clone manifest and latency from shared state:

```rust
let (cached_manifest, cached_latency) = {
    let st = state.0.lock().unwrap();
    (st.manifest.clone().expect("ready=true implies manifest is Some"), st.latency.clone())
};
```

Add `manifest: manifest::Manifest` to `ConnectConfig` (replacing `cached_latency`):

```rust
pub struct ConnectConfig {
    // ... existing fields ...
    pub cached_latency: pinger::LatencyCache,
    pub manifest: manifest::Manifest,  // NEW
    // Remove on_server_ips — manifest loop handles IP population now
}
```

**Step 3: Simplify fetch_initial_data to use cached manifest**

`fetch_initial_data` no longer fetches the manifest. It:
1. Uses `config.manifest` for server list
2. Fetches only UserInfo (WG keys — per-connect)
3. Reads `config.cached_latency` for ping data
4. Removes the `on_server_ips` callback (manifest loop handles this now)

```rust
fn fetch_initial_data(
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    config: &ConnectConfig,
) -> anyhow::Result<SessionData> {
    emit(config, crate::ipc::EngineEvent::Log {
        level: "info".into(),
        message: format!("Using cached server list ({} servers)", config.manifest.servers.len()),
    });

    // Fetch user info (WG keys — needed fresh per-connect)
    let user_info = fetch_user(provider_config, params)?;

    // Server filtering
    let filtered_servers: Vec<manifest::Server> = server::filter_servers(
        &config.manifest.servers,
        &config.allow_server,
        &config.deny_server,
        &config.allow_country,
        &config.deny_country,
    )
    .into_iter()
    .cloned()
    .collect();
    if filtered_servers.is_empty() {
        anyhow::bail!("no servers match the allow/deny filters");
    }
    // ... rest of filtering log, lock_last, start_last resolution stays the same ...

    let ping_results = config.cached_latency.clone();

    Ok(SessionData {
        manifest: config.manifest.clone(),
        user_info,
        filtered_servers,
        ping_results,
        lock_last,
        start_last_name,
    })
}
```

Extract `fetch_user` as a separate function from the current `fetch_manifest_and_user`.

**Step 4: Remove on_server_ips from ConnectConfig and all call sites**

Remove the `on_server_ips` field, the callback construction in `handle_connect_async`, and the callback invocation in `fetch_initial_data`.

**Step 5: Build and verify**

Run: `cargo build 2>&1`

**Step 6: Commit**

```
feat: connect reads cached manifest, waits for pinger ready

Connect no longer fetches manifest — uses SharedState cache.
503 returned if helper still warming up (first 60s).
on_server_ips callback removed; manifest loop handles IP population.
```

---

### Task 6: Update /servers endpoint to use cached manifest

**Files:**
- Modify: `src/helper.rs:929-971` (handle_list_servers)
- Modify: `src/helper.rs:1244-1300` (dispatch_list_servers)

**Step 1: Simplify handle_list_servers**

Read manifest from SharedState instead of fetching via API. Return 503 if not yet available:

```rust
fn handle_list_servers(query: &HashMap<String, String>, state: &State) -> Response<HyperBody> {
    let sort = query.get("sort").map(|s| s.as_str());

    let st = lock_state(state);
    let manifest = match &st.manifest {
        Some(m) => m.clone(),
        None => return error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Server list not yet available — helper is warming up.",
        ),
    };
    let latency = st.latency.clone();
    drop(st);

    let profile_options = config::load_profile_options();
    let score_type = server::ScoreType::from_profile(
        profile_options.get("servers.scoretype").map(|s| s.as_str()).unwrap_or("Speed"),
    );

    // Score and format servers (no API call, no IP population needed)
    // ... adapt dispatch_list_servers or inline the scoring logic ...
}
```

**Step 2: Simplify dispatch_list_servers**

Remove the cred parameters and API call. It now takes a `&Manifest` and `&LatencyCache` directly:

```rust
fn dispatch_list_servers(
    manifest: &manifest::Manifest,
    latency: &pinger::LatencyCache,
    sort: Option<&str>,
    score_type: server::ScoreType,
) -> Vec<ipc::ServerInfo> {
    // Score and sort servers using manifest + latency data
    // No API call, no fallback measurement
}
```

**Step 3: Remove send_list_servers skip_ping parameter (already done in earlier work)**

Verify `cli_client::send_list_servers` no longer has `skip_ping`. Already removed.

**Step 4: Build and verify**

Run: `cargo build 2>&1`

**Step 5: Commit**

```
feat: /servers reads cached manifest from SharedState

No more per-request manifest fetch. Returns 503 if warming up.
```

---

### Task 7: Handle reconnection manifest refresh

**Files:**
- Modify: `src/connect.rs:654-709` (refresh_manifest_if_needed)

**Step 1: Decide reconnection strategy**

The reconnect loop currently re-fetches the manifest directly via API. Two options:
- (a) Keep this — reconnection is already connected, has a tunnel, small overhead
- (b) Read from SharedState cache (needs a handle passed into connect)

Recommend (a): keep reconnection's own manifest fetch. It's the fallback path, runs rarely, and the connect thread doesn't hold SharedState. The background manifest loop handles the 30-min refresh independently. The reconnect fetch also refreshes UserInfo (WG keys may rotate), which we wouldn't want cached.

**No code changes needed.** Just verify `refresh_manifest_if_needed` still compiles after the ConnectConfig changes.

**Step 2: Build and verify**

Run: `cargo build 2>&1`

**Step 3: Commit (if any fixups needed)**

---

### Task 8: Warm-start optimization — set ready=true if latency.json has data

**Files:**
- Modify: `src/helper.rs:120-136` (SharedState::new)

**Step 1: If latency.json has data, skip the cold-start wait**

On warm start, `latency.json` already has EWMA data from last run. The pinger will refine it, but there's no reason to make the first connect wait for a full ping cycle.

```rust
impl SharedState {
    fn new() -> Self {
        let latency = pinger::LatencyCache::load(pinger::LATENCY_CACHE_PATH);
        let ready = latency.has_data(); // warm start = ready immediately

        if !latency.server_ips().is_empty() {
            let ips: Vec<String> = latency.server_ips().values().cloned().collect();
            if let Err(e) = netlock::populate_ping_allow(&ips) {
                log::warn!("Failed to populate ping_allow from cached IPs: {e}");
            }
        }
        Self {
            conn: ConnState::new(),
            subscribers: Vec::new(),
            latency,
            manifest: None,
            ready,
        }
    }
}
```

Note: `manifest` is still `None` here — on warm start the manifest loop will populate it quickly (creds exist, API call is fast). Connect still needs to check `manifest.is_some()` OR we could also wait on a manifest-available condition. But since the manifest loop fires immediately on startup with creds, the window is tiny (~200-500ms). If a connect races and finds `manifest=None` but `ready=true`, it should wait briefly for manifest or fall back to its own fetch.

Simplest approach: the ready check in Task 5 also checks `manifest.is_some()`:
```rust
let result = state.1.ready_cv.wait_timeout_while(
    guard,
    Duration::from_secs(60),
    |st| !st.ready || st.manifest.is_none(),
);
```

And the manifest loop signals `ready_cv` after storing the manifest (in addition to `pinger_cv`).

**Step 2: Build and verify**

Run: `cargo build && cargo build --release 2>&1`

**Step 3: Commit**

```
feat: warm start skips pinger wait, uses cached latency.json

ready=true on startup if latency.json has data.
Connect only stalls on cold start (no cached data).
```

---

### Task 9: Integration test and cleanup

**Files:**
- Modify: `src/helper.rs` (any dead code removal)
- Modify: `src/connect.rs` (any dead code removal)

**Step 1: Remove dead code**

- `measure_all_inline` already removed (earlier in this session)
- `on_server_ips` field and callback — removed in Task 5
- Any unused imports

**Step 2: Full build both profiles**

Run: `cargo build && cargo build --release 2>&1`

**Step 3: Run tests**

Run: `cargo test 2>&1`

**Step 4: Manual smoke test**

```bash
# Start helper with socket activation
sudo systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper

# Check status (should work, may show "warming up" briefly)
curl --unix-socket /run/airvpn-rs/helper.sock http://localhost/status

# Connect (should use cached manifest, no "Skipping ping" message)
sudo ./target/debug/airvpn connect
```

**Step 5: Commit any cleanup**

```
chore: remove dead code from manifest caching refactor
```
