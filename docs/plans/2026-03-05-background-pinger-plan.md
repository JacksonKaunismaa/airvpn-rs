# Background Pinger Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a continuous background pinger to the helper daemon so server latency data is always fresh and available without blocking connect or server list requests.

**Architecture:** Replace `PingResults` with `LatencyCache` (EWMA α=0.3, persisted to disk). Background tokio task in the helper pings all servers every 3 minutes. While connected, ping the connected server through the tunnel and all others outside via host routes + nftables allowlist. While disconnected, ping directly with ICMP holes in persistent lock. Match Eddie's all-server allowlist in the session lock.

**Tech Stack:** Rust, tokio (async runtime already in helper), nftables, ip routing

**Tested assumptions** (see `scripts/test-ping-routing.sh` results):
- Host routes bypass tunnel routing via `suppress_prefixlength 0` (T2 routing works)
- Both session AND persistent lock must allow the traffic (T4/T5 each alone FAIL)
- Allowlist entries (`ip daddr <ip> accept`) work in both locks (T7 PASS)
- `nft -f` batch: 1024 rules in 25ms (T20)
- `ip -batch` routes: 1024 routes in 18ms (T22)
- 256 servers, 1024 unique IPv4 entry IPs (T18)
- Connected server pinged through tunnel is accurate (same path as real traffic)

---

## Task 1: LatencyCache — Replace PingResults

**Files:**
- Modify: `src/pinger.rs` (full rewrite of PingResults, keep ping_ip/median_ping/measure_all)
- Modify: `src/server.rs:7,298,316` (update PingResults → LatencyCache references)
- Modify: `src/connect.rs:468,658,674,1184` (SessionData field, usage)
- Modify: `src/helper.rs:1102-1106` (dispatch_list_servers usage)
- Test: existing tests in `src/pinger.rs:65-95`, `src/server.rs`

**Step 1: Write failing tests for LatencyCache**

Add to `src/pinger.rs` tests:

```rust
#[test]
fn test_ewma_first_sample_seeds_directly() {
    let mut cache = LatencyCache::new();
    cache.update("server1", 100.0);
    assert_eq!(cache.get("server1"), 100);
}

#[test]
fn test_ewma_smooths_subsequent_samples() {
    let mut cache = LatencyCache::new();
    cache.update("server1", 100.0);
    cache.update("server1", 200.0);
    // α=0.3: 0.3*200 + 0.7*100 = 60 + 70 = 130
    assert_eq!(cache.get("server1"), 130);
}

#[test]
fn test_ewma_third_sample() {
    let mut cache = LatencyCache::new();
    cache.update("server1", 100.0);
    cache.update("server1", 200.0);
    // After 2: 130.0
    cache.update("server1", 50.0);
    // α=0.3: 0.3*50 + 0.7*130 = 15 + 91 = 106
    assert_eq!(cache.get("server1"), 106);
}

#[test]
fn test_unknown_server_returns_negative_one() {
    let cache = LatencyCache::new();
    assert_eq!(cache.get("unknown"), -1);
}

#[test]
fn test_update_failed_keeps_stale_data() {
    let mut cache = LatencyCache::new();
    cache.update("server1", 100.0);
    cache.update_failed("server1");
    assert_eq!(cache.get("server1"), 100); // keeps old value
}

#[test]
fn test_update_failed_no_prior_stays_none() {
    let mut cache = LatencyCache::new();
    cache.update_failed("server1");
    assert_eq!(cache.get("server1"), -1);
}

#[test]
fn test_has_data() {
    let mut cache = LatencyCache::new();
    assert!(!cache.has_data());
    cache.update("server1", 100.0);
    assert!(cache.has_data());
}

#[test]
fn test_server_ips_management() {
    let mut cache = LatencyCache::new();
    cache.set_server_ips(vec![
        ("server1".into(), "1.2.3.4".into()),
        ("server2".into(), "5.6.7.8".into()),
    ]);
    assert_eq!(cache.server_ips().len(), 2);
}

#[test]
fn test_persist_and_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("latency.json");

    let mut cache = LatencyCache::new();
    cache.update("server1", 100.0);
    cache.update("server2", 200.0);
    cache.set_server_ips(vec![
        ("server1".into(), "1.2.3.4".into()),
        ("server2".into(), "5.6.7.8".into()),
    ]);
    cache.save(&path).unwrap();

    let loaded = LatencyCache::load(&path).unwrap();
    assert_eq!(loaded.get("server1"), 100);
    assert_eq!(loaded.get("server2"), 200);
    assert_eq!(loaded.server_ips().len(), 2);
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test --lib pinger -- --nocapture`
Expected: FAIL — LatencyCache doesn't exist yet

**Step 3: Implement LatencyCache**

Replace `PingResults` in `src/pinger.rs`:

```rust
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use log::info;
use serde::{Deserialize, Serialize};

const ALPHA: f64 = 0.3;

/// EWMA-smoothed latency cache with per-server tracking.
/// Replaces the old PingResults (single-shot HashMap).
#[derive(Default, Serialize, Deserialize)]
pub struct LatencyCache {
    ewma: HashMap<String, f64>,
    server_ips: HashMap<String, String>,
}

impl LatencyCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update a server's latency with a new sample.
    /// First sample seeds directly; subsequent samples use EWMA.
    pub fn update(&mut self, server_name: &str, sample_ms: f64) {
        let entry = self.ewma.entry(server_name.to_string()).or_insert(sample_ms);
        if (*entry - sample_ms).abs() < f64::EPSILON {
            // First insertion — already seeded
        } else {
            *entry = ALPHA * sample_ms + (1.0 - ALPHA) * *entry;
        }
    }

    /// Record a failed ping. Keeps stale data if prior exists.
    pub fn update_failed(&mut self, server_name: &str) {
        // No-op if server has prior data (keep stale-but-real).
        // If no prior data, don't insert anything (stays as -1 via get()).
    }

    /// Get latency for a server. Returns -1 if not measured.
    pub fn get(&self, server_name: &str) -> i64 {
        self.ewma
            .get(server_name)
            .map(|v| v.round() as i64)
            .unwrap_or(-1)
    }

    /// Whether any server has been measured.
    pub fn has_data(&self) -> bool {
        !self.ewma.is_empty()
    }

    /// Set the server name → entry IP mapping (from manifest).
    pub fn set_server_ips(&mut self, ips: Vec<(String, String)>) {
        self.server_ips = ips.into_iter().collect();
    }

    /// Get the server IP map.
    pub fn server_ips(&self) -> &HashMap<String, String> {
        &self.server_ips
    }

    /// All entry IPs (for allowlist/route setup).
    pub fn all_entry_ips(&self) -> Vec<String> {
        self.server_ips.values().cloned().collect()
    }

    /// Persist to disk as JSON.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load from disk. Returns default if file doesn't exist.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let json = std::fs::read_to_string(path)?;
        let cache: Self = serde_json::from_str(&json)?;
        Ok(cache)
    }
}
```

Note: Keep `ping_ip()`, `median_ping()`, `PING_ROUNDS`, and `measure_all()` unchanged for now — they'll be used by the background pinger task. `measure_all()` still returns the old format; the background task will feed results into `LatencyCache`.

Actually — `measure_all` should return raw results that the caller feeds into `LatencyCache`. Change its return type:

```rust
/// Measure latency for all servers. Returns (server_name, latency_ms) pairs.
/// -1 means measurement failed.
pub fn measure_all(servers: &[(String, String)]) -> Vec<(String, i64)> {
    // servers is now (name, ip) pairs instead of &[manifest::Server]
    // ... same thread-per-server logic, just takes (name, ip) tuples
}
```

**Step 4: Update all call sites**

- `src/server.rs`: Change `PingResults` → `LatencyCache` in imports and function signatures
- `src/connect.rs`: Change `SessionData.ping_results` type, update `fetch_initial_data` and `select_server_with_penalties` calls
- `src/helper.rs`: Update `dispatch_list_servers`

**Step 5: Run all tests**

Run: `cargo test --lib`
Expected: All pass

**Step 6: Commit**

```
feat: replace PingResults with LatencyCache (EWMA α=0.3)
```

---

## Task 2: Persist LatencyCache to Disk

**Files:**
- Modify: `src/pinger.rs` (save/load already in Task 1)
- Modify: `src/helper.rs` (load on startup, save after each ping cycle)
- Create: `/var/lib/airvpn-rs/` directory via install.sh

**Step 1: Add persistence path constant**

In `src/pinger.rs`:
```rust
pub const LATENCY_CACHE_PATH: &str = "/var/lib/airvpn-rs/latency.json";
```

**Step 2: Update `scripts/install.sh` to create the directory**

Add: `mkdir -p /var/lib/airvpn-rs`

**Step 3: Test save/load roundtrip**

Already covered by `test_persist_and_load_roundtrip` in Task 1.

**Step 4: Commit**

```
feat: persist LatencyCache to /var/lib/airvpn-rs/latency.json
```

---

## Task 3: All-Server Allowlist in Session Lock (Match Eddie)

**Files:**
- Modify: `src/connect.rs:808,1235` (pass all server IPs, not just selected server)
- Modify: `src/connect.rs:796-864` (activate_netlock takes all server IPs)
- Test: add test verifying all IPs are passed

**Step 1: Write failing test**

Test that `activate_netlock` receives all server entry IPs, not just the selected one. This is a behavior change — currently line 1235 passes `&server_ref.ips_entry` (just the selected server). It should pass all filtered server entry IPs.

**Step 2: Change activate_netlock call**

In `connect.rs`, before the reconnection loop, collect all entry IPs:
```rust
let all_server_ips: Vec<String> = data.filtered_servers
    .iter()
    .flat_map(|s| s.ips_entry.iter().cloned())
    .collect();
```

Pass `&all_server_ips` to `activate_netlock` instead of `&server_ref.ips_entry`.

**Step 3: Move lock activation before the reconnection loop**

Currently `activate_netlock` is called inside the loop (line 1235), meaning it's rebuilt on every reconnection. Move it before the loop (after `fetch_initial_data`) so it's only called once. On manifest refresh, update the allowlist if server IPs changed (new atomic `nft -f` load).

**Step 4: Run tests**

Run: `cargo test --lib`

**Step 5: Commit**

```
feat: allowlist all server IPs in session lock (match Eddie)
```

---

## Task 4: Host Routes for All Server IPs

**Files:**
- Modify: `src/wireguard.rs:463-545` (setup_routing adds all server routes)
- Modify: `src/wireguard.rs:592-615` (teardown_routing removes them)
- Modify: `src/connect.rs` (pass server IPs to setup_routing)

**Step 1: Extend setup_routing to accept additional IPs**

Add a parameter `server_ips: &[String]` to `setup_routing()`. After adding the endpoint host route (line 489-510), add `/32` routes for all server IPs via `ip -batch`:

```rust
fn add_server_host_routes(server_ips: &[String], gateway: &str, dev_hint: &str) -> Result<()> {
    if server_ips.is_empty() {
        return Ok(());
    }
    let mut batch = String::new();
    for ip in server_ips {
        // Skip the endpoint IP (already has a route)
        batch.push_str(&format!("route add {}/32 via {} dev {}\n", ip, gateway, dev_hint));
    }
    // Use ip -batch for performance (tested: 1024 routes in 18ms)
    let mut child = Command::new("ip")
        .args(["-batch", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    child.stdin.as_mut().unwrap().write_all(batch.as_bytes())?;
    let output = child.wait_with_output()?;
    // Non-fatal: some routes may already exist
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        warn!("Some server host routes failed (non-fatal): {}", stderr.trim());
    }
    Ok(())
}
```

**Step 2: Extend teardown to remove server routes**

Add corresponding removal in `teardown_routing` using `ip -batch`.

**Step 3: Pass server IPs through the connect flow**

The connect path needs to pass the server IP list to `setup_routing`. Store `all_entry_ips` in `SessionData` or `SessionParams` so it's available.

**Step 4: Test**

Build and test manually (routing tests require root). Verify with `ip route show` that routes appear.

**Step 5: Commit**

```
feat: add /32 host routes for all server IPs during connection
```

---

## Task 5: Allowlist Server IPs in Persistent Lock

**Files:**
- Modify: `src/netlock.rs` (extend open_ping_holes or add new function)
- Modify: `src/pinger.rs` or `src/helper.rs` (call it when pinger starts)

**Step 1: Add `open_server_allowlist()` to netlock.rs**

Similar to `open_ping_holes()` but adds `ip daddr <ip> counter accept` (all protocols, not just ICMP) to the persistent lock's `ping_allow` chain:

```rust
/// Allow all traffic to server IPs in the persistent lock.
/// Used by the background pinger to enable outside-tunnel pings.
/// Uses the existing ping_allow subchain. No-op if persistent lock inactive.
pub fn open_server_allowlist(server_ips: &[String]) -> Result<()> {
    if !is_persist_active() {
        return Ok(());
    }
    // Build batch: ip daddr <ip> accept (all protocols)
    // Use nft -f for atomic batch (tested: 1024 rules in 25ms)
    // ...
}
```

**Step 2: Call on manifest load**

When the background pinger gets a server list (or manifest refreshes), call `open_server_allowlist()`. On helper shutdown, call `close_ping_holes()` (existing function flushes the chain).

**Step 3: Test**

Existing `build_ping_hole_rules` tests cover the nft rule generation. Add a test for the new all-protocol variant.

**Step 4: Commit**

```
feat: allowlist server IPs in persistent lock for background pinger
```

---

## Task 6: Background Pinger Task in Helper

**Files:**
- Modify: `src/helper.rs` (add LatencyCache to SharedState, spawn background task)
- Modify: `src/pinger.rs` (add `ping_cycle()` function for one round)

**Step 1: Add LatencyCache to SharedState**

```rust
struct SharedState {
    conn: ConnState,
    subscribers: Vec<mpsc::Sender<ipc::HelperEvent>>,
    latency: Arc<Mutex<LatencyCache>>,
}
```

Load from disk on startup in `async_run()`:
```rust
let latency_cache = Arc::new(Mutex::new(
    LatencyCache::load(Path::new(pinger::LATENCY_CACHE_PATH)).unwrap_or_default()
));
```

**Step 2: Add ping_cycle() to pinger.rs**

```rust
/// Run one ping cycle: ping all servers, update cache.
/// `connected_server`: if Some, skip this server (ping it through tunnel separately).
/// `server_ips`: (name, ip) pairs to ping outside tunnel.
pub fn ping_cycle(
    cache: &mut LatencyCache,
    connected_server: Option<&str>,
) {
    let ips = cache.server_ips().clone();
    // Ping all servers (except connected) via measure_all
    let to_ping: Vec<(String, String)> = ips.iter()
        .filter(|(name, _)| connected_server.map_or(true, |cs| cs != name.as_str()))
        .map(|(n, ip)| (n.clone(), ip.clone()))
        .collect();

    let results = measure_all(&to_ping);
    for (name, latency) in results {
        if latency >= 0 {
            cache.update(&name, latency as f64);
        } else {
            cache.update_failed(&name);
        }
    }
}
```

**Step 3: Spawn background task in async_run()**

```rust
// Spawn background pinger
let pinger_latency = Arc::clone(&latency_cache);
let pinger_shutdown = Arc::clone(&shutdown);
tokio::task::spawn_blocking(move || {
    loop {
        if pinger_shutdown.load(Ordering::Relaxed) {
            break;
        }
        {
            let mut cache = pinger_latency.lock().unwrap();
            if cache.server_ips().is_empty() {
                // No server list yet — wait
                drop(cache);
                std::thread::sleep(Duration::from_secs(10));
                continue;
            }
            // Determine connected server (if any)
            let connected = /* read from ConnState */;

            // Open ping holes if persistent lock active
            let ips = cache.all_entry_ips();
            let _ = netlock::open_server_allowlist(&ips);

            pinger::ping_cycle(&mut cache, connected.as_deref());

            // Persist to disk
            let _ = cache.save(Path::new(pinger::LATENCY_CACHE_PATH));
        }
        // Sleep 3 minutes (interruptible)
        for _ in 0..180 {
            if pinger_shutdown.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }
});
```

**Step 4: Update manifest loading to populate server_ips**

When `dispatch_list_servers()` or `connect::run()` fetches a manifest, update `LatencyCache.server_ips` in SharedState. This is the signal for the pinger to start.

**Step 5: Run tests**

Run: `cargo test --lib`

**Step 6: Commit**

```
feat: background pinger task in helper daemon (3-min cycle, EWMA)
```

---

## Task 7: Connect Path Uses Cached Data

**Files:**
- Modify: `src/connect.rs:605-674` (use cached latency instead of measure_all)
- Modify: `src/helper.rs` (pass latency cache to connect thread)

**Step 1: Change fetch_initial_data to use cache**

Instead of calling `pinger::measure_all()`, read from the shared `LatencyCache`. If cache is empty (first ever run, no background data yet), fall back to one-shot `measure_all()` and seed the cache.

**Step 2: Remove ping hole open/close from connect path**

The background pinger now manages ping holes. Remove lines 631-660 from `fetch_initial_data()`.

**Step 3: Test**

Build and test connecting. Verify no blocking ping delay.

**Step 4: Commit**

```
feat: connect uses cached latency data from background pinger
```

---

## Task 8: /servers Endpoint Uses Cached Data

**Files:**
- Modify: `src/helper.rs:1096-1158` (dispatch_list_servers reads cache)

**Step 1: Change dispatch_list_servers**

Instead of calling `pinger::measure_all()`, read from `LatencyCache` in SharedState. The `skip_ping` parameter becomes irrelevant (always use cache). If cache is empty, return servers with `ping_ms: None`.

**Step 2: Test**

`curl --unix-socket /run/airvpn-rs/helper.sock http://localhost/servers?sort=score` should return instantly with cached ping data.

**Step 3: Commit**

```
feat: /servers endpoint uses cached latency (instant response)
```

---

## Task 9: Connected Server Ping Through Tunnel

**Files:**
- Modify: `src/pinger.rs` (ping_cycle handles connected server specially)

**Step 1: Add tunnel ping for connected server**

In `ping_cycle()`, if there's a connected server, ping its entry IP normally (no host route needed — it goes through the tunnel, which is the accurate path):

```rust
if let Some(connected_name) = connected_server {
    if let Some(ip) = ips.get(connected_name) {
        let rounds: Vec<Option<u64>> = (0..PING_ROUNDS).map(|_| ping_ip(ip)).collect();
        match median_ping(&rounds) {
            Some(ms) => cache.update(connected_name, ms as f64),
            None => cache.update_failed(connected_name),
        }
    }
}
```

**Step 2: Test**

Verify while connected that the connected server has ping data in the cache.

**Step 3: Commit**

```
feat: ping connected server through tunnel (accurate path latency)
```

---

## Task 10: Integration Testing & Docs

**Files:**
- Modify: `docs/known_divergences.md` (document Eddie differences)
- Modify: `CLAUDE.md` (update learnings)
- Modify: `tests/integration.rs` (if applicable)

**Step 1: Document divergences from Eddie**

- Eddie stops pinging while connected; we continue (connected server through tunnel, others outside)
- Eddie uses `(old + new) / 2` smoothing; we use EWMA α=0.3
- Eddie pings one server at a time; we ping all in parallel
- Eddie doesn't persist ping data to disk; we do
- We allowlist all server IPs upfront (Eddie does too, but for different reasons)

**Step 2: Manual integration test**

1. Start helper, verify pinger starts after first manifest fetch
2. Connect, verify pinger continues (connected server through tunnel)
3. Disconnect, verify pinger continues with persistent lock holes
4. Reconnect, verify cached latency is used (fast connect)
5. Check `/servers` returns instant results with ping data

**Step 3: Commit**

```
docs: background pinger divergences and integration notes
```

---

## Dependency Order

```
Task 1 (LatencyCache)
  └→ Task 2 (Persistence)
  └→ Task 6 (Background task) — depends on 1, 2
       └→ Task 7 (Connect uses cache) — depends on 6
       └→ Task 8 (/servers uses cache) — depends on 6
       └→ Task 9 (Connected server ping) — depends on 6
Task 3 (All-server allowlist) — independent
Task 4 (Host routes) — independent
Task 5 (Persistent lock allowlist) — independent
Task 10 (Docs) — depends on all
```

Tasks 1-2, 3, 4, 5 can be done in parallel. Task 6 integrates them. Tasks 7-9 build on 6.
