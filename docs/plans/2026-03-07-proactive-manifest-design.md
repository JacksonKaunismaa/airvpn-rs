# Proactive Manifest Fetch + Pinger Warmup

## Problem

The helper only fetches the server manifest during connect or `/servers` requests.
This means:
- On first-ever connect, the pinger has no IPs and latency scores are all 0
- The client sees a stale "Skipping ping" message from a now-dead code path
- Connect has to do its own manifest fetch, adding latency to every connection

Eddie caches the manifest in Storage.xml and refreshes it every 30 min
(server-recommended `next_update=30` × 60s). Its pinger has server IPs from
startup via the cached manifest.

## Design

### Approach: Two independent background loops (matches Eddie)

1. **Background manifest loop** — fetches manifest, caches it in SharedState
2. **Background pinger loop** (already exists) — pings all servers, updates EWMA cache

Decoupled so a slow/failed manifest fetch doesn't block pinging, and vice versa.

### SharedState changes

```rust
struct SharedState {
    conn: ConnState,
    subscribers: Vec<mpsc::Sender<ipc::HelperEvent>>,
    latency: pinger::LatencyCache,
    manifest: Option<manifest::Manifest>,  // NEW
    ready: bool,                           // NEW — true after first ping cycle
}
```

### Condvar chain (cold start coordination)

Three condvars on SharedState's mutex eliminate polling:

```
creds saved ──notify──> manifest_cv
manifest loop wakes ──fetch──> populate IPs ──notify──> pinger_cv
pinger wakes ──ping cycle──> set ready=true ──notify──> ready_cv
connect arrives ──if !ready──> wait on ready_cv (60s timeout)
```

- `manifest_cv`: signaled when creds become available (eddie import, profile save)
- `pinger_cv`: signaled when manifest loop populates server_ips
- `ready_cv`: signaled when pinger completes first cycle

After first cycle, everything is warm — subsequent connects never wait.

### Background manifest loop

```
loop:
  1. Load profile creds
  2. If no creds → wait on manifest_cv
  3. Fetch manifest via encrypted API (fetch_manifest)
  4. Store in state.manifest
  5. Extract (name, ip) pairs → state.latency.set_server_ips()
  6. Populate ping_allow in nftables
  7. Signal pinger_cv
  8. Sleep 30 min
```

### Background pinger loop (modified)

```
loop:
  1. Check for server IPs → if none, wait on pinger_cv
  2. Copy IPs out (quick lock), ping all servers, merge results back (quick lock)
  3. If first cycle: set state.ready = true, signal ready_cv
  4. Sleep 3 min
```

### Connect flow (modified)

1. If `!state.ready` → wait on `ready_cv` with 60s timeout → 503 on timeout
2. Read `state.manifest` directly (no manifest API call)
3. Fetch UserInfo via API (WG keys — needed fresh per-connect, not cached)
4. Read `state.latency` for scoring
5. Score servers, select, connect as before

### `/servers` endpoint (modified)

Reads `state.manifest` instead of fetching its own. Returns 503 if manifest
not yet available.

### Cred-arrival paths that signal `manifest_cv`

- `POST /import-eddie` handler
- `POST /connect` stdin cred flow (profile written for first time)
- Any future cred-save path

### What got removed

- `skip_ping` flag (CLI, IPC, GUI, ConnectConfig) — dead with background pinger
- `measure_all_inline` — no more synchronous ping sweep during connect
- Client-facing "Skipping ping" messages — pinging is fully transparent now
- `cached_latency` as `Option` on ConnectConfig — always provided, non-optional

### Eddie parity

| Behavior | Eddie | Us (after) |
|----------|-------|------------|
| Manifest cached from last run | Storage.xml | latency.json (IPs), state.manifest (runtime) |
| Manifest refresh interval | 30 min (server next_update) | 30 min |
| Pinger has IPs from startup | Yes (cached manifest) | Yes (latency.json server_ips) |
| Pinger cycle | While disconnected only | Always (background, via host routes) |
| First-ever connect | Pinger idles until manifest | Pinger idles until manifest, connect waits for first cycle |
