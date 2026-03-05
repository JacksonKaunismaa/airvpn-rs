# HTTP IPC Design: Multi-Client Helper

**Date:** 2026-03-05
**Status:** Approved
**Problem:** Helper daemon is single-client. When GUI is connected, CLI commands (status, servers, etc.) can't connect to the socket.
**Solution:** Replace JSON-lines protocol with HTTP/1.1 over Unix socket. Thread-per-connection gives multi-client for free.

## Prior Art

Researched Tailscale and Mullvad daemon architectures:

- **Tailscale:** HTTP/1.1 over Unix socket. Go's `http.Server` spawns goroutine per connection. Streaming via chunked `GET /watch-ipn-bus`. State behind `sync.Mutex`.
- **Mullvad:** gRPC (tonic) over Unix socket. Fan-out via `Arc<Mutex<Vec<UnboundedSender>>>`. Unary RPCs for queries, server-streaming for events.

Both are fully multi-client. Short-lived CLI queries are completely independent of long-lived GUI event streams.

## HTTP Server

`tiny_http` crate -- synchronous, thread-per-connection, supports chunked transfer encoding. No async runtime needed.

Listens on the existing systemd-activated Unix socket fd (same `SO_PEERCRED`, same permissions).

## Routes

| Route | Method | Body | Response |
|---|---|---|---|
| `/connect` | POST | `ConnectRequest` JSON | 200 chunked stream of `HelperEvent` lines, or 409 `{eddie_profile: path}` |
| `/disconnect` | POST | (empty) | 200 `StateChanged{Disconnected}` |
| `/status` | GET | - | 200 `{state: ConnectionState, lock: LockStatus}` |
| `/lock/enable` | POST | (empty) | 200 `LockStatus` |
| `/lock/disable` | POST | (empty) | 200 `LockStatus` |
| `/lock/install` | POST | (empty) | 200 `LockStatus` (+ log message) |
| `/lock/uninstall` | POST | (empty) | 200 `LockStatus` (+ log message) |
| `/lock/status` | GET | - | 200 `LockStatus` |
| `/servers` | GET | query: `?skip_ping=true&sort=name` | 200 `ServerList` |
| `/profile` | GET | - | 200 `Profile` (credentials stripped) |
| `/profile` | POST | `{options: HashMap}` | 200 `ProfileSaved` |
| `/import-eddie` | POST | `{accept: bool}` | 200 `{imported: bool}` |
| `/recover` | POST | (empty) | 200 log message |
| `/shutdown` | POST | (empty) | 200 `Shutdown` |
| `/events` | GET | - | Chunked stream of `HelperEvent` JSON lines (never closes) |

## Connect Flow (Two-Phase)

```
CLI/GUI                           Helper
  |                                 |
  |-- POST /connect --------------->|
  |                                 | (checks profile for credentials)
  |<-- 409 {eddie_profile: path} ---|  (no creds, Eddie profile found)
  |                                 |
  |-- POST /import-eddie ---------->|  {accept: true}
  |<-- 200 {imported: true} --------|  (helper imports & saves creds)
  |                                 |
  |-- POST /connect --------------->|  (now has creds)
  |<-- 200 (chunked) ---------------|
  |<-- {"event":"StateChanged",...}  |
  |<-- {"event":"Log",...}           |
  |<-- {"event":"StateChanged","state":{"Connected":...}}
  |<-- ... (keeps streaming until disconnect)
```

If credentials are already configured, POST /connect returns 200 immediately and starts streaming.

## Event Streaming (`GET /events`)

Fan-out pattern (from Mullvad):

```rust
struct SharedState {
    conn_state: ConnState,
    subscribers: Vec<mpsc::Sender<HelperEvent>>,
}

type State = Arc<Mutex<SharedState>>;
```

- GUI opens `GET /events`, gets a chunked response
- Helper creates an mpsc channel, adds sender to `subscribers`
- State changes broadcast to all subscribers; dead senders removed on send failure
- Stats polled every 2s, broadcast to all subscribers
- When GUI disconnects, its sender drops, cleanup happens on next broadcast

CLI clients (e.g. `airvpn status`) do NOT open `/events` -- they use `GET /status` (request/response).

## Security Model (Unchanged)

- Helper runs as root via systemd socket activation
- Socket permissions: 0660 root:wheel (unchanged)
- `SO_PEERCRED` for peer identity (unchanged)
- Credentials read from root-owned profile in root process only
- `GET /profile` strips credentials before responding
- `POST /connect` body contains no credentials
- `GET /events` stream contains no credentials
- HTTP is just framing -- doesn't change what data flows where

## Shared State

```rust
struct ConnState {
    connect_handle: Option<JoinHandle<()>>,
    stats_handle: Option<JoinHandle<()>>,
    stats_stop: Arc<AtomicBool>,
    server_info: Arc<Mutex<(String, String, String)>>,
}

struct SharedState {
    conn: ConnState,
    subscribers: Vec<mpsc::Sender<HelperEvent>>,
    shutdown: Arc<AtomicBool>,
}
```

All handlers receive `Arc<Mutex<SharedState>>`. Lock briefly, read/mutate, release.

Long-running operations (Connect, ListServers) hold the lock only to check/set state, not during the actual work.

## Helper Lifecycle

- Systemd socket activation starts helper on first connection
- No auto-shutdown on client disconnect (let systemd `IdleTimeout` handle it, or explicit `POST /shutdown`)
- `POST /shutdown` triggers graceful VPN disconnect + helper exit

## Files Changed

| File | Change |
|---|---|
| `Cargo.toml` | Add `tiny_http` dependency |
| `src/helper.rs` | Replace accept loop with `tiny_http` server; split `handle_client` match into route handler functions; add event fan-out |
| `src/cli_client.rs` | HTTP requests instead of socket read/write |
| `src/gui/ipc.rs` | `HelperClient` becomes HTTP client + event stream reader |
| `src/ipc.rs` | Minor: add `ConnectRequest`, `StatusResponse` wrapper types |

## What Stays The Same

- All command logic (connect engine, netlock, recovery, config, pinger)
- `ipc.rs` core types (`HelperEvent`, `HelperCommand`, `ConnectionState`)
- Systemd socket/service unit files
- Socket path (`/run/airvpn-rs/helper.sock`)
- Profile security model
