# Known Divergences from Eddie

> **This document may be stale.** It is maintained on a best-effort basis and
> is not guaranteed to be complete or current. When in doubt, check the source
> code comments (search for "Eddie" or "diverge") and compare against
> [Eddie's source](https://github.com/AirVPN/Eddie).
>
> Last reviewed: 2026-03-07

This codebase is a faithful Rust reimplementation of Eddie (AirVPN's official
C# client). The vast majority of behavior — scoring formulas, penalty system,
API envelope protocol, verification, reconnection loop — matches Eddie 1:1
with source file citations in comments throughout the code.

This file documents the **intentional** divergences where we deliberately
chose a different approach. These are improvements, not bugs.

---

## 1. Server scoring with unmeasured ping

**Eddie:** `Ping == -1` returns sentinel `99995`, short-circuiting all other
scoring (penalties, load, users, scorebase are ignored). All unmeasured servers
score identically.

**airvpn-rs:** `Ping == -1` contributes `0` to the score. The remaining
factors (load, users, scorebase) still differentiate servers, and penalties
still apply.

**Why:** Eddie's sentinel makes the penalty system completely inert when pings
are unavailable. With `--skip-ping`, all 266 servers scored 99995, penalties
were skipped (sentinels >= 99995 are not modified by penalty scoring — Eddie's
`Score()` short-circuits before reaching the penalty term, and our
`score_with_penalty` explicitly preserves them), and `min_by` tiebreaks by
iterator order — which is manifest order — which is alphabetical. This caused
the client to always select Achernar (alphabetically first) regardless of
penalties or server quality.

Eddie masks this by waiting for all pings to complete before the first
connection (`PingerInvalid() == 0` loop in Session.cs). It also persists ping
values across reconnections, so the sentinel is rarely hit in practice. Our
`--skip-ping` flag has no equivalent in Eddie and exposed the latent bug.

**Files:** `src/server.rs` — `score_with_ping()`

**Eddie ref:** `ConnectionInfo.cs` `Score()` lines 219-246

---

## 2. Dedicated nftables table instead of flush ruleset

**Eddie:** Uses `flush ruleset` to clear all nftables state before applying
its own rules. Eddie has separate lock implementations for iptables
(`NetworkLockIptables.cs`) and nftables (`NetworkLockNftables.cs`); the
`flush ruleset` is nftables-specific, not a cross-compatibility mechanism.
Eddie backs up the existing ruleset before flushing and restores it on
deactivation — so rules are recoverable unless Eddie crashes mid-session.

**airvpn-rs:** Uses a dedicated `table inet airvpn_lock` at priority `-300`.
Our chains run before everything else and default to `drop`. The filter chain
rules match Eddie's `NetworkLockNftables.cs`; we use a single `inet` table
instead of Eddie's separate IPv4/IPv6 tables for filter, nat, and mangle.

**Why:** `flush ruleset` is destructive during the session — it wipes all
existing firewall rules (Docker, fail2ban, custom rules, etc.). A dedicated
table at high priority is equally secure (nftables `drop` is terminal across
all tables — a packet must be `accept`ed by ALL chains at the same hook to
proceed) but doesn't destroy the user's existing firewall configuration.

**Files:** `src/netlock.rs` — `TABLE_NAME`, `PRIORITY`

**Eddie ref:** `src/Lib.Platform.Linux/NetworkLockNftables.cs`

---

## 3. Nftables kill switch monitoring

**Eddie:** Does not actively monitor whether its firewall rules are still in
place during an active connection. If an external process deletes Eddie's
rules, traffic leaks silently.

**airvpn-rs:** The monitor loop checks `netlock::is_active()` — which runs
`nft list table inet airvpn_lock` — to verify the kill switch table still
exists. If deleted externally, triggers `ResetLevel::Error` and reconnects
to restore it.

**Why:** External tools (firewall managers, system updates, manual `nft`
commands) can delete the lock table. Without monitoring, the kill switch fails
silently and traffic leaks outside the tunnel. This is especially important
because we use a dedicated table (divergence #2) which is easier for external
tools to accidentally remove than a flushed-and-replaced ruleset.

**Files:** `src/netlock.rs` — `is_active()`, `src/connect.rs` —
`run_monitor_loop()`

**Eddie ref:** No equivalent in Eddie

---

## 4. servers.startlast defaults to true

**Eddie:** Both `servers.locklast` and `servers.startlast` default to `false`
(ProfileOptions.cs lines 435-436). Users must explicitly enable them in the
GUI.

**airvpn-rs:** `servers.locklast` now defaults to `false` (matching Eddie).
`servers.startlast` still defaults to `true` — a laptop-first preference for
resuming the last-used server on startup.

Network-down detection (`has_default_gateway()`) handles the WiFi-drop case
that originally motivated the `locklast=true` default: when there's no gateway,
the server is not penalized and is retried. When the gateway exists, the server
is penalized and rotation occurs.

**Files:** `src/connect.rs` — lock_last/start_last resolution

**Eddie ref:** `ProfileOptions.cs` lines 435-436

---

## 5. WireGuard-only, via `wg` CLI instead of `libwg` kernel API

**Eddie:** Supports both OpenVPN and WireGuard. Eddie's WireGuard
implementation on Linux uses the `libwg` C kernel API (`wg_add_device`,
`wg_set_device`, `wg_del_device`) plus `ip` commands for addresses, MTU,
and link management. Eddie does not use wg-quick.

**airvpn-rs:** WireGuard-only. Uses `ip link add` / `wg setconf` /
`ip address add` commands. No dependency on `wg-quick` or `libwg`.

**Why:** wg-quick is a convenience wrapper that adds routing, DNS, and
firewall rules we don't need (we manage those ourselves via `netlock.rs`,
`dns.rs`, and `setup_routing()`). Using `wg setconf` (CLI) instead of `libwg`
(C library) avoids a native dependency while achieving the same result. Direct
commands also enable matching Eddie's IPv6 blocking behavior: `block_all()`
sets `net.ipv6.conf.default.disable_ipv6=1` before the WireGuard interface is
created, so it inherits disabled IPv6 with no race condition.

**Files:** `src/wireguard.rs` — `connect()`, `disconnect()`

**Eddie ref:** `src/Lib.Core/ConnectionTypes/WireGuard.cs`,
`src/App.CLI.Linux.Elevated/src/impl.cpp` (WireGuard setup via libwg)

---

## 6. Persistent network lock (kill switch)

**Eddie:** Network lock activates at session start and deactivates at session end.
Between sessions, traffic is unrestricted. Eddie uses a single nftables table and
resolves hostnames before activating the lock (NetworkLockManager.cs:133), creating
a leak window during DNS resolution.

**airvpn-rs:** Uses two fully independent nftables tables:
- `airvpn_persist` (priority -400): persistent always-on lock, loaded at boot by a
  systemd service (`Before=network-pre.target`). Allows LAN, DHCP, ICMP, bootstrap
  IPs, and VPN tunnel traffic (`oifname "avpn0"` for inner packets, `meta mark 51820`
  for WireGuard outer packets). Uses `flags owner, persist` (kernel 5.12+/6.9+).
  Blocks DNS (port 53/853) to RFC1918 destinations on non-tunnel interfaces to
  prevent plaintext DNS leaks through the LAN rules during reconnection.
- `airvpn_lock` (priority -300): session lock, identical to Eddie's. Created at
  connect, deleted at disconnect. Completely unaware of the persistent table.

Both have `policy drop` — a packet must pass both to get through. When VPN is
connected, both allow VPN traffic. When VPN disconnects, `airvpn_lock` is deleted
and `airvpn_persist` blocks everything. The two tables don't interact: `lock
disable/uninstall` can run while VPN is connected without conflict.

Users who don't install the persistent lock get the same transient session lock
behavior as Eddie.

**Why:** Eliminates the startup leak window entirely — the persistent lock loads
before networking, so traffic is never unprotected. The two-table design avoids
operational conflicts (disabling the persistent lock while VPN runs, uninstalling
while connected). Similar to Android's always-on VPN, which uses routing-layer
enforcement independently of the VPN tunnel itself. Android uses `ip rule` with
UID ranges + fwmark; we use nftables with interface wildcard + fwmark (desktop Linux
doesn't have per-app UIDs, so the nftables approach is more appropriate).

**Files:** `src/netlock.rs` (persistent + session ruleset generation), `src/main.rs`
(Lock subcommand)

**Eddie ref:** `src/Lib.Core/NetworkLockManager.cs`, `src/Lib.Platform.Linux/NetworkLockNftables.cs`

---

## 8. Single control plane with systemd socket activation

**Eddie:** CLI connects directly (elevated via pkexec, sudo, or suid root,
depending on what's available). GUI launches a separate elevated C++ binary,
communicates over TCP localhost with session-key auth. CLI and GUI share the
same Engine/Session class but run as independent processes.

**airvpn-rs:** Single daemon (helper) started by systemd socket activation. Both
CLI and GUI are thin clients that send JSON-lines commands over a Unix socket at
`/run/airvpn-rs/helper.sock`. The helper is the sole VPN control plane — it runs
`connect::run()`, manages recovery state, and handles all privileged operations.
All commands (connect, disconnect, status, servers, lock, recover) go through the
socket. The CLI has no direct operations.

The helper resolves credentials from its root-owned profile (`/etc/airvpn-rs/`,
0600). For Eddie profile import, the helper reads the user's file using the peer
UID from `SO_PEERCRED` and asks the client to confirm (only "yes/no" transits the
socket — no credentials). First-time setup without an Eddie profile requires
`sudo airvpn connect` so interactive password entry stays in root process memory.

**Why:** Eddie's dual-process model requires conflict guards to prevent CLI and
GUI from stepping on each other. A single control plane eliminates this
complexity. systemd socket activation creates the socket atomically with correct
permissions before the process starts.

Socket permissions are `0660` with group `wheel`. Any wheel user can connect
without sudo. `SO_PEERCRED` captures the connecting UID on every accept (used for
Eddie profile discovery and audit logging).

**Files:** `src/helper.rs`, `src/cli_client.rs`, `resources/airvpn-helper.socket`,
`resources/airvpn-helper.service`

**Eddie ref:** `src/Lib.Core/Elevated/IElevated.cs`, `src/Lib.Core/Elevated/ISocket.cs`

---

## 9. Persistent lock: ICMP allowlist for background pinger

**Eddie:** Session lock allows ICMP when `netlock.allow_ping = true` (default).
Input: echo-request accept. Output: echo-reply accept (IPv4) or all ICMPv6
(IPv6). Eddie's pinger runs before the session lock activates, so it never
needs outbound ICMP during the lock. Eddie does not have a persistent lock.

**airvpn-rs:** Persistent lock uses Eddie's ICMP model by default (inbound
echo-request, outbound echo-reply — be pingable, but don't initiate pings).
The background pinger needs outbound ICMP to reach server IPs, so
`populate_ping_allow()` adds per-server-IP ICMP echo-request rules to the
`ping_allow` subchain. Rules are permanent — populated on startup, manifest
refresh, and after `lock install`, rather than opened/closed per ping cycle.
No-op if the persistent table is not active.

**Why:** The persistent lock is always active, unlike Eddie's session lock.
The background pinger needs to reach server IPs outside the tunnel for latency
measurement. ICMP-only rules (not all-protocol) are sufficient since the pinger
only needs echo-request/reply.

**Files:** `src/netlock.rs` (`populate_ping_allow()`, `build_ping_hole_rules()`),
`src/helper.rs` (background pinger loop)

**Eddie ref:** `src/Lib.Core/NetworkLockPlugin.cs` (`GetIpsAllowlistOutgoing`)

---

## 10. Background pinger with EWMA smoothing

**Eddie:** Background `Jobs/Latency.cs` pings servers sequentially, every 180s
(success) or 5s (retry). Uses running average `(old + new) / 2` (α=0.5). Stops
pinging while connected. Ping results are in-memory only (lost on restart).
Allowlists ALL server IPs in the session lock outgoing allowlist (for
reconnection readiness, not pinging).

**airvpn-rs:** Background pinger in the helper daemon pings ALL servers in
parallel every 3 minutes, one ping per server per cycle. Uses EWMA (α=0.3)
instead of simple running average — EWMA smoothing across cycles makes
multi-round median unnecessary. **Continues pinging while connected** — all
servers are pinged equally via host routes (`/32` via physical gateway) through
the physical NIC for consistent raw network latency. No special-casing for the
connected server. Results are persisted to `/var/lib/airvpn-rs/latency.json`
(survive restarts).

Matches Eddie's all-server allowlist: session lock allowlists all server entry
IPs (not just the selected server), activated once before the reconnection loop
instead of per-iteration. Persistent lock uses `populate_ping_allow()` for the
background pinger's ICMP access.

**Why:**
- EWMA α=0.3 gives more control over smoothing than `(old + new) / 2` (which
  is equivalent to α=0.5). A spike takes ~3 cycles (~9min) to decay.
- Pinging while connected keeps data fresh for server re-selection on reconnect.
- Parallel pinging is faster (~30s for all servers vs Eddie's sequential approach).
- Persistence means data is available immediately after restart.

**Files:** `src/pinger.rs` (`LatencyCache`, `measure_all_from_ips`),
`src/helper.rs` (`background_pinger_loop`), `src/wireguard.rs`
(`add_server_host_routes`), `src/netlock.rs` (`populate_ping_allow`),
`src/connect.rs` (cached latency, all-server allowlist)

**Eddie ref:** `src/Lib.Core/Jobs/Latency.cs`, `src/Lib.Core/NetworkLockPlugin.cs`
(`GetIpsAllowlistOutgoing`)

---

## 11. Exponential backoff on reconnection

**Eddie:** Uses fixed delays between reconnection attempts: 3 seconds for
connection errors (Session.cs line 484-485), 5 seconds for server-initiated
rotation, 10 seconds for generic retry.

**airvpn-rs:** Uses exponential backoff: `3 × 2^(n-1)` capped at 192 seconds
(exponent capped at 6). Sequence: 3s, 6s, 12s, 24s, 48s, 96s, 192s.

**Why:** Fixed 3-second retry hammers the server during extended outages.
Exponential backoff reduces load on both the client and server while still
reconnecting quickly after transient failures.

**Files:** `src/common.rs` — `backoff_secs()`

**Eddie ref:** `Session.cs` lines 477-485

---

## 12. V2N-only credential storage

**Eddie:** Supports V2N (hardcoded key, no real encryption), V2S (Linux
secret-tool / keyring), and V2P (password-protected) profile formats. Profile
lives in user's `~/.config/eddie/default.profile`.

**airvpn-rs:** Always saves credentials in V2N format at
`/etc/airvpn-rs/default.profile` (root:root 0600). Can read all Eddie formats
(V2N/V2S/V2P) for one-time import.

**Why:** The profile is root-owned with mode 0600 — file permissions are the
security, not encryption. The user's keyring (V2S) is not accessible when
running as root, and password prompts (V2P) don't work for a background daemon.
V2N with filesystem permissions provides equivalent security to V2S for a
root-owned file.

**Files:** `src/config.rs` — `save_options()`

**Eddie ref:** `Storage.cs` (Save/Load), `ProfileOptions.cs`

---

## 13. Penalty cap at 120

**Eddie:** Penalties accumulate without an upper bound. `ConnectionInfo.Penality`
is incremented by `advanced.penality_on_error` (default 30) on each failure,
with linear decay of 1/minute (`Jobs/Penalities.cs`). A server that fails 10
times accumulates penalty 300 — 5 hours of decay.

**airvpn-rs:** Penalties are capped at `MAX_PENALTY = 120` (~2 hours of decay
at 1/minute). Prevents unbounded accumulation from repeated failures.

**Why:** Eddie's uncapped penalties can effectively blacklist a server for hours
or days after a transient outage (e.g., server restart during maintenance). The
cap ensures servers return to the selection pool within a reasonable time.

**Files:** `src/server.rs` — `ServerPenalties::MAX_PENALTY`

**Eddie ref:** `ConnectionInfo.cs` (`Penality` field), `Jobs/Penalities.cs`

---

## 14. No pre-connection ping gate

**Eddie:** Blocks the connection loop until ALL server pings complete
(`PingerInvalid() == 0` loop in Session.cs lines 121-142). This ensures the
scoring formula has latency data for every server before selection.

**airvpn-rs:** Uses whatever cached latency data is available from the
background pinger. On first run with no cache, does a best-effort one-shot
parallel ping but does not block on completion — servers that fail to respond
get `-1` (unmeasured, contributes 0 to score per divergence #1).

**Why:** The blocking ping gate can delay connection by 30-60 seconds while
waiting for all ~266 servers to respond. Using cached data from the persistent
background pinger provides near-instant startup on subsequent runs, and the
EWMA smoothing (divergence #10) ensures data stays fresh across cycles.

**Files:** `src/connect.rs` — server selection, `src/pinger.rs` —
`LatencyCache::load()`

**Eddie ref:** `Session.cs` lines 121-142 (`PingerInvalid` loop)
