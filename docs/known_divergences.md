# Known Divergences from Eddie

> **This document may be stale.** It is maintained on a best-effort basis and
> is not guaranteed to be complete or current. When in doubt, check the source
> code comments (search for "Eddie" or "diverge") and compare against
> [Eddie's source](https://github.com/AirVPN/Eddie).
>
> Last reviewed: 2026-03-04

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
were skipped (score_with_penalty doesn't modify sentinels >= 99995), and
`min_by` tiebreaks by iterator order — which is manifest order — which is
alphabetical. This caused the client to always select Achernar (alphabetically
first) regardless of penalties or server quality.

Eddie masks this by waiting for all pings to complete before the first
connection (`PingerInvalid() == 0` loop in Session.cs). It also persists ping
values across reconnections, so the sentinel is rarely hit in practice. Our
`--skip-ping` flag has no equivalent in Eddie and exposed the latent bug.

**Files:** `src/server.rs` — `score_with_ping()`

**Eddie ref:** `ConnectionInfo.cs` `Score()` lines 219-246

---

## 2. Dedicated nftables table instead of flush ruleset

**Eddie:** Uses `flush ruleset` to clear all firewall rules before applying
its own. This is a cross-compatibility approach that works across iptables and
nftables.

**airvpn-rs:** Uses a dedicated `table inet airvpn_lock` at priority `-300`.
Our chains run before everything else and default to `drop`. The rule contents
and ordering are 1:1 with Eddie's `NetworkLockNftables.cs`.

**Why:** `flush ruleset` is destructive — it wipes all existing firewall
rules (Docker, fail2ban, custom rules, etc.). A dedicated table at high
priority is equally secure (nftables `drop` is terminal across all tables —
a packet must be `accept`ed by ALL chains at the same hook to proceed) but
doesn't destroy the user's existing firewall configuration.

**Files:** `src/netlock.rs` — `TABLE_NAME`, `PRIORITY`

**Eddie ref:** `src/Lib.Platform.Linux/NetworkLockNftables.cs`

---

## 3. Nftables kill switch monitoring

**Eddie:** Does not actively monitor whether its firewall rules are still in
place during an active connection. If an external process deletes Eddie's
rules, traffic leaks silently.

**airvpn-rs:** The monitor loop (runs every 1s) checks
`netlock::is_active()` — which runs `nft list table inet airvpn_lock` — to
verify the kill switch table still exists. If deleted externally, triggers
`ResetLevel::Error` and reconnects to restore it.

**Why:** External tools (firewall managers, system updates, manual `nft`
commands) can delete the lock table. Without monitoring, the kill switch fails
silently and traffic leaks outside the tunnel. This is especially important
because we use a dedicated table (divergence #2) which is easier for external
tools to accidentally remove than a flushed-and-replaced ruleset.

**Files:** `src/netlock.rs` — `is_active()`, `src/main.rs` — monitor loop

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

**Files:** `src/connect.rs` — lock_last resolution, `src/config.rs` — profile options

**Eddie ref:** `ProfileOptions.cs` lines 435-436

---

## 5. Direct ip/wg commands instead of wg-quick

**Eddie:** Uses OpenVPN with its own tun device management.

**airvpn-rs:** Uses WireGuard via direct `ip link add` / `wg setconf` / `ip address add`
commands. No dependency on `wg-quick`.

**Why:** wg-quick is a convenience wrapper that adds routing, DNS, and firewall rules
we don't need (we manage those ourselves via `netlock.rs`, `dns.rs`, and
`setup_routing()`). Removing wg-quick also enables matching Eddie's IPv6
blocking behavior: `block_all()` sets `net.ipv6.conf.default.disable_ipv6=1`
before the WireGuard interface is created, so it inherits disabled IPv6
with no race condition. With wg-quick, this was impossible because wg-quick's
`ip -6 address add` would fail on an interface with IPv6 disabled.

**Files:** `src/wireguard.rs` — `connect()`, `disconnect()`

**Eddie ref:** `src/Lib.Platform.Linux/Platform.cs`, `src/App.CLI.Linux.Elevated/src/impl.cpp`

---

## 6. Persistent network lock (kill switch)

**Eddie:** Network lock activates at session start and deactivates at session end.
Between sessions, traffic is unrestricted. Eddie uses a single nftables table and
resolves hostnames before activating the lock (NetworkLockManager.cs:127), creating
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

**Eddie:** CLI connects directly (elevated via pkexec). GUI launches a separate
elevated C++ binary via pkexec, communicates over TCP localhost with session-key
auth. CLI and GUI are independent VPN managers.

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

**Why:** Eddie's dual-manager model requires conflict guards
(`refuse_if_helper_running`, recovery state PID checks) to prevent CLI and GUI
from stepping on each other. A single control plane eliminates this complexity.
systemd socket activation eliminates Eddie's pkexec race condition (socket appears
before `chown()` completes) by creating the socket atomically with correct
permissions before the process starts.

Socket permissions are `0660` with group `wheel`. Any wheel user can connect
without sudo. `SO_PEERCRED` captures the connecting UID on every accept (used for
Eddie profile discovery and audit logging).

**Files:** `src/helper.rs`, `src/cli_client.rs`, `resources/airvpn-helper.socket`,
`resources/airvpn-helper.service`

**Eddie ref:** `src/Lib.Core/Elevated/IElevated.cs`, `src/Lib.Core/Elevated/ISocket.cs`

---

## 9. Persistent lock: per-server allowlist for background pinger

**Eddie:** Session lock allows ICMP when `netlock.allow_ping = true` (default).
Input: echo-request accept. Output: echo-reply accept. No outgoing echo-request.
Eddie's pinger runs before the session lock activates, so it never needs outbound
ICMP during the lock. Eddie does not have a persistent lock.

**airvpn-rs:** Persistent lock uses Eddie's ICMP model by default (inbound
echo-request, outbound echo-reply — be pingable, but don't initiate pings).
The `ping_allow` subchain is permanently populated with ICMP-only rules
(`ip daddr <server-ip> icmp type echo-request accept`) via `populate_ping_allow()`.
Rules are set at helper startup (from cached IPs), on manifest fetch, and after
lock enable/install (which recreates the table with an empty chain).

**Why:** The persistent lock is always active, unlike Eddie's session lock.
The background pinger needs outbound ICMP to server IPs outside the tunnel.
ICMP-only rules (not all-protocol) minimize the attack surface while allowing
latency measurement. Permanent rules avoid per-cycle nft churn.

**Files:** `src/netlock.rs` (`populate_ping_allow()`), `src/helper.rs`
(`SharedState::new`, `on_server_ips` callback, `repopulate_ping_allow()`)

---

## 10. Background pinger with EWMA smoothing

**Eddie:** Background `Jobs/Latency.cs` pings one server at a time, every 180s
(success) or 5s (retry). Uses running average `(old + new) / 2` (α=0.5). Stops pinging
while connected. Ping results are in-memory only (lost on restart). Allowlists
ALL server IPs in the session lock outgoing allowlist (for reconnection
readiness, not pinging).

**airvpn-rs:** Background pinger in the helper daemon pings ALL servers in
parallel every 3 minutes, one ping per server per cycle. Uses EWMA (α=0.3)
instead of simple running average — EWMA smoothing across cycles makes
multi-round median unnecessary. **Continues pinging while connected** —
all servers (including the connected one) are pinged via host routes through
the physical NIC for consistent raw network latency. No tunnel special-casing.
Results are persisted to `/var/lib/airvpn-rs/latency.json` (survive restarts).

Matches Eddie's all-server allowlist: session lock allowlists all server entry
IPs (not just the selected server), activated once before the reconnection loop
instead of per-iteration. Persistent lock's `ping_allow` subchain provides
ICMP-only access. Host routes (`/32` via physical gateway, added with
`ip -force -batch`) bypass tunnel routing for direct pings.

**Why:**
- EWMA α=0.3 gives more control over smoothing than `(old + new) / 2` (which
  is equivalent to α=0.5). A spike takes ~3 cycles (~9min) to decay.
- Pinging while connected keeps data fresh for server re-selection on reconnect.
- Parallel pinging is faster (~30s for all servers vs Eddie's sequential approach).
- Persistence means data is available immediately after restart.

**Files:** `src/pinger.rs` (`LatencyCache`, `measure_all_from_ips`),
`src/helper.rs` (`background_pinger_loop`), `src/wireguard.rs`
(`add_server_host_routes` with `-force`), `src/netlock.rs` (`populate_ping_allow`),
`src/connect.rs` (cached latency, all-server allowlist)

**Eddie ref:** `src/Lib.Core/Jobs/Latency.cs`, `src/Lib.Core/NetworkLockPlugin.cs`
(`GetIpsAllowlistOutgoing`)
