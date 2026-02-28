# Known Divergences from Eddie

> **This document may be stale.** It is maintained on a best-effort basis and
> is not guaranteed to be complete or current. When in doubt, check the source
> code comments (search for "Eddie" or "diverge") and compare against
> [Eddie's source](https://github.com/AirVPN/Eddie).
>
> Last reviewed: 2026-02-27

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

## 4. servers.locklast and servers.startlast default to true

**Eddie:** Both `servers.locklast` and `servers.startlast` default to `false`
(ProfileOptions.cs lines 435-436). Users must explicitly enable them in the
GUI.

**airvpn-rs:** Both default to `true` when not set in the profile. If reading
from an Eddie profile where these were explicitly set, those values are
respected.

**Why:** This is a laptop-first client where moving between WiFi networks is
common. Defaulting to "retry the same server" avoids unnecessary rotation to
worse servers after transient network drops. Users can disable with
`--no-lock-last` / `--no-start-last`.

**Files:** `src/main.rs` — connection loop setup, `src/config.rs` — profile options

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
  IPs, and VPN tunnel traffic (`oifname "avpn-*"` for inner packets, `meta mark 51820`
  for WireGuard outer packets). Uses `flags owner, persist` (kernel 5.12+/6.9+).
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

