# GUI M3 Planned Fixes — COMPLETE (2026-03-10)

Milestone 3 for airvpn-rs: settings parity with Eddie, security hardening,
and UX polish. M1 built the GUI scaffold + IPC. M2 wired all tabs and
core features. M3 fills in the gaps found by exhaustive comparison against
Eddie's `ProfileOptions.cs`.

## Foundational: unified options system ✓

`src/options.rs` — central registry with 51 option constants, typed getters,
`resolve(profile, overrides)` merging. `ConnectRequest` carries overrides
HashMap. CLI keeps clap derive (deliberate — better DX than auto-derivation).

## Security ✓

- [x] **SaveProfile: block credential writes** — returns 403 for login/password keys
- [x] **SaveProfile: atomic writes** — write-to-temp → sync_all → rename

## UX fixes ✓

- [x] **Eddie import confirmation dialog**
- [x] **Server list auto-refresh** — every ~3 minutes on Servers tab
- [x] **Progressive server list loading** — periodic re-fetch picks up pinger updates
- [x] **Remove `?sort=` dead code** — removed from handler and dispatch
- [x] **`servers.startlast` default → false** — matches Eddie
- [x] **Log memory growth** — `VecDeque<LogEntry>` with 10,000 cap
- [x] **ListServers loading feedback** — animated loading dots
- [x] **Clean up dead hook code** — all hook fields/UI removed

## Settings: high value ✓

- [x] `wireguard.interface.mtu` → WireGuard section
- [x] `wireguard.peer.persistentkeepalive` → WireGuard section
- [x] `netlock.incoming` → Network Lock section
- [x] `netlock.allow_private` → Network Lock section
- [x] `dns.mode` → Network section
- [x] `network.iface.name` → Connection section
- [x] `mode.port` → Advanced section
- [x] `network.entry.iplayer` → Network section

## Settings: medium value ✓

- [x] Scoring factors (speed, latency, load, users, ping, penality) → Advanced section
- [x] `pinger.timeout` → Advanced section
- [x] `advanced.manifest.refresh` → Advanced section
- [x] `advanced.penality_on_error` → Advanced section

## Settings: low effort ✓

- [x] `netlock.allow_ping` → Network Lock section
- [x] `network.ipv4.mode` (in/block) → Network section
- [x] `network.entry.iface` → Network section
- [x] `wireguard.handshake.timeout.first` / `.connected` → WireGuard section
- [x] `pinger.enabled` → Advanced section
- [x] `pinger.jobs` → Advanced section
- [x] `log.file.enabled` / `log.file.path` → Advanced section (backend wired to init_logging)
- [x] `log.level.debug` → Advanced section (runtime toggle via log::set_max_level)
- [x] `checking.ntry` → Advanced section
- [x] `http.timeout` → Advanced section
- [x] `advanced.check.route` → Advanced section (post-connect route verification)
- [x] `ui.unit` / `ui.iec` → General section
- [x] `linux.dns.services` → Network section

## Settings: explicitly skipped

| Option | Reason |
|--------|--------|
| `remember` | Eddie-specific — our creds always persist in root-owned profile |
| `server` | Covered by `servers.last` + `servers.startlast` |
| `netlock.allow_dns` | Allowing DNS through kill switch = DNS leak |
| `netlock.outgoing` | "Allow outgoing" defeats kill switch purpose |
| `netlock.connection` | Don't give users options to weaken lock defaults |
| `dns.check` toggle | Feature exists (verify.rs), always-on is correct |
| `dns.cache.ttl` | Hardcoded 3600s is fine |
| `event.app.start/stop` | Scrapping hook system for security |
| `event.session.start/stop` | Same |
| `routes.catch_all_mode` | No split tunnel support |
| `discover.*` | One-shot verify at connect time is sufficient |
| `proxy.*` / `openvpn.*` / `ssh.*` / `ssl.*` | N/A — WireGuard only |
| `windows.*` / `macos.*` | N/A — Linux only |
| `gui.*` (window state, tray, etc.) | Different toolkit, different UX model |
| `language.iso` | English only |
| `updater.channel` | Package manager handles updates |

## Features ✓

- [x] **Device/key selection** — `select_key()` matches by name, fallback to first with warning. GUI dropdown populated from `GET /keys` API (hidden when ≤1 key, like Eddie) + CLI `--key <name>`.
- [x] **Connect button labeling** — "Connect to {server}" / "Connect (best server)"
- [x] **Bandwidth capacity weighting** — `servers.capacity_factor` (default 0 = disabled)
- [x] **Custom routes + netlock allowlist** — both wired to nftables + routing
- [x] **Settings sub-tabs** — General, Network, WireGuard, Network Lock, Advanced
- [x] **Country filter on Servers tab** — unified search bar (matches name, country code, country name, location) + persistent areas.allowlist/denylist in Settings
- [x] **Account status check** — checks UserInfo.message, `connections.allow_anyway` option
- [x] **Helper reconnection** — auto-retry with 5s backoff, re-fetches /status

## Scrapped features

- **Countries tab** — folded into Servers tab country filter
- **Speed chart tab** — folded into Overview (live speeds already shown)
- **Stats tab** — folded into Overview (uptime, connection count, bytes already shown)
- **System tray** — user has app selector, not needed
- **Desktop notifications** — not needed
- **Keyboard shortcuts** — not needed
- **Window size/position persistence** — not needed
- **Credential setup from GUI** — credentials live in root-owned profile,
  can't safely handle from user-owned GUI process
