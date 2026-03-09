# GUI M3 Planned Fixes

Milestone 3 for airvpn-rs: settings parity with Eddie, security hardening,
and UX polish. M1 built the GUI scaffold + IPC. M2 wired all tabs and
core features. M3 fills in the gaps found by exhaustive comparison against
Eddie's `ProfileOptions.cs`.

Event hooks (vpn.pre/up/down) are being scrapped for security reasons in a
separate effort. They may be gone by the time M3 starts — adjust accordingly.

## Security

- [ ] **SaveProfile: block credential writes** — `handle_save_profile` accepts
  `login`/`password` keys from any socket client (0660/wheel). Should reject
  these — credential setup must go through `sudo airvpn connect` or Eddie import.
- [ ] **SaveProfile: atomic writes** — currently saves one key at a time. Use
  write-to-temp-then-rename for crash safety.

## UX fixes

- [ ] **Eddie import confirmation dialog** — GUI auto-accepts Eddie imports.
  Add a confirmation dialog showing the Eddie profile path before importing.
- [ ] **Server list auto-refresh** — fetched once on first Servers tab visit,
  never refreshed. Refresh every ~3 minutes (match Eddie).
- [ ] **Progressive server list loading** — background pinger populates the
  latency cache, but GUI fetches `/servers` once and never re-fetches to pick
  up updated ping data. GUI should periodically re-fetch (or subscribe to
  latency updates) so scores update as pings complete.
- [ ] **Remove `?sort=` dead code** — GUI already sorts client-side, but
  `handle_list_servers` still accepts and uses `?sort=` query param. Remove
  the `sort` parameter from the handler and `dispatch_list_servers`.
- [ ] **`servers.startlast` default → false** — currently defaults to `true`,
  diverging from Eddie's `false`. Unintentional. Match Eddie.
- [ ] **Log memory growth** — `Vec<LogEntry>` in GUI grows unbounded. VPN
  sessions can run for months. Use a ring buffer or periodic pruning.
- [ ] **ListServers loading feedback** — shows "Loading servers..." text with
  no spinner or timeout message. Add proper loading indicator.

## Settings: high value

- [ ] `wireguard.interface.mtu` — hardcoded 1320. Users on different networks need to tune. → WireGuard section
- [ ] `wireguard.peer.persistentkeepalive` — hardcoded 15s. Some want 0 or higher behind NAT. → WireGuard section
- [ ] `netlock.incoming` — hardcoded block. Some users need incoming (port forwarding). → Network Lock section
- [ ] `netlock.allow_private` — hardcoded true. Eddie has toggle for strict LAN isolation. → Network Lock section
- [ ] `dns.mode` — auto-detects resolv.conf + systemd-resolved. Eddie lets users force a mode. → Network section
- [ ] `network.iface.name` — hardcoded "avpn0". Niche but needed for naming conflicts. → Connection section
- [ ] `mode.port` — auto-selected. Restrictive networks may need port 443/53. → Connection section
- [ ] `network.entry.iplayer` — hardcoded IPv4-first. Some need IPv6 entry. → Network section

## Settings: medium value

- [ ] Scoring factors (`speed_factor`, `latency_factor`, `load_factor`, `users_factor` etc.) — all hardcoded. → Advanced section
- [ ] `pinger.timeout` — hardcoded 3000ms. → Advanced section
- [ ] `advanced.manifest.refresh` — hardcoded 30 min. → Advanced section
- [ ] `advanced.penality_on_error` — hardcoded 30. → Advanced section

## Settings: low effort (swap constant for config read)

- [ ] `netlock.allow_ping` — hardcoded true. Toggle to block ICMP. Background pinger uses host routes so disabling won't break it. → Network Lock section
- [ ] `network.ipv4.mode` — we have ipv6.mode but no ipv4 equivalent. Eddie supports "in", "in-out", "in-block", "out", "block". → Network section
- [ ] `network.entry.iface` — bind endpoint traffic to specific physical NIC (eth0 vs wlan0). → Network section
- [ ] `wireguard.handshake.timeout.first` (default 50s) and `wireguard.handshake.timeout.connected` (default 200s) — both hardcoded. → WireGuard section
- [ ] `pinger.enabled` — hardcoded always-on. Toggle to disable background pinger. → Advanced section
- [ ] `pinger.delay` (default 0), `pinger.retry` (default 0), `pinger.jobs` (default 25), `pinger.valid` (default 0) — all hardcoded. Pure constant-to-config swaps. → Advanced section
- [ ] `log.file.enabled` (default false) and `log.file.path` — all logging is ephemeral. Long sessions need persistent logs. → Advanced section
- [ ] `log.level.debug` — controlled by `RUST_LOG` env var. Profile-backed toggle is GUI-friendlier. → Advanced section
- [ ] `checking.ntry` — hardcoded 5 retries for tunnel verification. → Advanced section
- [ ] `http.timeout` — hardcoded 10s for API calls. → Advanced section
- [ ] `advanced.check.route` — verify routing table after connect. Eddie default true. → Advanced section
- [ ] `ui.unit` (bytes/s vs bits/s) and `ui.iec` (KiB vs KB) — display unit toggles. → General section
- [ ] `linux.dns.services` — hardcoded `["nscd", "dnsmasq", "named", "bind9"]` in `dns.rs:126`. Make configurable. → Network section

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

## Features

- [ ] **Device/key selection** — AirVPN "devices" map to `<key name="...">` in
  the API response. Eddie stores selected device as profile option `key`
  (default "Default"). airvpn-rs parses all keys but `connect.rs:1104` does
  `keys.first()`, ignoring the setting. Fix: match by name. Add dropdown in
  Settings > WireGuard (populated from UserInfo keys). Add CLI `--key <name>`.
  Fall back to first key with warning if name not found. Needed for port
  forwarding and phone relay setup.

- [ ] **Connect button labeling** — Overview Connect button sends `server: None`
  and the helper handles it correctly (startlast → best score). But the label
  just says "Connect". Should show: "Connect to Alchiba" (if startlast resolves)
  or "Connect (best server)" (if scoring). Informational, no logic change.

- [ ] **Bandwidth capacity weighting** — Eddie's scoring treats 20 Gbps at 10%
  load identically to 2 Gbps at 10% load. New feature (not in Eddie): add
  `servers.capacity_factor` (default 0 = disabled). When set, subtracts a
  capacity bonus: `-(bandwidth_max / 1000) * capacity_factor`.

- [ ] **LAN / IP exceptions** — reach printers, NAS, etc. without routing through
  VPN. Two parts: nftables allow rules + `ip route` exceptions via default
  gateway. Profile option `netlock.allowlist.ips` (comma-separated CIDRs).
  Apply in both session and persistent locks. GUI: text input in Network Lock
  section.

- [ ] **Settings sub-tabs** — settings view needs sub-navigation with ~30 options:
  - General (credentials, server prefs, connection flags, display units)
  - Network (IPv6, IPv4, DNS, interface binding, DNS services)
  - WireGuard (MTU, keepalive, handshake timeouts, device/key)
  - Network Lock (install/enable, incoming policy, allow LAN/ping, IP exceptions)
  - Event Hooks (pre/up/down) — remove if hooks scrapped before M3
  - Advanced (scoring, pinger, manifest, penalty, logging, timeouts)

- [ ] **Country filter on Servers tab** — allow/deny country fields exist in
  `ConnectRequest` but no GUI. Add country filter dropdown/chips on Servers tab.
  Client-side filtering. Persist as `servers.allow_country` / `servers.deny_country`.

- [ ] **Account status check** — Eddie verifies account status pre-connect.
  airvpn-rs skips this — expired accounts get cryptic errors. Check `/userinfo`
  response for warnings. Profile option `connections.allow_anyway` (default false).

- [ ] **Custom routes** — `routes.custom` profile option (comma-separated CIDRs).
  Routes traffic for specified CIDRs outside the VPN tunnel. Complements the
  netlock allowlist (which opens the firewall; custom routes steer the traffic).

- [ ] **Helper reconnection** — if helper dies, GUI shows error with no recovery.
  systemd socket activation means the socket still exists — GUI just needs to
  reconnect (next request re-triggers helper). Detect dead helper, show
  "reconnecting..." message, re-fetch `/status` to rebuild state.

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
