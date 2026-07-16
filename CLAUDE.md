# airvpn-rs

Rust reimplementation of Eddie (AirVPN's official C# client). WireGuard-only, Linux-only, CLI.
Single control plane: helper daemon (root, systemd socket-activated) manages all VPN operations.
CLI and GUI are thin HTTP clients over `/run/airvpn-rs/helper.sock` (0660 root:wheel).
HTTP/1.1 over Unix socket, thread-per-connection — multiple clients work concurrently.
Profile at `/etc/airvpn-rs/default.profile` (0600 root:root).

## Always Do

- **To (re)install/deploy, use `sudo ./scripts/install.sh`** — the one and only install method. It's idempotent and does everything: builds release binaries, installs binaries/config/systemd units/desktop entry, daemon-reload, restart. If the script is missing a step, fix the script.
- Build both debug and release: `cargo build && cargo build --release`
- Rebuild before telling user to test — they don't rebuild themselves
- Check `docs/known_divergences.md` before claiming Eddie parity
- Helper uses peer UID (SO_PEERCRED) to find user's Eddie profile; `sudo airvpn connect` uses `$SUDO_USER`
- Update `scripts/install.sh` when adding new components (binaries, systemd units, config files, directories) to the installation

## Key Gotchas

- Root can't access user's D-Bus keyring — `eddie_keyring_read` drops to original user
- Eddie's `servers.last` = `SHA256(server_name)`, not plain text
- `expand_tilde("~/...")` resolves to `/root/` under sudo — don't use for user paths
- Profile options must be loaded once and passed around (not loaded multiple times, causes re-prompting)
- Eddie keyring attribute: `"Eddie Profile" = "<profile_id>"` (not "application"/"profile-id")
- v2n encryption is fine for root-owned files — file perms are the real security
- `score_with_ping` returns 0 for unmeasured ping (divergence from Eddie's 99995 sentinel)
- No wg-quick dependency — uses direct `ip link add` / `wg setconf` / `ip addr add`
- IPv6 blocked on ALL interfaces including `default` (matches Eddie's `in-block` mode)

## Eddie Source References

- `ConnectionInfo.cs` — server scoring (`Score()`, `LoadPerc()`, `UsersPerc()`)
- `Session.cs` — reconnection loop, server selection priority chain
- `Storage.cs` — profile save/load, encryption formats
- `ProfileOptions.cs` — setting defaults (locklast=false, startlast=false)
- `Jobs/Penalities.cs` — penalty decay (1/minute)
- `Jobs/Latency.cs` — ping measurement (disabled during reconnection)
- `NetworkLockNftables.cs` — nftables kill switch

## User Preferences

- Wants Eddie compliance unless there's a good reason to diverge
- Document all divergences in `docs/known_divergences.md`
- Don't guess about Eddie behavior — read the source or ask
- Profile security matters — warn on insecure v2n for non-root files
- User doesn't write Rust — explain test behavior if they ask

## Learnings

- `pub(crate)` doesn't work for lib→bin visibility — this crate has separate lib.rs and main.rs, so library items called from main.rs must be `pub` (2026-02-28)
- `servers.locklast` now defaults false (matching Eddie). `has_default_gateway()` handles WiFi-drop case correctly (2026-03-01)
- DNS deadlock during reconnection: resolv.conf points to VPN DNS, which is unreachable without tunnel. Bootstrap IPs bypass this since they use direct HTTP. Eddie has same issue (2026-03-01)
- `nft -f` ownership is ephemeral (new portid per invocation). `reclaim_and_delete()` must do both in single nft -f call (2026-02-28)
- ConnState (connect/stats thread handles) must live outside `handle_client()` — persists across GUI reconnections (2026-03-02)
- DNS leaks through LAN rules during reconnection: both IPs in same RFC1918 /8. Fix: `oifname != "avpn0" dport { 53, 853 } drop` before LAN accept rules in both locks (2026-03-04)
- `partial_disconnect()` intentionally keeps DNS pointing to VPN DNS during reconnection — restoring original would leak to local resolver (2026-03-04)
- Two-phase connect for Eddie import: POST /connect returns 409 + EddieImportNeeded if no creds; client POSTs /import-eddie then retries (2026-03-05)
- Both nftables locks block outbound ICMP echo-request on non-tunnel interfaces. Persistent lock has permanent `ping_allow` subchain (ICMP-only per-server-IP rules). Session lock allowlists all server IPs for all protocols. Pinger needs BOTH to pass (2026-03-07)
- Persistent lock's `ping_allow` is populated at helper startup, on manifest fetch, and after lock enable/install. `lock install` recreates the table from `lock.nft` (empty ping_allow), so `repopulate_ping_allow()` must follow (2026-03-07)
- SharedState mutex must NEVER be held during pinging (~30-60s). Pattern: copy IPs out (quick lock), ping without lock, merge results back (quick lock) (2026-03-05)
- Background pinger: 1 ping per server per cycle, EWMA α=0.3 smooths across cycles. All servers pinged equally by binding each ping to the physical NIC (`ping -I`); no tunnel special-casing. Persisted to `/var/lib/airvpn-rs/latency.json` (2026-03-07)
- Scoring verified 1:1 against Eddie's `ConnectionInfo.cs` + actual AirVPN manifest. Factor defaults: speed_factor=1, latency_factor=500, penality_factor=1000, ping_factor=1, load_factor=1, users_factor=1 (2026-03-07)
- ScoreType enum (Speed/Latency) matching Eddie's `servers.scoretype` profile option. Latency mode: ScoreB/=500, LoadB/=10, UsersB/=10 — ping dominates (2026-03-07)
- Dev testing: `systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper`. `curl --unix-socket /run/airvpn-rs/helper.sock http://localhost/status` for debugging (2026-03-05)
- Proactive manifest fetch: background_manifest_loop fetches every 30 min (Eddie: next_update=30 × 60s). Condvar chain: creds→manifest_cv→manifest loop→pinger_cv→pinger→ready_cv→connect. State type is `Arc<(Mutex<SharedState>, Notify)>` (2026-03-07)
- Connect no longer fetches manifest — reads from SharedState cache. Only fetches UserInfo (WG keys) per-connect. Returns 503 if helper still warming up. Reconnection still does its own manifest+user fetch (2026-03-07)
- `skip_ping` CLI flag fully removed — background pinger makes latency transparent. `measure_all_inline` removed. No client-facing ping messages (2026-03-07)
- Eddie does NOT ship the manifest — caches it in Storage.xml from prior API fetch. Refresh interval: server-recommended `next_update` from manifest (× 60s), fallback 24h. Pinger has IPs from cached manifest at startup (2026-03-07)
- Event hooks (event.vpn.pre/up/down) removed — split-process architecture means socket clients could execute arbitrary commands as root. Documented in known_divergences.md (2026-03-09)
- Credentials use `Zeroizing<String>` end-to-end: profile decryption, config resolution, API calls, connect flow. Eddie uses plain String everywhere — we're strictly better (2026-03-09)
- `WireGuardKey` and `WgConnectParams` have manual Debug impls that redact private keys — `Zeroizing<String>` delegates Debug to inner String (2026-03-09)
- `dns.rs` now validates interface names like all other modules. Previously was the only module that didn't call `validate_interface_name()` (2026-03-09)
- DNS deadlock in `activate_netlock()`: `resolve_bootstrap_host("bootme.org")` blocks ~30s when persistent lock drops port 53. Fix: skip hostname resolution when persistent lock active (IPs sufficient) (2026-03-12)
- `force_recover()` was useless without state.json — returned "nothing to recover" even with orphaned session locks, stale DNS, routing rules. Now does unconditional orphan cleanup (2026-03-12)
- Pinger steers pings out the physical NIC by binding the ICMP socket (`ping -I <iface>`, SO_BINDTODEVICE; iface from main-table default route), NOT by inserting /32 host routes. The old host-route approach broke because NM flushes routes it doesn't own on every WiFi roam/DHCP renew/resume, so pings silently went through the tunnel (connected POP's city ranked closest). The entire add/remove_server_host_routes subsystem + its recover/orphan/disconnect cleanup paths were deleted. The kill-switch allowlist (all_entry_ips→activate_netlock) is what permits the egress and is unchanged — routing only steers, firewall gates (2026-06-24)
- Connect thread error left stale state.json + locks: `check_and_recover()` found helper's own PID alive → "another instance running". Fix: connect thread calls `force_recover()` on error exit; helper pre-cleans stale state with own PID before starting new connect (2026-03-12)
- Device/key selector is now a `pick_list` dropdown populated from `GET /keys` (cached in SharedState by background_manifest_loop). Hidden when ≤1 key, like Eddie's ComboBox. Needs `credentials_configured` to distinguish "loading" from "no creds" (2026-03-13)
- Country filter replaced with unified search bar — searches name, country_code, country_name (via `countries::country_name()`), and location. `src/countries.rs` has zero-allocation byte-match lookup (2026-03-13)
- DNS restore no longer uses snapshot+replay. On disconnect, `dns::deactivate()` deletes our `/etc/resolv.conf` and runs `nmcli dev reapply <default-route-iface>` (NetworkManager) and/or `resolvectl revert <iface>` (systemd-resolved) to regenerate DNS from the system's current state. Eddie's snapshot pattern goes stale across network changes and unclean shutdowns; deferring to NM/resolved eliminates the staleness window. Drops `RESOLV_WAS_IMMUTABLE`, `BACKUP_PATH`, `resolv_was_immutable` state field, and ~150 lines of replay logic. Documented in `known_divergences.md` #14 (2026-05-03)
- `connect_in_progress` has explicit ownership: handle_connect_async claims it via `swap()`; only the request that flipped false→true may take the fresh-connect fall-through or arm the early-exit ConnectGuard. Requests entering via the already-connected exception own nothing and 409 if the connection drops mid-request. `switch_in_progress` must be checked before computing is_connected/has_orphan in /disconnect, and before /recover's flag-clear + force_recover (same hazard: mid-switch force_recover races the switch thread's teardown). Background threads + /recover use `lock_state()` (poison-tolerant); request handlers use plain `.unwrap()`. Residual known races: /disconnect's stale-flag clear can't cancel a pre-thread in-flight connect; /recover's gate serializes the flag handoff but not the teardown itself (comments in handle_disconnect/handle_recover) (2026-06-11)
- `cargo test | tail` masks compile failures (pipe exit code) — integration tests sat broken (removed `resolv_was_immutable` field) without anyone noticing; lib tests don't run when any test target fails to compile (2026-06-11)
- Connect-at-boot: `airvpn-autoconnect.service` (oneshot, `After=network-online.target`) runs `airvpn autoconnect`, which reads the profile `connect` flag (Eddie parity, default false) and does a best-server connect with retries. Unit is enabled unconditionally by install.sh and self-gates on the flag (no-op when off), so the GUI "Connect at startup" checkbox only writes the flag — no systemctl from the thin client. Feasible because V2N profile is root-decryptable without the user's (boot-locked) D-Bus keyring. install.sh also now reconnects to the previously-connected server after a reinstall (captures via status socket, redials with warmup retries). Divergence #15 (2026-07-01)
- Carrier-aware reconnect: WiFi flaps were misattributed to servers (handshake goes stale only after 200s; by then the flap healed so `!has_default_gateway()` read false → penalize + hop). `run_monitor_loop` now tracks physical-link carrier loss during the connection; flaps retry the same server, no penalty. Genuine server death still penalizes (setup-time failures pass net_flapped=false) (2026-06-30)
- AirDNS self-heal: built (post-connect authoritative check + capped corrective reconnect, `ddns.hostname` option + GUI field) and REVERTED next day — it fired on the record's normal ~30-60s post-connect propagation (5s grace was guaranteed false-positive) and its 6-connects-in-3-min churn wedged the account's DDNS record for 3h38m. Code parked on branch `ddns-selfheal`; do not resurrect without measuring the monitored signal's normal dynamics first. A leftover `ddns.hostname` value may remain in encrypted profiles — inert, nothing reads it (2026-07-01)
- TLS backend is rustls, NOT OpenSSL. `reqwest` uses `default-features=false` + `["blocking","http2","charset","rustls-tls-native-roots"]` — this removes the entire openssl/openssl-sys/native-tls C-dependency chain (was the source of a recurring rust-openssl CVE class; 8 Dependabot alerts in one batch). native-roots keeps the system CA trust store. Only ONE request does real cert verification: the `https://airvpn.org` bootstrap fallback in `resources/provider.json` (bootstrap IPs are plain HTTP + RSA/AES envelope; `verify.rs` tunnel/DNS checks use `danger_accept_invalid_certs`). If you re-add default features or a native-tls dep, openssl comes back (2026-07-15)
