# airvpn-rs

Rust reimplementation of Eddie (AirVPN's official C# client). WireGuard-only, Linux-only, CLI.
Single control plane: helper daemon (root, systemd socket-activated) manages all VPN operations.
CLI and GUI are thin HTTP clients over `/run/airvpn-rs/helper.sock` (0660 root:wheel).
HTTP/1.1 over Unix socket, thread-per-connection — multiple clients work concurrently.
Profile at `/etc/airvpn-rs/default.profile` (0600 root:root).

## Always Do

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
- `ip -batch` without `-force` stops on first error ("File exists" for duplicate routes). Must use `-force` flag or only a fraction of routes get added. The log count was misleading (printed input count, not actual adds) (2026-03-07)
- SharedState mutex must NEVER be held during pinging (~30-60s). Pattern: copy IPs out (quick lock), ping without lock, merge results back (quick lock) (2026-03-05)
- Background pinger: 1 ping per server per cycle, EWMA α=0.3 smooths across cycles. All servers pinged equally via host routes (no tunnel special-casing). Persisted to `/var/lib/airvpn-rs/latency.json` (2026-03-07)
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
- Server host routes (~1000 /32 routes from pinger) not cleaned by `recover_from_state()`. Helper's `handle_recover` and orphan disconnect path now use manifest IPs from SharedState to clean them (2026-03-12)
