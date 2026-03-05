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

- `sudo` strips most env vars but preserves `$SUDO_USER` — use it to find user's home for Eddie profile import (2026-02-26)
- Root can't access user's D-Bus keyring — `eddie_keyring_read` drops to original user via `sudo -u $SUDO_USER` (2026-02-26)
- Always rebuild both debug and release binaries after changes (2026-02-26)
- Replaced wg-quick with direct ip/wg commands — enables Eddie-matching IPv6 behavior with no race (2026-02-27)
- Eddie blocks IPv6 on `default` sysctl (not just existing interfaces) — new interfaces inherit disabled IPv6 (2026-02-27)
- Validation scripts in `scripts/`: leak-monitor, rule-diff, chaos-test, eddie-compare (2026-02-27)
- Persistent lock uses separate `airvpn_persist` table (priority -400) from session `airvpn_lock` (-300). Two independent tables, fully decoupled — can disable/uninstall persistent lock while VPN runs (2026-02-28)
- Persistent table uses `flags owner, persist` + `oifname "avpn-*"` (inner) + `meta mark 51820` (outer WireGuard). No server IP knowledge needed (2026-02-28)
- `nft -f` ownership is ephemeral (new portid per invocation). `reclaim_and_delete()` must do both in single nft -f call. Owner flag protection is transient — persist flag is the real value (2026-02-28)
- Eddie has same resolve-then-lock leak window (NetworkLockManager.cs:127) — persistent lock eliminates it entirely (2026-02-28)
- Connect lifecycle lives in `src/connect.rs` (run, preflight, session, data fetch, reconnection loop). `main.rs` is thin socket client dispatching to helper via `cli_client.rs` (2026-03-04)
- Shared utils in `src/common.rs`: validate_interface_name, read_stdin_password, backoff_secs, MAX_RULE_DELETIONS (2026-02-28)
- `pub(crate)` doesn't work for lib→bin visibility — this crate has separate lib.rs and main.rs, so library items called from main.rs must be `pub` (2026-02-28)
- Backoff formula max is 192s (not 300) — exponent capped at 6 via `.min(6)`, so `3 * 2^6 = 192`. The 300 cap is a dead safety net (2026-02-28)
- `servers.locklast` now defaults false (matching Eddie). `has_default_gateway()` handles WiFi-drop case correctly — locklast=true was redundant and prevented server rotation when server died with WiFi up (2026-03-01)
- DNS deadlock during reconnection: resolv.conf points to VPN DNS, which is unreachable without tunnel, so `bootme.org` can't resolve. Bootstrap IPs bypass this since they use direct HTTP. Eddie has same issue (2026-03-01)
- Single control plane: helper daemon is the sole VPN manager. CLI (`src/cli_client.rs`) and GUI are both thin socket clients. ALL commands go through `/run/airvpn-rs/helper.sock` — no direct CLI operations remain (2026-03-04)
- Helper resolves credentials (saved profile → Eddie import via peer UID → error). No credentials enter non-root memory or transit the socket. First-time setup: `sudo airvpn connect` prompts in root process, helper saves to profile (2026-03-04)
- GUI uses iced 0.14 with split-process architecture: `airvpn-gui` (user) + `airvpn helper` (root via systemd socket activation). HTTP/1.1 over Unix socket (2026-03-05)
- Helper uses systemd socket activation — no manual bind/chown. Dev testing: `systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper`. Unit files in `resources/` (2026-03-02)
- SO_PEERCRED logs connecting UID on every accept(). Socket is 0660/wheel — migrate to dedicated airvpn group for AUR packaging (2026-03-02)
- `/run/airvpn-rs/` created by systemd (`DirectoryMode=0755` in .socket unit). `recovery::ensure_state_dir()` still creates it for standalone CLI use (2026-03-02)
- `setup_signal_handler()` must be idempotent — helper installs it once, `connect::run()` reuses the existing flag. OnceLock returns existing value instead of failing (2026-03-02)
- Rust's `UnixListener` retries on EINTR internally — signals don't break `accept()`. Use nonblocking accept + 1s sleep loop to check shutdown flag (2026-03-02)
- ConnState (connect/stats thread handles) must live outside `handle_client()` — persists across GUI reconnections so the helper knows about running VPN from previous GUI session (2026-03-02)
- Skip ping when server is predetermined (--server or startlast) — saves ~10s on every connect (2026-03-02)
- Fixed VPN interface name `avpn0` (`VPN_INTERFACE` constant in `wireguard.rs`) — enables exact nft matching instead of wildcard `avpn-*` (2026-03-04)
- DNS leaks through LAN rules during reconnection: both IPs in same RFC1918 /8 (WiFi 10.73.x.x → VPN DNS 10.128.0.1). Fix: `oifname != "avpn0" dport { 53, 853 } drop` before LAN accept rules in both locks (2026-03-04)
- `partial_disconnect()` intentionally keeps DNS pointing to VPN DNS during reconnection — restoring original would leak to local resolver. The DNS block rules handle the remaining leak vector (2026-03-04)
- Helper uses HTTP/1.1 over Unix socket (not JSON-lines). Thread-per-connection enables multiple concurrent clients (CLI + GUI). `curl --unix-socket /run/airvpn-rs/helper.sock http://localhost/status` works for debugging (2026-03-05)
- Event streaming via `GET /events` (chunked transfer encoding). Fan-out pattern: `Vec<mpsc::Sender>` in SharedState, dead subscribers pruned on send failure (2026-03-05)
- Two-phase connect for Eddie import: POST /connect returns 409 + EddieImportNeeded if no creds; client POSTs /import-eddie then retries. No inline back-and-forth on same connection (2026-03-05)
- `src/http.rs`: minimal HTTP parser (~120 lines, no dependencies). Handles request parsing, JSON responses, and chunked streaming. Tested with `UnixStream::pair()` (2026-03-05)
- Background pinger: LatencyCache (EWMA α=0.3) replaces PingResults. Persisted to `/var/lib/airvpn-rs/latency.json`. Helper spawns `tokio::task::spawn_blocking` pinger loop (2026-03-05)
- Both nftables locks block outbound ICMP echo-request on non-tunnel interfaces. Session lock OUTPUT has echo-reply only (not echo-request). `oifname "avpn0" accept` allows everything through tunnel. Outside-tunnel pings need per-IP allowlist in BOTH active locks (2026-03-05)
- Eddie allowlists ALL server entry IPs in session lock (NetworkLockPlugin.cs:199-201), not just the connected server. We now match this — enables reconnection and background pinging (2026-03-05)
- Eddie does NOT ping while connected (Jobs/Latency.cs:121-124 `canRun = false`). We diverge: ping connected server through tunnel (`ping -I avpn0`), others outside via host routes (2026-03-05)
- Host routes (`/32` via physical gateway) bypass tunnel policy routing thanks to `suppress_prefixlength 0`. Tested: 1024 routes via `ip -batch` in 18ms, 1024 nft rules via `nft -f` in 25ms (2026-03-05)
- SharedState mutex must NEVER be held during pinging (~30-60s). Pattern: copy IPs out (quick lock), ping without lock, merge results back (quick lock) (2026-03-05)
