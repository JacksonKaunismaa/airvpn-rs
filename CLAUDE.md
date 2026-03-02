# airvpn-rs

Rust reimplementation of Eddie (AirVPN's official C# client). WireGuard-only, Linux-only, CLI.
Runs as root via `sudo`. Profile at `/etc/airvpn-rs/default.profile`.

## Always Do

- Build both debug and release: `cargo build && cargo build --release`
- Rebuild before telling user to test — they don't rebuild themselves
- Check `docs/known_divergences.md` before claiming Eddie parity
- Use `$SUDO_USER` (not `$HOME`) to find user paths when running as root

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
- Connect lifecycle lives in `src/connect.rs` (run, preflight, session, data fetch, reconnection loop). `main.rs` is CLI parsing + dispatch only (2026-02-28)
- Shared utils in `src/common.rs`: validate_interface_name, read_stdin_password, backoff_secs, MAX_RULE_DELETIONS (2026-02-28)
- `pub(crate)` doesn't work for lib→bin visibility — this crate has separate lib.rs and main.rs, so library items called from main.rs must be `pub` (2026-02-28)
- Backoff formula max is 192s (not 300) — exponent capped at 6 via `.min(6)`, so `3 * 2^6 = 192`. The 300 cap is a dead safety net (2026-02-28)
- `servers.locklast` now defaults false (matching Eddie). `has_default_gateway()` handles WiFi-drop case correctly — locklast=true was redundant and prevented server rotation when server died with WiFi up (2026-03-01)
- DNS deadlock during reconnection: resolv.conf points to VPN DNS, which is unreachable without tunnel, so `bootme.org` can't resolve. Bootstrap IPs bypass this since they use direct HTTP. Eddie has same issue (2026-03-01)
- GUI uses iced 0.14 with split-process architecture: `airvpn-gui` (user) + `airvpn helper` (root via systemd socket activation). JSON-lines over Unix socket at `/run/airvpn-rs/helper.sock` (2026-03-02)
- Helper uses systemd socket activation — no manual bind/chown. Dev testing: `systemd-socket-activate -l /run/airvpn-rs/helper.sock -- ./target/debug/airvpn helper`. Unit files in `resources/` (2026-03-02)
- SO_PEERCRED logs connecting UID on every accept(). Socket is 0660/wheel — migrate to dedicated airvpn group for AUR packaging (2026-03-02)
- `refuse_if_helper_running()` checks PID file (`/run/airvpn-rs/helper.pid`), not socket connect — socket connect triggers activation (2026-03-02)
- `/run/airvpn-rs/` created by systemd (`DirectoryMode=0755` in .socket unit). `recovery::ensure_state_dir()` still creates it for standalone CLI use (2026-03-02)
- `setup_signal_handler()` must be idempotent — helper installs it once, `connect::run()` reuses the existing flag. OnceLock returns existing value instead of failing (2026-03-02)
- Rust's `UnixListener` retries on EINTR internally — signals don't break `accept()`. Use nonblocking accept + 1s sleep loop to check shutdown flag (2026-03-02)
- ConnState (connect/stats thread handles) must live outside `handle_client()` — persists across GUI reconnections so the helper knows about running VPN from previous GUI session (2026-03-02)
- CLI and GUI are independent control paths — don't mix them. No coordination between `sudo airvpn connect` and the helper daemon (known M1 limitation) (2026-03-02)
- Skip ping when server is predetermined (--server or startlast) — saves ~10s on every connect (2026-03-02)
