# Code Quality Refactoring Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Eliminate code duplication, fix all clippy warnings, and decompose the 990-line `cmd_connect` into a dedicated `src/connect.rs` module with functions ≤100 lines each.

**Architecture:** Two-phase approach. Phase 1 creates `src/common.rs` for shared utilities, fixes clippy/dead code. Phase 2 moves `cmd_connect` into `src/connect.rs` with a `ConnectConfig` struct, then decomposes it into named phases. Each phase is one commit.

**Tech Stack:** Rust, anyhow, zeroize, clap

---

## Phase 1: Quick Wins

### Task 1: Create `src/common.rs` with shared utilities

**Files:**
- Create: `src/common.rs`
- Modify: `src/lib.rs`

**Step 1: Create `src/common.rs`**

```rust
//! Shared utilities used across multiple modules.

use anyhow::Result;
use zeroize::Zeroizing;

/// Maximum routing rule deletions per teardown pass.
///
/// Used by `wireguard::teardown_routing` and `recovery::recover_from_state`
/// to bound the deletion loop and prevent infinite iteration if rule deletion
/// keeps "succeeding" without actually removing the rule.
pub const MAX_RULE_DELETIONS: usize = 100;

/// Validate a network interface name.
///
/// Linux interface names: max 15 chars, ASCII alphanumeric + '-' + '_'.
/// Used for defense-in-depth against command/path injection in nft commands,
/// sysctl paths, and WireGuard config.
pub fn validate_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Read password from stdin when `--password-stdin` is set.
///
/// Returns `None` if `password_stdin` is false. Trims trailing newlines
/// and rejects empty input. The returned string is wrapped in `Zeroizing`
/// to clear it from memory on drop.
pub fn read_stdin_password(password_stdin: bool) -> Result<Option<Zeroizing<String>>> {
    if !password_stdin {
        return Ok(None);
    }
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| anyhow::anyhow!("failed to read password from stdin: {}", e))?;
    let trimmed = line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    if trimmed.is_empty() {
        anyhow::bail!("--password-stdin: received empty password");
    }
    Ok(Some(Zeroizing::new(trimmed)))
}

/// Exponential backoff: `3 * 2^(n-1)` capped at 300 seconds.
///
/// Used by the reconnection loop after WireGuard failures, handshake
/// timeouts, and verification failures.
pub fn backoff_secs(consecutive_failures: u32) -> u64 {
    std::cmp::min(
        3u64.saturating_mul(
            2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(6)),
        ),
        300,
    )
}
```

**Step 2: Register in `src/lib.rs`**

Add `pub mod common;` to `src/lib.rs` (alphabetical order, before `config`).

**Step 3: Build to verify**

Run: `cargo build 2>&1`
Expected: compiles with no errors (warnings OK for now)

---

### Task 2: Replace interface name validation (6 sites)

**Files:**
- Modify: `src/wireguard.rs:41-48`
- Modify: `src/recovery.rs:57-63`
- Modify: `src/netlock.rs:568`
- Modify: `src/netlock.rs:616`
- Modify: `src/ipv6.rs:50-52`
- Modify: `src/ipv6.rs:86-88`

**Step 1: `wireguard.rs` — change private fn to use common**

Replace the private `validate_interface_name` function (lines 41-48) with a call to `common::validate_interface_name`. The wireguard version returns `Result<()>` while common returns `bool`, so wrap it:

```rust
fn validate_interface_name(iface: &str) -> Result<()> {
    if !crate::common::validate_interface_name(iface) {
        anyhow::bail!("invalid interface name: {:?}", iface);
    }
    Ok(())
}
```

Keep the private wrapper since callers in wireguard.rs expect `Result<()>`.

**Step 2: `recovery.rs` — replace `is_valid_interface_name`**

Replace the `is_valid_interface_name` function body (lines 57-63) to delegate:

```rust
fn is_valid_interface_name(name: &str) -> bool {
    crate::common::validate_interface_name(name)
}
```

Or better: remove `is_valid_interface_name` entirely and replace all call sites with `crate::common::validate_interface_name`. There are 2 call sites in `validate_state` (lines 68 and 74). Search with grep first.

**Step 3: `netlock.rs:568` — `allow_interface` inline validation**

Replace the inline validation:
```rust
    if iface.len() > 15 || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!("invalid interface name: {:?}", iface);
    }
```

With:
```rust
    if !crate::common::validate_interface_name(iface) {
        anyhow::bail!("invalid interface name: {:?}", iface);
    }
```

**Step 4: `netlock.rs:616` — `deallow_interface` inline validation**

Same replacement as step 3.

**Step 5: `ipv6.rs:50-52` — `block_all` inline validation**

Replace:
```rust
        if name.is_empty()
            || name.len() > 15
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
```

With:
```rust
        if !crate::common::validate_interface_name(&name) {
```

**Step 6: `ipv6.rs:86-88` — `restore` inline validation**

Replace:
```rust
        if name.is_empty()
            || name.len() > 15
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
```

With:
```rust
        if !crate::common::validate_interface_name(name) {
```

**Step 7: Build + test**

Run: `cargo build && cargo test 2>&1`
Expected: compiles, all tests pass. No behavior change.

---

### Task 3: Replace password-stdin reading (2 sites)

**Files:**
- Modify: `src/main.rs:550-561` (in `cmd_connect`)
- Modify: `src/main.rs:1610-1621` (in `cmd_servers`)

**Step 1: Replace in `cmd_connect`**

Replace lines 550-561:
```rust
    let stdin_password: Option<Zeroizing<String>> = if password_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin().read_line(&mut line)
            .map_err(|e| anyhow::anyhow!("failed to read password from stdin: {}", e))?;
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r').to_string();
        if trimmed.is_empty() {
            anyhow::bail!("--password-stdin: received empty password");
        }
        Some(Zeroizing::new(trimmed))
    } else {
        None
    };
```

With:
```rust
    let stdin_password = airvpn::common::read_stdin_password(password_stdin)?;
```

**Step 2: Replace in `cmd_servers`**

Replace lines 1610-1621 (same code block) with:
```rust
    let stdin_password = airvpn::common::read_stdin_password(password_stdin)?;
```

**Step 3: Build + test**

Run: `cargo build && cargo test 2>&1`
Expected: compiles, all tests pass.

---

### Task 4: Replace backoff formula (4 sites)

**Files:**
- Modify: `src/main.rs` — 4 inline occurrences of the backoff formula

**Step 1: Find all 4 sites**

Run: `rg "saturating_mul.*saturating_pow" src/main.rs`

These are in the reconnection loop in `cmd_connect` — after WireGuard connect failure (~line 1142), handshake failure (~line 1186), verification failure (~line 1324), and monitor loop reset (~line 1425).

**Step 2: Replace each occurrence**

Replace every instance of:
```rust
let backoff_secs = std::cmp::min(3u64.saturating_mul(2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(6))), 300);
```

With:
```rust
let backoff_secs = airvpn::common::backoff_secs(consecutive_failures);
```

**Step 3: Build + test**

Run: `cargo build && cargo test 2>&1`
Expected: compiles, all tests pass.

---

### Task 5: Replace `MAX_RULE_DELETIONS` (2 sites)

**Files:**
- Modify: `src/wireguard.rs:608`
- Modify: `src/recovery.rs:361`

**Step 1: `wireguard.rs`**

Remove `const MAX_RULE_DELETIONS: usize = 100;` at line 608 and replace all references in `teardown_routing` with `crate::common::MAX_RULE_DELETIONS`.

**Step 2: `recovery.rs`**

Remove `const MAX_RULE_DELETIONS: usize = 100;` at line 361 and replace all references in `recover_from_state` with `crate::common::MAX_RULE_DELETIONS`.

**Step 3: Build + test**

Run: `cargo build && cargo test 2>&1`
Expected: compiles, all tests pass.

---

### Task 6: Fix clippy warnings

**Files:**
- Modify: `src/config.rs:45, 285, 300, 310, 322, 372`
- Modify: `src/crypto.rs:165`
- Modify: `src/main.rs:1544, 1644, 1652`

**Step 1: `config.rs:45` — useless PathBuf::from()**

Replace `PathBuf::from(user.dir)` with `user.dir` (it's already a PathBuf).

**Step 2: `config.rs:285, 310, 372` — `&PathBuf` → `&Path`**

Change function signatures:
- `fn load_eddie_profile(path: &PathBuf)` → `fn load_eddie_profile(path: &Path)`
- `fn load_options_from_path(path: &PathBuf)` → `fn load_options_from_path(path: &Path)`
- `fn save_options(path: &PathBuf, ...)` → `fn save_options(path: &Path, ...)`

Add `use std::path::Path;` if not already imported.

**Step 3: `config.rs:300, 322` — `map_or` → `is_some_and`**

Replace:
```rust
let is_xml = trimmed.map_or(false, |i| data[i] == b'<');
```

With:
```rust
let is_xml = trimmed.is_some_and(|i| data[i] == b'<');
```

(Two occurrences, in `load_eddie_profile` and `load_options_from_path`.)

**Step 4: `crypto.rs:165` — explicit auto-deref**

Replace:
```rust
let d_encrypted = aes_cbc_encrypt(&d_plaintext, &*key, &*iv);
```

With:
```rust
let d_encrypted = aes_cbc_encrypt(&d_plaintext, &key, &iv);
```

**Step 5: `main.rs:1544` — collapsible if**

Replace:
```rust
    if lock_active {
        if !iface.is_empty() {
            let _ = netlock::deallow_interface(iface);
        }
    }
```

With:
```rust
    if lock_active && !iface.is_empty() {
        let _ = netlock::deallow_interface(iface);
    }
```

**Step 6: `main.rs:1644, 1652` — `sort_by` → `sort_by_key`**

Replace:
```rust
"score" => servers.sort_by(|a, b| server::score(a).cmp(&server::score(b))),
```

With:
```rust
"score" => servers.sort_by_key(|s| server::score(s)),
```

And same for the fallback at line 1652.

**Step 7: Run clippy to verify zero warnings**

Run: `cargo clippy 2>&1`
Expected: zero warnings (or only `dead_code` for `ResetLevel::Switch` which has `#[allow]`)

---

### Task 7: Dead code cleanup

**Files:**
- Modify: `src/main.rs:1531` (`teardown_lock_state` signature)
- Modify: `src/netlock.rs:620-626` (degenerate match)

**Step 1: `teardown_lock_state` — remove unused parameters**

Replace:
```rust
fn teardown_lock_state(_persistent_lock: bool, _server_ips: &[String]) {
```

With:
```rust
fn teardown_lock_state() {
```

Then update all call sites in main.rs. Search with: `rg "teardown_lock_state" src/main.rs`

Replace every `teardown_lock_state(persistent_lock, &server_ref.ips_entry)` with `teardown_lock_state()`.

**Step 2: `netlock.rs:620-626` — remove degenerate match**

Replace:
```rust
    for chain in &["input", "forward", "output"] {
        let dir = match *chain {
            "input" => "input",
            "forward" => "forward",
            "output" => "output",
            _ => unreachable!(),
        };
        let comment = format!("airvpn_interface_{}_{}", dir, iface);
```

With:
```rust
    for chain in &["input", "forward", "output"] {
        let comment = format!("airvpn_interface_{}_{}", chain, iface);
```

**Step 3: Build + test + clippy**

Run: `cargo build && cargo test && cargo clippy 2>&1`
Expected: compiles, all tests pass, zero/minimal clippy warnings.

---

### Task 8: Commit Phase 1

**Step 1: Verify clean state**

Run: `cargo build && cargo build --release && cargo test && cargo clippy 2>&1`
Expected: all pass.

**Step 2: Commit**

```bash
git add src/common.rs src/lib.rs src/main.rs src/wireguard.rs src/recovery.rs src/netlock.rs src/ipv6.rs src/config.rs src/crypto.rs
git commit -m "refactor: extract common.rs, fix clippy, deduplicate code

- Create src/common.rs with validate_interface_name, read_stdin_password,
  backoff_secs, MAX_RULE_DELETIONS
- Replace 6 copies of interface validation with common::validate_interface_name
- Replace 2 copies of password-stdin reading with common::read_stdin_password
- Replace 4 inline backoff formulas with common::backoff_secs
- Replace 2 MAX_RULE_DELETIONS definitions with common::MAX_RULE_DELETIONS
- Fix all clippy warnings (&PathBuf→&Path, map_or→is_some_and, etc.)
- Remove unused params from teardown_lock_state
- Remove degenerate identity match in netlock::deallow_interface"
```

---

## Phase 2: `cmd_connect` Decomposition

### Task 9: Create `src/connect.rs` with ConnectConfig and move types

**Files:**
- Create: `src/connect.rs`
- Modify: `src/lib.rs`
- Modify: `src/main.rs`

**Step 1: Create `src/connect.rs` with the config struct and helper types**

Move from `main.rs` to `connect.rs`:
- `Ipv6Mode` enum + `parse()` impl (main.rs lines 10-30)
- `ResetLevel` enum (main.rs lines 387-399, keep `#[allow(dead_code)]`)
- `EventHook` struct + `resolve()` + `is_empty()` (main.rs lines 409-444)
- `run_hook()` fn (main.rs lines 451-473)
- `ConnectConfig` struct (new)

```rust
//! VPN connection orchestration.
//!
//! Contains the main connect loop, server selection, netlock management,
//! and reconnection logic. Extracted from main.rs for readability.

use std::sync::atomic::Ordering;

use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use zeroize::Zeroizing;

use crate::{api, common, config, dns, ipv6, manifest, netlock, pinger, recovery, server, verify, wireguard};

/// Configuration for the connect command, built from CLI args.
pub struct ConnectConfig {
    pub server_name: Option<String>,
    pub no_lock: bool,
    pub allow_lan: bool,
    pub no_reconnect: bool,
    pub cli_username: Option<String>,
    pub password_stdin: bool,
    pub allow_server: Vec<String>,
    pub deny_server: Vec<String>,
    pub allow_country: Vec<String>,
    pub deny_country: Vec<String>,
    pub skip_ping: bool,
    pub no_verify: bool,
    pub no_lock_last: bool,
    pub no_start_last: bool,
    pub cli_ipv6_mode: Option<String>,
    pub cli_dns_servers: Vec<String>,
    pub cli_event_pre: [Option<String>; 3],
    pub cli_event_up: [Option<String>; 3],
    pub cli_event_down: [Option<String>; 3],
}
```

Also move `Ipv6Mode`, `ResetLevel`, `EventHook`, `run_hook` here verbatim.

**Step 2: Register in lib.rs**

Add `pub mod connect;` to `src/lib.rs`.

**Step 3: Build (won't pass yet — just checking syntax)**

Run: `cargo check 2>&1`

---

### Task 10: Move `cmd_connect` to `connect.rs` as `pub fn run`

**Files:**
- Modify: `src/connect.rs` — add the function body
- Modify: `src/main.rs` — replace `cmd_connect` with a call to `connect::run`

**Step 1: Move the entire `cmd_connect` function body to `connect.rs`**

Rename to `pub fn run(provider_config: &mut api::ProviderConfig, config: &ConnectConfig) -> Result<()>`.

Replace all 20 parameters with reads from `config.field_name`. For example:
- `no_lock` → `config.no_lock`
- `server_name` → `config.server_name.clone()`
- etc.

Also move these helper functions that are only used by cmd_connect:
- `extract_ip_from_url()` (private helper)
- `resolve_bootstrap_host()` (private helper)
- `interruptible_sleep()` (private helper)

**Step 2: Update `main.rs` dispatch**

In `main.rs`, replace the `cmd_connect(...)` call with:
```rust
connect::run(provider_config, &connect::ConnectConfig {
    server_name: server,
    no_lock,
    allow_lan,
    // ... all fields from CLI args
})
```

Remove the moved types and functions from main.rs (Ipv6Mode, ResetLevel, EventHook, run_hook, extract_ip_from_url, resolve_bootstrap_host, interruptible_sleep).

Keep in main.rs: `preflight_checks`, `cmd_disconnect_internal`, `partial_disconnect`, `teardown_lock_state` — these are used by other commands too.

**Important:** `cmd_disconnect_internal`, `partial_disconnect`, and `teardown_lock_state` are called from within `cmd_connect`. Since they stay in main.rs, they need to be made `pub(crate)` and called as `crate::` from connect.rs. OR move them to connect.rs too if they're only used by connect. Check with: `rg "cmd_disconnect_internal|partial_disconnect|teardown_lock_state" src/main.rs` to see if other commands use them.

If `cmd_disconnect` (the CLI command) also uses `cmd_disconnect_internal`, keep it in main.rs and make it `pub(crate)`. Otherwise move it.

**Step 3: Build + test**

Run: `cargo build && cargo test 2>&1`
Expected: compiles, all tests pass. Behavior identical.

---

### Task 11: Decompose — extract `preflight_and_cleanup`

**Files:**
- Modify: `src/connect.rs`

**Step 1: Extract function**

Extract lines that do pre-flight checks and orphaned state cleanup (currently the first ~40 lines of `run()`) into:

```rust
/// Pre-flight checks and orphaned state cleanup.
///
/// Verifies root, wg, nft are available, then cleans up orphaned DNS backups,
/// nftables tables, and WireGuard config files from crashed sessions.
fn preflight_and_cleanup() -> Result<()> {
    // Move: preflight_checks(), DNS backup restore, nftables orphan check,
    // WG config file cleanup, recovery::check_and_recover()
}
```

Replace in `run()` with: `preflight_and_cleanup()?;`

**Step 2: Build + test**

Run: `cargo build && cargo test 2>&1`

---

### Task 12: Decompose — extract `resolve_session` → `SessionParams`

**Files:**
- Modify: `src/connect.rs`

**Step 1: Define `SessionParams` struct**

```rust
/// Resolved session parameters derived from config + profile + environment.
struct SessionParams {
    shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    nonce: u64,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
    hook_pre: EventHook,
    hook_up: EventHook,
    hook_down: EventHook,
    ipv6_mode: Ipv6Mode,
    custom_dns_ips: Vec<String>,
    blocked_ipv6_ifaces: Vec<String>,
    persistent_lock: bool,
    profile_options: std::collections::HashMap<String, String>,
}
```

**Step 2: Extract function**

```rust
/// Resolve session parameters from config, profile, and environment.
///
/// Sets up signal handler, resolves credentials (stdin/profile/interactive),
/// event hooks, IPv6 mode, custom DNS, blocks IPv6 on all interfaces,
/// and detects persistent lock state.
fn resolve_session(config: &ConnectConfig) -> Result<SessionParams> {
    // Move: signal handler, stdin password, profile options, credential resolution,
    // hook resolution, IPv6 mode parsing, custom DNS parsing/validation,
    // ipv6::block_all(), persistent lock detection
}
```

**Step 3: Build + test**

Run: `cargo build && cargo test 2>&1`

---

### Task 13: Decompose — extract `fetch_initial_data` → `SessionData`

**Files:**
- Modify: `src/connect.rs`

**Step 1: Define `SessionData` struct**

```rust
/// Mutable session data that can be refreshed on reconnection.
struct SessionData {
    manifest: manifest::Manifest,
    user_info: manifest::UserInfo,
    filtered_servers: Vec<manifest::Server>,
    ping_results: pinger::PingResults,
    lock_last: bool,
    start_last_name: Option<String>,
}
```

**Step 2: Extract function**

```rust
/// Fetch manifest + user data, filter servers, measure latencies.
fn fetch_initial_data(
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    config: &ConnectConfig,
) -> Result<SessionData> {
    // Move: manifest fetch, RSA key update, user data fetch,
    // server filtering, ping measurement, lock_last/start_last resolution
}
```

**Step 3: Build + test**

Run: `cargo build && cargo test 2>&1`

---

### Task 14: Decompose — extract reconnection loop sub-functions

**Files:**
- Modify: `src/connect.rs`

**Step 1: Extract `refresh_manifest_if_needed`**

```rust
/// Re-fetch manifest and user data on reconnection (non-fatal).
///
/// Falls back to existing data if re-fetch fails (e.g., network disrupted).
fn refresh_manifest_if_needed(
    provider_config: &mut api::ProviderConfig,
    params: &SessionParams,
    data: &mut SessionData,
    config: &ConnectConfig,
) {
    // Move: the `if !first_iteration { ... }` block
}
```

**Step 2: Extract `run_monitor_loop`**

```rust
/// Monitor connected VPN tunnel. Returns the reset level when connection ends.
///
/// Checks every 1s: interface existence, handshake staleness, kill switch,
/// DNS re-apply, and resolv.conf verification.
fn run_monitor_loop(
    shutdown: &std::sync::atomic::AtomicBool,
    iface: &str,
    no_lock: bool,
    dns_ipv4: &str,
    dns_ipv6: &str,
) -> ResetLevel {
    // Move: the inner `loop { ... }` that currently starts at "13. Monitor loop"
}
```

**Step 3: Extract `handle_connection_failure`**

This handles the repeated pattern of "penalize → backoff → continue" that appears 3 times (WG fail, handshake fail, verify fail):

```rust
/// Handle a connection failure: penalize server, compute backoff, sleep.
/// Returns true if the loop should `continue` (reconnect), false if it should return an error.
fn handle_connection_failure(
    reason: &str,
    server_name: &str,
    lock_last: bool,
    no_reconnect: bool,
    no_lock: bool,
    penalties: &mut server::ServerPenalties,
    forced_server: &mut Option<&str>,
    consecutive_failures: &mut u32,
    blocked_ipv6_ifaces: &[String],
    shutdown: &std::sync::atomic::AtomicBool,
) -> Result<()> {
    // Shared logic for penalize + backoff + sleep
}
```

Note: this function's exact signature will depend on what the reconnection loop looks like after earlier extractions. The implementer should determine the minimal set of parameters needed.

**Step 4: Build + test**

Run: `cargo build && cargo test 2>&1`

---

### Task 15: Final verification and commit Phase 2

**Step 1: Verify everything**

Run: `cargo build && cargo build --release && cargo test && cargo clippy 2>&1`
Expected: all pass, zero clippy warnings.

**Step 2: Check line counts**

Run: `wc -l src/main.rs src/connect.rs src/common.rs`
Expected: main.rs ~500-700, connect.rs ~600-800, common.rs ~60

**Step 3: Commit**

```bash
git add src/connect.rs src/lib.rs src/main.rs
git commit -m "refactor: extract connect.rs from cmd_connect

Move the ~990-line cmd_connect into src/connect.rs with structured
decomposition:
- ConnectConfig struct replaces 20 function parameters
- preflight_and_cleanup: pre-flight checks + orphaned state cleanup
- resolve_session: credential/hook/IPv6/DNS resolution → SessionParams
- fetch_initial_data: manifest + user data + filtering → SessionData
- reconnection_loop with named sub-functions:
  - refresh_manifest_if_needed (non-fatal re-fetch)
  - run_monitor_loop (1s tick health checks)
  - handle_connection_failure (penalize + backoff)

Also moves Ipv6Mode, ResetLevel, EventHook types to connect.rs.
main.rs now only contains CLI parsing and dispatch (~600 lines)."
```

---

## Verification Checklist

After both phases:

- [ ] `cargo build` — compiles debug
- [ ] `cargo build --release` — compiles release
- [ ] `cargo test` — all unit tests pass
- [ ] `cargo clippy` — zero warnings
- [ ] `main.rs` ≤ 700 lines
- [ ] No function > 100 lines in `connect.rs`
- [ ] `rg "validate_interface_name|is_valid_interface" src/` — only in `common.rs` + thin wrappers
- [ ] `rg "MAX_RULE_DELETIONS" src/` — only in `common.rs` + use sites
- [ ] `rg "saturating_mul.*saturating_pow" src/` — zero hits (all replaced by `backoff_secs`)
