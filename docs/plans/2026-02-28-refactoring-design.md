# Code Quality Refactoring Design

**Date:** 2026-02-28
**Approach:** Phased (C) — quick wins first, then structural extraction

## Problem

The codebase is ~11K lines with solid module structure, but has accumulated
technical debt:

- `cmd_connect` is ~990 lines with 20 parameters
- Interface name validation duplicated 6 times
- Password-stdin reading duplicated verbatim in 2 places
- Backoff formula duplicated 4 times inline
- `MAX_RULE_DELETIONS` constant defined twice
- 13 clippy warnings
- Dead parameters and degenerate pattern matches

## Phase 1: Quick Wins

One commit. Low risk, high value.

### 1a. Create `src/common.rs`

Shared utilities that don't belong to any single module:

```rust
// src/common.rs

/// Interface name validation (replaces 6 copies across wireguard, netlock, ipv6, recovery).
/// Linux interface names: max 15 chars, alphanumeric + '-' + '_'.
pub fn validate_interface_name(name: &str) -> bool

/// Read password from stdin when --password-stdin is set.
/// Used by cmd_connect and cmd_servers.
pub fn read_stdin_password(password_stdin: bool) -> Result<Option<Zeroizing<String>>>

/// Exponential backoff: 3 * 2^(n-1) capped at 300 seconds.
/// Replaces 4 inline copies in the reconnection loop.
pub fn backoff_secs(consecutive_failures: u32) -> u64

/// Maximum routing rule deletions per teardown pass.
/// Used by wireguard::teardown_routing and recovery::recover_from_state.
pub const MAX_RULE_DELETIONS: usize = 100;
```

Register in `src/lib.rs`:
```rust
pub mod common;
```

### 1b. Fix all 13 clippy warnings

| File | Warning | Fix |
|------|---------|-----|
| `config.rs:45` | useless `PathBuf::from()` conversion | Remove wrapper |
| `config.rs:285,310,372` | `&PathBuf` → `&Path` | Change param type |
| `config.rs:300,322` | `map_or(false, \|i\| ...)` | Use `is_some_and()` |
| `crypto.rs:165` | explicit auto-deref `&*key`, `&*iv` | Use `&key`, `&iv` |
| `main.rs:1544` | collapsible `if` | Merge conditions |
| `main.rs:1644,1652` | `sort_by` → `sort_by_key` | Use `sort_by_key` |

### 1c. Dead code cleanup

- **`teardown_lock_state`**: Remove unused `_persistent_lock` and `_server_ips` parameters
- **`netlock.rs:620`**: Remove degenerate `match *chain { "input" => "input", ... }` — use `chain` directly
- **`ResetLevel::Switch`**: Keep (documents Eddie protocol completeness, has match arm)

## Phase 2: `cmd_connect` Decomposition

Second commit. Structural change, same behavior.

### 2a. `ConnectConfig` struct

Replace the 20 parameters with a config struct built from CLI args in `main.rs`:

```rust
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

### 2b. Create `src/connect.rs`

Function decomposition:

```
pub fn run(provider_config: &mut ProviderConfig, config: &ConnectConfig) -> Result<()>
│
├── preflight_and_cleanup()
│     Pre-flight checks (root, wg, nft)
│     Orphaned DNS/nftables/WG config cleanup
│
├── resolve_session() → SessionParams
│     Signal handler setup
│     Credential resolution (stdin, profile, interactive)
│     Event hook resolution
│     IPv6 mode + custom DNS resolution
│     IPv6 blocking (block_all)
│     Persistent lock detection
│
├── fetch_initial_data() → SessionData
│     Manifest fetch + RSA key update
│     User data fetch
│     Server filtering
│     Ping measurement
│     Lock/start last resolution
│
└── reconnection_loop(params, data, ...)
      The outer loop { ... } broken into:
      ├── refresh_manifest_if_needed()   non-fatal re-fetch
      ├── select_server_and_connect()    server pick → netlock → auth → WG → handshake
      ├── post_connect_setup()           DNS, creds save, recovery state
      ├── verify_connection()            tunnel + DNS verification
      ├── monitor_loop()                 1s tick checks (interface, handshake, DNS, netlock)
      └── handle_reset()                 ResetLevel dispatch (None/Error/Retry/Switch)
```

Target: each extracted function ≤100 lines.

### 2c. Types moved to `connect.rs`

- `Ipv6Mode` + `parse()`
- `EventHook` + `resolve()` + `run_hook()`
- `ResetLevel` enum
- `interruptible_sleep()`
- `extract_ip_from_url()`, `resolve_bootstrap_host()`

### 2d. What stays in `main.rs`

- `Cli` / `Commands` structs (clap derive)
- `main()` → dispatch
- `cmd_servers`, `cmd_disconnect`, `cmd_lock_*`
- `init_logging`, `preflight_checks`
- `cmd_disconnect_internal`, `partial_disconnect`, `teardown_lock_state`

Expected result: `main.rs` drops from 2052 → ~600 lines.

## Constraints

- Every commit must compile and pass `cargo test`
- No behavior changes — pure refactor
- Existing integration tests (`tests/integration.rs`) must pass unchanged
- No new dependencies
