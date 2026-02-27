# Plan: Replace wg-quick with Direct WireGuard Setup

## Goal

Remove wg-quick dependency and use direct `ip`/`wg` commands. This enables:
1. Setting `net.ipv6.conf.default.disable_ipv6=1` BEFORE interface creation (no race)
2. Matching Eddie's IPv6 behavior exactly (no IPv6 on tunnel in block mode)
3. Removing IPv6 DNS nameserver (matching Eddie)
4. Fewer moving parts — we already do routing, DNS, and netlock ourselves

## Current State

wg-quick is only used for 5 commands (with `Table = off`, no DNS, no PostUp/PostDown):
- `ip link add dev <iface> type wireguard`
- `wg setconf <iface> <conf>`
- `ip -4 address add` + `ip -6 address add`
- `ip link set mtu` + `ip link set up`
- Disconnect: `ip link delete`

We already handle: routing (`setup_routing`), DNS (`dns.rs`), netlock (`netlock.rs`).

## Changes

### 1. `src/ipv6.rs` — Block `default` (matches Eddie)

**In `block_all()`:**
- Remove `"default"` from skip list on line 44: `"all" | "lo" | "lo0"` (was `"all" | "default" | "lo" | "lo0"`)
- Delete lines 28-33 that force `default` to 0
- Fix the incorrect doc comment (lines 18-23) that claims Eddie doesn't set `default`

**Result:** New interfaces (including WireGuard) inherit `disable_ipv6=1`. No race.

### 2. `src/wireguard.rs` — Replace wg-quick

**Split `generate_config()` return value:**

Currently returns `(Zeroizing<String>, String)` where the String is endpoint_ip.
The config contains wg-quick extensions (`Address`, `MTU`, `Table = off`).

New approach: return a struct with the wg-native config AND the address/MTU info separately.

```rust
pub struct WgConnectParams {
    /// wg-native config (PrivateKey + Peer section only, for `wg setconf`)
    pub wg_config: zeroize::Zeroizing<String>,
    /// IPv4 address with CIDR (e.g., "10.167.32.97/32")
    pub ipv4_address: String,
    /// IPv6 address with CIDR — kept for future `in` mode but NOT used in block mode
    pub ipv6_address: String,
    /// MTU value
    pub mtu: u16,
    /// VPN server endpoint IP
    pub endpoint_ip: String,
}
```

The `wg_config` only contains fields `wg setconf` understands:
```ini
[Interface]
PrivateKey = ...

[Peer]
PublicKey = ...
PresharedKey = ...       (if present)
Endpoint = ...
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
```

No `Address`, no `MTU`, no `Table = off`.

**Rewrite `connect()`:**

Replace `wg-quick up <config>` with:
1. Write wg-native config to temp file (same secure dir, same cleanup)
2. `ip link add dev <iface> type wireguard`
3. `wg setconf <iface> <config_path>` — private key stays in file, not cmdline
4. `ip -4 address add <ipv4>/32 dev <iface>` — IPv4 only (no IPv6 in block mode)
5. `ip link set mtu 1320 dev <iface>`
6. `ip link set up dev <iface>`
7. `setup_routing()` — unchanged

Error handling: if any step fails, clean up previous steps (delete interface, remove config file). Same pattern as current code.

**Rewrite `disconnect()`:**

Replace `wg-quick down <config>` with:
1. `teardown_routing()` — unchanged (already called first)
2. Derive interface name from config path (already done)
3. `ip link delete dev <iface>`
4. Clean up config file (already done)

The `disconnect()` signature stays the same: `fn disconnect(config_path: &str, endpoint_ip: &str)`.

**Update callers in `main.rs`:**

`generate_config()` is called at ~line 800. Currently:
```rust
let (wg_config, endpoint_ip) = wireguard::generate_config(&wg_key, &server, &mode, &user)?;
```

New:
```rust
let params = wireguard::generate_config(&wg_key, &server, &mode, &user)?;
```

Then `connect()` takes `&params` instead of `(config: &str, endpoint_ip: &str)`.

### 3. `src/dns.rs` — Skip IPv6 nameserver in block mode

**In `build_resolv_conf()` and `activate()`:**

Pass empty string for `dns_ipv6` when IPv6 is blocked. This is simplest — the caller in `main.rs` already has the `blocked_ipv6_ifaces` list. If it's non-empty, pass `""` for dns_ipv6.

No change to `dns.rs` itself — just the call site in `main.rs` (~line 923):
```rust
// Before:
dns::activate(&wg_key.wg_dns_ipv4, &wg_key.wg_dns_ipv6, &iface)?;

// After:
let dns_ipv6 = if blocked_ipv6_ifaces.is_empty() { &wg_key.wg_dns_ipv6 } else { "" };
dns::activate(&wg_key.wg_dns_ipv4, dns_ipv6, &iface)?;
```

### 4. Tests — Update for new config format

In `wireguard.rs` tests:
- `test_generate_config_format`: Remove assertions for `Table = off`, `Address =`, `MTU =`. Add assertions for wg-native format (no Address/MTU/Table lines).
- Other `test_generate_config_*` tests: Update to use new return type (`WgConnectParams`). Endpoint IP moves from tuple element to struct field.
- Keep all validation tests unchanged (key injection, IP injection, etc.)

### 5. `docs/known_divergences.md` — Update

- Remove mention of wg-quick if no longer relevant
- Note that IPv6 handling now matches Eddie's `in-block` mode

## File Change Summary

| File | Change | Scope |
|------|--------|-------|
| `src/ipv6.rs` | Remove `default` from skip list, delete force-reset, fix comment | 3 edits |
| `src/wireguard.rs` | Add `WgConnectParams`, rewrite `generate_config`, `connect`, `disconnect` | ~150 lines |
| `src/main.rs` | Update `generate_config` and `connect` call sites, skip IPv6 DNS | ~10 lines |
| `src/dns.rs` | No changes | — |
| `docs/known_divergences.md` | Update IPv6 section | Small |

## Verification

1. `cargo build && cargo build --release` — both must compile
2. `cargo test` — all tests pass
3. `sudo ./scripts/rule-diff.sh --verbose` — 0 errors
4. Connect to VPN, verify:
   - `wg show` shows connected interface
   - Interface has IPv4 address only (no IPv6)
   - `cat /etc/resolv.conf` shows only IPv4 nameserver
   - `sysctl net.ipv6.conf.default.disable_ipv6` = 1
   - `sudo ./scripts/chaos-test.sh all` — netlock holds
5. `sudo ./scripts/eddie-compare.sh capture-airvpn` — compare against previous Eddie snapshot
