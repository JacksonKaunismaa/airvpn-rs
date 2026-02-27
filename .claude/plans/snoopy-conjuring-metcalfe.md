# Plan: Add `--ipv6-mode` Setting (Eddie Parity)

## Context

Eddie has `network.ipv6.mode` with three values: `in`, `in-block` (default), `block`. We hardcoded `block` behavior. The user wants the full setting to match Eddie.

**Eddie's logic (Session.cs):**
- `block` → always disable IPv6
- `in-block` (default) → disable IPv6 if `!server.support_ipv6`, allow if server supports it
- `in` → always allow IPv6 through tunnel

For WireGuard (unlike OpenVPN), there's no version restriction, so `in-block` on a server with `support_ipv6=true` means IPv6 is allowed.

## Design

### IPv6 mode enum

```rust
enum Ipv6Mode { In, InBlock, Block }
```

### Behavior per mode

| Mode | `ipv6::block_all()` | WG IPv6 addr | IPv6 DNS | `default.disable_ipv6` |
|------|---------------------|--------------|----------|------------------------|
| `block` | All interfaces + default | No | No | 1 |
| `in-block` + `!server.support_ipv6` | Same as `block` | No | No | 1 |
| `in-block` + `server.support_ipv6` | Same as `in` | Yes | Yes | 1 |
| `in` | All interfaces + default, then re-enable on WG interface | Yes | Yes | 1 |

**Key security property:** `default.disable_ipv6=1` is ALWAYS set (all modes). In `in`/`in-block` mode, IPv6 is explicitly re-enabled on just the WG interface after creation. No race — the interface inherits disabled, we re-enable it.

### Resolution chain (highest priority first)

1. CLI `--ipv6-mode in|in-block|block`
2. Profile `network.ipv6.mode` (from `/etc/airvpn-rs/default.profile`)
3. Default: `in-block` (matches Eddie)

## Files to Modify

### 1. `src/main.rs` — CLI flag + flow control

**CLI struct (~line 19):** Add `--ipv6-mode` to `Commands::Connect`:
```rust
#[arg(long, default_value = "in-block")]
ipv6_mode: String,
```

**`cmd_connect()` signature (~line 285):** Add `ipv6_mode: String` parameter.

**Resolve effective mode (~line 535, before the loop):**
```rust
// Resolve IPv6 mode: CLI flag > profile option > default (in-block)
let ipv6_mode_str = if cli_ipv6_mode != "in-block" {
    cli_ipv6_mode.clone()  // CLI explicitly set
} else {
    profile_options.get("network.ipv6.mode")
        .cloned()
        .unwrap_or_else(|| "in-block".to_string())
};
let ipv6_mode = Ipv6Mode::parse(&ipv6_mode_str)?;
```

**IPv6 blocking (~line 535):** Still always call `block_all()` (blocks everything including default).

**Inside the loop — after server selection (~line 640):** Compute effective IPv6 for this connection:
```rust
let ipv6_enabled = match ipv6_mode {
    Ipv6Mode::In => true,
    Ipv6Mode::InBlock => server_ref.support_ipv6,
    Ipv6Mode::Block => false,
};
```

**WireGuard connect (~line 822):** Pass `ipv6_enabled` to `connect()`:
```rust
let (config_path, iface) = wireguard::connect(&wg_params, ipv6_enabled)?;
```

**DNS activate (~line 927):** Conditional IPv6 DNS:
```rust
let dns_ipv6 = if ipv6_enabled { &wg_key.wg_dns_ipv6 } else { "" };
dns::activate(&wg_key.wg_dns_ipv4, dns_ipv6, &iface)?;
```

**All `check_and_reapply` and `verify_resolv_conf` calls in monitor loop:** Same conditional.

### 2. `src/wireguard.rs` — Conditional IPv6 address

**`connect()` (~line 204):** Add `ipv6_enabled: bool` parameter. After bringing interface up:
```rust
if ipv6_enabled && !params.ipv6_address.is_empty() {
    // Re-enable IPv6 on this specific interface (inherits disabled from default)
    let _ = std::fs::write(
        format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", iface), "0"
    );
    // Add IPv6 address
    let output = Command::new("ip")
        .args(["-6", "address", "add", &params.ipv6_address, "dev", &iface])
        ...
}
```

### 3. `src/ipv6.rs` — No changes

`block_all()` always blocks everything including `default`. The per-interface re-enable for `in` mode happens in `wireguard::connect()`.

### 4. `src/netlock.rs` — No changes

The nftables rules already handle both IPv4 and IPv6 in the `inet` table. When IPv6 is enabled on the tunnel, traffic flows through the WG interface which is already allowlisted.

## What Does NOT Change

- `ipv6.rs` — always blocks everything (security baseline)
- `netlock.rs` — already handles IPv6
- `recovery.rs` — unchanged
- `setup_routing()` — already adds IPv6 routes in table 51820

## Verification

1. `cargo build && cargo build --release && cargo test`
2. `--ipv6-mode block`: same as current (no IPv6 addr, no IPv6 DNS, disable_ipv6=1 everywhere)
3. `--ipv6-mode in`: IPv6 addr on WG interface, IPv6 DNS in resolv.conf, disable_ipv6=0 on WG only
4. `--ipv6-mode in-block` on server with `support_ipv6=true`: same as `in`
5. `--ipv6-mode in-block` on server with `support_ipv6=false`: same as `block`
6. `sudo ./scripts/rule-diff.sh --verbose` — 0 errors in all modes
