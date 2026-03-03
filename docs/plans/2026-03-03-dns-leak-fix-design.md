# DNS Leak Fix: Fixed Interface Name + LAN DNS Block

## Context

DNS queries leak in plaintext through the physical WiFi interface during VPN
reconnection. The persistent and session nftables locks allow RFC1918 LAN traffic
(`ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 accept`), and since both the user's
WiFi IP (e.g. `10.73.33.211`) and AirVPN's DNS (`10.128.0.1`) are in the same
`/8`, DNS queries pass through the LAN rule when the tunnel is down.

Domain names are visible in plaintext to anyone on the local network. Eddie has
the same vulnerability.

Additionally, the WireGuard interface uses a random tempfile-derived name
(`avpn-XXXXX`) each connection, forcing wildcard matching (`avpn-*`) in nftables
rules. A fixed name is more secure (exact match) and simpler to debug.

## Changes

### 1. Fixed interface name `avpn0`

- Add `pub const VPN_INTERFACE: &str = "avpn0"` in `wireguard.rs`
- Use constant in `connect()` instead of deriving from tempfile basename
- Replace all `avpn-*` wildcards with exact `"avpn0"` in nft rulesets
- Update cleanup code, shell scripts, tests, and docs

### 2. DNS leak block rules (output chain only)

Insert before LAN rules in both `generate_persistent_ruleset()` and
`generate_ruleset()` (when `allow_lan` is true):

```
oifname != "avpn0" ip daddr { 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 } udp dport { 53, 853 } counter drop
oifname != "avpn0" ip daddr { 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 } tcp dport { 53, 853 } counter drop
oifname != "avpn0" ip6 daddr { fe80::/10, ff00::/8, fc00::/7 } udp dport { 53, 853 } counter drop
oifname != "avpn0" ip6 daddr { fe80::/10, ff00::/8, fc00::/7 } tcp dport { 53, 853 } counter drop
```

When tunnel is up: DNS to `10.128.0.1` goes via `avpn0` -> doesn't match
`!= "avpn0"` -> passes to tunnel accept rule. When tunnel is down: DNS falls
back to physical interface -> matches `!= "avpn0"` -> dropped.

## Files

| File | Change |
|------|--------|
| `src/wireguard.rs` | Add `VPN_INTERFACE` constant, use in `connect()`, update tests |
| `src/netlock.rs` | DNS block rules + `avpn-*` -> `avpn0` in both rulesets + tests |
| `src/connect.rs` | Update cleanup pattern for config files |
| `src/recovery.rs` | Update cleanup pattern + test fixtures |
| `src/common.rs` | Update test example |
| `scripts/leak-monitor.sh` | Update interface filter regex |
| `scripts/rule-diff.sh` | Update interface detection regex |
| `tests/robustness-tier2.sh` | Update grep pattern |
| `tests/adversarial-tier3.sh` | Update grep pattern |
| `tests/integration.rs` | Update pattern matching |
| `docs/known_divergences.md` | Update examples, document DNS leak fix as divergence |

## Verification

1. `cargo build && cargo build --release`
2. `cargo test` (especially netlock and wireguard tests)
3. Manual: `sudo ./target/debug/airvpn connect` -- interface is `avpn0`
4. Manual: `sudo nft list table inet airvpn_persist` -- DNS drop rules before LAN rules
5. Manual: `sudo ./scripts/leak-monitor.sh --strict` -- no DNS leaks during reconnection
