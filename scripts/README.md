# Validation Toolkit

Scripts for validating airvpn-rs against Eddie (reference implementation) and detecting security leaks.

## Quick Start

```bash
# Terminal 1: Start leak monitor (run throughout all tests)
sudo ./leak-monitor.sh

# Terminal 2: Run validation
sudo ./rule-diff.sh              # Check netlock rules match Eddie spec
sudo ./chaos-test.sh suspend     # Test suspend/resume
sudo ./chaos-test.sh all         # Run all non-destructive chaos tests
```

## Scripts

### `leak-monitor.sh` — Real-time Leak Detection

Watches physical interfaces for any traffic not going to the VPN endpoint. **Run this in a separate terminal during all testing.**

```bash
sudo ./leak-monitor.sh                           # Auto-detect endpoint
sudo ./leak-monitor.sh --endpoint 1.2.3.4        # Manual endpoint
sudo ./leak-monitor.sh --duration 60             # Run for 60 seconds
```

Any traffic that appears is a **potential leak**. Captured to `/tmp/leak-monitor/` for analysis.

### `rule-diff.sh` — Eddie Compliance Check

Verifies nftables rules match Eddie's required structure:

```bash
sudo ./rule-diff.sh              # Human-readable report
sudo ./rule-diff.sh --verbose    # Show passing checks too
sudo ./rule-diff.sh --json       # Machine-readable output
```

Checks:
- All chains have `policy drop`
- Required rules present (loopback, conntrack, NDP, RH0 drop, etc.)
- Priority is -300 or lower (runs before other tables)
- VPN endpoint is allowlisted

### `chaos-test.sh` — Edge Case Simulation

Simulates failure scenarios to verify netlock holds:

| Test | What it does | Destructive? |
|------|--------------|--------------|
| `suspend` | SIGSTOP/SIGCONT (simulates sleep) | No |
| `net-down` | Physical interface down/up | No |
| `dns-block` | Temporarily blocks port 53 | No |
| `kill-interface` | Deletes WireGuard interface | Yes (needs reconnect) |
| `sigkill` | SIGKILL the process | Yes (needs recovery) |
| `all` | Runs non-destructive tests | No |

```bash
sudo ./chaos-test.sh suspend              # Test suspend/resume
sudo ./chaos-test.sh --dry-run sigkill    # See what would happen
sudo ./chaos-test.sh all                  # Full non-destructive suite
```

**Always run `leak-monitor.sh` in parallel** to detect any leaks during chaos.

### `eddie-compare.sh` — Behavioral Diff

Captures system state snapshots from both implementations for comparison:

```bash
# 1. Connect with airvpn-rs, then capture
sudo ./eddie-compare.sh capture-airvpn

# 2. Disconnect airvpn-rs, connect with Eddie (same server)
sudo ./eddie-compare.sh capture-eddie

# 3. Compare
./eddie-compare.sh diff
./eddie-compare.sh report    # Generate markdown report
```

Captures: nftables, iptables, routes, DNS, WireGuard config, IPv6 status.

## Recommended Test Sequence

### Daily/CI Validation
```bash
# With VPN connected:
sudo ./rule-diff.sh && echo "Rules OK"
```

### Full Security Validation (manual)
```bash
# Terminal 1 (keep running):
sudo ./leak-monitor.sh

# Terminal 2:
sudo ./rule-diff.sh
sudo ./chaos-test.sh suspend
sudo ./chaos-test.sh net-down
sudo ./chaos-test.sh dns-block

# Check Terminal 1 - should show NO traffic
```

### Eddie Parity Check
```bash
# Connect airvpn-rs to server X
sudo ./eddie-compare.sh capture-airvpn
airvpn disconnect

# Connect Eddie to same server X
# (via Eddie GUI or CLI)
sudo ./eddie-compare.sh capture-eddie

# Compare
./eddie-compare.sh report
```

## Exit Codes

| Script | 0 | 1 | 2 |
|--------|---|---|---|
| leak-monitor | No leaks | Leak detected | Setup error |
| rule-diff | Rules match | Differences found | Setup error |
| chaos-test | Test completed | Test failed | Usage error |
| eddie-compare | Success | — | Error |

## Dependencies

- `tcpdump` (leak-monitor)
- `nft` (rule-diff, chaos-test)
- `jq` (all scripts, for state file parsing)
- `wg` (wireguard-tools)
- `ip` (iproute2)

## Files

- `/run/airvpn-rs/state.json` — airvpn-rs recovery state
- `/tmp/leak-monitor/` — Captured leak traffic (pcap + txt)
- `/tmp/vpn-compare/` — Eddie comparison snapshots
