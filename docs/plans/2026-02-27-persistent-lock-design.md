# Persistent Network Lock (Kill Switch)

Android-style "always-on VPN" for Linux: nftables rules that block all non-VPN
traffic, surviving crashes, `flush ruleset`, and reboots.

## Problem

The current session netlock has a leak window during startup: DNS resolution for
bootstrap hostnames (e.g. `bootme.org`) blocks for 10-30 seconds before the
nftables rules are installed. Eddie has the same design (resolve-then-lock) and
the same leak window.

## Solution

A persistent nftables table (`airvpn_lock`) loaded at boot by a systemd service,
before networking comes up. The table blocks all outgoing traffic except:
bootstrap API IPs, LAN, DHCP, loopback, ICMP, and the VPN tunnel interface.

### Key properties

- **Crash-proof**: `flags owner, persist` — table survives process exit
- **Flush-proof**: `owner` flag makes the table immune to `nft flush ruleset`
- **Reboot-proof**: systemd oneshot service loads rules at boot (`Before=network-pre.target`)
- **Tamper-proof**: only the owning process can modify the table (others get EPERM)

Kernel requirements: `owner` flag (kernel 5.12+), `persist` flag (kernel 6.9+).

## Architecture

No explicit "modes." The table's existence determines behavior:

### Connect flow

```
table inet airvpn_lock exists?
├─ YES (persistent lock installed)
│   → reclaim ownership: nft add table inet airvpn_lock { flags owner, persist; }
│   → add server entry IP to output chain
│   → (after tunnel up) add interface rules
│   → skip session netlock activation
│
└─ NO (no persistent lock)
    → create table from scratch (current session netlock behavior)
    → full ruleset with server IPs baked in
```

### Disconnect flow

```
/etc/airvpn-rs/lock.nft exists?
├─ YES (persistent lock installed)
│   → remove server IP rule
│   → remove interface rules
│   → release ownership (table stays, becomes orphaned)
│   → base rules remain active — all non-VPN traffic still blocked
│
└─ NO (transient session lock)
    → delete entire table (current behavior)
```

### Recovery

`airvpn-rs recover` checks for `/etc/airvpn-rs/lock.nft`:
- If present: remove only dynamic rules (server IP, interface), keep base table
- If absent: delete entire table (current behavior)

## Persistent ruleset (`/etc/airvpn-rs/lock.nft`)

Base rules only — no server IPs, no tunnel interface, no `flags owner, persist`
(the file is loaded by a systemd oneshot that exits immediately).

```
table inet airvpn_lock {
  chain input {
    type filter hook input priority -300; policy drop;
    iifname "lo" counter accept
    iifname != "lo" ip6 saddr ::1 counter drop
    ip saddr 255.255.255.255 counter accept          # DHCP
    ip6 saddr ff02::1:2 counter accept                # DHCPv6
    ip6 saddr ff05::1:3 counter accept                # DHCPv6
    ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept  # LAN
    ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept
    ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept
    ip6 saddr fe80::/10 ip6 daddr fe80::/10 counter accept
    ip6 saddr ff00::/8 ip6 daddr ff00::/8 counter accept
    ip6 saddr fc00::/7 ip6 daddr fc00::/7 counter accept
    icmp type echo-request counter accept
    icmpv6 type { echo-request, echo-reply, ... } counter accept
    rt type 0 counter drop
    meta l4proto ipv6-icmp icmpv6 type nd-router-advert ip6 hoplimit 255 counter accept
    meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit ip6 hoplimit 255 counter accept
    meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert ip6 hoplimit 255 counter accept
    meta l4proto ipv6-icmp icmpv6 type nd-redirect ip6 hoplimit 255 counter accept
    ct state related,established counter accept
    counter drop comment "airvpn_filter_input_latest_rule"
  }
  chain forward { ... }  # same structure
  chain output {
    type filter hook output priority -300; policy drop;
    oifname "lo" counter accept
    # DHCP, LAN, ICMP, NDP, conntrack (same as input, mirrored)
    # Bootstrap API IPs:
    ip daddr 63.33.78.166 counter accept
    ip daddr 54.93.175.114 counter accept
    ip daddr 82.196.3.205 counter accept
    ip daddr 63.33.116.50 counter accept
    ip6 daddr 2a03:b0c0:0:1010::9b:c001 counter accept
    counter drop comment "airvpn_filter_output_latest_rule"
  }
}
```

## Systemd service (`/etc/systemd/system/airvpn-lock.service`)

```ini
[Unit]
Description=AirVPN persistent kill switch
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nft -f /etc/airvpn-rs/lock.nft
ExecStop=/usr/bin/nft delete table inet airvpn_lock

[Install]
WantedBy=sysinit.target
```

## CLI subcommands

```
airvpn-rs lock install      # generate lock.nft + service, enable, load now
airvpn-rs lock uninstall    # stop + disable service, remove files, delete table
airvpn-rs lock enable       # reload table now (nft -f)
airvpn-rs lock disable      # delete table temporarily (returns on reboot)
airvpn-rs lock status       # table active? service enabled? owned/orphaned?
```

## Edge cases

**`lock install` while connected**: Writes files, enables service. Table already
exists with dynamic rules — that's fine. Next disconnect sees `lock.nft` on disk,
keeps the base table.

**`lock uninstall` while connected**: Removes files. Table stays (in-kernel, owned
by running process). Next disconnect sees no `lock.nft`, deletes the whole table.

**Stale bootstrap IPs**: Provider.json IPs are infrastructure — rarely change.
If they do, user updates airvpn-rs and re-runs `lock install`.

**Reboot**: Systemd service loads table (unowned). airvpn-rs connect reclaims
ownership. Between boot and connect, table is unowned but active and blocking.
Nothing else touches nftables during early boot (`Before=network-pre.target`).

## Files touched

- New: `/etc/airvpn-rs/lock.nft`
- New: `/etc/systemd/system/airvpn-lock.service`
- Modified: `src/netlock.rs` — persistent ruleset generation, ownership reclaim/release
- Modified: `src/main.rs` — `Lock` subcommand, connect/disconnect flow changes
- Modified: `src/recovery.rs` — persistent-aware cleanup
