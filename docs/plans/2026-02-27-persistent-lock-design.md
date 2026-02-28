# Persistent Network Lock (Kill Switch)

Android-style "always-on VPN" for Linux: nftables rules that block all non-VPN
traffic, surviving crashes, `flush ruleset`, and reboots.

## Problem

The session netlock has a leak window during startup: DNS resolution for bootstrap
hostnames (e.g. `bootme.org`) blocks for 10-30 seconds before the nftables rules
are installed. Eddie has the same design (resolve-then-lock) and the same leak
window (NetworkLockManager.cs:127).

## Solution

Two fully independent nftables tables:

- **`airvpn_persist`** (priority -400): persistent always-on lock, loaded at boot
- **`airvpn_lock`** (priority -300): session lock (unchanged — created at connect,
  deleted at disconnect)

Both have `policy drop`. A packet must pass both chains to get through. The two
tables don't know about each other — no interaction, no coordination, no conflicts.

### How the persistent table allows VPN traffic without knowing the server IP

- Inner packets (app → internet via tunnel): `oifname "avpn-*" accept`
- Outer packets (WireGuard → server): `meta mark 51820 accept` (WireGuard stamps
  fwmark 51820 on encapsulated packets)
- Responses: `ct state related,established accept`
- Bootstrap API calls: explicit IP allowlist from provider.json

Security model: forging fwmark requires `CAP_NET_ADMIN` (root-equivalent), same
boundary as Android's always-on VPN.

### Key properties

- **Crash-proof**: `persist` flag — table survives process exit
- **Reboot-proof**: systemd oneshot service loads rules before networking
- **Operationally independent**: `lock disable/uninstall` while VPN runs — no conflict

Note on `owner` flag: owner protection only lasts while the owning netlink socket
is open. Since we use `nft -f` (opens/closes socket per invocation), the table is
effectively unowned between invocations. The `persist` flag (table survives socket
close) is the important one. `reclaim_and_delete()` must do both in a single
`nft -f` transaction.

Kernel requirements: `owner` (5.12+), `persist` (6.9+).

## Flows

### Boot (no VPN)

```
systemd loads airvpn_persist → blocks everything except LAN/DHCP/bootstrap
no airvpn_lock exists → only one table, everything blocked
```

### Connect

```
airvpn connect → auth via bootstrap IPs (allowed by airvpn_persist)
              → creates airvpn_lock (session lock, same as before)
              → starts WireGuard
              → outer packets (fwmark 51820) pass airvpn_persist
              → inner packets (oifname avpn-*) pass airvpn_persist
              → server IP + interface pass airvpn_lock
              → connected
```

### Disconnect

```
airvpn disconnect → deletes airvpn_lock (session lock gone)
                  → airvpn_persist stays → everything blocked again
```

### lock disable while VPN running

```
lock disable → deletes airvpn_persist only
             → airvpn_lock still running → VPN works, session lock protects
             → no conflict, no crash
```

### lock uninstall while VPN running

```
lock uninstall → removes files + service, deletes airvpn_persist
               → airvpn_lock still running → VPN works
               → on disconnect → airvpn_lock deleted → internet open
```

## Persistent ruleset (`/etc/airvpn-rs/lock.nft`)

```
table inet airvpn_persist {
  flags owner, persist;

  chain input {
    type filter hook input priority -400; policy drop;
    iifname "lo" counter accept
    iifname != "lo" ip6 saddr ::1 counter drop
    iifname "avpn-*" counter accept                    # VPN tunnel
    # DHCP, LAN, ICMP, NDP, NAT64, conntrack...
    ct state related,established counter accept
    counter drop
  }

  chain forward {
    type filter hook forward priority -400; policy drop;
    rt type 0 counter drop
    iifname "avpn-*" counter accept                    # tunnel → local
    oifname "avpn-*" counter accept                    # local → tunnel
    counter drop
  }

  chain output {
    type filter hook output priority -400; policy drop;
    oifname "lo" counter accept
    oifname "avpn-*" counter accept                    # inner VPN packets
    meta mark 51820 counter accept                     # outer WireGuard packets
    # DHCP, LAN, ICMP, NDP, NAT64...
    # Bootstrap IPs:
    ip daddr 63.33.78.166 counter accept
    ip daddr 54.93.175.114 counter accept
    ip daddr 82.196.3.205 counter accept
    ip daddr 63.33.116.50 counter accept
    ip6 daddr 2a03:b0c0:0:1010::9b:c001 counter accept
    counter drop
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
ExecStop=/bin/sh -c 'printf "add table inet airvpn_persist { flags owner, persist; }\\ndelete table inet airvpn_persist\\n" | /usr/bin/nft -f -'

[Install]
WantedBy=sysinit.target
```

## CLI subcommands

```
airvpn-rs lock install      # generate lock.nft + service, enable, load now
airvpn-rs lock uninstall    # stop + disable service, remove files, delete table
airvpn-rs lock enable       # reload table now (nft -f)
airvpn-rs lock disable      # delete table temporarily (returns on reboot)
airvpn-rs lock status       # table active? service enabled?
```

## Edge cases

**Stale bootstrap IPs**: Provider.json IPs are infrastructure — rarely change.
If they do, user updates airvpn-rs and re-runs `lock install`.

**Reboot**: Systemd service loads table (orphaned after nft exits). Active and
blocking before networking comes up.

## Files

- `/etc/airvpn-rs/lock.nft` — persistent ruleset
- `/etc/systemd/system/airvpn-lock.service` — boot-time loader
- `src/netlock.rs` — persistent + session ruleset generation
- `src/main.rs` — Lock subcommand (session lock code untouched)

## Design history

Initial implementation used a single shared table (`airvpn_lock`) for both
persistent and session lock. This caused operational conflicts: couldn't
disable/uninstall persistent lock while VPN was running, monitor loop fought
with lock management commands, reclaim_ownership semantics were broken by
nft -f's ephemeral netlink sockets. Reworked to two independent tables based
on Android's approach (separate enforcement layers). See git history for the
single-table iteration.
