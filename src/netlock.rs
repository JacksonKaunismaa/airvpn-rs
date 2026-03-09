//! Network lock (nftables kill switch) — prevents IP leaks when VPN is down.
//!
//! Uses a dedicated `table inet airvpn_lock` at priority -300 instead of
//! Eddie's `flush ruleset` approach. Eddie has separate lock implementations
//! for iptables and nftables; we are nftables-only. The filter chain rules
//! match Eddie's NetworkLockNftables.cs.
//!
//! Security model: nftables `drop` is terminal across all tables. A packet
//! must be `accept`ed by ALL chains at the same hook to proceed. Our chains
//! at priority -300 run before everything else and default to `drop`.
//!
//! Reference: Eddie src/Lib.Platform.Linux/NetworkLockNftables.cs

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::IpAddr;
use std::process::Command;

const TABLE_NAME: &str = "airvpn_lock";
const PRIORITY: i32 = -300;

const PERSIST_TABLE_NAME: &str = "airvpn_persist";
const PERSIST_PRIORITY: i32 = -400;

/// Path to the persistent lock rules file.
pub const PERSISTENT_RULES_PATH: &str = "/etc/airvpn-rs/lock.nft";

/// Path to the persistent lock systemd service.
pub const PERSISTENT_SERVICE_PATH: &str = "/etc/systemd/system/airvpn-lock.service";

/// Configuration for the network lock.
///
/// Eddie splits allowlisted IPs into two categories:
/// - **incoming**: IPs that may initiate connections TO us. In INPUT they get
///   unrestricted `saddr accept`; in OUTPUT they get restricted
///   `daddr ct state established accept` (response-only).
/// - **outgoing**: IPs that WE initiate connections to (VPN servers, API IPs).
///   They only appear in OUTPUT with unrestricted `daddr accept`.
pub struct NetlockConfig {
    pub allow_lan: bool,
    pub allow_dhcp: bool,
    pub allow_ping: bool,
    pub allow_ipv4ipv6translation: bool,
    pub allowed_ips_incoming: Vec<String>,
    pub allowed_ips_outgoing: Vec<String>,
    /// Whether incoming policy is accept (true) or drop (false, default).
    /// Eddie: `netlock.incoming == "allow"` → "accept" policy.
    /// When false (block/block mode), the OUTPUT conntrack rule is omitted
    /// to avoid interfering with WireGuard keepalive packets.
    /// Reference: NetworkLockNftables.cs line 274
    pub incoming_policy_accept: bool,
    /// WireGuard interface name for tunnel traffic matching in DNS leak rules.
    /// Resolved from `network.iface.name` option (default: "avpn0").
    pub iface_name: String,
    /// CIDRs from custom routes with action="out" — bypass VPN tunnel.
    /// These get `daddr accept` in the OUTPUT chain so traffic isn't blocked.
    pub custom_route_out_cidrs: Vec<String>,
    /// CIDRs from `netlock.allowlist.outgoing.ips` — allowed through firewall only.
    /// No routing change, just firewall passthrough.
    pub allowlist_out_cidrs: Vec<String>,
    /// Local interfaces (e.g. phone-relay) to allow forwarding through the VPN tunnel.
    /// Adds FORWARD rules (iface↔vpn) to both lock chains and NAT masquerade to persist.
    pub local_forward_ifaces: Vec<String>,
}

/// Compute SHA-256 hex digest of a string (matching Eddie's Crypto.Manager.HashSHA256).
fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Classify an IP/CIDR string as v4 or v6.
fn classify_ip(ip_str: &str) -> Option<IpVersion> {
    // Strip CIDR prefix if present
    let addr_part = ip_str.split('/').next()?;
    let addr: IpAddr = addr_part.parse().ok()?;
    match addr {
        IpAddr::V4(_) => Some(IpVersion::V4),
        IpAddr::V6(_) => Some(IpVersion::V6),
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum IpVersion {
    V4,
    V6,
}

/// Ensure an IP string has a CIDR suffix. If none, appends /32 (v4) or /128 (v6).
fn ensure_cidr(ip_str: &str) -> String {
    if ip_str.contains('/') {
        return ip_str.to_string();
    }
    match classify_ip(ip_str) {
        Some(IpVersion::V4) => format!("{}/32", ip_str),
        Some(IpVersion::V6) => format!("{}/128", ip_str),
        None => ip_str.to_string(),
    }
}

/// Generate the full nftables ruleset as a string (for writing to tmpfile + nft -f).
///
/// Rule ordering matches Eddie's NetworkLockNftables.cs Activation() exactly,
/// adapted from separate ip/ip6 tables to a single inet table.
pub fn generate_ruleset(config: &NetlockConfig) -> String {
    let mut r = String::new();

    // Table definition
    r.push_str(&format!("table inet {} {{\n", TABLE_NAME));

    // =========================================================================
    // INPUT chain
    // =========================================================================
    r.push_str(&format!(
        "  chain input {{\n    type filter hook input priority {}; policy drop;\n",
        PRIORITY
    ));

    // 1. Loopback accept (Eddie: ip filter INPUT iifname "lo" + ip6 filter INPUT iifname "lo")
    r.push_str("    iifname \"lo\" counter accept\n");

    // 2. IPv6 anti-spoof: drop ::1 not from lo
    //    Eddie uses "reject" in a separate ip6 table. In our inet table,
    //    bare "reject" fails on some nftables versions (needs icmpx type).
    //    "drop" achieves the same anti-spoof protection.
    r.push_str("    iifname != \"lo\" ip6 saddr ::1 counter drop\n");

    // 3. DHCP rules
    if config.allow_dhcp {
        // Eddie: ip filter INPUT ip saddr 255.255.255.255 counter accept
        r.push_str("    ip saddr 255.255.255.255 counter accept\n");
        // Eddie: ip6 filter INPUT ip6 saddr ff02::1:2 counter accept
        r.push_str("    ip6 saddr ff02::1:2 counter accept\n");
        // Eddie: ip6 filter INPUT ip6 saddr ff05::1:3 counter accept
        r.push_str("    ip6 saddr ff05::1:3 counter accept\n");
    }

    // IPv4/IPv6 translation (NAT64 — RFC 6052/8215)
    if config.allow_ipv4ipv6translation {
        r.push_str("    ip6 saddr 64:ff9b::/96 ip6 daddr 64:ff9b::/96 counter accept\n");
        r.push_str("    ip6 saddr 64:ff9b:1::/48 ip6 daddr 64:ff9b:1::/48 counter accept\n");
    }

    // 4. LAN rules (Eddie: netlock.allow_private)
    if config.allow_lan {
        // IPv4 RFC1918 bidirectional
        r.push_str("    ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept\n");
        r.push_str("    ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept\n");
        r.push_str("    ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept\n");

        // IPv6 link-local, multicast, ULA
        r.push_str("    ip6 saddr fe80::/10 ip6 daddr fe80::/10 counter accept\n");
        r.push_str("    ip6 saddr ff00::/8 ip6 daddr ff00::/8 counter accept\n");
        r.push_str("    ip6 saddr fc00::/7 ip6 daddr fc00::/7 counter accept\n");
    }

    // 5. ICMP/ICMPv6 (Eddie: netlock.allow_ping)
    if config.allow_ping {
        // Eddie: ip filter INPUT icmp type echo-request counter accept
        r.push_str("    icmp type echo-request counter accept\n");
        // ICMPv6: only allow safe diagnostic types (not all ICMPv6 — broad accept
        // would permit tunneling via unused types like mobile/experimental).
        // NDP types are handled separately below with hoplimit 255 restriction.
        r.push_str("    icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } counter accept\n");
    }

    // 6. IPv6 RH0 drop — disable processing of routing header type 0 (ping-pong attack)
    //    (Eddie: ip6 filter INPUT rt type 0 counter drop)
    r.push_str("    rt type 0 counter drop\n");

    // 7. IPv6 NDP — required for IPv6 address allocation (hoplimit 255)
    //    (Eddie: 4 separate rules for router-advert, neighbor-solicit, neighbor-advert, redirect)
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-router-advert ip6 hoplimit 255 counter accept\n",
    );
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit ip6 hoplimit 255 counter accept\n",
    );
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert ip6 hoplimit 255 counter accept\n",
    );
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-redirect ip6 hoplimit 255 counter accept\n",
    );

    // 8. Conntrack: allow established/related
    //    (Eddie: ip filter INPUT ct state related,established + ip6 filter INPUT ct state related,established)
    r.push_str("    ct state related,established counter accept\n");

    // 9. Per-IP allowlist incoming (only incoming IPs get saddr accept in INPUT)
    for ip_str in &config.allowed_ips_incoming {
        let cidr = ensure_cidr(ip_str);
        match classify_ip(&cidr) {
            Some(IpVersion::V4) => {
                let comment =
                    format!("eddie_ip_{}", sha256_hex(&format!("ipv4_in_{}_1", cidr)));
                r.push_str(&format!(
                    "    ip saddr {} counter accept comment \"{}\"\n",
                    cidr, comment
                ));
            }
            Some(IpVersion::V6) => {
                let comment =
                    format!("eddie_ip_{}", sha256_hex(&format!("ipv6_in_{}_1", cidr)));
                r.push_str(&format!(
                    "    ip6 saddr {} counter accept comment \"{}\"\n",
                    cidr, comment
                ));
            }
            None => {}
        }
    }

    // 10. Final drop (redundant with policy, but provides a handle for rule insertion)
    //     (Eddie: "eddie_ip_filter_INPUT_latest_rule" / "eddie_ip6_filter_INPUT_latest_rule")
    r.push_str("    counter drop comment \"airvpn_filter_input_latest_rule\"\n");

    r.push_str("  }\n\n");

    // =========================================================================
    // FORWARD chain
    // =========================================================================
    r.push_str(&format!(
        "  chain forward {{\n    type filter hook forward priority {}; policy drop;\n",
        PRIORITY
    ));

    // 1. IPv6 RH0 drop
    r.push_str("    rt type 0 counter drop\n");

    // Local interfaces forwarded through VPN (e.g. phone-relay)
    for local_iface in &config.local_forward_ifaces {
        r.push_str(&format!(
            "    iifname \"{}\" oifname \"{}\" ct state new,established counter accept\n",
            local_iface, config.iface_name
        ));
        r.push_str(&format!(
            "    iifname \"{}\" oifname \"{}\" ct state related,established counter accept\n",
            config.iface_name, local_iface
        ));
    }

    // Final drop (handle for interface insertion)
    r.push_str("    counter drop comment \"airvpn_filter_forward_latest_rule\"\n");

    r.push_str("  }\n\n");

    // =========================================================================
    // OUTPUT chain
    // =========================================================================
    r.push_str(&format!(
        "  chain output {{\n    type filter hook output priority {}; policy drop;\n",
        PRIORITY
    ));

    // 1. Loopback accept
    r.push_str("    oifname \"lo\" counter accept\n");

    // 2. IPv6 RH0 drop (Eddie puts this before DHCP/LAN in output)
    r.push_str("    rt type 0 counter drop\n");

    // 3. DHCP rules
    if config.allow_dhcp {
        // Eddie: ip filter OUTPUT ip daddr 255.255.255.255 counter accept
        r.push_str("    ip daddr 255.255.255.255 counter accept\n");
        // Eddie: ip6 filter OUTPUT ip6 daddr ff02::1:2 counter accept
        r.push_str("    ip6 daddr ff02::1:2 counter accept\n");
        // Eddie: ip6 filter OUTPUT ip6 daddr ff05::1:3 counter accept
        r.push_str("    ip6 daddr ff05::1:3 counter accept\n");
    }

    // IPv4/IPv6 translation (NAT64 — RFC 6052/8215)
    if config.allow_ipv4ipv6translation {
        r.push_str("    ip6 saddr 64:ff9b::/96 ip6 daddr 64:ff9b::/96 counter accept\n");
        r.push_str("    ip6 saddr 64:ff9b:1::/48 ip6 daddr 64:ff9b:1::/48 counter accept\n");
    }

    // 4. Block DNS (port 53/853) to LAN destinations on non-tunnel interfaces.
    // Must come before LAN rules to prevent DNS from leaking through the RFC1918
    // accept rules when the tunnel is down (e.g., WiFi 10.73.x.x -> VPN DNS 10.128.0.1).
    if config.allow_lan {
        let iface = &config.iface_name;
        r.push_str(&format!("    oifname != \"{}\" ip daddr {{ 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 }} udp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface));
        r.push_str(&format!("    oifname != \"{}\" ip daddr {{ 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 }} tcp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface));
        r.push_str(&format!("    oifname != \"{}\" ip6 daddr {{ fe80::/10, ff00::/8, fc00::/7 }} udp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface));
        r.push_str(&format!("    oifname != \"{}\" ip6 daddr {{ fe80::/10, ff00::/8, fc00::/7 }} tcp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface));
    }

    // 4b. LAN rules (Eddie: netlock.allow_private)
    if config.allow_lan {
        // IPv4 RFC1918 bidirectional (same as input)
        r.push_str("    ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept\n");
        r.push_str("    ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept\n");
        r.push_str("    ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept\n");

        // IPv4 multicast (output only — Eddie has these in output but not input)
        r.push_str("    ip saddr 192.168.0.0/16 ip daddr 224.0.0.0/24 counter accept\n");
        r.push_str("    ip saddr 10.0.0.0/8 ip daddr 224.0.0.0/24 counter accept\n");
        r.push_str("    ip saddr 172.16.0.0/12 ip daddr 224.0.0.0/24 counter accept\n");

        // SSDP (Simple Service Discovery Protocol)
        r.push_str("    ip saddr 192.168.0.0/16 ip daddr 239.255.255.250 counter accept\n");
        r.push_str("    ip saddr 10.0.0.0/8 ip daddr 239.255.255.250 counter accept\n");
        r.push_str("    ip saddr 172.16.0.0/12 ip daddr 239.255.255.250 counter accept\n");

        // SLPv2 (Service Location Protocol version 2)
        r.push_str("    ip saddr 192.168.0.0/16 ip daddr 239.255.255.253 counter accept\n");
        r.push_str("    ip saddr 10.0.0.0/8 ip daddr 239.255.255.253 counter accept\n");
        r.push_str("    ip saddr 172.16.0.0/12 ip daddr 239.255.255.253 counter accept\n");

        // IPv6 link-local, multicast, ULA
        r.push_str("    ip6 saddr fe80::/10 ip6 daddr fe80::/10 counter accept\n");
        r.push_str("    ip6 saddr ff00::/8 ip6 daddr ff00::/8 counter accept\n");
        r.push_str("    ip6 saddr fc00::/7 ip6 daddr fc00::/7 counter accept\n");
    }

    // 5. ICMP/ICMPv6 (Eddie: netlock.allow_ping)
    if config.allow_ping {
        // Eddie: ip filter OUTPUT icmp type echo-reply counter accept
        r.push_str("    icmp type echo-reply counter accept\n");
        // ICMPv6: only allow safe diagnostic types (matching INPUT restrictions).
        r.push_str("    icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } counter accept\n");
    }

    // 6. Conntrack in OUTPUT: only when incoming policy is accept (Eddie behavior).
    //    In block/block mode (default), this is omitted to avoid interfering with
    //    WireGuard keepalive packets.
    //    Eddie: NetworkLockNftables.cs line 272-278 — `if (defaultPolicyInput == "ACCEPT")`
    //    Note: Eddie uses `ct state established` (not `related,established`) here.
    if config.incoming_policy_accept {
        r.push_str("    ct state established counter accept\n");
    }

    // 7a. Allowlist incoming IPs — response-only (ct state established)
    //     Eddie: foreach ipsAllowlistIncoming → daddr + ct state established, suffix _2
    for ip_str in &config.allowed_ips_incoming {
        let cidr = ensure_cidr(ip_str);
        match classify_ip(&cidr) {
            Some(IpVersion::V4) => {
                let comment =
                    format!("eddie_ip_{}", sha256_hex(&format!("ipv4_in_{}_2", cidr)));
                r.push_str(&format!(
                    "    ip daddr {} ct state established counter accept comment \"{}\"\n",
                    cidr, comment
                ));
            }
            Some(IpVersion::V6) => {
                let comment =
                    format!("eddie_ip_{}", sha256_hex(&format!("ipv6_in_{}_2", cidr)));
                r.push_str(&format!(
                    "    ip6 daddr {} ct state established counter accept comment \"{}\"\n",
                    cidr, comment
                ));
            }
            None => {}
        }
    }

    // 7b. Allowlist outgoing IPs — unrestricted
    //     Eddie: foreach ipsAllowlistOutgoing → daddr accept, suffix _1
    for ip_str in &config.allowed_ips_outgoing {
        let cidr = ensure_cidr(ip_str);
        match classify_ip(&cidr) {
            Some(IpVersion::V4) => {
                let comment =
                    format!("eddie_ip_{}", sha256_hex(&format!("ipv4_out_{}_1", cidr)));
                r.push_str(&format!(
                    "    ip daddr {} counter accept comment \"{}\"\n",
                    cidr, comment
                ));
            }
            Some(IpVersion::V6) => {
                let comment =
                    format!("eddie_ip_{}", sha256_hex(&format!("ipv6_out_{}_1", cidr)));
                r.push_str(&format!(
                    "    ip6 daddr {} counter accept comment \"{}\"\n",
                    cidr, comment
                ));
            }
            None => {}
        }
    }

    // 8. Custom route "out" CIDRs — bypass tunnel (unrestricted daddr accept)
    for cidr_str in &config.custom_route_out_cidrs {
        let cidr = ensure_cidr(cidr_str);
        match classify_ip(&cidr) {
            Some(IpVersion::V4) => {
                r.push_str(&format!(
                    "    ip daddr {} counter accept comment \"airvpn_custom_route_out\"\n",
                    cidr
                ));
            }
            Some(IpVersion::V6) => {
                r.push_str(&format!(
                    "    ip6 daddr {} counter accept comment \"airvpn_custom_route_out\"\n",
                    cidr
                ));
            }
            None => {}
        }
    }

    // 9. Netlock allowlist CIDRs — firewall passthrough only (no routing change)
    for cidr_str in &config.allowlist_out_cidrs {
        let cidr = ensure_cidr(cidr_str);
        match classify_ip(&cidr) {
            Some(IpVersion::V4) => {
                r.push_str(&format!(
                    "    ip daddr {} counter accept comment \"airvpn_allowlist_out\"\n",
                    cidr
                ));
            }
            Some(IpVersion::V6) => {
                r.push_str(&format!(
                    "    ip6 daddr {} counter accept comment \"airvpn_allowlist_out\"\n",
                    cidr
                ));
            }
            None => {}
        }
    }

    // 10. Final drop (handle for rule insertion)
    r.push_str("    counter drop comment \"airvpn_filter_output_latest_rule\"\n");

    r.push_str("  }\n");
    r.push_str("}\n");

    r
}

/// Generate the persistent lock ruleset for `/etc/airvpn-rs/lock.nft`.
///
/// This is a base ruleset with LAN, DHCP, ICMP, NDP, conntrack, and bootstrap
/// API IPs. No server IPs, no tunnel interface rules.
///
/// The table is created with `flags owner, persist`. When the systemd oneshot
/// loads this at boot and exits, `persist` keeps the table alive in an orphaned
/// state (owner process exited).
///
/// This is a standalone `airvpn_persist` table, fully independent from the
/// session lock (`airvpn_lock`). VPN traffic passes via `oifname "<iface>"`
/// (inner packets) and `meta mark 51820` (outer WireGuard packets).
///
/// This table is independent of the session lock (`airvpn_lock`). It runs at
/// priority -400 (before the session lock at -300). A packet must pass BOTH
/// tables to get through.
///
/// The persistent table allows VPN traffic generically:
/// - `oifname "<iface>"` / `iifname "<iface>"`: inner tunnel packets
/// - `meta mark 51820`: outer WireGuard packets (marked by routing policy)
///
/// The `iface_name` parameter specifies the WireGuard interface name
/// (resolved from `network.iface.name` option, default "avpn0").
pub fn generate_persistent_ruleset(bootstrap_ips: &[String], iface_name: &str, allowlist_out_cidrs: &[String], local_forward_ifaces: &[String]) -> String {
    let mut r = String::new();

    // Table definition with owner+persist flags
    r.push_str(&format!("table inet {} {{\n", PERSIST_TABLE_NAME));
    r.push_str("  flags owner, persist;\n");

    // =========================================================================
    // INPUT chain
    // =========================================================================
    r.push_str(&format!(
        "  chain input {{\n    type filter hook input priority {}; policy drop;\n",
        PERSIST_PRIORITY
    ));

    // 1. Loopback
    r.push_str("    iifname \"lo\" counter accept\n");

    // 2. IPv6 anti-spoof: drop ::1 not from lo
    r.push_str("    iifname != \"lo\" ip6 saddr ::1 counter drop\n");

    // 3. DHCP
    r.push_str("    ip saddr 255.255.255.255 counter accept\n");
    r.push_str("    ip6 saddr ff02::1:2 counter accept\n");
    r.push_str("    ip6 saddr ff05::1:3 counter accept\n");

    // 4. NAT64 (IPv4/IPv6 translation — RFC 6052/8215)
    r.push_str("    ip6 saddr 64:ff9b::/96 ip6 daddr 64:ff9b::/96 counter accept\n");
    r.push_str("    ip6 saddr 64:ff9b:1::/48 ip6 daddr 64:ff9b:1::/48 counter accept\n");

    // 5. LAN (always enabled for persistent lock)
    // IPv4 RFC1918 bidirectional
    r.push_str("    ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept\n");
    r.push_str("    ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept\n");
    r.push_str("    ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept\n");
    // IPv6 link-local, multicast, ULA
    r.push_str("    ip6 saddr fe80::/10 ip6 daddr fe80::/10 counter accept\n");
    r.push_str("    ip6 saddr ff00::/8 ip6 daddr ff00::/8 counter accept\n");
    r.push_str("    ip6 saddr fc00::/7 ip6 daddr fc00::/7 counter accept\n");

    // 6. ICMP/ICMPv6 (Eddie model: be pingable — accept inbound requests, no outbound initiation)
    r.push_str("    icmp type echo-request counter accept\n");
    r.push_str("    icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } counter accept\n");

    // 7. IPv6 RH0 drop
    r.push_str("    rt type 0 counter drop\n");

    // 8. IPv6 NDP (hoplimit 255)
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-router-advert ip6 hoplimit 255 counter accept\n",
    );
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit ip6 hoplimit 255 counter accept\n",
    );
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert ip6 hoplimit 255 counter accept\n",
    );
    r.push_str(
        "    meta l4proto ipv6-icmp icmpv6 type nd-redirect ip6 hoplimit 255 counter accept\n",
    );

    // 9. Conntrack
    r.push_str("    ct state related,established counter accept\n");

    // 10. VPN tunnel interface (inner packets arriving from tunnel)
    r.push_str(&format!("    iifname \"{}\" counter accept\n", iface_name));

    // Final drop sentinel
    r.push_str("    counter drop comment \"airvpn_persist_input_latest_rule\"\n");

    r.push_str("  }\n\n");

    // =========================================================================
    // FORWARD chain
    // =========================================================================
    r.push_str(&format!(
        "  chain forward {{\n    type filter hook forward priority {}; policy drop;\n",
        PERSIST_PRIORITY
    ));

    // IPv6 RH0 drop
    r.push_str("    rt type 0 counter drop\n");

    // VPN tunnel interface (forwarded traffic through tunnel)
    r.push_str(&format!("    iifname \"{}\" counter accept\n", iface_name));
    r.push_str(&format!("    oifname \"{}\" counter accept\n", iface_name));

    // Local interfaces forwarded through VPN (e.g. phone-relay)
    for local_iface in local_forward_ifaces {
        r.push_str(&format!(
            "    iifname \"{}\" oifname \"{}\" ct state new,established counter accept\n",
            local_iface, iface_name
        ));
        r.push_str(&format!(
            "    iifname \"{}\" oifname \"{}\" ct state related,established counter accept\n",
            iface_name, local_iface
        ));
    }

    // Final drop sentinel
    r.push_str("    counter drop comment \"airvpn_persist_forward_latest_rule\"\n");

    r.push_str("  }\n\n");

    // NAT chain for local interfaces forwarded through VPN
    if !local_forward_ifaces.is_empty() {
        r.push_str("  chain postrouting {\n");
        r.push_str("    type nat hook postrouting priority srcnat; policy accept;\n");
        for local_iface in local_forward_ifaces {
            r.push_str(&format!(
                "    iifname \"{}\" oifname \"{}\" counter masquerade comment \"local_forward_masq_{}\"\n",
                local_iface, iface_name, local_iface
            ));
        }
        r.push_str("  }\n\n");
    }

    // =========================================================================
    // ping_allow subchain (empty by default — populated by populate_ping_allow())
    // =========================================================================
    r.push_str("  chain ping_allow {\n");
    r.push_str("  }\n\n");

    // =========================================================================
    // OUTPUT chain
    // =========================================================================
    r.push_str(&format!(
        "  chain output {{\n    type filter hook output priority {}; policy drop;\n",
        PERSIST_PRIORITY
    ));

    // 1. Loopback
    r.push_str("    oifname \"lo\" counter accept\n");

    // 2. IPv6 RH0 drop
    r.push_str("    rt type 0 counter drop\n");

    // 3. DHCP
    r.push_str("    ip daddr 255.255.255.255 counter accept\n");
    r.push_str("    ip6 daddr ff02::1:2 counter accept\n");
    r.push_str("    ip6 daddr ff05::1:3 counter accept\n");

    // 4. NAT64
    r.push_str("    ip6 saddr 64:ff9b::/96 ip6 daddr 64:ff9b::/96 counter accept\n");
    r.push_str("    ip6 saddr 64:ff9b:1::/48 ip6 daddr 64:ff9b:1::/48 counter accept\n");

    // 5. Block DNS (port 53/853) to LAN destinations on non-tunnel interfaces.
    // Without this, DNS queries leak through the LAN rules below when the tunnel
    // is down (e.g., during reconnection). The VPN DNS (10.128.0.1) is in the
    // same RFC1918 /8 as many WiFi networks, so the LAN rule accepts it.
    // Queries through the tunnel are unaffected.
    r.push_str(&format!("    oifname != \"{}\" ip daddr {{ 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 }} udp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface_name));
    r.push_str(&format!("    oifname != \"{}\" ip daddr {{ 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 }} tcp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface_name));
    r.push_str(&format!("    oifname != \"{}\" ip6 daddr {{ fe80::/10, ff00::/8, fc00::/7 }} udp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface_name));
    r.push_str(&format!("    oifname != \"{}\" ip6 daddr {{ fe80::/10, ff00::/8, fc00::/7 }} tcp dport {{ 53, 853 }} counter drop comment \"block_lan_dns_leak\"\n", iface_name));

    // 6. LAN (always enabled)
    // RFC1918 bidirectional
    r.push_str("    ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept\n");
    r.push_str("    ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept\n");
    r.push_str("    ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept\n");
    // IPv6
    r.push_str("    ip6 saddr fe80::/10 ip6 daddr fe80::/10 counter accept\n");
    r.push_str("    ip6 saddr ff00::/8 ip6 daddr ff00::/8 counter accept\n");
    r.push_str("    ip6 saddr fc00::/7 ip6 daddr fc00::/7 counter accept\n");
    // LAN multicast (mDNS, SSDP, SLPv2)
    for subnet in &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"] {
        r.push_str(&format!(
            "    ip saddr {} ip daddr 224.0.0.0/24 counter accept\n",
            subnet
        ));
        r.push_str(&format!(
            "    ip saddr {} ip daddr 239.255.255.250 counter accept\n",
            subnet
        ));
        r.push_str(&format!(
            "    ip saddr {} ip daddr 239.255.255.253 counter accept\n",
            subnet
        ));
    }

    // 6. ICMP/ICMPv6 (Eddie model: respond to pings only — no outbound initiation)
    r.push_str("    icmp type echo-reply counter accept\n");
    // ICMPv6: no echo-request in output (matches IPv4 treatment). Outbound echo-request
    // for IPv6 servers is handled by per-IP rules in the ping_allow subchain.
    r.push_str("    icmpv6 type { echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } counter accept\n");

    // 7. Per-server ICMP hole-punching (jump to subchain, empty by default)
    r.push_str("    jump ping_allow\n");

    // 8. Bootstrap IPs (allow API access without VPN)
    for ip_str in bootstrap_ips {
        let cidr = ensure_cidr(ip_str);
        match classify_ip(&cidr) {
            Some(IpVersion::V4) => {
                r.push_str(&format!(
                    "    ip daddr {} counter accept comment \"airvpn_persist_bootstrap\"\n",
                    cidr
                ));
            }
            Some(IpVersion::V6) => {
                r.push_str(&format!(
                    "    ip6 daddr {} counter accept comment \"airvpn_persist_bootstrap\"\n",
                    cidr
                ));
            }
            None => {}
        }
    }

    // 9. Netlock allowlist CIDRs — firewall passthrough (persists across reconnections)
    for cidr_str in allowlist_out_cidrs {
        let cidr = ensure_cidr(cidr_str);
        match classify_ip(&cidr) {
            Some(IpVersion::V4) => {
                r.push_str(&format!(
                    "    ip daddr {} counter accept comment \"airvpn_persist_allowlist_out\"\n",
                    cidr
                ));
            }
            Some(IpVersion::V6) => {
                r.push_str(&format!(
                    "    ip6 daddr {} counter accept comment \"airvpn_persist_allowlist_out\"\n",
                    cidr
                ));
            }
            None => {}
        }
    }

    // 10. VPN tunnel interface (inner packets going into tunnel)
    r.push_str(&format!("    oifname \"{}\" counter accept\n", iface_name));

    // 11. WireGuard outer packets (marked by routing policy table 51820)
    r.push_str("    meta mark 51820 counter accept\n");

    // Final drop sentinel
    r.push_str("    counter drop comment \"airvpn_persist_output_latest_rule\"\n");

    r.push_str("  }\n\n");

    // Close table
    r.push_str("}\n");

    r
}

/// Activate the network lock: write ruleset to tmpfile and load via `nft -f`.
///
/// If the table already exists (e.g., reconnection), performs an atomic
/// replacement by prepending `flush table inet airvpn_lock` to the ruleset
/// and loading both in a single `nft -f` call. This avoids the leak window
/// that would occur if we deleted the table first and then created a new one.
pub fn activate(config: &NetlockConfig) -> Result<()> {
    let ruleset = generate_ruleset(config);

    // If the table already exists, prepend a flush command so the kernel
    // processes flush + new rules atomically in a single nft -f transaction.
    let content = if is_active() {
        format!("flush table inet {}\n{}", TABLE_NAME, ruleset)
    } else {
        ruleset
    };

    // Write to a temporary file
    let mut tmpfile =
        tempfile::NamedTempFile::new().context("failed to create temporary nftables file")?;
    tmpfile
        .write_all(content.as_bytes())
        .context("failed to write nftables ruleset to tmpfile")?;
    tmpfile
        .flush()
        .context("failed to flush nftables tmpfile")?;

    let output = Command::new("nft")
        .arg("-f")
        .arg(tmpfile.path())
        .output()
        .context("failed to execute nft")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft -f failed: {}", stderr);
    }

    Ok(())
}

/// Deactivate the network lock: delete our dedicated table.
///
/// Idempotent — returns Ok(()) if the table doesn't exist.
pub fn deactivate() -> Result<()> {
    if !is_active() {
        return Ok(());
    }

    let output = Command::new("nft")
        .args(["delete", "table", "inet", TABLE_NAME])
        .output()
        .context("failed to execute nft delete table")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft delete table failed: {}", stderr);
    }

    Ok(())
}

/// Reclaim ownership and delete the persistent table in a single nft -f transaction.
///
/// Because each `nft` invocation opens a new netlink socket (new portid),
/// reclaim and delete must happen in the SAME invocation. Otherwise:
/// 1. reclaim — nft opens socket, reclaims, exits → table orphaned
/// 2. delete — new nft, new portid, can't delete orphaned owner table → EPERM
///
/// This function writes both commands to a single tmpfile and loads atomically.
/// Operates on `airvpn_persist`, NOT `airvpn_lock`.
pub fn reclaim_and_delete() -> Result<()> {
    if !is_persist_active() {
        return Ok(());
    }

    let cmd = format!(
        "add table inet {} {{ flags owner, persist; }}\ndelete table inet {}\n",
        PERSIST_TABLE_NAME, PERSIST_TABLE_NAME
    );
    let mut tmpfile =
        tempfile::NamedTempFile::new().context("failed to create temp nft file")?;
    tmpfile
        .write_all(cmd.as_bytes())
        .context("failed to write nft commands")?;
    tmpfile.flush().context("failed to flush nft commands")?;

    let output = Command::new("nft")
        .arg("-f")
        .arg(tmpfile.path())
        .output()
        .context("failed to execute nft")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft reclaim+delete failed: {}", stderr);
    }
    Ok(())
}

/// Check if our session nftables table (`airvpn_lock`) exists.
pub fn is_active() -> bool {
    let output = Command::new("nft")
        .args(["list", "table", "inet", TABLE_NAME])
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Check if the persistent nftables table (`airvpn_persist`) exists.
pub fn is_persist_active() -> bool {
    let output = Command::new("nft")
        .args(["list", "table", "inet", PERSIST_TABLE_NAME])
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Build the nft batch commands for per-IP ICMP ping holes.
///
/// Returns the batch string and the count of valid rules generated.
/// Pure function — no side effects, testable without root.
fn build_ping_hole_rules(server_ips: &[String]) -> (String, usize) {
    let mut batch = String::new();
    let mut seen = std::collections::HashSet::new();
    let mut count = 0;

    for ip_str in server_ips {
        let ip_str = ip_str.trim();
        if ip_str.is_empty() {
            continue;
        }
        // Validate it's a real IP to prevent injection
        if ip_str.parse::<IpAddr>().is_err() {
            continue;
        }
        // Deduplicate (multiple servers can share entry IPs)
        if !seen.insert(ip_str.to_string()) {
            continue;
        }
        if ip_str.contains(':') {
            // IPv6
            batch.push_str(&format!(
                "add rule inet {} ping_allow ip6 daddr {} icmpv6 type echo-request counter accept\n",
                PERSIST_TABLE_NAME, ip_str
            ));
        } else {
            // IPv4
            batch.push_str(&format!(
                "add rule inet {} ping_allow ip daddr {} icmp type echo-request counter accept\n",
                PERSIST_TABLE_NAME, ip_str
            ));
        }
        count += 1;
    }

    (batch, count)
}

/// Build the nft batch commands for per-IP all-protocol allowlist rules.
///
/// Unlike `build_ping_hole_rules` (ICMP-only), this generates `ip daddr <ip> accept`
/// rules that allow all protocols. Only used in tests.
#[cfg(test)]
fn build_server_allowlist_rules(server_ips: &[String]) -> (String, usize) {
    let mut batch = String::new();
    let mut seen = std::collections::HashSet::new();
    let mut count = 0;

    for ip_str in server_ips {
        let ip_str = ip_str.trim();
        if ip_str.is_empty() {
            continue;
        }
        // Validate it's a real IP to prevent injection
        if ip_str.parse::<IpAddr>().is_err() {
            continue;
        }
        // Deduplicate (multiple servers can share entry IPs)
        if !seen.insert(ip_str.to_string()) {
            continue;
        }
        if ip_str.contains(':') {
            // IPv6
            batch.push_str(&format!(
                "add rule inet {} ping_allow ip6 daddr {} counter accept\n",
                PERSIST_TABLE_NAME, ip_str
            ));
        } else {
            // IPv4
            batch.push_str(&format!(
                "add rule inet {} ping_allow ip daddr {} counter accept\n",
                PERSIST_TABLE_NAME, ip_str
            ));
        }
        count += 1;
    }

    (batch, count)
}

/// Populate the persistent lock's `ping_allow` subchain with ICMP-only rules
/// for all known server IPs. These rules stay permanently so the background
/// pinger can always reach servers without per-cycle open/close overhead.
///
/// Flushes existing rules first, then adds fresh ones. Idempotent — safe to
/// call whenever the server IP list changes (manifest refresh, cache load).
///
/// No-op if the persistent table is not active.
pub fn populate_ping_allow(server_ips: &[String]) -> Result<()> {
    if !is_persist_active() {
        return Ok(());
    }
    if server_ips.is_empty() {
        return Ok(());
    }

    let (rules, count) = build_ping_hole_rules(server_ips);
    if rules.is_empty() {
        return Ok(());
    }

    // Flush + repopulate in a single nft -f transaction
    let batch = format!(
        "flush chain inet {} ping_allow\n{}",
        PERSIST_TABLE_NAME, rules
    );

    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to spawn nft for ping_allow")?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(batch.as_bytes())
            .context("failed to write ping_allow rules")?;
    }
    let output = child
        .wait_with_output()
        .context("failed to wait on nft for ping_allow")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft failed to populate ping_allow: {}", stderr.trim());
    }

    log::info!(
        "Populated ping_allow in persistent lock ({} server IPs)",
        count
    );
    Ok(())
}

/// Allow VPN interface traffic (called when tunnel comes up).
///
/// Inserts accept rules for the interface into input, forward, and output chains,
/// positioned before the final drop rule (matching Eddie's handle-based insertion).
///
/// Eddie equivalent: netlock-nftables-interface action=add
pub fn allow_interface(iface: &str) -> Result<()> {
    // Validate interface name to prevent nft command injection
    if !crate::common::validate_interface_name(iface) {
        anyhow::bail!("invalid interface name: {:?}", iface);
    }

    // Input: iifname "<iface>" accept
    nft_insert_before_latest(
        "input",
        &format!(
            "iifname \"{}\" counter accept comment \"airvpn_interface_input_{}\"",
            iface, iface
        ),
    )?;

    // Forward: iifname "<iface>" accept (traffic forwarded FROM tunnel)
    nft_insert_before_latest(
        "forward",
        &format!(
            "iifname \"{}\" counter accept comment \"airvpn_interface_forward_{}\"",
            iface, iface
        ),
    )?;

    // Forward: oifname "<iface>" accept (traffic forwarded TO tunnel)
    nft_insert_before_latest(
        "forward",
        &format!(
            "oifname \"{}\" counter accept comment \"airvpn_interface_forward_out_{}\"",
            iface, iface
        ),
    )?;

    // Output: oifname "<iface>" accept
    nft_insert_before_latest(
        "output",
        &format!(
            "oifname \"{}\" counter accept comment \"airvpn_interface_output_{}\"",
            iface, iface
        ),
    )?;

    Ok(())
}

/// Remove VPN interface rules (called when tunnel goes down).
///
/// Eddie equivalent: netlock-nftables-interface action=del
pub fn deallow_interface(iface: &str) -> Result<()> {
    // Validate interface name to prevent nft command injection
    if !crate::common::validate_interface_name(iface) {
        anyhow::bail!("invalid interface name: {:?}", iface);
    }

    for chain in &["input", "forward", "output"] {
        let comment = format!("airvpn_interface_{}_{}", chain, iface);
        nft_delete_by_comment(chain, &comment)?;
    }

    // Also remove the oifname forward rule
    let comment_out = format!("airvpn_interface_forward_out_{}", iface);
    nft_delete_by_comment("forward", &comment_out)?;

    Ok(())
}

/// Insert a rule into a chain, positioned before the "latest_rule" sentinel.
///
/// Uses `nft -a list chain` to find the handle of the sentinel rule,
/// then `nft insert rule ... position <handle>`.
fn nft_insert_before_latest(chain: &str, rule: &str) -> Result<()> {
    let comment_search = format!("airvpn_filter_{}_latest_rule", chain);
    let handle = find_rule_handle(chain, &comment_search)?;

    // Write command to tmpfile and use nft -f to avoid
    // split_whitespace breaking quoted arguments
    let cmd = format!(
        "insert rule inet {} {} position {} {}\n",
        TABLE_NAME, chain, handle, rule
    );

    let mut tmpfile =
        tempfile::NamedTempFile::new().context("failed to create temporary nft command file")?;
    tmpfile
        .write_all(cmd.as_bytes())
        .context("failed to write nft command")?;
    tmpfile.flush().context("failed to flush nft command file")?;

    let output = Command::new("nft")
        .arg("-f")
        .arg(tmpfile.path())
        .output()
        .context("failed to execute nft insert rule")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft insert rule failed: {}", stderr);
    }

    Ok(())
}

/// Delete a rule by its comment tag.
fn nft_delete_by_comment(chain: &str, comment: &str) -> Result<()> {
    match find_rule_handle(chain, comment) {
        Ok(handle) => {
            let output = Command::new("nft")
                .args([
                    "delete",
                    "rule",
                    "inet",
                    TABLE_NAME,
                    chain,
                    "handle",
                    &handle,
                ])
                .output()
                .context("failed to execute nft delete rule")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("nft delete rule failed: {}", stderr);
            }
            Ok(())
        }
        Err(_) => {
            // Rule already removed — not an error
            Ok(())
        }
    }
}

/// Find the nftables handle number for a rule identified by its comment.
///
/// Runs `nft -n -a list chain inet airvpn_lock <chain>` and searches
/// for the line containing the comment, extracting `# handle <N>`.
fn find_rule_handle(chain: &str, comment: &str) -> Result<String> {
    let output = Command::new("nft")
        .args(["-n", "-a", "list", "chain", "inet", TABLE_NAME, chain])
        .output()
        .context("failed to execute nft list chain")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nft list chain failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains(comment) {
            // Lines look like: `    counter drop comment "..." # handle 42`
            if let Some(handle_pos) = line.rfind("# handle ") {
                let handle_str = &line[handle_pos + 9..];
                let handle = handle_str.trim();
                if !handle.is_empty() {
                    return Ok(handle.to_string());
                }
            }
        }
    }

    anyhow::bail!(
        "rule with comment '{}' not found in chain '{}'",
        comment,
        chain
    )
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> NetlockConfig {
        NetlockConfig {
            allow_lan: false,
            allow_dhcp: true,
            allow_ping: true,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        }
    }

    #[test]
    fn test_ruleset_basic() {
        let config = default_config();
        let ruleset = generate_ruleset(&config);

        // Table structure
        assert!(ruleset.contains(&format!("table inet {}", TABLE_NAME)));

        // Chain definitions with correct priority and policy
        assert!(ruleset.contains(&format!(
            "type filter hook input priority {}; policy drop;",
            PRIORITY
        )));
        assert!(ruleset.contains(&format!(
            "type filter hook forward priority {}; policy drop;",
            PRIORITY
        )));
        assert!(ruleset.contains(&format!(
            "type filter hook output priority {}; policy drop;",
            PRIORITY
        )));

        // Loopback accept (input and output)
        assert!(ruleset.contains("iifname \"lo\" counter accept"));
        assert!(ruleset.contains("oifname \"lo\" counter accept"));

        // IPv6 anti-spoof
        assert!(ruleset.contains("iifname != \"lo\" ip6 saddr ::1 counter drop"));

        // Conntrack only in input (OUTPUT conntrack omitted when incoming_policy_accept=false)
        let ct_count = ruleset.matches("ct state related,established counter accept").count();
        assert_eq!(ct_count, 1, "should have conntrack rule only in input when incoming_policy_accept=false");

        // Final sentinel rules
        assert!(ruleset.contains("airvpn_filter_input_latest_rule"));
        assert!(ruleset.contains("airvpn_filter_forward_latest_rule"));
        assert!(ruleset.contains("airvpn_filter_output_latest_rule"));

        // DHCP rules present (allow_dhcp=true by default)
        assert!(ruleset.contains("ip saddr 255.255.255.255 counter accept"));
        assert!(ruleset.contains("ip6 saddr ff02::1:2 counter accept"));

        // Ping rules present (allow_ping=true by default)
        assert!(ruleset.contains("icmp type echo-request counter accept"));
        assert!(ruleset.contains("icmp type echo-reply counter accept"));
    }

    #[test]
    fn test_ruleset_with_allowed_ips() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![
                "185.236.200.1".to_string(),
                "2001:db8::1".to_string(),
            ],
            allowed_ips_outgoing: vec![
                "10.128.0.0/24".to_string(),
                "203.0.113.5".to_string(),
            ],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // --- INPUT chain: incoming IPs get saddr accept ---

        // IPv4 incoming: saddr accept (comment suffix _1)
        let expected_v4_in_comment = format!(
            "eddie_ip_{}",
            sha256_hex("ipv4_in_185.236.200.1/32_1")
        );
        assert!(
            ruleset.contains(&format!(
                "ip saddr 185.236.200.1/32 counter accept comment \"{}\"",
                expected_v4_in_comment
            )),
            "INPUT should contain IPv4 incoming allowlist saddr rule"
        );

        // IPv6 incoming: saddr accept (comment suffix _1)
        let expected_v6_in_comment = format!(
            "eddie_ip_{}",
            sha256_hex("ipv6_in_2001:db8::1/128_1")
        );
        assert!(
            ruleset.contains(&format!(
                "ip6 saddr 2001:db8::1/128 counter accept comment \"{}\"",
                expected_v6_in_comment
            )),
            "INPUT should contain IPv6 incoming allowlist saddr rule"
        );

        // Outgoing IPs should NOT appear in INPUT
        assert!(
            !ruleset.contains("ip saddr 10.128.0.0/24"),
            "outgoing IPs should not appear as saddr in INPUT"
        );
        assert!(
            !ruleset.contains("ip saddr 203.0.113.5"),
            "outgoing IPs should not appear as saddr in INPUT"
        );

        // --- OUTPUT chain: incoming IPs get ct state established (response-only) ---

        // IPv4 incoming in OUTPUT: daddr + ct state established (comment suffix _2)
        let expected_v4_in_out_comment = format!(
            "eddie_ip_{}",
            sha256_hex("ipv4_in_185.236.200.1/32_2")
        );
        assert!(
            ruleset.contains(&format!(
                "ip daddr 185.236.200.1/32 ct state established counter accept comment \"{}\"",
                expected_v4_in_out_comment
            )),
            "OUTPUT should contain IPv4 incoming allowlist with ct state established"
        );

        // IPv6 incoming in OUTPUT: daddr + ct state established (comment suffix _2)
        let expected_v6_in_out_comment = format!(
            "eddie_ip_{}",
            sha256_hex("ipv6_in_2001:db8::1/128_2")
        );
        assert!(
            ruleset.contains(&format!(
                "ip6 daddr 2001:db8::1/128 ct state established counter accept comment \"{}\"",
                expected_v6_in_out_comment
            )),
            "OUTPUT should contain IPv6 incoming allowlist with ct state established"
        );

        // --- OUTPUT chain: outgoing IPs get unrestricted daddr accept ---

        // IPv4 outgoing: daddr accept (comment suffix _1)
        let expected_cidr_out_comment = format!(
            "eddie_ip_{}",
            sha256_hex("ipv4_out_10.128.0.0/24_1")
        );
        assert!(
            ruleset.contains(&format!(
                "ip daddr 10.128.0.0/24 counter accept comment \"{}\"",
                expected_cidr_out_comment
            )),
            "OUTPUT should contain outgoing allowlist with plain accept (CIDR preserved)"
        );

        let expected_v4_out_comment = format!(
            "eddie_ip_{}",
            sha256_hex("ipv4_out_203.0.113.5/32_1")
        );
        assert!(
            ruleset.contains(&format!(
                "ip daddr 203.0.113.5/32 counter accept comment \"{}\"",
                expected_v4_out_comment
            )),
            "OUTPUT should contain outgoing allowlist with plain accept"
        );

        // Incoming IPs should NOT get unrestricted outgoing accept
        assert!(
            !ruleset.contains(&format!(
                "ip daddr 185.236.200.1/32 counter accept comment \"eddie_ip_{}\"",
                sha256_hex("ipv4_out_185.236.200.1/32_1")
            )),
            "incoming IPs should not get unrestricted outgoing accept"
        );
    }

    #[test]
    fn test_ruleset_allow_lan() {
        let config = NetlockConfig {
            allow_lan: true,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // RFC1918 in input
        assert!(ruleset.contains("ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16 counter accept"));
        assert!(ruleset.contains("ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept"));
        assert!(ruleset.contains("ip saddr 172.16.0.0/12 ip daddr 172.16.0.0/12 counter accept"));

        // IPv6 link-local, multicast, ULA in input
        assert!(ruleset.contains("ip6 saddr fe80::/10 ip6 daddr fe80::/10 counter accept"));
        assert!(ruleset.contains("ip6 saddr ff00::/8 ip6 daddr ff00::/8 counter accept"));
        assert!(ruleset.contains("ip6 saddr fc00::/7 ip6 daddr fc00::/7 counter accept"));

        // Output-only multicast rules
        assert!(ruleset.contains("ip saddr 192.168.0.0/16 ip daddr 224.0.0.0/24 counter accept"));
        assert!(ruleset.contains("ip saddr 10.0.0.0/8 ip daddr 224.0.0.0/24 counter accept"));
        assert!(ruleset.contains("ip saddr 172.16.0.0/12 ip daddr 224.0.0.0/24 counter accept"));

        // SSDP
        assert!(ruleset.contains("ip saddr 192.168.0.0/16 ip daddr 239.255.255.250 counter accept"));
        assert!(ruleset.contains("ip saddr 10.0.0.0/8 ip daddr 239.255.255.250 counter accept"));
        assert!(ruleset.contains("ip saddr 172.16.0.0/12 ip daddr 239.255.255.250 counter accept"));

        // SLPv2
        assert!(ruleset.contains("ip saddr 192.168.0.0/16 ip daddr 239.255.255.253 counter accept"));
        assert!(ruleset.contains("ip saddr 10.0.0.0/8 ip daddr 239.255.255.253 counter accept"));
        assert!(ruleset.contains("ip saddr 172.16.0.0/12 ip daddr 239.255.255.253 counter accept"));
    }

    #[test]
    fn test_ruleset_dns_leak_block_with_lan() {
        let config = NetlockConfig {
            allow_lan: true,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // DNS leak block rules should be present
        assert!(ruleset.contains("block_lan_dns_leak"),
            "session ruleset should have DNS leak block rules when allow_lan is true");

        // DNS block must come BEFORE LAN accept in output chain
        let output_start = ruleset.find("chain output").expect("output chain");
        let output_section = &ruleset[output_start..];
        let dns_block_pos = output_section.find("block_lan_dns_leak").unwrap();
        let lan_accept_pos = output_section.find("ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept").unwrap();
        assert!(dns_block_pos < lan_accept_pos,
            "DNS leak block rules must come before LAN accept rules in output chain");
    }

    #[test]
    fn test_ruleset_no_dns_leak_block_without_lan() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);
        assert!(!ruleset.contains("block_lan_dns_leak"),
            "session ruleset should NOT have DNS leak block rules when allow_lan is false");
    }

    #[test]
    fn test_ruleset_no_lan() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // No RFC1918
        assert!(!ruleset.contains("192.168.0.0/16"));
        assert!(!ruleset.contains("10.0.0.0/8"));
        assert!(!ruleset.contains("172.16.0.0/12"));

        // No IPv6 LAN
        assert!(!ruleset.contains("fe80::/10"));
        assert!(!ruleset.contains("ff00::/8"));
        assert!(!ruleset.contains("fc00::/7"));

        // No multicast
        assert!(!ruleset.contains("224.0.0.0/24"));
        assert!(!ruleset.contains("239.255.255.250"));
        assert!(!ruleset.contains("239.255.255.253"));
    }

    #[test]
    fn test_ruleset_ipv6_ndp() {
        let config = default_config();
        let ruleset = generate_ruleset(&config);

        // All four NDP types with hoplimit 255 (Eddie's exact rules)
        assert!(
            ruleset.contains(
                "meta l4proto ipv6-icmp icmpv6 type nd-router-advert ip6 hoplimit 255 counter accept"
            ),
            "should have NDP router-advert rule"
        );
        assert!(
            ruleset.contains(
                "meta l4proto ipv6-icmp icmpv6 type nd-neighbor-solicit ip6 hoplimit 255 counter accept"
            ),
            "should have NDP neighbor-solicit rule"
        );
        assert!(
            ruleset.contains(
                "meta l4proto ipv6-icmp icmpv6 type nd-neighbor-advert ip6 hoplimit 255 counter accept"
            ),
            "should have NDP neighbor-advert rule"
        );
        assert!(
            ruleset.contains(
                "meta l4proto ipv6-icmp icmpv6 type nd-redirect ip6 hoplimit 255 counter accept"
            ),
            "should have NDP redirect rule"
        );
    }

    #[test]
    fn test_ruleset_ipv6_rh0_drop() {
        let config = default_config();
        let ruleset = generate_ruleset(&config);

        // RH0 drop in input, forward, and output chains
        let rh0_count = ruleset
            .matches("rt type 0 counter drop")
            .count();
        assert_eq!(
            rh0_count, 3,
            "should have IPv6 RH0 drop in input, forward, and output chains"
        );
    }

    #[test]
    fn test_ensure_cidr() {
        assert_eq!(ensure_cidr("10.0.0.1"), "10.0.0.1/32");
        assert_eq!(ensure_cidr("10.0.0.0/8"), "10.0.0.0/8");
        assert_eq!(ensure_cidr("2001:db8::1"), "2001:db8::1/128");
        assert_eq!(ensure_cidr("2001:db8::/32"), "2001:db8::/32");
    }

    #[test]
    fn test_ruleset_rule_ordering() {
        // Verify the exact ordering within the input chain matches Eddie
        let config = NetlockConfig {
            allow_lan: true,
            allow_dhcp: true,
            allow_ping: true,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec!["1.2.3.4".to_string()],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // Extract just the input chain rules (between "chain input" and next "chain")
        let input_start = ruleset.find("chain input").expect("input chain");
        let input_end = ruleset[input_start..]
            .find("\n  }\n")
            .map(|p| input_start + p)
            .expect("input chain end");
        let input_section = &ruleset[input_start..input_end];

        // Verify ordering: loopback < anti-spoof < dhcp < lan < ping < rh0 < ndp < ct < allowlist < sentinel
        let pos_lo = input_section.find("iifname \"lo\"").expect("loopback");
        let pos_antispoof = input_section.find("iifname != \"lo\" ip6 saddr ::1").expect("antispoof");
        let pos_dhcp = input_section.find("ip saddr 255.255.255.255").expect("dhcp");
        let pos_lan = input_section.find("ip saddr 192.168.0.0/16 ip daddr 192.168.0.0/16").expect("lan");
        let pos_ping = input_section.find("icmp type echo-request").expect("ping");
        let pos_rh0 = input_section.find("rt type 0 counter drop").expect("rh0");
        let pos_ndp = input_section.find("icmpv6 type nd-router-advert").expect("ndp");
        let pos_ct = input_section.find("ct state related,established").expect("ct");
        let pos_allowlist = input_section.find("ip saddr 1.2.3.4/32").expect("allowlist");
        let pos_sentinel = input_section.find("airvpn_filter_input_latest_rule").expect("sentinel");

        assert!(pos_lo < pos_antispoof, "loopback before anti-spoof");
        assert!(pos_antispoof < pos_dhcp, "anti-spoof before dhcp");
        assert!(pos_dhcp < pos_lan, "dhcp before lan");
        assert!(pos_lan < pos_ping, "lan before ping");
        assert!(pos_ping < pos_rh0, "ping before rh0");
        assert!(pos_rh0 < pos_ndp, "rh0 before ndp");
        assert!(pos_ndp < pos_ct, "ndp before conntrack");
        assert!(pos_ct < pos_allowlist, "conntrack before allowlist");
        assert!(pos_allowlist < pos_sentinel, "allowlist before sentinel");
    }

    // -------------------------------------------------------------------
    // classify_ip tests
    // -------------------------------------------------------------------

    #[test]
    fn test_classify_ip_invalid() {
        assert_eq!(classify_ip("not-an-ip"), None);
    }

    #[test]
    fn test_classify_ip_empty() {
        assert_eq!(classify_ip(""), None);
    }

    // -------------------------------------------------------------------
    // ensure_cidr edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_ensure_cidr_empty_string() {
        // Empty string can't be parsed as IP — returned as-is
        assert_eq!(ensure_cidr(""), "");
    }

    #[test]
    fn test_ensure_cidr_invalid_ip() {
        // Invalid IP — returned as-is (no CIDR appended)
        assert_eq!(ensure_cidr("not-an-ip"), "not-an-ip");
    }

    // -------------------------------------------------------------------
    // generate_ruleset with allow_ipv4ipv6translation: true (NAT64)
    // -------------------------------------------------------------------

    #[test]
    fn test_ruleset_nat64_enabled() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: true,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // NAT64 rules should appear in both INPUT and OUTPUT chains
        let nat64_well_known = "ip6 saddr 64:ff9b::/96 ip6 daddr 64:ff9b::/96 counter accept";
        let nat64_local = "ip6 saddr 64:ff9b:1::/48 ip6 daddr 64:ff9b:1::/48 counter accept";

        // Count occurrences — should be 2 each (input + output)
        let wk_count = ruleset.matches(nat64_well_known).count();
        let local_count = ruleset.matches(nat64_local).count();
        assert_eq!(wk_count, 2, "NAT64 well-known prefix should appear in input and output");
        assert_eq!(local_count, 2, "NAT64 local-use prefix should appear in input and output");
    }

    #[test]
    fn test_ruleset_nat64_disabled() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        assert!(!ruleset.contains("64:ff9b::"), "NAT64 rules should NOT appear when disabled");
    }

    // -------------------------------------------------------------------
    // generate_ruleset with incoming_policy_accept: true
    // -------------------------------------------------------------------

    #[test]
    fn test_ruleset_incoming_policy_accept_adds_output_conntrack() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: true,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // INPUT chain always has ct state related,established
        // OUTPUT chain should ALSO have ct state established when incoming_policy_accept=true
        // The OUTPUT version uses "ct state established" (not "related,established")
        assert!(
            ruleset.contains("ct state established counter accept"),
            "OUTPUT should have conntrack when incoming_policy_accept=true"
        );

        // INPUT still has related,established
        assert!(
            ruleset.contains("ct state related,established counter accept"),
            "INPUT should still have related,established conntrack"
        );
    }

    #[test]
    fn test_ruleset_incoming_policy_drop_no_output_conntrack() {
        let config = default_config(); // incoming_policy_accept=false
        let ruleset = generate_ruleset(&config);

        // Only INPUT should have conntrack, not OUTPUT
        // Count "ct state" occurrences
        let ct_related = ruleset.matches("ct state related,established counter accept").count();
        assert_eq!(ct_related, 1, "only INPUT should have ct state related,established");

        // "ct state established counter accept" should NOT appear (that's the OUTPUT-only rule)
        assert!(
            !ruleset.contains("ct state established counter accept"),
            "OUTPUT conntrack should be absent when incoming_policy_accept=false"
        );
    }

    // -------------------------------------------------------------------
    // Ruleset with both incoming AND outgoing allowlisted IPs
    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // Invalid IP in allowlist should be silently skipped
    // -------------------------------------------------------------------

    #[test]
    fn test_ruleset_invalid_ip_in_allowlist_skipped() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec!["not-an-ip".to_string()],
            allowed_ips_outgoing: vec!["also-invalid".to_string()],
            incoming_policy_accept: false,
            iface_name: crate::wireguard::VPN_INTERFACE.to_string(),
            custom_route_out_cidrs: vec![],
            allowlist_out_cidrs: vec![],
            local_forward_ifaces: vec![],
        };
        let ruleset = generate_ruleset(&config);

        // Invalid IPs should not appear in any rule
        assert!(!ruleset.contains("not-an-ip"), "invalid IP should be skipped");
        assert!(!ruleset.contains("also-invalid"), "invalid IP should be skipped");

        // Ruleset should still be structurally valid
        assert!(ruleset.contains("table inet"));
        assert!(ruleset.contains("chain input"));
        assert!(ruleset.contains("chain output"));
    }

    // -------------------------------------------------------------------
    // generate_persistent_ruleset tests (airvpn_persist table)
    // -------------------------------------------------------------------

    #[test]
    fn test_persistent_ruleset_uses_persist_table_name() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("table inet airvpn_persist"),
            "persistent ruleset should use airvpn_persist table name");
        assert!(!ruleset.contains("table inet airvpn_lock"),
            "persistent ruleset should NOT use airvpn_lock table name");
    }

    #[test]
    fn test_persistent_ruleset_has_owner_persist_flags() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("flags owner, persist;"),
            "persistent ruleset should have owner+persist flags");
    }

    #[test]
    fn test_persistent_ruleset_has_meta_mark_in_output() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("meta mark 51820 counter accept"),
            "persistent ruleset should allow WireGuard outer packets via meta mark");
    }

    #[test]
    fn test_persistent_ruleset_has_avpn_oifname_in_output() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("oifname \"avpn0\" counter accept"),
            "persistent ruleset should allow VPN tunnel output via oifname");
    }

    #[test]
    fn test_persistent_ruleset_has_avpn_iifname_in_input() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("iifname \"avpn0\" counter accept"),
            "persistent ruleset should allow VPN tunnel input via iifname");
    }

    #[test]
    fn test_persistent_ruleset_has_avpn_in_forward() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        let forward_start = ruleset.find("chain forward").expect("forward chain");
        let forward_end = ruleset[forward_start..]
            .find("\n  }\n")
            .map(|p| forward_start + p)
            .expect("forward chain end");
        let forward_section = &ruleset[forward_start..forward_end];
        assert!(forward_section.contains("iifname \"avpn0\" counter accept"),
            "forward chain should allow incoming VPN tunnel traffic");
        assert!(forward_section.contains("oifname \"avpn0\" counter accept"),
            "forward chain should allow outgoing VPN tunnel traffic");
    }

    #[test]
    fn test_persistent_ruleset_has_dns_leak_block() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("block_lan_dns_leak"),
            "persistent ruleset should have DNS leak block rules");
        // DNS block must come BEFORE LAN accept rules in the OUTPUT chain
        let output_start = ruleset.find("chain output").expect("output chain");
        let output_section = &ruleset[output_start..];
        let dns_block_pos = output_section.find("block_lan_dns_leak").unwrap();
        let lan_accept_pos = output_section.find("ip saddr 10.0.0.0/8 ip daddr 10.0.0.0/8 counter accept").unwrap();
        assert!(dns_block_pos < lan_accept_pos,
            "DNS leak block rules must come before LAN accept rules in output chain");
    }

    #[test]
    fn test_persistent_ruleset_has_bootstrap_ips() {
        let bootstrap_ips = vec![
            "63.33.78.166".to_string(),
            "54.93.175.114".to_string(),
            "82.196.3.205".to_string(),
        ];
        let ruleset = generate_persistent_ruleset(&bootstrap_ips, crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("ip daddr 63.33.78.166/32"));
        assert!(ruleset.contains("ip daddr 54.93.175.114/32"));
        assert!(ruleset.contains("ip daddr 82.196.3.205/32"));
    }

    #[test]
    fn test_persistent_ruleset_ipv6_bootstrap() {
        let bootstrap_ips = vec![
            "1.2.3.4".to_string(),
            "2a03:b0c0:0:1010::9b:c001".to_string(),
        ];
        let ruleset = generate_persistent_ruleset(&bootstrap_ips, crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("ip6 daddr 2a03:b0c0:0:1010::9b:c001/128"));
    }

    #[test]
    fn test_persistent_ruleset_always_allows_lan() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("192.168.0.0/16"));
        assert!(ruleset.contains("10.0.0.0/8"));
        assert!(ruleset.contains("172.16.0.0/12"));
        assert!(ruleset.contains("fe80::/10"));
    }

    #[test]
    fn test_persistent_ruleset_priority_minus_400() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(ruleset.contains("priority -400;"),
            "persistent ruleset should use priority -400");
        assert!(!ruleset.contains("priority -300;"),
            "persistent ruleset should NOT use priority -300");
    }

    #[test]
    fn test_persistent_ruleset_input_allows_inbound_ping_only() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        let input_start = ruleset.find("chain input").expect("input chain");
        let input_end = ruleset[input_start..]
            .find("\n  }\n")
            .map(|p| input_start + p)
            .expect("input chain end");
        let input_section = &ruleset[input_start..input_end];

        // Should allow inbound echo-request (others can ping us)
        assert!(
            input_section.contains("icmp type echo-request counter accept"),
            "input chain should accept inbound echo-request"
        );
        // Should NOT have blanket echo-reply in input (that would be for outbound ping responses
        // arriving — conntrack handles that via established state)
        assert!(
            !input_section.contains("icmp type { echo-request, echo-reply }"),
            "input chain should NOT have blanket echo-request + echo-reply"
        );
    }

    #[test]
    fn test_persistent_ruleset_output_allows_echo_reply_only() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        let output_start = ruleset.find("chain output").expect("output chain");
        let output_end = ruleset[output_start..]
            .find("\n  }\n")
            .map(|p| output_start + p)
            .expect("output chain end");
        let output_section = &ruleset[output_start..output_end];

        // Should allow outbound echo-reply (respond to pings)
        assert!(
            output_section.contains("icmp type echo-reply counter accept"),
            "output chain should accept outbound echo-reply"
        );
        // Should NOT allow blanket outbound echo-request
        assert!(
            !output_section.contains("icmp type echo-request counter accept"),
            "output chain should NOT have blanket outbound echo-request"
        );
        // Should NOT have the old blanket rule
        assert!(
            !output_section.contains("icmp type { echo-request, echo-reply }"),
            "output chain should NOT have blanket echo-request + echo-reply"
        );
    }

    #[test]
    fn test_persistent_ruleset_has_ping_allow_subchain() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(
            ruleset.contains("chain ping_allow {"),
            "persistent ruleset should have a ping_allow subchain"
        );
    }

    #[test]
    fn test_persistent_ruleset_output_jumps_to_ping_allow() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        let output_start = ruleset.find("chain output").expect("output chain");
        let output_end = ruleset[output_start..]
            .find("\n  }\n")
            .map(|p| output_start + p)
            .expect("output chain end");
        let output_section = &ruleset[output_start..output_end];

        assert!(
            output_section.contains("jump ping_allow"),
            "output chain should jump to ping_allow subchain"
        );
    }

    #[test]
    fn test_persistent_ruleset_ping_allow_is_empty_by_default() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        let chain_start = ruleset.find("chain ping_allow {").expect("ping_allow chain");
        let chain_end = ruleset[chain_start..]
            .find("\n  }\n")
            .map(|p| chain_start + p)
            .expect("ping_allow chain end");
        let chain_body = &ruleset[chain_start + "chain ping_allow {".len()..chain_end];

        // Should be empty (no rules) — just whitespace
        assert!(
            chain_body.trim().is_empty(),
            "ping_allow chain should be empty by default, got: {:?}",
            chain_body.trim()
        );
    }

    // -------------------------------------------------------------------
    // build_ping_hole_rules tests
    // -------------------------------------------------------------------

    #[test]
    fn test_build_ping_hole_rules_ipv4() {
        let ips = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
        let (batch, count) = build_ping_hole_rules(&ips);
        assert_eq!(count, 2);
        assert!(batch.contains("ip daddr 1.2.3.4 icmp type echo-request"));
        assert!(batch.contains("ip daddr 5.6.7.8 icmp type echo-request"));
    }

    #[test]
    fn test_build_ping_hole_rules_ipv6() {
        let ips = vec!["2001:db8::1".to_string()];
        let (batch, count) = build_ping_hole_rules(&ips);
        assert_eq!(count, 1);
        assert!(batch.contains("ip6 daddr 2001:db8::1 icmpv6 type echo-request"));
    }

    #[test]
    fn test_build_ping_hole_rules_deduplicates() {
        let ips = vec![
            "1.2.3.4".to_string(),
            "1.2.3.4".to_string(),
            "5.6.7.8".to_string(),
        ];
        let (batch, count) = build_ping_hole_rules(&ips);
        assert_eq!(count, 2);
        assert_eq!(batch.matches("1.2.3.4").count(), 1);
    }

    #[test]
    fn test_build_ping_hole_rules_skips_invalid() {
        let ips = vec![
            "1.2.3.4".to_string(),
            "not-an-ip".to_string(),
            "".to_string(),
            "  ".to_string(),
            "5.6.7.8".to_string(),
        ];
        let (batch, count) = build_ping_hole_rules(&ips);
        assert_eq!(count, 2);
        assert!(!batch.contains("not-an-ip"));
    }

    #[test]
    fn test_build_ping_hole_rules_rejects_injection() {
        let ips = vec![
            "1.2.3.4; drop table".to_string(),
            "1.2.3.4\ndrop table".to_string(),
        ];
        let (batch, count) = build_ping_hole_rules(&ips);
        assert_eq!(count, 0);
        assert!(batch.is_empty());
    }

    // -------------------------------------------------------------------
    // build_server_allowlist_rules tests
    // -------------------------------------------------------------------

    #[test]
    fn test_build_server_allowlist_rules_ipv4() {
        let ips = vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()];
        let (batch, count) = build_server_allowlist_rules(&ips);
        assert_eq!(count, 2);
        // All-protocol: "ip daddr X counter accept" with NO icmp restriction
        assert!(batch.contains("ip daddr 1.2.3.4 counter accept"));
        assert!(batch.contains("ip daddr 5.6.7.8 counter accept"));
        assert!(!batch.contains("icmp"), "allowlist rules must not restrict to ICMP");
    }

    #[test]
    fn test_build_server_allowlist_rules_ipv6() {
        let ips = vec!["2001:db8::1".to_string()];
        let (batch, count) = build_server_allowlist_rules(&ips);
        assert_eq!(count, 1);
        assert!(batch.contains("ip6 daddr 2001:db8::1 counter accept"));
        assert!(!batch.contains("icmp"), "allowlist rules must not restrict to ICMP");
    }

    #[test]
    fn test_build_server_allowlist_rules_deduplicates() {
        let ips = vec![
            "1.2.3.4".to_string(),
            "1.2.3.4".to_string(),
            "5.6.7.8".to_string(),
        ];
        let (batch, count) = build_server_allowlist_rules(&ips);
        assert_eq!(count, 2);
        assert_eq!(batch.matches("1.2.3.4").count(), 1);
    }

    #[test]
    fn test_build_server_allowlist_rules_skips_invalid() {
        let ips = vec![
            "1.2.3.4".to_string(),
            "not-an-ip".to_string(),
            "".to_string(),
            "  ".to_string(),
            "5.6.7.8".to_string(),
        ];
        let (batch, count) = build_server_allowlist_rules(&ips);
        assert_eq!(count, 2);
        assert!(!batch.contains("not-an-ip"));
    }

    #[test]
    fn test_build_server_allowlist_rules_rejects_injection() {
        let ips = vec![
            "1.2.3.4; drop table".to_string(),
            "1.2.3.4\ndrop table".to_string(),
        ];
        let (batch, count) = build_server_allowlist_rules(&ips);
        assert_eq!(count, 0);
        assert!(batch.is_empty());
    }

    #[test]
    fn test_server_allowlist_vs_ping_holes_differ() {
        // Verify the two builders produce different rule types
        let ips = vec!["10.0.0.1".to_string()];
        let (ping_batch, _) = build_ping_hole_rules(&ips);
        let (allow_batch, _) = build_server_allowlist_rules(&ips);

        assert!(ping_batch.contains("icmp type echo-request"),
            "ping holes must be ICMP-only");
        assert!(!allow_batch.contains("icmp"),
            "server allowlist must be all-protocol");
        // Both target the same chain
        assert!(ping_batch.contains("ping_allow"));
        assert!(allow_batch.contains("ping_allow"));
    }

    #[test]
    fn test_persistent_ruleset_output_icmpv6_no_echo_request() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        let output_start = ruleset.find("chain output").expect("output chain");
        let output_end = ruleset[output_start..]
            .find("\n  }\n")
            .map(|p| output_start + p)
            .expect("output chain end");
        let output_section = &ruleset[output_start..output_end];

        // Find the ICMPv6 rule in output and verify no echo-request
        for line in output_section.lines() {
            if line.contains("icmpv6 type") && !line.contains("jump") {
                assert!(
                    !line.contains("echo-request"),
                    "output ICMPv6 should NOT contain echo-request, got: {}",
                    line.trim()
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Custom routes and allowlist tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_lock_custom_route_out_ipv4() {
        let config = NetlockConfig {
            custom_route_out_cidrs: vec!["192.168.1.0/24".to_string()],
            ..default_config()
        };
        let ruleset = generate_ruleset(&config);
        assert!(
            ruleset.contains("ip daddr 192.168.1.0/24 counter accept comment \"airvpn_custom_route_out\""),
            "session lock must contain custom route out CIDR accept rule"
        );
    }

    #[test]
    fn test_session_lock_custom_route_out_ipv6() {
        let config = NetlockConfig {
            custom_route_out_cidrs: vec!["2001:db8::/32".to_string()],
            ..default_config()
        };
        let ruleset = generate_ruleset(&config);
        assert!(
            ruleset.contains("ip6 daddr 2001:db8::/32 counter accept comment \"airvpn_custom_route_out\""),
            "session lock must contain IPv6 custom route out accept rule"
        );
    }

    #[test]
    fn test_session_lock_allowlist_ipv4() {
        let config = NetlockConfig {
            allowlist_out_cidrs: vec!["1.2.3.4".to_string()],
            local_forward_ifaces: vec![],
            ..default_config()
        };
        let ruleset = generate_ruleset(&config);
        // Bare IP should get /32 suffix from ensure_cidr
        assert!(
            ruleset.contains("ip daddr 1.2.3.4/32 counter accept comment \"airvpn_allowlist_out\""),
            "session lock must contain allowlist CIDR with /32 suffix"
        );
    }

    #[test]
    fn test_session_lock_allowlist_ipv6() {
        let config = NetlockConfig {
            allowlist_out_cidrs: vec!["2001:db8::1".to_string()],
            local_forward_ifaces: vec![],
            ..default_config()
        };
        let ruleset = generate_ruleset(&config);
        assert!(
            ruleset.contains("ip6 daddr 2001:db8::1/128 counter accept comment \"airvpn_allowlist_out\""),
            "session lock must contain IPv6 allowlist with /128 suffix"
        );
    }

    #[test]
    fn test_session_lock_custom_and_allowlist_before_final_drop() {
        let config = NetlockConfig {
            custom_route_out_cidrs: vec!["10.0.0.0/8".to_string()],
            allowlist_out_cidrs: vec!["5.6.7.0/24".to_string()],
            local_forward_ifaces: vec![],
            ..default_config()
        };
        let ruleset = generate_ruleset(&config);

        let custom_pos = ruleset.find("airvpn_custom_route_out").expect("custom route rule");
        let allowlist_pos = ruleset.find("airvpn_allowlist_out").expect("allowlist rule");
        let drop_pos = ruleset.find("airvpn_filter_output_latest_rule").expect("final drop");

        assert!(custom_pos < drop_pos, "custom route must come before final drop");
        assert!(allowlist_pos < drop_pos, "allowlist must come before final drop");
        assert!(custom_pos < allowlist_pos, "custom routes before allowlist (order)");
    }

    #[test]
    fn test_session_lock_empty_custom_and_allowlist() {
        let config = default_config();
        let ruleset = generate_ruleset(&config);
        assert!(
            !ruleset.contains("airvpn_custom_route_out"),
            "no custom route rules when list is empty"
        );
        assert!(
            !ruleset.contains("airvpn_allowlist_out"),
            "no allowlist rules when list is empty"
        );
    }

    #[test]
    fn test_persistent_lock_allowlist_ipv4() {
        let allowlist = vec!["203.0.113.0/24".to_string()];
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &allowlist, &vec![]);
        assert!(
            ruleset.contains("ip daddr 203.0.113.0/24 counter accept comment \"airvpn_persist_allowlist_out\""),
            "persistent lock must contain allowlist CIDR accept rule"
        );
    }

    #[test]
    fn test_persistent_lock_allowlist_ipv6() {
        let allowlist = vec!["2001:db8:abcd::/48".to_string()];
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &allowlist, &vec![]);
        assert!(
            ruleset.contains("ip6 daddr 2001:db8:abcd::/48 counter accept comment \"airvpn_persist_allowlist_out\""),
            "persistent lock must contain IPv6 allowlist accept rule"
        );
    }

    #[test]
    fn test_persistent_lock_allowlist_before_final_drop() {
        let allowlist = vec!["198.51.100.0/24".to_string()];
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &allowlist, &vec![]);

        let allowlist_pos = ruleset.find("airvpn_persist_allowlist_out").expect("allowlist rule");
        let drop_pos = ruleset.find("airvpn_persist_output_latest_rule").expect("final drop");
        assert!(allowlist_pos < drop_pos, "allowlist must come before final drop in persistent lock");
    }

    #[test]
    fn test_persistent_lock_empty_allowlist() {
        let ruleset = generate_persistent_ruleset(&vec![], crate::wireguard::VPN_INTERFACE, &vec![], &vec![]);
        assert!(
            !ruleset.contains("airvpn_persist_allowlist_out"),
            "no allowlist rules in persistent lock when list is empty"
        );
    }

    #[test]
    fn test_session_lock_invalid_cidr_skipped() {
        let config = NetlockConfig {
            custom_route_out_cidrs: vec!["not-a-cidr".to_string(), "192.168.1.0/24".to_string()],
            allowlist_out_cidrs: vec!["also-invalid".to_string(), "10.0.0.1".to_string()],
            local_forward_ifaces: vec![],
            ..default_config()
        };
        let ruleset = generate_ruleset(&config);
        // Invalid entries should be silently skipped (classify_ip returns None)
        assert!(!ruleset.contains("not-a-cidr"));
        assert!(!ruleset.contains("also-invalid"));
        // Valid entries should still be present
        assert!(ruleset.contains("192.168.1.0/24"));
        assert!(ruleset.contains("10.0.0.1/32"));
    }
}
