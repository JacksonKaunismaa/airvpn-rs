//! Network lock (nftables kill switch) — prevents IP leaks when VPN is down.
//!
//! Uses a dedicated `table inet airvpn_lock` at priority -300 instead of
//! Eddie's `flush ruleset` approach. Eddie uses flush-ruleset for iptables
//! cross-compatibility; we are nftables-only. The rule contents and ordering
//! are 1:1 with Eddie's NetworkLockNftables.cs.
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

    // 4. LAN rules (Eddie: netlock.allow_private)
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

    // 8. Final drop (handle for rule insertion)
    r.push_str("    counter drop comment \"airvpn_filter_output_latest_rule\"\n");

    r.push_str("  }\n");
    r.push_str("}\n");

    r
}

/// Generate the persistent lock ruleset for `/etc/airvpn-rs/lock.nft`.
///
/// This is a base ruleset with LAN, DHCP, ICMP, NDP, conntrack, and bootstrap
/// API IPs. No server IPs, no tunnel interface, no `flags owner, persist`
/// (those are set at runtime when airvpn-rs reclaims the table).
///
/// The systemd service loads this at boot with `nft -f`.
pub fn generate_persistent_ruleset(bootstrap_ips: &[String]) -> String {
    let config = NetlockConfig {
        allow_lan: true,
        allow_dhcp: true,
        allow_ping: true,
        allow_ipv4ipv6translation: true,
        allowed_ips_incoming: vec![],
        allowed_ips_outgoing: bootstrap_ips.to_vec(),
        incoming_policy_accept: false,
    };
    generate_ruleset(&config)
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

/// Check if our nftables table exists.
pub fn is_active() -> bool {
    let output = Command::new("nft")
        .args(["list", "table", "inet", TABLE_NAME])
        .output();

    match output {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

/// Allow VPN interface traffic (called when tunnel comes up).
///
/// Inserts accept rules for the interface into input, forward, and output chains,
/// positioned before the final drop rule (matching Eddie's handle-based insertion).
///
/// Eddie equivalent: netlock-nftables-interface action=add
pub fn allow_interface(iface: &str) -> Result<()> {
    // Validate interface name to prevent nft command injection
    if iface.len() > 15 || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
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
    if iface.len() > 15 || !iface.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!("invalid interface name: {:?}", iface);
    }

    for chain in &["input", "forward", "output"] {
        let dir = match *chain {
            "input" => "input",
            "forward" => "forward",
            "output" => "output",
            _ => unreachable!(),
        };
        let comment = format!("airvpn_interface_{}_{}", dir, iface);
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
    fn test_ruleset_no_lan() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![],
            allowed_ips_outgoing: vec![],
            incoming_policy_accept: false,
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
    fn test_sha256_hex_deterministic() {
        // Verify our SHA-256 produces consistent results
        let hash1 = sha256_hex("ipv4_in_185.236.200.1/32_1");
        let hash2 = sha256_hex("ipv4_in_185.236.200.1/32_1");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64, "SHA-256 hex digest should be 64 characters");
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
    fn test_classify_ip_ipv4() {
        assert_eq!(classify_ip("192.168.1.1"), Some(IpVersion::V4));
    }

    #[test]
    fn test_classify_ip_ipv6() {
        assert_eq!(classify_ip("2001:db8::1"), Some(IpVersion::V6));
    }

    #[test]
    fn test_classify_ip_ipv4_cidr() {
        assert_eq!(classify_ip("10.0.0.0/8"), Some(IpVersion::V4));
    }

    #[test]
    fn test_classify_ip_ipv6_cidr() {
        assert_eq!(classify_ip("fe80::/10"), Some(IpVersion::V6));
    }

    #[test]
    fn test_classify_ip_invalid() {
        assert_eq!(classify_ip("not-an-ip"), None);
    }

    #[test]
    fn test_classify_ip_empty() {
        assert_eq!(classify_ip(""), None);
    }

    #[test]
    fn test_classify_ip_loopback_v4() {
        assert_eq!(classify_ip("127.0.0.1"), Some(IpVersion::V4));
    }

    #[test]
    fn test_classify_ip_loopback_v6() {
        assert_eq!(classify_ip("::1"), Some(IpVersion::V6));
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

    #[test]
    fn test_ensure_cidr_already_has_cidr_v4() {
        assert_eq!(ensure_cidr("10.0.0.0/8"), "10.0.0.0/8");
    }

    #[test]
    fn test_ensure_cidr_already_has_cidr_v6() {
        assert_eq!(ensure_cidr("fe80::/10"), "fe80::/10");
    }

    #[test]
    fn test_ensure_cidr_bare_v4() {
        assert_eq!(ensure_cidr("192.168.1.1"), "192.168.1.1/32");
    }

    #[test]
    fn test_ensure_cidr_bare_v6() {
        assert_eq!(ensure_cidr("::1"), "::1/128");
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

    #[test]
    fn test_ruleset_mixed_incoming_outgoing_ips() {
        let config = NetlockConfig {
            allow_lan: false,
            allow_dhcp: false,
            allow_ping: false,
            allow_ipv4ipv6translation: false,
            allowed_ips_incoming: vec![
                "10.0.0.1".to_string(),
                "2001:db8::1".to_string(),
            ],
            allowed_ips_outgoing: vec![
                "203.0.113.5".to_string(),
                "2001:db8::ff".to_string(),
            ],
            incoming_policy_accept: false,
        };
        let ruleset = generate_ruleset(&config);

        // INPUT: incoming IPs get saddr accept
        assert!(ruleset.contains("ip saddr 10.0.0.1/32 counter accept"),
            "incoming IPv4 should have saddr accept in INPUT");
        assert!(ruleset.contains("ip6 saddr 2001:db8::1/128 counter accept"),
            "incoming IPv6 should have saddr accept in INPUT");

        // OUTPUT: incoming IPs get daddr + ct state established (response only)
        assert!(ruleset.contains("ip daddr 10.0.0.1/32 ct state established counter accept"),
            "incoming IPv4 should have daddr ct state established in OUTPUT");
        assert!(ruleset.contains("ip6 daddr 2001:db8::1/128 ct state established counter accept"),
            "incoming IPv6 should have daddr ct state established in OUTPUT");

        // OUTPUT: outgoing IPs get unrestricted daddr accept
        assert!(ruleset.contains("ip daddr 203.0.113.5/32 counter accept"),
            "outgoing IPv4 should have unrestricted daddr accept in OUTPUT");
        assert!(ruleset.contains("ip6 daddr 2001:db8::ff/128 counter accept"),
            "outgoing IPv6 should have unrestricted daddr accept in OUTPUT");

        // Outgoing IPs should NOT appear in INPUT
        assert!(!ruleset.contains("ip saddr 203.0.113.5"),
            "outgoing IPs should not appear as saddr in INPUT");
        assert!(!ruleset.contains("ip6 saddr 2001:db8::ff"),
            "outgoing IPv6 should not appear as saddr in INPUT");
    }

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
    // SHA-256 consistency test
    // -------------------------------------------------------------------

    #[test]
    fn test_sha256_hex_different_inputs() {
        let hash_a = sha256_hex("input_a");
        let hash_b = sha256_hex("input_b");
        assert_ne!(hash_a, hash_b, "different inputs should produce different hashes");
        assert_eq!(hash_a.len(), 64);
        assert_eq!(hash_b.len(), 64);
    }

    // -------------------------------------------------------------------
    // generate_persistent_ruleset tests
    // -------------------------------------------------------------------

    #[test]
    fn test_persistent_ruleset_has_bootstrap_ips() {
        let bootstrap_ips = vec![
            "63.33.78.166".to_string(),
            "54.93.175.114".to_string(),
            "82.196.3.205".to_string(),
        ];
        let ruleset = generate_persistent_ruleset(&bootstrap_ips);
        assert!(ruleset.contains("table inet airvpn_lock"));
        assert!(ruleset.contains("ip daddr 63.33.78.166/32"));
        assert!(ruleset.contains("ip daddr 54.93.175.114/32"));
        assert!(ruleset.contains("ip daddr 82.196.3.205/32"));
        assert!(!ruleset.contains("flags"));
        assert!(ruleset.contains("airvpn_filter_input_latest_rule"));
        assert!(ruleset.contains("airvpn_filter_output_latest_rule"));
        assert!(ruleset.contains("airvpn_filter_forward_latest_rule"));
    }

    #[test]
    fn test_persistent_ruleset_no_server_ips_beyond_bootstrap() {
        let bootstrap_ips = vec!["1.2.3.4".to_string()];
        let ruleset = generate_persistent_ruleset(&bootstrap_ips);
        // Only the bootstrap IP should be in output allowlist
        assert!(ruleset.contains("ip daddr 1.2.3.4/32"));
    }

    #[test]
    fn test_persistent_ruleset_ipv6_bootstrap() {
        let bootstrap_ips = vec![
            "1.2.3.4".to_string(),
            "2a03:b0c0:0:1010::9b:c001".to_string(),
        ];
        let ruleset = generate_persistent_ruleset(&bootstrap_ips);
        assert!(ruleset.contains("ip6 daddr 2a03:b0c0:0:1010::9b:c001/128"));
    }

    #[test]
    fn test_persistent_ruleset_always_allows_lan() {
        let ruleset = generate_persistent_ruleset(&vec![]);
        assert!(ruleset.contains("192.168.0.0/16"));
        assert!(ruleset.contains("10.0.0.0/8"));
        assert!(ruleset.contains("172.16.0.0/12"));
        assert!(ruleset.contains("fe80::/10"));
    }
}
