//! AirDNS DDNS self-heal: authoritative-NS lookup of the user's AirDNS record.
//!
//! AirVPN's "AirDNS" updates the user's DDNS record (e.g. `host.airdns.org`) to
//! the exit IP of the last server a *fresh connect* was performed to. The record
//! is rewritten ONLY on a connect event — never cleared on disconnect, and not
//! refreshed by an in-loop reconnect/retry. After a server hop the record can be
//! stale, stranding inbound clients until the next full connect.
//!
//! This module queries AirVPN's authoritative nameserver directly (bypassing
//! resolver caches and propagation delay) so `connect::run()` can detect drift
//! and trigger a corrective full reconnect (which is what rewrites the record).
//!
//! No external crates: the DNS A-query is hand-rolled over `std::net::UdpSocket`.

use std::net::{Ipv4Addr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use log::{debug, warn};

/// Authoritative nameservers for the `airdns.org` zone, tried in order.
const AUTH_NAMESERVERS: &[&str] = &["ns2.airvpn.org", "ns1.airvpn.org"];

/// UDP timeout for a single authoritative query.
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);

/// Resolve `hostname`'s A record by querying AirVPN's authoritative nameserver
/// directly. Returns the first A record, or `None` on any failure (unresolvable
/// NS, socket error, timeout, malformed response, NXDOMAIN, no A record).
///
/// Querying the authoritative NS bypasses recursive-resolver caches so we see
/// the record AirVPN's backend actually published, not a stale cached copy.
pub fn lookup_authoritative(hostname: &str) -> Option<Ipv4Addr> {
    for ns in AUTH_NAMESERVERS {
        // Resolve the NS host to an IP via the system resolver (NS hostnames are
        // stable; only the user's DDNS record is volatile).
        let ns_addr = match (*ns, 53u16).to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(a) => a,
                None => {
                    warn!("airdns: nameserver {} resolved to no addresses", ns);
                    continue;
                }
            },
            Err(e) => {
                warn!("airdns: failed to resolve nameserver {}: {}", ns, e);
                continue;
            }
        };

        match query_a(ns_addr, hostname) {
            Some(ip) => {
                debug!("airdns: {} -> {} (via {})", hostname, ip, ns);
                return Some(ip);
            }
            None => {
                debug!("airdns: no A record for {} from {}", hostname, ns);
                // Fall through to the next nameserver.
            }
        }
    }
    None
}

/// Send a single A-query for `hostname` to `ns_addr` and parse the first A record.
fn query_a(ns_addr: std::net::SocketAddr, hostname: &str) -> Option<Ipv4Addr> {
    // Bind to the wildcard matching the NS address family.
    let bind = if ns_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = match UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            warn!("airdns: udp bind failed: {}", e);
            return None;
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(QUERY_TIMEOUT)) {
        warn!("airdns: set_read_timeout failed: {}", e);
        return None;
    }

    // Fixed query ID. We talk to one NS over a fresh socket per query, so a
    // constant ID is fine (we still validate it on the response).
    let query_id: u16 = 0x4744;
    let query = build_query(query_id, hostname)?;

    if let Err(e) = socket.send_to(&query, ns_addr) {
        warn!("airdns: send_to {} failed: {}", ns_addr, e);
        return None;
    }

    let mut buf = [0u8; 1500];
    let n = match socket.recv(&mut buf) {
        Ok(n) => n,
        Err(e) => {
            warn!("airdns: recv from {} failed/timed out: {}", ns_addr, e);
            return None;
        }
    };

    parse_first_a(&buf[..n], query_id)
}

/// Build a minimal DNS query packet for an A record of `hostname`.
///
/// Header: id, flags=0x0100 (standard query, recursion desired — harmless when
/// talking to an authoritative server), QDCOUNT=1, rest zero. Question: QNAME
/// (length-prefixed labels + root), QTYPE=A(1), QCLASS=IN(1).
fn build_query(id: u16, hostname: &str) -> Option<Vec<u8>> {
    let mut pkt = Vec::with_capacity(hostname.len() + 18);
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in hostname.trim_end_matches('.').split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None; // invalid label
        }
        pkt.push(bytes.len() as u8);
        pkt.extend_from_slice(bytes);
    }
    pkt.push(0); // root label terminator

    pkt.extend_from_slice(&1u16.to_be_bytes()); // QTYPE = A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN
    Some(pkt)
}

/// Parse a DNS response and return the first A record in the answer section.
///
/// Pure function over the raw response bytes — no I/O — so it can be unit-tested
/// with canned packets. Handles name compression pointers (RFC 1035 §4.1.4) when
/// skipping the question and answer owner names. Returns `None` on any malformed
/// input, header-ID mismatch, RCODE != 0, or absence of an A record.
fn parse_first_a(resp: &[u8], expected_id: u16) -> Option<Ipv4Addr> {
    if resp.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([resp[0], resp[1]]);
    if id != expected_id {
        return None;
    }
    let flags = u16::from_be_bytes([resp[2], resp[3]]);
    // QR bit must be set (response); RCODE (low nibble) must be 0 (NOERROR).
    if flags & 0x8000 == 0 || (flags & 0x000F) != 0 {
        return None;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    if ancount == 0 {
        return None;
    }

    let mut pos = 12usize;

    // Skip the question section: QNAME + QTYPE(2) + QCLASS(2), for each question.
    for _ in 0..qdcount {
        pos = skip_name(resp, pos)?;
        pos = pos.checked_add(4)?;
        if pos > resp.len() {
            return None;
        }
    }

    // Walk the answer section looking for the first A record (TYPE=1, CLASS=IN).
    for _ in 0..ancount {
        pos = skip_name(resp, pos)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes of fixed RR header.
        if pos.checked_add(10)? > resp.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rclass = u16::from_be_bytes([resp[pos + 2], resp[pos + 3]]);
        let rdlength = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        let rdata_start = pos + 10;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > resp.len() {
            return None;
        }
        if rtype == 1 && rclass == 1 && rdlength == 4 {
            return Some(Ipv4Addr::new(
                resp[rdata_start],
                resp[rdata_start + 1],
                resp[rdata_start + 2],
                resp[rdata_start + 3],
            ));
        }
        pos = rdata_end; // not an A record — skip its RDATA
    }
    None
}

/// Advance past a DNS name starting at `pos`, returning the offset of the first
/// byte after the name. Follows the encoding rules but does NOT decode the name
/// (we never need the string): a length-prefixed label sequence terminated by a
/// zero byte, OR a compression pointer (top two bits `11`) which is itself the
/// end of the name in the current record (2 bytes total).
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Some(pos + 1); // root label: name ends here
                }
                pos = pos.checked_add(1 + len as usize)?;
            }
            0xC0 => {
                // Compression pointer: 2 bytes, and the name ends here. We don't
                // follow it because we don't need the decoded name.
                return pos.checked_add(2);
            }
            _ => return None, // 0x40 / 0x80 are reserved/invalid
        }
        if pos > buf.len() {
            return None;
        }
    }
}

// ---------------------------------------------------------------------------
// Corrective-action decision (pure)
// ---------------------------------------------------------------------------

/// What to do after comparing the authoritative record against the current
/// server's exit IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealAction {
    /// Record matches (or lookup matched): proceed into the monitor loop and
    /// reset the per-episode corrective-attempt counter.
    Proceed,
    /// Drift detected and budget remains: do a corrective full reconnect.
    /// Carries the new attempt count to store.
    Correct { attempt: u32 },
    /// Drift detected but the cap is exhausted: give up, leave the connection
    /// up, and proceed into the monitor loop.
    GiveUp,
}

/// Maximum corrective full reconnects per drift episode.
pub const CORRECTIVE_CAP: u32 = 2;

/// Decide the corrective action given the lookup outcome and attempts so far.
///
/// `looked_up` is the authoritative A record (None if the query failed),
/// `exit_ip` is the current server's exit IP (None/parse-failure means we can't
/// compare). `attempts` is how many corrective reconnects this drift episode has
/// already triggered.
///
/// Decision rules:
/// - Match  -> `Proceed` (and the caller resets the counter to 0).
/// - We can't determine drift (lookup failed, or exit IP missing/unparseable)
///   -> `Proceed`: don't tear down a working connection on uncertain evidence.
/// - Mismatch with `attempts < cap` -> `Correct { attempt: attempts + 1 }`.
/// - Mismatch with `attempts >= cap` -> `GiveUp`.
pub fn decide_heal(looked_up: Option<Ipv4Addr>, exit_ip: Option<Ipv4Addr>, attempts: u32, cap: u32) -> HealAction {
    let (Some(got), Some(want)) = (looked_up, exit_ip) else {
        // Inconclusive: can't prove drift, so don't disturb the connection.
        return HealAction::Proceed;
    };
    if got == want {
        return HealAction::Proceed;
    }
    if attempts < cap {
        HealAction::Correct { attempt: attempts + 1 }
    } else {
        HealAction::GiveUp
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DNS response: 12-byte header + one question (uncompressed name)
    /// + the given answer-section bytes. Caller supplies ancount and answers.
    fn make_response(id: u16, flags: u16, qname: &str, ancount: u16, answers: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&flags.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        p.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
        p.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        p.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        // Question: QNAME labels + root, QTYPE=A, QCLASS=IN
        for label in qname.trim_end_matches('.').split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(answers);
        p
    }

    /// An A record whose owner name is a compression pointer to offset 12 (the
    /// question's QNAME), as real resolvers emit. TYPE=A CLASS=IN TTL RDLEN=4 IP.
    fn a_record_compressed(ip: [u8; 4], ttl: u32) -> Vec<u8> {
        let mut r = Vec::new();
        r.extend_from_slice(&0xC00Cu16.to_be_bytes()); // pointer to offset 0x0C
        r.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        r.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        r.extend_from_slice(&ttl.to_be_bytes()); // TTL
        r.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        r.extend_from_slice(&ip);
        r
    }

    #[test]
    fn build_query_roundtrips_qname() {
        let q = build_query(0x1234, "host.airdns.org").unwrap();
        // header(12) + 4+1 host + 6+1 airdns + 3+1 org + 1 root + 4 (qtype+qclass)
        assert_eq!(&q[0..2], &[0x12, 0x34]);
        assert_eq!(&q[2..4], &[0x01, 0x00]); // RD flag
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT=1
        // First label length + content.
        assert_eq!(q[12], 4);
        assert_eq!(&q[13..17], b"host");
        // Trailing QTYPE=A, QCLASS=IN.
        assert_eq!(&q[q.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
    }

    #[test]
    fn build_query_rejects_oversized_label() {
        let long = "a".repeat(64);
        assert!(build_query(1, &long).is_none());
    }

    #[test]
    fn parse_compressed_a_record() {
        let ans = a_record_compressed([203, 0, 113, 7], 300);
        let resp = make_response(0x4744, 0x8180, "host.airdns.org", 1, &ans);
        assert_eq!(parse_first_a(&resp, 0x4744), Some(Ipv4Addr::new(203, 0, 113, 7)));
    }

    #[test]
    fn parse_uncompressed_owner_name() {
        // Answer with a full (uncompressed) owner name instead of a pointer.
        let mut ans = Vec::new();
        for label in "host.airdns.org".split('.') {
            ans.push(label.len() as u8);
            ans.extend_from_slice(label.as_bytes());
        }
        ans.push(0);
        ans.extend_from_slice(&1u16.to_be_bytes()); // A
        ans.extend_from_slice(&1u16.to_be_bytes()); // IN
        ans.extend_from_slice(&60u32.to_be_bytes());
        ans.extend_from_slice(&4u16.to_be_bytes());
        ans.extend_from_slice(&[10, 11, 12, 13]);
        let resp = make_response(0x4744, 0x8180, "host.airdns.org", 1, &ans);
        assert_eq!(parse_first_a(&resp, 0x4744), Some(Ipv4Addr::new(10, 11, 12, 13)));
    }

    #[test]
    fn parse_skips_non_a_then_finds_a() {
        // First answer is a CNAME (TYPE=5) with compressed owner; second is the A.
        let mut cname = Vec::new();
        cname.extend_from_slice(&0xC00Cu16.to_be_bytes());
        cname.extend_from_slice(&5u16.to_be_bytes()); // TYPE CNAME
        cname.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        cname.extend_from_slice(&100u32.to_be_bytes());
        // RDATA: a single-label target + root (6 bytes).
        let rdata: &[u8] = &[3, b'a', b'b', b'c', 0];
        cname.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        cname.extend_from_slice(rdata);

        let mut ans = cname;
        ans.extend_from_slice(&a_record_compressed([1, 2, 3, 4], 50));
        let resp = make_response(0x4744, 0x8180, "host.airdns.org", 2, &ans);
        assert_eq!(parse_first_a(&resp, 0x4744), Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn parse_rejects_id_mismatch() {
        let ans = a_record_compressed([1, 1, 1, 1], 1);
        let resp = make_response(0x0001, 0x8180, "host.airdns.org", 1, &ans);
        assert_eq!(parse_first_a(&resp, 0x4744), None);
    }

    #[test]
    fn parse_rejects_nxdomain_rcode() {
        // RCODE=3 (NXDOMAIN) in low nibble of flags.
        let resp = make_response(0x4744, 0x8183, "host.airdns.org", 0, &[]);
        assert_eq!(parse_first_a(&resp, 0x4744), None);
    }

    #[test]
    fn parse_rejects_no_answers() {
        let resp = make_response(0x4744, 0x8180, "host.airdns.org", 0, &[]);
        assert_eq!(parse_first_a(&resp, 0x4744), None);
    }

    #[test]
    fn parse_rejects_truncated_rdata() {
        // Claim RDLENGTH=4 but supply only 2 bytes of RDATA.
        let mut ans = Vec::new();
        ans.extend_from_slice(&0xC00Cu16.to_be_bytes());
        ans.extend_from_slice(&1u16.to_be_bytes());
        ans.extend_from_slice(&1u16.to_be_bytes());
        ans.extend_from_slice(&10u32.to_be_bytes());
        ans.extend_from_slice(&4u16.to_be_bytes()); // claims 4
        ans.extend_from_slice(&[9, 9]); // only 2
        let resp = make_response(0x4744, 0x8180, "host.airdns.org", 1, &ans);
        assert_eq!(parse_first_a(&resp, 0x4744), None);
    }

    #[test]
    fn parse_rejects_short_header() {
        assert_eq!(parse_first_a(&[0, 0, 0], 0), None);
    }

    // --- decide_heal ---

    #[test]
    fn heal_match_proceeds() {
        let ip = Ipv4Addr::new(5, 5, 5, 5);
        assert_eq!(decide_heal(Some(ip), Some(ip), 0, CORRECTIVE_CAP), HealAction::Proceed);
    }

    #[test]
    fn heal_lookup_failed_proceeds() {
        let want = Ipv4Addr::new(5, 5, 5, 5);
        assert_eq!(decide_heal(None, Some(want), 0, CORRECTIVE_CAP), HealAction::Proceed);
    }

    #[test]
    fn heal_unknown_exit_proceeds() {
        let got = Ipv4Addr::new(5, 5, 5, 5);
        assert_eq!(decide_heal(Some(got), None, 0, CORRECTIVE_CAP), HealAction::Proceed);
    }

    #[test]
    fn heal_drift_under_cap_corrects() {
        let got = Ipv4Addr::new(1, 1, 1, 1);
        let want = Ipv4Addr::new(2, 2, 2, 2);
        assert_eq!(decide_heal(Some(got), Some(want), 0, CORRECTIVE_CAP), HealAction::Correct { attempt: 1 });
        assert_eq!(decide_heal(Some(got), Some(want), 1, CORRECTIVE_CAP), HealAction::Correct { attempt: 2 });
    }

    #[test]
    fn heal_drift_at_cap_gives_up() {
        let got = Ipv4Addr::new(1, 1, 1, 1);
        let want = Ipv4Addr::new(2, 2, 2, 2);
        assert_eq!(decide_heal(Some(got), Some(want), 2, CORRECTIVE_CAP), HealAction::GiveUp);
        assert_eq!(decide_heal(Some(got), Some(want), 3, CORRECTIVE_CAP), HealAction::GiveUp);
    }
}
