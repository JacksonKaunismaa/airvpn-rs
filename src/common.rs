//! Shared utilities used across multiple modules.

use anyhow::Result;
use std::net::IpAddr;
use zeroize::Zeroizing;

/// Maximum routing rule deletions per teardown pass.
///
/// Used by `wireguard::teardown_routing` and `recovery::recover_from_state`
/// to bound the deletion loop and prevent infinite iteration if rule deletion
/// keeps "succeeding" without actually removing the rule.
pub const MAX_RULE_DELETIONS: usize = 100;

/// Validate a network interface name.
///
/// Allows the characters the Linux kernel permits that are also safe in every
/// context we interpolate the name into: ASCII alphanumerics, '-', '_', and '.'
/// ('.' is needed for VLAN sub-interfaces like "eth0.100"). This is safe because
/// every nft interpolation quotes the name (`oifname "{}"`), so '.' can't break
/// out of the string, and the IPv6 sysctl paths are built with path joins
/// (`/proc/sys/net/ipv6/conf/{iface}/...`), not dotted sysctl names, so '.' is a
/// normal path component there too.
///
/// Rejects (defense-in-depth against command/path injection in nft, `ip`/
/// `resolvectl` argv, sysctl paths, and WireGuard config):
/// - empty, or longer than the 15-char kernel limit (IFNAMSIZ - 1)
/// - the special names "." and ".." (path traversal in the /proc/sys joins;
///   the kernel rejects them anyway)
/// - a leading '-', which `ip`/`resolvectl` would parse as a flag (argv
///   option-injection)
pub fn validate_interface_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 15 || name == "." || name == ".." {
        return false;
    }
    if name.starts_with('-') {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
}

/// Validate that `s` is a bare IP address or an `IP/prefix` CIDR whose prefix
/// length is in range for its address family.
///
/// Crucially, this validates the ENTIRE string. A `split('/').next()`-style
/// check validates only the address and silently keeps any trailing bytes after
/// the prefix — which is dangerous because these strings are interpolated into
/// `nft -f` rulesets and `ip -batch` command streams. A value like
/// `1.2.3.4/32 ; <nft statements>` or `1.2.3.4/0\n<ip command>` would otherwise
/// pass (its address parses) and inject rules/commands that run as root. Every
/// IP/CIDR that reaches such a sink MUST pass through this check (or be skipped
/// when it returns false).
pub fn is_valid_ip_or_cidr(s: &str) -> bool {
    match s.split_once('/') {
        None => s.parse::<IpAddr>().is_ok(),
        Some((addr, prefix)) => match addr.parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => matches!(prefix.parse::<u8>(), Ok(p) if p <= 32),
            Ok(IpAddr::V6(_)) => matches!(prefix.parse::<u8>(), Ok(p) if p <= 128),
            Err(_) => false,
        },
    }
}

/// Read password from stdin when `--password-stdin` is set.
///
/// Returns `None` if `password_stdin` is false. Trims trailing newlines
/// and rejects empty input. The returned string is wrapped in `Zeroizing`
/// to clear it from memory on drop.
pub fn read_stdin_password(password_stdin: bool) -> Result<Option<Zeroizing<String>>> {
    if !password_stdin {
        return Ok(None);
    }
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| anyhow::anyhow!("failed to read password from stdin: {}", e))?;
    let trimmed = line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string();
    if trimmed.is_empty() {
        anyhow::bail!("--password-stdin: received empty password");
    }
    Ok(Some(Zeroizing::new(trimmed)))
}

/// Exponential backoff: `3 * 2^(n-1)` capped at 300 seconds.
///
/// Used by the reconnection loop after WireGuard failures, handshake
/// timeouts, and verification failures.
pub fn backoff_secs(consecutive_failures: u32) -> u64 {
    std::cmp::min(
        3u64.saturating_mul(
            2u64.saturating_pow(consecutive_failures.saturating_sub(1).min(6)),
        ),
        300,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_interface_name_valid() {
        assert!(validate_interface_name("wg0"));
        assert!(validate_interface_name("avpn0"));
        assert!(validate_interface_name("eth_0"));
        assert!(validate_interface_name("a")); // single char
        assert!(validate_interface_name("123456789012345")); // exactly 15 chars
        assert!(validate_interface_name("eth0.100")); // VLAN sub-interface
        assert!(validate_interface_name("br0.10")); // VLAN on a bridge
    }

    #[test]
    fn test_validate_interface_name_invalid() {
        assert!(!validate_interface_name("")); // empty
        assert!(!validate_interface_name("1234567890123456")); // 16 chars
        assert!(!validate_interface_name("a-very-long-interface-name")); // way too long
        assert!(!validate_interface_name("wg 0")); // space
        assert!(!validate_interface_name("../etc/passwd")); // path traversal ('/')
        assert!(!validate_interface_name("wg\0")); // null byte
        assert!(!validate_interface_name("-foo")); // leading '-' -> argv option injection
        assert!(!validate_interface_name(".")); // current dir
        assert!(!validate_interface_name("..")); // parent dir (traversal)
        assert!(!validate_interface_name("eth0\"; drop")); // nft quote break-out
    }

    #[test]
    fn test_is_valid_ip_or_cidr() {
        // Bare IPs
        assert!(is_valid_ip_or_cidr("1.2.3.4"));
        assert!(is_valid_ip_or_cidr("fd00::1"));
        // In-range CIDRs
        assert!(is_valid_ip_or_cidr("10.0.0.0/8"));
        assert!(is_valid_ip_or_cidr("1.2.3.4/32"));
        assert!(is_valid_ip_or_cidr("fd00::/64"));
        assert!(is_valid_ip_or_cidr("::/0"));
        // Out-of-range prefixes
        assert!(!is_valid_ip_or_cidr("1.2.3.4/33"));
        assert!(!is_valid_ip_or_cidr("fd00::1/129"));
        // Garbage / non-IP
        assert!(!is_valid_ip_or_cidr("not-an-ip"));
        assert!(!is_valid_ip_or_cidr(""));
        // Injection: address parses, but trailing bytes after the prefix must
        // make the WHOLE string invalid (this is the core guarantee).
        assert!(!is_valid_ip_or_cidr("1.2.3.4/32 ; ip daddr 0.0.0.0/0 counter accept #"));
        assert!(!is_valid_ip_or_cidr("1.2.3.4/0\nroute add 0.0.0.0/0 via 10.0.0.1"));
        assert!(!is_valid_ip_or_cidr("1.2.3.4/")); // empty prefix
        assert!(!is_valid_ip_or_cidr("1.2.3.4/32/8")); // double prefix
    }

    #[test]
    fn test_backoff_secs() {
        assert_eq!(backoff_secs(0), 3); // 3 * 2^0 = 3 (saturating_sub clamps to 0)
        assert_eq!(backoff_secs(1), 3); // 3 * 2^0 = 3
        assert_eq!(backoff_secs(2), 6); // 3 * 2^1 = 6
        assert_eq!(backoff_secs(3), 12); // 3 * 2^2 = 12
        assert_eq!(backoff_secs(4), 24); // 3 * 2^3 = 24
        assert_eq!(backoff_secs(5), 48); // 3 * 2^4 = 48
        assert_eq!(backoff_secs(6), 96); // 3 * 2^5 = 96
        assert_eq!(backoff_secs(7), 192); // 3 * 2^6 = 192 (exponent capped at 6)
        assert_eq!(backoff_secs(8), 192); // exponent still 6 due to .min(6)
        assert_eq!(backoff_secs(100), 192); // same — exponent maxes at 6
        assert_eq!(backoff_secs(u32::MAX), 192); // saturating, exponent capped at 6
    }

}
