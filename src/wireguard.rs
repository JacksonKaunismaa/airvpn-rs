//! WireGuard config generation and wg-quick management.
//!
//! Generates WireGuard config from manifest data and manages the tunnel
//! lifecycle via wg-quick up/down.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::manifest::{Mode, Server, UserInfo, WireGuardKey};

/// Generate a WireGuard config from manifest data.
///
/// The config format matches what wg-quick expects. IPv4 entry IPs are
/// preferred over IPv6 (matching Eddie's default `network.entry.iplayer =
/// "ipv4-ipv6"`), since we block IPv6 on all interfaces during connection.
/// The endpoint IP is selected at `mode.entry_index` within the preferred
/// IP version, falling back to the first IP of that version, then trying
/// the other version.
///
/// IPv6 endpoint IPs are wrapped in brackets per WireGuard convention.
pub fn generate_config(key: &WireGuardKey, server: &Server, mode: &Mode, user: &UserInfo) -> Result<String> {
    if key.wg_private_key.is_empty() {
        anyhow::bail!("missing WireGuard private key from API response");
    }
    if user.wg_public_key.is_empty() {
        anyhow::bail!("missing WireGuard server public key from API response");
    }
    if mode.port == 0 {
        anyhow::bail!("WireGuard mode has no port configured");
    }

    // Prefer IPv4 entry IPs (matching Eddie's default network.entry.iplayer="ipv4-ipv6")
    // Since we block IPv6 on all interfaces, IPv6 entry IPs would fail
    let ipv4_entries: Vec<&String> = server.ips_entry.iter()
        .filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
        .collect();
    let ipv6_entries: Vec<&String> = server.ips_entry.iter()
        .filter(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok())
        .collect();

    // Try IPv4 first (at entry_index), then fall back to IPv6
    let endpoint_ip = ipv4_entries.get(mode.entry_index)
        .or_else(|| ipv4_entries.first())
        .or_else(|| ipv6_entries.get(mode.entry_index))
        .or_else(|| ipv6_entries.first())
        .ok_or_else(|| anyhow::anyhow!("server {} has no entry IPs", server.name))?;

    // IPv6 addresses (containing ':') must be wrapped in brackets for the endpoint
    let endpoint = if endpoint_ip.contains(':') {
        format!("[{}]:{}", endpoint_ip, mode.port)
    } else {
        format!("{}:{}", endpoint_ip, mode.port)
    };

    let mut peer_section = format!(
        "\
[Peer]
PublicKey = {}
",
        user.wg_public_key,
    );

    if !key.wg_preshared.is_empty() {
        peer_section.push_str(&format!("PresharedKey = {}\n", key.wg_preshared));
    }

    peer_section.push_str(&format!(
        "\
Endpoint = {}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
",
        endpoint,
    ));

    Ok(format!(
        "\
[Interface]
PrivateKey = {}
Address = {}/32, {}/128
MTU = 1320

{}",
        key.wg_private_key,
        key.wg_ipv4,
        key.wg_ipv6,
        peer_section,
    ))
}

/// Write config to a tmpfile, run `wg-quick up`, return (config_path, interface_name).
///
/// The interface name is derived by wg-quick from the config filename
/// (basename without .conf extension).
pub fn connect(config: &str) -> Result<(String, String)> {
    // Write config to a temporary file with a recognizable prefix
    let tmpfile = tempfile::Builder::new()
        .prefix("avpn-")
        .suffix(".conf")
        .tempfile()
        .context("failed to create temporary WireGuard config file")?;

    // Persist the file so wg-quick can read it (NamedTempFile deletes on drop)
    let (_, path) = tmpfile.keep().context("failed to persist temporary config file")?;
    let config_path = path.to_string_lossy().to_string();

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&config_path)
            .with_context(|| format!("failed to create WireGuard config: {}", config_path))?;
        f.write_all(config.as_bytes())
            .with_context(|| format!("failed to write WireGuard config: {}", config_path))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&config_path, config)
            .with_context(|| format!("failed to write WireGuard config to {}", config_path))?;
    }

    // Interface name = basename without .conf
    let iface = Path::new(&config_path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .context("failed to derive interface name from config path")?;

    // Pre-cleanup: if interface already exists from a crash, remove it
    if is_connected(&iface) {
        eprintln!("Cleaning up stale WireGuard interface {}...", iface);
        let _ = Command::new("ip")
            .args(["link", "delete", &iface])
            .output();
    }

    let output = Command::new("wg-quick")
        .args(["up", &config_path])
        .output()
        .context("failed to execute wg-quick up")?;

    if !output.status.success() {
        // Clean up config file containing private keys
        let _ = std::fs::remove_file(&config_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("wg-quick up failed: {}", stderr);
    }

    Ok((config_path, iface))
}

/// Run `wg-quick down` to disconnect the WireGuard tunnel.
pub fn disconnect(config_path: &str) -> Result<()> {
    let output = Command::new("wg-quick")
        .args(["down", config_path])
        .output()
        .context("failed to execute wg-quick down")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("wg-quick down failed: {}", stderr);
    }

    // Clean up the config file
    let _ = std::fs::remove_file(config_path);

    Ok(())
}

/// Check if a WireGuard interface exists by looking for it in /sys/class/net.
pub fn is_connected(iface: &str) -> bool {
    Path::new(&format!("/sys/class/net/{}", iface)).exists()
}

/// Get the Unix timestamp of the latest handshake for an interface.
/// Returns None if no handshake has occurred yet.
///
/// Uses `wg show <iface> latest-handshakes` which outputs:
///   <public_key>\t<unix_timestamp>\n
/// A timestamp of 0 means no handshake yet.
pub fn latest_handshake(iface: &str) -> Option<u64> {
    let output = Command::new("wg")
        .args(["show", iface, "latest-handshakes"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Format: "<pubkey>\t<timestamp>\n"
    for line in stdout.lines() {
        if let Some(ts_str) = line.split('\t').nth(1) {
            if let Ok(ts) = ts_str.trim().parse::<u64>() {
                if ts > 0 {
                    return Some(ts);
                }
            }
        }
    }
    None
}

/// Wait for the first WireGuard handshake after connection.
///
/// Eddie uses handshake_timeout_first=50 seconds. If no handshake arrives
/// within the timeout, the tunnel is likely misconfigured (wrong key,
/// blocked port, unreachable server).
pub fn wait_for_handshake(iface: &str, timeout_secs: u64) -> Result<()> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            anyhow::bail!(
                "no WireGuard handshake within {}s — server may be unreachable or key may be wrong",
                timeout_secs
            );
        }

        if latest_handshake(iface).is_some() {
            return Ok(());
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// Check if the latest handshake is stale (older than threshold).
///
/// Eddie uses handshake_timeout_connected=200 seconds.
/// Returns true if handshake is stale or missing.
pub fn is_handshake_stale(iface: &str, max_age_secs: u64) -> bool {
    match latest_handshake(iface) {
        None => true,
        Some(ts) => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now.saturating_sub(ts) > max_age_secs
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> WireGuardKey {
        WireGuardKey {
            name: "default".to_string(),
            wg_private_key: "PrivateKeyBase64==".to_string(),
            wg_ipv4: "10.128.0.42".to_string(),
            wg_ipv6: "fd7d:76ee:3c49:9950::42".to_string(),
            wg_dns_ipv4: "10.128.0.1".to_string(),
            wg_dns_ipv6: "fd7d:76ee:3c49:9950::1".to_string(),
            wg_preshared: "PresharedKeyBase64==".to_string(),
        }
    }

    fn test_server() -> Server {
        Server {
            name: "Alchiba".to_string(),
            group: "eu-it".to_string(),
            ips_entry: vec!["185.32.12.1".to_string(), "185.32.12.2".to_string()],
            ips_exit: vec!["185.32.12.10".to_string()],
            country_code: "IT".to_string(),
            location: "Milan".to_string(),
            scorebase: 0,
            bandwidth: 500_000,
            bandwidth_max: 1_000_000,
            users: 42,
            users_max: 250,
            support_ipv4: true,
            support_ipv6: true,
            warning_open: String::new(),
            warning_closed: String::new(),
        }
    }

    fn test_mode() -> Mode {
        Mode {
            title: "WireGuard UDP 1637".to_string(),
            protocol: "UDP".to_string(),
            port: 1637,
            entry_index: 0,
        }
    }

    fn test_user() -> UserInfo {
        UserInfo {
            login: "testuser".to_string(),
            wg_public_key: "PublicKeyBase64==".to_string(),
            keys: vec![test_key()],
        }
    }

    #[test]
    fn test_generate_config_format() {
        let key = test_key();
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let config = generate_config(&key, &server, &mode, &user).unwrap();

        // Check [Interface] section
        assert!(config.contains("[Interface]"));
        assert!(config.contains("PrivateKey = PrivateKeyBase64=="));
        assert!(config.contains("Address = 10.128.0.42/32, fd7d:76ee:3c49:9950::42/128"));
        assert!(config.contains("MTU = 1320"));
        // DNS is NOT in config — managed by dns.rs to avoid double-configuration
        assert!(!config.contains("DNS ="), "DNS line should not be in WireGuard config (managed by dns.rs)");

        // Check [Peer] section
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PublicKey = PublicKeyBase64=="));
        assert!(config.contains("PresharedKey = PresharedKeyBase64=="));
        assert!(config.contains("Endpoint = 185.32.12.1:1637"));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(config.contains("PersistentKeepalive = 15"));
    }

    #[test]
    fn test_generate_config_empty_preshared_key() {
        let mut key = test_key();
        key.wg_preshared = String::new();
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let config = generate_config(&key, &server, &mode, &user).unwrap();
        assert!(
            !config.contains("PresharedKey"),
            "empty preshared key should not produce PresharedKey line"
        );
    }

    #[test]
    fn test_generate_config_entry_index() {
        let key = test_key();
        let server = test_server();
        let user = test_user();

        // Use entry_index=1 to select the second IP
        let mode = Mode {
            title: "WireGuard UDP 1637".to_string(),
            protocol: "UDP".to_string(),
            port: 1637,
            entry_index: 1,
        };

        let config = generate_config(&key, &server, &mode, &user).unwrap();
        assert!(
            config.contains("Endpoint = 185.32.12.2:1637"),
            "should use second entry IP when entry_index=1"
        );
    }

    #[test]
    fn test_generate_config_entry_index_out_of_bounds_falls_back() {
        let key = test_key();
        let server = test_server();
        let user = test_user();

        // entry_index=99 is out of bounds — should fall back to first IP
        let mode = Mode {
            title: "WireGuard UDP 1637".to_string(),
            protocol: "UDP".to_string(),
            port: 1637,
            entry_index: 99,
        };

        let config = generate_config(&key, &server, &mode, &user).unwrap();
        assert!(
            config.contains("Endpoint = 185.32.12.1:1637"),
            "should fall back to first entry IP when entry_index is out of bounds"
        );
    }

    #[test]
    fn test_generate_config_no_entry_ips_errors() {
        let key = test_key();
        let user = test_user();
        let mode = test_mode();

        let server = Server {
            name: "EmptyServer".to_string(),
            group: "eu-it".to_string(),
            ips_entry: vec![],
            ips_exit: vec![],
            country_code: "IT".to_string(),
            location: "Milan".to_string(),
            scorebase: 0,
            bandwidth: 0,
            bandwidth_max: 0,
            users: 0,
            users_max: 0,
            support_ipv4: true,
            support_ipv6: true,
            warning_open: String::new(),
            warning_closed: String::new(),
        };

        let result = generate_config(&key, &server, &mode, &user);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no entry IPs"));
    }

    #[test]
    fn test_generate_config_ipv6_endpoint_brackets() {
        let key = test_key();
        let user = test_user();
        let mode = test_mode();

        let server = Server {
            name: "IPv6Server".to_string(),
            group: "eu-de".to_string(),
            ips_entry: vec!["fd00::1".to_string()],
            ips_exit: vec!["fd00::10".to_string()],
            country_code: "DE".to_string(),
            location: "Berlin".to_string(),
            scorebase: 0,
            bandwidth: 500_000,
            bandwidth_max: 1_000_000,
            users: 10,
            users_max: 250,
            support_ipv4: true,
            support_ipv6: true,
            warning_open: String::new(),
            warning_closed: String::new(),
        };

        let config = generate_config(&key, &server, &mode, &user).unwrap();
        assert!(
            config.contains("Endpoint = [fd00::1]:1637"),
            "IPv6 endpoint should be wrapped in brackets, got: {}",
            config
        );
    }

    #[test]
    fn test_generate_config_different_port() {
        let key = test_key();
        let server = test_server();
        let user = test_user();

        let mode = Mode {
            title: "WireGuard UDP 443".to_string(),
            protocol: "UDP".to_string(),
            port: 443,
            entry_index: 0,
        };

        let config = generate_config(&key, &server, &mode, &user).unwrap();
        assert!(config.contains("Endpoint = 185.32.12.1:443"));
    }

    #[test]
    fn test_generate_config_section_ordering() {
        let key = test_key();
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let config = generate_config(&key, &server, &mode, &user).unwrap();

        let interface_pos = config.find("[Interface]").expect("[Interface]");
        let peer_pos = config.find("[Peer]").expect("[Peer]");
        assert!(
            interface_pos < peer_pos,
            "[Interface] section should come before [Peer]"
        );
    }

    #[test]
    fn test_is_connected_nonexistent_iface() {
        // A random interface name should not exist
        assert!(!is_connected("airvpn-rs-nonexistent-test-12345"));
    }
}
