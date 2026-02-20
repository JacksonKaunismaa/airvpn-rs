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
/// The config format matches what wg-quick expects. The endpoint IP is
/// selected from `server.ips_entry` using `mode.entry_index`.
pub fn generate_config(key: &WireGuardKey, server: &Server, mode: &Mode, user: &UserInfo) -> String {
    let endpoint_ip = &server.ips_entry[mode.entry_index];

    format!(
        "\
[Interface]
PrivateKey = {}
Address = {}/32, {}/128
DNS = {}, {}

[Peer]
PublicKey = {}
PresharedKey = {}
Endpoint = {}:{}
AllowedIPs = 0.0.0.0/0, ::/0
",
        key.wg_private_key,
        key.wg_ipv4,
        key.wg_ipv6,
        key.wg_dns_ipv4,
        key.wg_dns_ipv6,
        user.wg_public_key,
        key.wg_preshared,
        endpoint_ip,
        mode.port,
    )
}

/// Write config to a tmpfile, run `wg-quick up`, return (config_path, interface_name).
///
/// The interface name is derived by wg-quick from the config filename
/// (basename without .conf extension).
pub fn connect(config: &str) -> Result<(String, String)> {
    // Write config to a temporary file with a recognizable prefix
    let tmpfile = tempfile::Builder::new()
        .prefix("airvpn-rs-")
        .suffix(".conf")
        .tempfile()
        .context("failed to create temporary WireGuard config file")?;

    // Persist the file so wg-quick can read it (NamedTempFile deletes on drop)
    let (_, path) = tmpfile.keep().context("failed to persist temporary config file")?;
    let config_path = path.to_string_lossy().to_string();

    std::fs::write(&config_path, config)
        .with_context(|| format!("failed to write WireGuard config to {}", config_path))?;

    // Interface name = basename without .conf
    let iface = Path::new(&config_path)
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .context("failed to derive interface name from config path")?;

    let output = Command::new("wg-quick")
        .args(["up", &config_path])
        .output()
        .context("failed to execute wg-quick up")?;

    if !output.status.success() {
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

        let config = generate_config(&key, &server, &mode, &user);

        // Check [Interface] section
        assert!(config.contains("[Interface]"));
        assert!(config.contains("PrivateKey = PrivateKeyBase64=="));
        assert!(config.contains("Address = 10.128.0.42/32, fd7d:76ee:3c49:9950::42/128"));
        assert!(config.contains("DNS = 10.128.0.1, fd7d:76ee:3c49:9950::1"));

        // Check [Peer] section
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PublicKey = PublicKeyBase64=="));
        assert!(config.contains("PresharedKey = PresharedKeyBase64=="));
        assert!(config.contains("Endpoint = 185.32.12.1:1637"));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
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

        let config = generate_config(&key, &server, &mode, &user);
        assert!(
            config.contains("Endpoint = 185.32.12.2:1637"),
            "should use second entry IP when entry_index=1"
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

        let config = generate_config(&key, &server, &mode, &user);
        assert!(config.contains("Endpoint = 185.32.12.1:443"));
    }

    #[test]
    fn test_generate_config_section_ordering() {
        let key = test_key();
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let config = generate_config(&key, &server, &mode, &user);

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
