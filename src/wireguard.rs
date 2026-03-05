//! WireGuard config generation and tunnel lifecycle management.
//!
//! Generates wg-native config from manifest data and manages the tunnel
//! via direct `ip`/`wg` commands (no wg-quick dependency).

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use log::{debug, error, warn};

use crate::manifest::{Mode, Server, UserInfo, WireGuardKey};

/// Secure directory for WireGuard config files (mode 0o700).
/// Avoids /tmp which is world-readable and vulnerable to symlink attacks.
const WG_CONFIG_DIR: &str = "/run/airvpn-rs";

/// MTU for the WireGuard interface. Matches Eddie's WireGuard MTU.
const WG_MTU: u16 = 1320;

/// Fixed WireGuard interface name. Using a constant instead of a random
/// tempfile-derived name enables exact nftables matching (`oifname "avpn0"`)
/// rather than wildcard matching (`oifname "avpn-*"`), which is more secure
/// and easier to debug.
pub const VPN_INTERFACE: &str = "avpn0";

/// Parameters for establishing a WireGuard connection.
///
/// Returned by `generate_config()` with the wg-native config and the
/// address/MTU info that `connect()` needs to set up the interface.
#[derive(Debug)]
pub struct WgConnectParams {
    /// wg-native config (PrivateKey + Peer section only, for `wg setconf`).
    /// Wrapped in Zeroizing because it contains the private key.
    pub wg_config: zeroize::Zeroizing<String>,
    /// IPv4 address with CIDR (e.g., "10.167.32.97/32")
    pub ipv4_address: String,
    /// IPv6 address with CIDR (e.g., "fd7d:76ee:.../128").
    /// Kept for future IPv6-through-tunnel support but NOT assigned in block mode.
    pub ipv6_address: String,
    /// VPN server endpoint IP (without port)
    pub endpoint_ip: String,
}

/// Validate an interface name: alphanumeric + dash + underscore, max 15 chars.
/// Matches the validation in netlock.rs to prevent path traversal and command injection.
fn validate_interface_name(iface: &str) -> Result<()> {
    if !crate::common::validate_interface_name(iface) {
        anyhow::bail!("invalid interface name: {:?}", iface);
    }
    Ok(())
}

/// Validate a WireGuard key (private, public, or preshared).
///
/// WireGuard keys are 32 bytes encoded as base64, producing exactly 44 characters
/// of [A-Za-z0-9+/=]. Rejects newlines, carriage returns, and non-printable
/// characters to prevent config injection (e.g., injecting PostUp/PostDown lines).
fn validate_wg_key(key: &str, name: &str) -> Result<()> {
    if key.len() != 44 {
        anyhow::bail!("{} has unexpected length {} (expected 44)", name, key.len());
    }
    if key
        .chars()
        .any(|c| c == '\n' || c == '\r' || !c.is_ascii_graphic())
    {
        anyhow::bail!("{} contains invalid characters", name);
    }
    // Strict base64 character set
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    {
        anyhow::bail!("{} contains non-base64 characters", name);
    }
    Ok(())
}

/// Validate a WireGuard IP address (IPv4 or IPv6, with optional CIDR suffix).
///
/// Strips any CIDR suffix before parsing. Rejects newlines, carriage returns,
/// and non-printable characters to prevent config injection.
fn validate_wg_ip(ip: &str, name: &str) -> Result<()> {
    if ip
        .chars()
        .any(|c| c == '\n' || c == '\r' || !c.is_ascii_graphic())
    {
        anyhow::bail!("{} contains invalid characters", name);
    }
    // Strip CIDR suffix if present (e.g., "10.0.0.1/32" -> "10.0.0.1")
    let addr_part = ip.split('/').next().unwrap_or(ip);
    if addr_part.parse::<std::net::IpAddr>().is_err() {
        anyhow::bail!("{} is not a valid IP address: {:?}", name, ip);
    }
    Ok(())
}

/// Ensure an IP address has a CIDR suffix. If it already has one, return as-is.
/// If not, append the default suffix.
fn ensure_cidr(ip: &str, default_suffix: &str) -> String {
    if ip.contains('/') {
        ip.to_string()
    } else {
        format!("{}{}", ip, default_suffix)
    }
}

/// Generate a WireGuard config from manifest data.
///
/// Returns `(config_string, endpoint_ip)`. The endpoint IP is needed by
/// `connect()` to set up a host route through the original default gateway,
/// preventing a routing loop when policy routing sends all traffic through
/// the VPN.
///
/// The config format is wg-native (suitable for `wg setconf`), NOT wg-quick.
/// It contains only fields the WireGuard kernel module understands:
/// `[Interface]` with `PrivateKey`, and `[Peer]` with keys/endpoint/AllowedIPs.
///
/// wg-quick-only directives (Address, MTU, Table, DNS, PostUp/PostDown) are
/// NOT included — we handle those via direct `ip` commands in `connect()`.
///
/// IPv4 entry IPs are preferred over IPv6 (matching Eddie's default
/// `network.entry.iplayer = "ipv4-ipv6"`), since we block IPv6 on all
/// interfaces during connection.
///
/// Returns `WgConnectParams` containing the config and separated address/MTU info.
pub fn generate_config(key: &WireGuardKey, server: &Server, mode: &Mode, user: &UserInfo) -> Result<WgConnectParams> {
    if key.wg_private_key.is_empty() {
        anyhow::bail!("missing WireGuard private key from API response");
    }
    if user.wg_public_key.is_empty() {
        anyhow::bail!("missing WireGuard server public key from API response");
    }
    if mode.port == 0 {
        anyhow::bail!("WireGuard mode has no port configured");
    }

    // Validate key values to prevent config injection via newlines or shell metacharacters.
    // A malicious API response could inject PostUp/PostDown commands into the config.
    validate_wg_key(&key.wg_private_key, "wg_private_key")?;
    validate_wg_key(&user.wg_public_key, "wg_public_key")?;
    if !key.wg_preshared.is_empty() {
        validate_wg_key(&key.wg_preshared, "wg_preshared")?;
    }
    validate_wg_ip(&key.wg_ipv4, "wg_ipv4")?;
    validate_wg_ip(&key.wg_ipv6, "wg_ipv6")?;

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
        peer_section.push_str(&format!("PresharedKey = {}\n", &*key.wg_preshared));
    }

    peer_section.push_str(&format!(
        "\
Endpoint = {}
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 15
",
        endpoint,
    ));

    // wg-native config: only fields `wg setconf` understands.
    // No Address, MTU, Table, DNS, PostUp/PostDown (those are wg-quick extensions).
    let config = zeroize::Zeroizing::new(format!(
        "\
[Interface]
PrivateKey = {}

{}",
        &*key.wg_private_key,
        peer_section,
    ));

    Ok(WgConnectParams {
        wg_config: config,
        ipv4_address: ensure_cidr(&key.wg_ipv4, "/32").to_string(),
        ipv6_address: ensure_cidr(&key.wg_ipv6, "/128").to_string(),
        endpoint_ip: endpoint_ip.to_string(),
    })
}

/// Set up a WireGuard tunnel using direct `ip`/`wg` commands (no wg-quick).
///
/// Steps:
/// 1. Write wg-native config to a temp file (private key stays in file, not cmdline)
/// 2. `ip link add dev <iface> type wireguard`
/// 3. `wg setconf <iface> <config_path>`
/// 4. `ip -4 address add <ipv4> dev <iface>` (IPv4 only — no IPv6 in block mode)
/// 5. `ip link set mtu <mtu> dev <iface>`
/// 6. `ip link set up dev <iface>`
/// 7. `setup_routing()` — policy routing through the tunnel
///
/// Returns (config_path, interface_name) on success.
pub fn connect(params: &WgConnectParams, ipv6_enabled: bool) -> Result<(String, String)> {
    debug!("WireGuard connect: endpoint_ip={}, config_len={} bytes",
           params.endpoint_ip, params.wg_config.len());

    // Ensure secure config directory exists with mode 0o700
    let config_dir = Path::new(WG_CONFIG_DIR);
    if !config_dir.exists() {
        std::fs::create_dir_all(config_dir)
            .with_context(|| format!("failed to create config directory: {}", WG_CONFIG_DIR))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to set permissions on {}", WG_CONFIG_DIR))?;
    }

    // Write config to a temporary file in the secure directory with a recognizable prefix
    let tmpfile = tempfile::Builder::new()
        .prefix("avpn-")
        .suffix(".conf")
        .tempfile_in(config_dir)
        .context("failed to create WireGuard config file in /run/airvpn-rs/")?;

    // Persist the file (NamedTempFile deletes on drop)
    let (_, path) = tmpfile.keep().context("failed to persist config file")?;
    let config_path = path.to_string_lossy().to_string();

    // Helper to clean up the persisted config file (contains private key) on error.
    let cleanup_config = |path: &str| {
        let _ = std::fs::remove_file(path);
    };

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&config_path)
        {
            Ok(f) => f,
            Err(e) => {
                cleanup_config(&config_path);
                return Err(anyhow::Error::new(e)
                    .context(format!("failed to create WireGuard config: {}", config_path)));
            }
        };
        if let Err(e) = f.write_all(params.wg_config.as_bytes()) {
            cleanup_config(&config_path);
            return Err(anyhow::Error::new(e)
                .context(format!("failed to write WireGuard config: {}", config_path)));
        }
    }
    #[cfg(not(unix))]
    {
        if let Err(e) = std::fs::write(&config_path, &*params.wg_config) {
            cleanup_config(&config_path);
            return Err(anyhow::Error::new(e)
                .context(format!("failed to write WireGuard config to {}", config_path)));
        }
    }

    // Fixed interface name (decoupled from config file naming)
    let iface = VPN_INTERFACE.to_string();

    // Pre-cleanup: if interface already exists from a crash, remove it
    if is_connected(&iface) {
        warn!("Cleaning up stale WireGuard interface {}...", iface);
        let _ = Command::new("ip")
            .args(["link", "delete", &iface])
            .output();
    }

    // Helper to clean up interface + config on failure
    let cleanup_all = |iface: &str, config_path: &str| {
        let _ = Command::new("ip").args(["link", "delete", iface]).output();
        let _ = std::fs::remove_file(config_path);
    };

    // 1. Create WireGuard interface
    let output = Command::new("ip")
        .args(["link", "add", "dev", &iface, "type", "wireguard"])
        .output()
        .context("failed to execute: ip link add type wireguard")?;
    if !output.status.success() {
        cleanup_config(&config_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip link add dev {} type wireguard failed: {}", iface, stderr.trim());
    }

    // 2. Load config (keys + peer) — private key stays in file, not on cmdline
    let output = Command::new("wg")
        .args(["setconf", &iface, &config_path])
        .output()
        .context("failed to execute: wg setconf")?;
    if !output.status.success() {
        cleanup_all(&iface, &config_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("wg setconf {} {} failed: {}", iface, config_path, stderr.trim());
    }

    // 3. Add IPv4 address only (no IPv6 — matches Eddie's in-block mode)
    let output = Command::new("ip")
        .args(["-4", "address", "add", &params.ipv4_address, "dev", &iface])
        .output()
        .context("failed to execute: ip address add")?;
    if !output.status.success() {
        cleanup_all(&iface, &config_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip -4 address add {} dev {} failed: {}", params.ipv4_address, iface, stderr.trim());
    }

    // 4. Set MTU
    let mtu_str = WG_MTU.to_string();
    let output = Command::new("ip")
        .args(["link", "set", "mtu", &mtu_str, "dev", &iface])
        .output()
        .context("failed to execute: ip link set mtu")?;
    if !output.status.success() {
        cleanup_all(&iface, &config_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip link set mtu {} dev {} failed: {}", WG_MTU, iface, stderr.trim());
    }

    // 5. Bring interface up
    let output = Command::new("ip")
        .args(["link", "set", "up", "dev", &iface])
        .output()
        .context("failed to execute: ip link set up")?;
    if !output.status.success() {
        cleanup_all(&iface, &config_path);
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ip link set up dev {} failed: {}", iface, stderr.trim());
    }

    // 6. Optionally enable IPv6 on the WG interface (for "in" / "in-block" mode)
    //    The interface inherits disable_ipv6=1 from the default sysctl template.
    //    We explicitly re-enable IPv6 on just this interface, then add the address.
    //    This is race-free: all other interfaces stay blocked.
    if ipv6_enabled && !params.ipv6_address.is_empty() {
        let disable_path = format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", iface);
        if let Err(e) = std::fs::write(&disable_path, "0") {
            warn!("failed to re-enable IPv6 on {}: {} (continuing without IPv6)", iface, e);
        } else {
            let output = Command::new("ip")
                .args(["-6", "address", "add", &params.ipv6_address, "dev", &iface])
                .output()
                .context("failed to execute: ip -6 address add")?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("ip -6 address add {} dev {} failed: {} (continuing without IPv6)",
                      params.ipv6_address, iface, stderr.trim());
            } else {
                debug!("IPv6 address {} added to {}", params.ipv6_address, iface);
            }
        }
    }

    // 7. Set up policy routing through the tunnel
    if let Err(e) = setup_routing(&iface, &params.endpoint_ip) {
        cleanup_all(&iface, &config_path);
        return Err(e);
    }

    Ok((config_path, iface))
}

/// Check if any IPv4 default gateway exists (i.e., is the network up?).
///
/// Used to distinguish "server failed" from "network is down" during
/// reconnection. After partial_disconnect removes the WireGuard interface,
/// a missing default gateway means the underlying network (WiFi/ethernet)
/// is down — not a server-specific failure.
pub fn has_default_gateway() -> bool {
    get_default_gateway().is_ok()
}

/// Get the current IPv4 default gateway from the main routing table.
///
/// Parses `ip -4 route show default` output which looks like:
///   default via 192.168.1.1 dev eth0 proto dhcp metric 100
fn get_default_gateway() -> Result<String> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .context("failed to execute: ip -4 route show default")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse "default via <gateway> ..."
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            return Ok(parts[2].to_string());
        }
    }

    anyhow::bail!("no IPv4 default gateway found (is the network up?)")
}

/// Get the current IPv6 default gateway from the main routing table.
///
/// Parses `ip -6 route show default` output which looks like:
///   default via fe80::1 dev eth0 proto ra metric 100
fn get_default_gateway_v6() -> Result<String> {
    let output = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .context("failed to execute: ip -6 route show default")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse "default via <gateway> ..."
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "default" && parts[1] == "via" {
            return Ok(parts[2].to_string());
        }
    }

    anyhow::bail!("no IPv6 default gateway found — cannot route to IPv6 VPN endpoint")
}

/// Set up routing for the VPN tunnel.
///
/// We manage routing directly via `ip` commands (no wg-quick). This matches
/// what Eddie does (Eddie manages routing via ip commands).
///
/// The sequence is critical to avoid a routing loop:
/// 1. Set fwmark on WireGuard interface so its encrypted packets use the main
///    routing table (not table 51820).
/// 2. Save the original default gateway before any route changes.
/// 3. Add a host route for the VPN endpoint through the original gateway so
///    encrypted packets can reach the server.
/// 4. Add default route through VPN interface in table 51820.
/// 5. Add policy rule: unmarked traffic uses table 51820.
/// 6. Suppress default route from main table to prevent leaks.
fn setup_routing(iface: &str, endpoint_ip: &str) -> Result<()> {
    debug!("Setting up routing: iface={}, endpoint_ip={}", iface, endpoint_ip);
    // 1. Set fwmark on WireGuard interface — MUST be first, before any policy
    //    routing rules. Without this, WireGuard's own encrypted packets (going
    //    to the real VPN server) would be routed through table 51820 (i.e.,
    //    back through the VPN interface), creating a routing loop.
    let output = Command::new("wg")
        .args(["set", iface, "fwmark", "51820"])
        .output()
        .context("failed to execute: wg set fwmark")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("wg set {} fwmark 51820 failed: {}", iface, stderr.trim());
    }

    // 2. Save original default gateway before any route changes.
    //    Use the correct IP version gateway for the endpoint to avoid creating
    //    invalid routes (e.g., IPv6 endpoint via IPv4 gateway).
    let is_ipv6_endpoint = endpoint_ip.contains(':');
    let original_gw = if is_ipv6_endpoint {
        get_default_gateway_v6()?
    } else {
        get_default_gateway()?
    };
    debug!("Original default gateway ({}): {}", if is_ipv6_endpoint { "v6" } else { "v4" }, original_gw);

    // 3. Add host route for VPN endpoint through original gateway.
    //    This ensures encrypted WireGuard packets reach the server even after
    //    our policy routing redirects everything else through the tunnel.
    let cidr_suffix = if is_ipv6_endpoint { "/128" } else { "/32" };
    let ip_version = if is_ipv6_endpoint { "-6" } else { "-4" };
    let endpoint_route = format!("{}{}", endpoint_ip, cidr_suffix);
    let output = Command::new("ip")
        .args([ip_version, "route", "add", &endpoint_route, "via", &original_gw])
        .output()
        .with_context(|| format!("failed to add host route for endpoint {}", endpoint_ip))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Non-fatal if route already exists (e.g., reconnection to same server)
        if !stderr.contains("File exists") {
            anyhow::bail!(
                "ip route add {} via {} failed: {}",
                endpoint_route,
                original_gw,
                stderr.trim()
            );
        }
    }

    // 4-5. Add default routes through the VPN interface in table 51820
    let route_commands = [
        // IPv4 default route through VPN
        vec!["ip", "-4", "route", "add", "0.0.0.0/0", "dev", iface, "table", "51820"],
        // IPv6 default route through VPN
        vec!["ip", "-6", "route", "add", "::/0", "dev", iface, "table", "51820"],
    ];

    for cmd in &route_commands {
        debug!("Routing command: {}", cmd.join(" "));
        let output = Command::new(cmd[0])
            .args(&cmd[1..])
            .output()
            .with_context(|| format!("failed to execute: {}", cmd.join(" ")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Non-fatal: routes may already exist or IPv6 may be disabled
            warn!("routing: {} -- {}", cmd.join(" "), stderr.trim());
        }
    }

    // 6. IPv4 fwmark policy rule — CRITICAL for VPN security.
    //    Without this rule, all non-VPN traffic bypasses the tunnel.
    {
        let cmd = vec!["ip", "-4", "rule", "add", "not", "fwmark", "51820", "table", "51820"];
        debug!("Routing command (critical): {}", cmd.join(" "));
        let output = Command::new(cmd[0])
            .args(&cmd[1..])
            .output()
            .with_context(|| format!("failed to execute: {}", cmd.join(" ")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("FATAL: IPv4 fwmark policy rule failed — all traffic would bypass VPN: {}", stderr.trim());
            anyhow::bail!(
                "IPv4 fwmark policy rule failed (traffic would leak): {}",
                stderr.trim()
            );
        }
    }

    // IPv6 fwmark policy rule — non-fatal since IPv6 may not be available
    {
        let cmd = vec!["ip", "-6", "rule", "add", "not", "fwmark", "51820", "table", "51820"];
        debug!("Routing command: {}", cmd.join(" "));
        let output = Command::new(cmd[0])
            .args(&cmd[1..])
            .output()
            .with_context(|| format!("failed to execute: {}", cmd.join(" ")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("IPv6 fwmark policy rule failed (IPv6 may not be available): {}", stderr.trim());
        }
    }

    // 7. Suppress default route from main table to prevent leaks
    let suppress_commands = [
        vec!["ip", "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0"],
        vec!["ip", "-6", "rule", "add", "table", "main", "suppress_prefixlength", "0"],
    ];

    for cmd in &suppress_commands {
        debug!("Routing command: {}", cmd.join(" "));
        let output = Command::new(cmd[0])
            .args(&cmd[1..])
            .output()
            .with_context(|| format!("failed to execute: {}", cmd.join(" ")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Non-fatal: may already exist or IPv6 may be disabled
            warn!("routing: {} -- {}", cmd.join(" "), stderr.trim());
        }
    }

    Ok(())
}

/// Tear down VPN routing (reverse of setup_routing).
///
/// `endpoint_ip` is used to remove the host route added during setup.
/// If empty, the host route removal is skipped (best-effort cleanup).
fn teardown_routing(_iface: &str, endpoint_ip: &str) {
    // Remove policy rules first (reverse order of setup).
    // Run each deletion in a loop until it fails, to clean up any duplicate rules
    // that may have been added from prior runs or crashes.
    let commands: &[&[&str]] = &[
        &["ip", "-4", "rule", "delete", "table", "main", "suppress_prefixlength", "0"],
        &["ip", "-6", "rule", "delete", "table", "main", "suppress_prefixlength", "0"],
        &["ip", "-4", "rule", "delete", "not", "fwmark", "51820", "table", "51820"],
        &["ip", "-6", "rule", "delete", "not", "fwmark", "51820", "table", "51820"],
    ];
    for cmd in commands {
        // Loop until the rule no longer exists (command fails).
        // Bound to MAX_RULE_DELETIONS to prevent infinite loops if deletion
        // keeps "succeeding" without actually removing the rule.
        let mut deleted = 0;
        for _ in 0..crate::common::MAX_RULE_DELETIONS {
            match Command::new(cmd[0]).args(&cmd[1..]).output() {
                Ok(output) if output.status.success() => {
                    deleted += 1;
                    continue;
                }
                _ => break,
            }
        }
        if deleted >= crate::common::MAX_RULE_DELETIONS {
            warn!(
                "hit {} rule deletions for {:?} — possible infinite loop",
                crate::common::MAX_RULE_DELETIONS,
                cmd.join(" ")
            );
        }
    }

    // Remove endpoint host route (best-effort — may already be gone if interface was deleted)
    if !endpoint_ip.is_empty() {
        let is_ipv6 = endpoint_ip.contains(':');
        let cidr_suffix = if is_ipv6 { "/128" } else { "/32" };
        let ip_version = if is_ipv6 { "-6" } else { "-4" };
        let endpoint_route = format!("{}{}", endpoint_ip, cidr_suffix);
        let _ = Command::new("ip")
            .args([ip_version, "route", "delete", &endpoint_route])
            .output();
    }
}

/// Disconnect the WireGuard tunnel using direct `ip` commands (no wg-quick).
///
/// Steps:
/// 1. Tear down routing rules (policy routes, endpoint host route)
/// 2. Delete the WireGuard interface (`ip link delete`)
/// 3. Clean up the config file (contains private key)
///
/// `endpoint_ip` is the VPN server's entry IP, needed to clean up the host
/// route added during `setup_routing`. Pass an empty string if unknown
/// (best-effort cleanup will skip the host route removal).
pub fn disconnect(config_path: &str, endpoint_ip: &str) -> Result<()> {
    debug!("WireGuard disconnect: config_path={}, endpoint_ip={}", config_path, endpoint_ip);

    // Validate config_path to prevent path traversal and command injection.
    // Must be under /run/airvpn-rs/ with no parent-dir components.
    if !config_path.is_empty() {
        let path = std::path::Path::new(config_path);
        if !config_path.starts_with("/run/airvpn-rs/")
            || path.components().any(|c| matches!(c, std::path::Component::ParentDir))
        {
            anyhow::bail!("invalid config_path: must be under /run/airvpn-rs/");
        }
    }

    // Fixed interface name (decoupled from config file naming)
    let iface = VPN_INTERFACE;

    // 1. Tear down routing rules before removing the interface
    teardown_routing(iface, endpoint_ip);

    // 2. Delete the WireGuard interface
    {
        let output = Command::new("ip")
            .args(["link", "delete", "dev", iface])
            .output()
            .context("failed to execute: ip link delete")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Non-fatal if interface already gone (e.g., crashed, removed externally)
            if !stderr.contains("Cannot find device") {
                anyhow::bail!("ip link delete dev {} failed: {}", iface, stderr.trim());
            }
        }
    }

    // 3. Clean up the config file (contains private key)
    let _ = std::fs::remove_file(config_path);

    Ok(())
}

/// Check if a WireGuard interface exists by looking for it in /sys/class/net.
///
/// Validates the interface name first to prevent path traversal attacks
/// (e.g., `../../etc/passwd` resolving to an existing file).
pub fn is_connected(iface: &str) -> bool {
    if validate_interface_name(iface).is_err() {
        return false;
    }
    Path::new(&format!("/sys/class/net/{}", iface)).exists()
}

/// Get the Unix timestamp of the latest handshake for an interface.
/// Returns None if no handshake has occurred yet.
///
/// Uses `wg show <iface> latest-handshakes` which outputs:
///   <public_key>\t<unix_timestamp>\n
/// A timestamp of 0 means no handshake yet.
pub fn latest_handshake(iface: &str) -> Option<u64> {
    if validate_interface_name(iface).is_err() {
        return None;
    }

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
    validate_interface_name(iface)?;

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

/// Get transfer statistics for a WireGuard interface.
/// Parses `wg show <iface> transfer` output: <pubkey>\t<rx>\t<tx>
pub fn get_transfer_stats(iface: &str) -> Result<(u64, u64)> {
    validate_interface_name(iface)?;
    let output = Command::new("wg")
        .args(["show", iface, "transfer"])
        .output()
        .context("failed to run wg show transfer")?;
    if !output.status.success() {
        anyhow::bail!("wg show transfer failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or("");
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() < 3 {
        anyhow::bail!("unexpected wg show transfer output: {:?}", line);
    }
    let rx: u64 = parts[1].trim().parse().context("parse rx_bytes")?;
    let tx: u64 = parts[2].trim().parse().context("parse tx_bytes")?;
    Ok((rx, tx))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Valid 44-character base64 strings (WireGuard keys are 32 bytes = 44 base64 chars)
    const TEST_PRIVATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const TEST_PUBLIC_KEY: &str  = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    const TEST_PRESHARED_KEY: &str = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";

    fn test_key() -> WireGuardKey {
        WireGuardKey {
            name: "default".to_string(),
            wg_private_key: zeroize::Zeroizing::new(TEST_PRIVATE_KEY.to_string()),
            wg_ipv4: "10.128.0.42".to_string(),
            wg_ipv6: "fd7d:76ee:3c49:9950::42".to_string(),
            wg_dns_ipv4: "10.128.0.1".to_string(),
            wg_dns_ipv6: "fd7d:76ee:3c49:9950::1".to_string(),
            wg_preshared: zeroize::Zeroizing::new(TEST_PRESHARED_KEY.to_string()),
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
            wg_public_key: TEST_PUBLIC_KEY.to_string(),
            keys: vec![test_key()],
        }
    }

    #[test]
    fn test_generate_config_format() {
        let key = test_key();
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let params = generate_config(&key, &server, &mode, &user).unwrap();
        let config = &*params.wg_config;

        // Verify returned fields
        assert_eq!(params.endpoint_ip, "185.32.12.1");
        assert_eq!(params.ipv4_address, "10.128.0.42/32");
        assert_eq!(params.ipv6_address, "fd7d:76ee:3c49:9950::42/128");

        // Check [Interface] section — wg-native format (no Address/MTU/Table)
        assert!(config.contains("[Interface]"));
        assert!(config.contains(&format!("PrivateKey = {}", TEST_PRIVATE_KEY)));
        // These wg-quick extensions must NOT be present
        assert!(!config.contains("Address ="), "Address is a wg-quick extension, not wg-native");
        assert!(!config.contains("MTU ="), "MTU is a wg-quick extension, not wg-native");
        assert!(!config.contains("Table ="), "Table is a wg-quick extension, not wg-native");
        assert!(!config.contains("DNS ="), "DNS is a wg-quick extension, not wg-native");

        // Check [Peer] section
        assert!(config.contains("[Peer]"));
        assert!(config.contains(&format!("PublicKey = {}", TEST_PUBLIC_KEY)));
        assert!(config.contains(&format!("PresharedKey = {}", TEST_PRESHARED_KEY)));
        assert!(config.contains("Endpoint = 185.32.12.1:1637"));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(config.contains("PersistentKeepalive = 15"));
    }

    #[test]
    fn test_generate_config_empty_preshared_key() {
        let mut key = test_key();
        key.wg_preshared = zeroize::Zeroizing::new(String::new());
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let params = generate_config(&key, &server, &mode, &user).unwrap();
        let config = &*params.wg_config;
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

        let params = generate_config(&key, &server, &mode, &user).unwrap();
        let config = &*params.wg_config;
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

        let params = generate_config(&key, &server, &mode, &user).unwrap();
        let config = &*params.wg_config;
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

        let params = generate_config(&key, &server, &mode, &user).unwrap();
        let config = &*params.wg_config;
        assert!(
            config.contains("Endpoint = [fd00::1]:1637"),
            "IPv6 endpoint should be wrapped in brackets, got: {}",
            &*config
        );
    }

    // -------------------------------------------------------------------
    // generate_config with mixed IPv4+IPv6 entry IPs — IPv4 preferred
    // -------------------------------------------------------------------

    #[test]
    fn test_generate_config_mixed_ips_prefers_ipv4() {
        let key = test_key();
        let user = test_user();
        let mode = test_mode();

        let server = Server {
            name: "MixedServer".to_string(),
            group: "eu-de".to_string(),
            ips_entry: vec![
                "fd00::1".to_string(),       // IPv6 first in list
                "203.0.113.1".to_string(),    // IPv4 second
                "fd00::2".to_string(),        // IPv6 third
            ],
            ips_exit: vec!["10.0.0.1".to_string()],
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

        let params = generate_config(&key, &server, &mode, &user).unwrap();
        let config = &*params.wg_config;
        assert!(
            config.contains("Endpoint = 203.0.113.1:1637"),
            "should prefer IPv4 even when IPv6 is listed first, got: {}",
            &*config
        );
    }

    // -------------------------------------------------------------------
    // generate_config with only IPv6 entries — fallback to IPv6
    // -------------------------------------------------------------------

    #[test]
    fn test_generate_config_only_ipv6_uses_ipv6() {
        let key = test_key();
        let user = test_user();
        let mode = test_mode();

        let server = Server {
            name: "IPv6Only".to_string(),
            group: "eu-de".to_string(),
            ips_entry: vec![
                "2001:db8::1".to_string(),
                "2001:db8::2".to_string(),
            ],
            ips_exit: vec!["2001:db8::10".to_string()],
            country_code: "DE".to_string(),
            location: "Berlin".to_string(),
            scorebase: 0,
            bandwidth: 500_000,
            bandwidth_max: 1_000_000,
            users: 10,
            users_max: 250,
            support_ipv4: false,
            support_ipv6: true,
            warning_open: String::new(),
            warning_closed: String::new(),
        };

        let params = generate_config(&key, &server, &mode, &user).unwrap();
        let config = &*params.wg_config;
        assert!(
            config.contains("Endpoint = [2001:db8::1]:1637"),
            "should fall back to IPv6 when no IPv4 available, got: {}",
            &*config
        );
    }

    // -------------------------------------------------------------------
    // generate_config validation — empty private key
    // -------------------------------------------------------------------

    #[test]
    fn test_generate_config_empty_private_key_errors() {
        let mut key = test_key();
        key.wg_private_key = zeroize::Zeroizing::new(String::new());
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let result = generate_config(&key, &server, &mode, &user);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("private key"),
            "error should mention private key"
        );
    }

    // -------------------------------------------------------------------
    // generate_config validation — empty public key
    // -------------------------------------------------------------------

    #[test]
    fn test_generate_config_empty_public_key_errors() {
        let key = test_key();
        let server = test_server();
        let mode = test_mode();
        let mut user = test_user();
        user.wg_public_key = String::new();

        let result = generate_config(&key, &server, &mode, &user);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("public key"),
            "error should mention public key"
        );
    }

    // -------------------------------------------------------------------
    // generate_config validation — port 0
    // -------------------------------------------------------------------

    #[test]
    fn test_generate_config_port_zero_errors() {
        let key = test_key();
        let server = test_server();
        let user = test_user();

        let mode = Mode {
            title: "Bad Mode".to_string(),
            protocol: "UDP".to_string(),
            port: 0,
            entry_index: 0,
        };

        let result = generate_config(&key, &server, &mode, &user);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("no port"),
            "error should mention port"
        );
    }

    // -------------------------------------------------------------------
    // is_connected with various interface names
    // -------------------------------------------------------------------

    #[test]
    fn test_is_connected_loopback() {
        // "lo" exists on all Linux systems
        assert!(is_connected("lo"), "loopback interface should exist");
    }

    // -------------------------------------------------------------------
    // validate_wg_key — config injection prevention
    // -------------------------------------------------------------------

    #[test]
    fn test_validate_wg_key_valid() {
        assert!(validate_wg_key(TEST_PRIVATE_KEY, "test").is_ok());
        assert!(validate_wg_key(TEST_PUBLIC_KEY, "test").is_ok());
        assert!(validate_wg_key(TEST_PRESHARED_KEY, "test").is_ok());
        // Key with mixed base64 characters including + and /
        assert!(validate_wg_key("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh+/0123456=", "test").is_ok());
    }

    #[test]
    fn test_validate_wg_key_wrong_length() {
        assert!(validate_wg_key("tooshort", "test").is_err());
        assert!(validate_wg_key("", "test").is_err());
        // 45 chars — too long
        assert!(validate_wg_key("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "test").is_err());
    }

    #[test]
    fn test_validate_wg_key_newline_injection() {
        // Contains a newline — the core injection attack vector.
        // \n is 1 byte, so we craft a 44-byte string with an embedded newline.
        let injected = "AAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(injected.len(), 44);
        assert!(validate_wg_key(injected, "test").is_err());
    }

    #[test]
    fn test_validate_wg_key_carriage_return_injection() {
        // Exactly 44 bytes with an embedded \r
        let injected = "AAAAAAAAAAAAAAAAA\rAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(injected.len(), 44);
        assert!(validate_wg_key(injected, "test").is_err());
    }

    #[test]
    fn test_validate_wg_key_non_base64_chars() {
        // 44 chars, all printable, but contains non-base64 chars (spaces, dashes)
        assert!(validate_wg_key("AAAA AAAA-AAAA_AAAA.AAAA!AAAA@AAAA#AAAA$AA=", "test").is_err());
    }

    // -------------------------------------------------------------------
    // validate_wg_ip — IP address validation
    // -------------------------------------------------------------------

    #[test]
    fn test_validate_wg_ip_valid() {
        assert!(validate_wg_ip("10.128.0.42", "test").is_ok());
        assert!(validate_wg_ip("10.128.0.42/32", "test").is_ok());
        assert!(validate_wg_ip("fd7d:76ee:3c49:9950::42", "test").is_ok());
        assert!(validate_wg_ip("fd7d:76ee:3c49:9950::42/128", "test").is_ok());
    }

    #[test]
    fn test_validate_wg_ip_invalid() {
        assert!(validate_wg_ip("not-an-ip", "test").is_err());
        assert!(validate_wg_ip("999.999.999.999", "test").is_err());
    }

    #[test]
    fn test_validate_wg_ip_newline_injection() {
        assert!(validate_wg_ip("10.0.0.1\nPostUp = evil", "test").is_err());
    }

    // -------------------------------------------------------------------
    // generate_config rejects injected keys
    // -------------------------------------------------------------------

    #[test]
    fn test_generate_config_rejects_injected_private_key() {
        let mut key = test_key();
        // Inject a newline into a 44-byte private key to try adding PostUp
        key.wg_private_key = zeroize::Zeroizing::new("AAAAAAAAAAAAAAAAA\nAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string());
        assert_eq!(key.wg_private_key.len(), 44);
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let result = generate_config(&key, &server, &mode, &user);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid characters"),
            "should reject key with newline injection, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_generate_config_rejects_injected_ip() {
        let mut key = test_key();
        key.wg_ipv4 = "10.0.0.1\nPostUp = evil".to_string();
        let server = test_server();
        let mode = test_mode();
        let user = test_user();

        let result = generate_config(&key, &server, &mode, &user);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("invalid characters"),
            "should reject IP with newline injection"
        );
    }

}
