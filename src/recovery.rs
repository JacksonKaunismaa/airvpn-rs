//! Crash recovery + signal handling for clean disconnect.
//!
//! Saves connection state to a JSON file so that if the process crashes or is
//! killed, a subsequent `airvpn recover` can clean up (tear down WireGuard,
//! restore DNS, remove nftables rules).
//!
//! Recovery sequence matches normal disconnect order (WireGuard → IPv6 → DNS → netlock):
//! 1. wireguard::disconnect(config_path) (ip link delete)
//! 2. ipv6::restore() (re-enable IPv6 on blocked interfaces)
//! 3. dns::deactivate() (restore resolv.conf)
//! 4. netlock::deactivate() (delete nft table — removed last to prevent leaks)
//! 5. Remove state file
//!
//! Reference: Eddie src/Lib.Core/Recovery.cs

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use log::{debug, info, warn};

use crate::{dns, ipv6, netlock, wireguard};

const STATE_DIR: &str = "/run/airvpn-rs";
const STATE_FILE: &str = "/run/airvpn-rs/state.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct State {
    pub lock_active: bool,
    pub wg_interface: String,
    pub wg_config_path: String,
    pub dns_ipv4: String,
    pub dns_ipv6: String,
    pub pid: u32,
    #[serde(default)]
    pub blocked_ipv6_ifaces: Vec<String>,
    /// VPN server endpoint IP — needed to clean up the host route on disconnect/recovery.
    #[serde(default)]
    pub endpoint_ip: String,
    /// Random nonce to detect PID reuse (TOCTOU race). Written by the process that
    /// created the state file; verified in `is_pid_alive` to ensure the PID still
    /// belongs to the same process instance.
    #[serde(default)]
    pub nonce: u64,
}

/// Validate deserialized state content to reject tampered/corrupted state files.
fn validate_state(state: &State) -> bool {
    // Validate interface name if present
    if !state.wg_interface.is_empty() && !crate::common::validate_interface_name(&state.wg_interface) {
        warn!("state validation failed: invalid wg_interface {:?}", state.wg_interface);
        return false;
    }

    // Validate blocked IPv6 interface names
    for iface in &state.blocked_ipv6_ifaces {
        if !crate::common::validate_interface_name(iface) {
            warn!("state validation failed: invalid blocked_ipv6_iface {:?}", iface);
            return false;
        }
    }

    // Validate wg_config_path: must be under /run/airvpn-rs/ with no path traversal
    if !state.wg_config_path.is_empty() {
        let path = std::path::Path::new(&state.wg_config_path);
        if !state.wg_config_path.starts_with("/run/airvpn-rs/")
            || path.components().any(|c| matches!(c, std::path::Component::ParentDir))
        {
            warn!(
                "state validation failed: invalid wg_config_path {:?}",
                state.wg_config_path
            );
            return false;
        }
    }

    // Validate IPs if present
    if !state.dns_ipv4.is_empty() && state.dns_ipv4.parse::<std::net::IpAddr>().is_err() {
        warn!("state validation failed: invalid dns_ipv4 {:?}", state.dns_ipv4);
        return false;
    }
    if !state.dns_ipv6.is_empty() && state.dns_ipv6.parse::<std::net::IpAddr>().is_err() {
        warn!("state validation failed: invalid dns_ipv6 {:?}", state.dns_ipv6);
        return false;
    }
    if !state.endpoint_ip.is_empty() && state.endpoint_ip.parse::<std::net::IpAddr>().is_err() {
        warn!("state validation failed: invalid endpoint_ip {:?}", state.endpoint_ip);
        return false;
    }

    true
}

/// Generate a random nonce for PID-reuse detection.
pub fn generate_nonce() -> u64 {
    rand::Rng::gen(&mut rand::thread_rng())
}

/// Ensure the state directory exists with mode 0o755.
/// The directory needs to be world-accessible because the GUI helper socket
/// lives here and non-root users need to connect to it. The state file itself
/// is 0o600 (root-only) so sensitive data is still protected.
fn ensure_state_dir() -> Result<()> {
    let dir = Path::new(STATE_DIR);
    if !dir.exists() {
        fs::create_dir_all(dir)
            .with_context(|| format!("failed to create state directory: {}", STATE_DIR))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to set permissions on {}", STATE_DIR))?;
    }
    Ok(())
}

/// Get the state file path. Only uses /run/airvpn-rs/ (no /tmp fallback).
fn state_path() -> PathBuf {
    PathBuf::from(STATE_FILE)
}

/// Find the state file if it exists.
fn find_state_file() -> Option<PathBuf> {
    let path = PathBuf::from(STATE_FILE);
    if path.exists() {
        return Some(path);
    }
    None
}

/// Save current connection state.
pub fn save(state: &State) -> Result<()> {
    debug!(
        "Saving recovery state: lock={}, iface={}, dns={}/{}, pid={}, ipv6_blocked={}, endpoint={}, nonce={}",
        state.lock_active,
        state.wg_interface,
        state.dns_ipv4,
        state.dns_ipv6,
        state.pid,
        state.blocked_ipv6_ifaces.len(),
        state.endpoint_ip,
        state.nonce,
    );
    ensure_state_dir()?;
    let path = state_path();
    let json = serde_json::to_string_pretty(state).context("failed to serialize state")?;

    // Write to temp file then atomic rename (crash-safe)
    let dir = path.parent().unwrap_or(Path::new(STATE_DIR));

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;

        let mut tmpfile = tempfile::NamedTempFile::new_in(dir)
            .with_context(|| format!("failed to create temp state file in {}", dir.display()))?;

        // Set permissions before writing content
        std::fs::set_permissions(tmpfile.path(), std::fs::Permissions::from_mode(0o600))
            .with_context(|| "failed to set temp state file permissions")?;

        tmpfile.write_all(json.as_bytes())
            .with_context(|| "failed to write state to temp file")?;
        tmpfile.as_file().sync_all()
            .with_context(|| "failed to sync state file")?;

        tmpfile.persist(&path)
            .with_context(|| format!("failed to persist state file: {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&path, json)
            .with_context(|| format!("failed to write state file: {}", path.display()))?;
    }

    Ok(())
}

/// Load state from file. Returns None if no state file exists.
pub fn load() -> Result<Option<State>> {
    match find_state_file() {
        Some(path) => {
            let json = match fs::read_to_string(&path) {
                Ok(j) => j,
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                    // State file exists but we can't read it (e.g., root-owned,
                    // running as non-root). Treat as "not our state file."
                    warn!("state file exists but not readable (permission denied): {}", path.display());
                    return Ok(None);
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("failed to read state file: {}: {}", path.display(), e));
                }
            };
            match serde_json::from_str::<State>(&json) {
                Ok(state) => {
                    if !validate_state(&state) {
                        warn!("state file failed validation, removing it");
                        let _ = fs::remove_file(&path);
                        return Ok(None);
                    }
                    Ok(Some(state))
                }
                Err(e) => {
                    warn!("corrupt state file ({}), removing it", e);
                    let _ = fs::remove_file(&path);
                    Ok(None)
                }
            }
        }
        None => Ok(None),
    }
}

/// Remove the state file.
pub fn remove() -> Result<()> {
    if let Some(path) = find_state_file() {
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove state file: {}", path.display()))?;
    }
    Ok(())
}

/// Check if a PID is still alive, with nonce verification to defeat PID reuse.
///
/// Three checks, in order:
/// 1. kill(pid, 0) — is the process alive at all?
/// 2. /proc/PID/comm == "airvpn" — is it our binary?
/// 3. Nonce from state file matches — is it the same instance?
///
/// The nonce check defeats the TOCTOU race where a PID is recycled between
/// checks: even if a new process happens to be named "airvpn" (unlikely but
/// possible), it won't have the same nonce in its state file.
pub fn is_pid_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    if kill(Pid::from_raw(pid as i32), None).is_err() {
        return false;
    }

    // Verify the process is actually airvpn (not a recycled PID)
    let comm_path = format!("/proc/{}/comm", pid);
    match std::fs::read_to_string(&comm_path) {
        Ok(name) => name.trim() == "airvpn",
        Err(_) => false, // Can't verify — assume dead
    }
}

/// Check if a PID is alive AND owns the current state file (nonce-verified).
///
/// This is the preferred check that uses the nonce to defeat PID reuse.
/// Falls back to basic `is_pid_alive()` if the state has no nonce (old format).
pub fn is_pid_alive_with_nonce(pid: u32, expected_nonce: u64) -> bool {
    if !is_pid_alive(pid) {
        return false;
    }

    // If no nonce was set (old state file format), fall back to basic PID check
    if expected_nonce == 0 {
        return true;
    }

    // Verify the nonce in the current state file matches what we expect.
    // If the PID was recycled and a new airvpn instance wrote a new state file,
    // its nonce will differ.
    match load() {
        Ok(Some(current_state)) => current_state.nonce == expected_nonce && current_state.pid == pid,
        _ => false, // Can't read state — assume dead
    }
}

/// Delete orphaned WireGuard config files (`avpn0.conf`, `avpn-*.conf`) from
/// the state directory. These contain private keys and must not linger after
/// disconnect or crash.
fn cleanup_wg_configs() {
    if let Ok(entries) = std::fs::read_dir(STATE_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if (name == "avpn0.conf" || name.starts_with("avpn-")) && name.ends_with(".conf") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// Delete orphaned routing policy rules (table 51820 fwmark and suppress_prefixlength)
/// and optionally the endpoint host route.
///
/// Each rule type is deleted in a bounded loop (up to `MAX_RULE_DELETIONS`) to
/// clean up duplicates while preventing infinite loops. If `endpoint_ip` is
/// provided, its host route (`/32` or `/128`) is also removed.
fn cleanup_routing_rules(endpoint_ip: Option<&str>) {
    let routing_cleanups: &[&[&str]] = &[
        &["ip", "-4", "rule", "delete", "table", "main", "suppress_prefixlength", "0"],
        &["ip", "-6", "rule", "delete", "table", "main", "suppress_prefixlength", "0"],
        &["ip", "-4", "rule", "delete", "not", "fwmark", "51820", "table", "51820"],
        &["ip", "-6", "rule", "delete", "not", "fwmark", "51820", "table", "51820"],
    ];
    for cmd in routing_cleanups {
        let mut deleted = 0;
        for _ in 0..crate::common::MAX_RULE_DELETIONS {
            match std::process::Command::new(cmd[0]).args(&cmd[1..]).output() {
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

    // Clean up endpoint host route if known
    if let Some(ip) = endpoint_ip {
        if !ip.is_empty() {
            let is_ipv6 = ip.contains(':');
            let cidr_suffix = if is_ipv6 { "/128" } else { "/32" };
            let ip_version = if is_ipv6 { "-6" } else { "-4" };
            let endpoint_route = format!("{}{}", ip, cidr_suffix);
            let _ = std::process::Command::new("ip")
                .args([ip_version, "route", "delete", &endpoint_route])
                .output();
        }
    }
}

/// Run the recovery cleanup sequence:
/// 1. wireguard::disconnect(config_path) (ip link delete)
/// 2. netlock::deactivate() (remove session lock — unblocks DNS for step 4)
/// 3. ipv6::restore() (re-enable IPv6 on blocked interfaces)
/// 4. dns::deactivate() (restore resolv.conf)
/// 5. Remove state file
fn recover_from_state(state: &State) -> Result<()> {
    let mut cleanup_failed = false;

    // 1. Disconnect WireGuard
    if !state.wg_config_path.is_empty() {
        let iface = if state.wg_interface.is_empty() { wireguard::VPN_INTERFACE } else { &state.wg_interface };
        if let Err(e) = wireguard::disconnect(&state.wg_config_path, &state.endpoint_ip, iface) {
            warn!("failed to disconnect WireGuard: {}", e);
            cleanup_failed = true;
        }
    } else if !state.wg_interface.is_empty() {
        if let Err(e) = std::process::Command::new("ip")
            .args(["link", "delete", &state.wg_interface])
            .output()
            .and_then(|o| if o.status.success() { Ok(()) } else {
                Err(std::io::Error::other(String::from_utf8_lossy(&o.stderr).to_string()))
            })
        {
            warn!("failed to delete WireGuard interface {}: {}", state.wg_interface, e);
            cleanup_failed = true;
        }
    }

    // 1b. Clean up any orphaned WireGuard config files (contain private keys)
    cleanup_wg_configs();

    // 1c. Clean up routing policy rules (table 51820) that setup_routing adds.
    cleanup_routing_rules(Some(&state.endpoint_ip));

    // 2. Deactivate session lock BEFORE DNS restore — the lock's policy drop
    //    blocks DNS to restored nameservers during the slow dns::deactivate() cleanup.
    if state.lock_active {
        if let Err(e) = netlock::deactivate() {
            warn!("failed to deactivate network lock: {}", e);
            cleanup_failed = true;
        }
    }

    // 3. Restore IPv6 on previously blocked interfaces
    if !state.blocked_ipv6_ifaces.is_empty() {
        ipv6::restore(&state.blocked_ipv6_ifaces);
        info!("restored IPv6 on {} interfaces", state.blocked_ipv6_ifaces.len());
    }

    // 4. Restore DNS (delete our resolv.conf, ask NM/resolved to regenerate)
    if let Err(e) = dns::deactivate() {
        warn!("failed to restore DNS: {}", e);
        cleanup_failed = true;
    }

    // 5. Only remove state file if all cleanup steps succeeded.
    // If any failed, keep it so next startup can retry recovery.
    if cleanup_failed {
        warn!("some cleanup steps failed; keeping state file for next recovery attempt");
    } else {
        remove()?;
    }

    Ok(())
}

/// Check for stale state and recover: if the PID in the state file is dead,
/// run the cleanup sequence.
pub fn check_and_recover() -> Result<()> {
    let state = match load()? {
        Some(s) => s,
        None => return Ok(()), // No state file, nothing to recover
    };

    if is_pid_alive_with_nonce(state.pid, state.nonce) {
        anyhow::bail!(
            "another airvpn-rs instance (PID {}) appears to be running",
            state.pid
        );
    }

    info!("recovering from stale state (PID {} is dead)...", state.pid);
    recover_from_state(&state)
}

/// Force recovery regardless of PID status.
///
/// If a state file exists, runs full `recover_from_state`. If no state file
/// exists, still checks for and cleans up orphaned system state (session lock,
/// DNS backup, WireGuard configs) that may have been left behind by a crash
/// where state.json was already removed (e.g., successful disconnect followed
/// by a helper kill that left the persistent lock blocking DNS).
pub fn force_recover() -> Result<()> {
    match load()? {
        Some(s) => {
            info!("force recovering from state file...");
            return recover_from_state(&s);
        }
        None => {
            info!("no state file found, checking for orphaned system state...");
        }
    }

    // Even without state.json, clean up anything that might be stuck.
    let mut found_orphans = false;

    // Orphaned resolv.conf with our header (left behind by an unclean shutdown
    // before the previous session could ask NM to regenerate it).
    let resolv = std::path::Path::new("/etc/resolv.conf");
    if resolv.exists() {
        let is_ours = std::fs::read_to_string(resolv)
            .map(|c| c.contains("Created by airvpn-rs"))
            .unwrap_or(false);
        if is_ours {
            warn!("restoring orphaned VPN resolv.conf");
            let _ = dns::deactivate();
            found_orphans = true;
        }
    }

    // Best-effort cleanup of any old-format DNS backup file from prior versions.
    let legacy_backup = std::path::Path::new("/etc/resolv.conf.airvpn-rs");
    if legacy_backup.exists() {
        warn!("removing stale DNS backup file from prior version");
        let _ = std::fs::remove_file(legacy_backup);
        found_orphans = true;
    }

    // Orphaned session lock (persistent lock is intentionally left alone)
    if netlock::is_active() {
        warn!("removing orphaned session nftables table");
        let _ = netlock::deactivate();
        found_orphans = true;
    }

    // Orphaned WireGuard configs — check if any exist before cleanup so we
    // can track whether orphans were found.
    if let Ok(entries) = std::fs::read_dir(STATE_DIR) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if (name == "avpn0.conf" || name.starts_with("avpn-")) && name.ends_with(".conf") {
                found_orphans = true;
                break;
            }
        }
    }
    cleanup_wg_configs();

    // Orphaned routing policy rules — do a trial delete to detect orphans,
    // then let cleanup_routing_rules handle the bounded loop for all rules.
    // We check just the first rule type to set found_orphans; the helper
    // cleans all 4 types regardless.
    let trial_cmd = ["ip", "-4", "rule", "delete", "table", "main", "suppress_prefixlength", "0"];
    if let Ok(output) = std::process::Command::new(trial_cmd[0]).args(&trial_cmd[1..]).output() {
        if output.status.success() {
            found_orphans = true;
        }
    }
    cleanup_routing_rules(None);

    if !found_orphans {
        info!("no orphaned state found");
    }

    Ok(())
}

/// Set up SIGINT/SIGTERM handler that sets a flag.
///
/// Returns an Arc<AtomicBool> that becomes true when a signal is received.
/// The caller should poll this flag in its main loop to trigger graceful shutdown.
pub fn setup_signal_handler() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));

    // SAFETY: signal_hook_registry style — we only set an atomic bool.
    // Using nix::sys::signal for the handler setup.
    //
    // NOTE: We intentionally do NOT use SA_RESTART. With SA_RESTART, blocking
    // syscalls (DNS resolution, HTTP requests via reqwest) auto-restart after
    // the signal, making Ctrl+C unresponsive during verification and other
    // blocking operations. Without SA_RESTART, these calls return EINTR,
    // causing reqwest/DNS to fail fast and letting the main thread check the
    // shutdown flag promptly.
    unsafe {
        nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGINT,
            &nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::Handler(signal_handler),
                nix::sys::signal::SaFlags::empty(),
                nix::sys::signal::SigSet::empty(),
            ),
        )
        .context("failed to install SIGINT handler")?;

        nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGTERM,
            &nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::Handler(signal_handler),
                nix::sys::signal::SaFlags::empty(),
                nix::sys::signal::SigSet::empty(),
            ),
        )
        .context("failed to install SIGTERM handler")?;

        nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGHUP,
            &nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::Handler(signal_handler),
                nix::sys::signal::SaFlags::empty(),
                nix::sys::signal::SigSet::empty(),
            ),
        )
        .context("failed to install SIGHUP handler")?;
    }

    // Store the flag in a global so the C-style handler can access it.
    // If already initialized (e.g. helper called us first, then connect::run()
    // calls us again), return the existing flag instead of failing.
    match SHUTDOWN_FLAG.set(Arc::clone(&shutdown)) {
        Ok(()) => Ok(shutdown),
        Err(_) => Ok(Arc::clone(SHUTDOWN_FLAG.get().unwrap())),
    }
}

/// Global storage for the shutdown flag, accessed from the signal handler.
static SHUTDOWN_FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

/// C-compatible signal handler that sets the shutdown flag.
extern "C" fn signal_handler(sig: nix::libc::c_int) {
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        flag.store(true, Ordering::SeqCst);
    }
    // Cannot use log macros in signal handlers (not async-signal-safe).
    // Signal number is recorded; the main loop will log when it detects the flag.
    let _ = sig;
}

/// Trigger the shutdown flag. Used by helper to request disconnect.
pub fn trigger_shutdown() {
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        flag.store(true, Ordering::SeqCst);
    }
}

/// Reset the shutdown flag for a new connection.
pub fn reset_shutdown() {
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        flag.store(false, Ordering::SeqCst);
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_serialization_roundtrip() {
        let state = State {
            lock_active: true,
            wg_interface: "avpn0".to_string(),
            wg_config_path: "/run/airvpn-rs/avpn0.conf".to_string(),
            dns_ipv4: "10.128.0.1".to_string(),
            dns_ipv6: "fd7d:76ee:3c49:9950::1".to_string(),
            pid: 12345,
            blocked_ipv6_ifaces: vec!["eth0".to_string(), "wlan0".to_string()],
            endpoint_ip: String::new(),
            nonce: 42424242,
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: State = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.lock_active, state.lock_active);
        assert_eq!(parsed.wg_interface, state.wg_interface);
        assert_eq!(parsed.wg_config_path, state.wg_config_path);
        assert_eq!(parsed.dns_ipv4, state.dns_ipv4);
        assert_eq!(parsed.dns_ipv6, state.dns_ipv6);
        assert_eq!(parsed.pid, state.pid);
        assert_eq!(parsed.blocked_ipv6_ifaces, state.blocked_ipv6_ifaces);
        assert_eq!(parsed.nonce, state.nonce);
    }

    #[test]
    fn test_state_deserialize_without_blocked_ipv6_ifaces() {
        // Old state files won't have the field — serde(default) should handle it
        let json = r#"{
            "lock_active": true,
            "wg_interface": "wg0",
            "wg_config_path": "/run/airvpn-rs/wg0.conf",
            "dns_ipv4": "10.0.0.1",
            "dns_ipv6": "fd00::1",
            "pid": 12345
        }"#;
        let state: State = serde_json::from_str(json).unwrap();
        assert!(state.blocked_ipv6_ifaces.is_empty());
        assert_eq!(state.nonce, 0, "old format without nonce should default to 0");
    }

    #[test]
    fn test_is_pid_alive_current_process() {
        // After PID-reuse fix, is_pid_alive checks /proc/<pid>/comm == "airvpn".
        // The test binary is not named "airvpn", so this should return false
        // even though the process is alive — by design.
        let pid = std::process::id();
        assert!(!is_pid_alive(pid), "non-airvpn process should not be considered alive");
    }

    #[test]
    fn test_is_pid_alive_dead_process() {
        // PID 2^31-1 (i32::MAX = 2147483647) is almost certainly not in use.
        // Note: u32::MAX wraps to -1 as i32, and kill(-1, 0) signals all
        // processes, so we avoid that.
        assert!(!is_pid_alive(i32::MAX as u32));
    }

    #[test]
    fn test_validate_state_valid() {
        let state = State {
            lock_active: true,
            wg_interface: "avpn0".to_string(),
            wg_config_path: "/run/airvpn-rs/avpn0.conf".to_string(),
            dns_ipv4: "10.0.0.1".to_string(),
            dns_ipv6: "fd00::1".to_string(),
            pid: 12345,
            blocked_ipv6_ifaces: vec!["eth0".to_string()],
            endpoint_ip: "1.2.3.4".to_string(),
            nonce: 42,
        };
        assert!(validate_state(&state));
    }

    #[test]
    fn test_validate_state_invalid_interface() {
        let state = State {
            lock_active: true,
            wg_interface: "../../../etc/passwd".to_string(),
            wg_config_path: String::new(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            pid: 12345,
            blocked_ipv6_ifaces: vec![],
            endpoint_ip: String::new(),
            nonce: 0,
        };
        assert!(!validate_state(&state));
    }

    #[test]
    fn test_validate_state_invalid_ip() {
        let state = State {
            lock_active: true,
            wg_interface: "wg0".to_string(),
            wg_config_path: String::new(),
            dns_ipv4: "not-an-ip".to_string(),
            dns_ipv6: String::new(),
            pid: 12345,
            blocked_ipv6_ifaces: vec![],
            endpoint_ip: String::new(),
            nonce: 0,
        };
        assert!(!validate_state(&state));
    }

    #[test]
    fn test_validate_state_invalid_blocked_iface() {
        let state = State {
            lock_active: true,
            wg_interface: String::new(),
            wg_config_path: String::new(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            pid: 12345,
            blocked_ipv6_ifaces: vec!["../../../etc".to_string()],
            endpoint_ip: String::new(),
            nonce: 0,
        };
        assert!(!validate_state(&state));
    }

    #[test]
    fn test_validate_state_empty_fields_valid() {
        // Empty optional fields should pass validation
        let state = State {
            lock_active: false,
            wg_interface: String::new(),
            wg_config_path: String::new(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            pid: 0,
            blocked_ipv6_ifaces: vec![],
            endpoint_ip: String::new(),
            nonce: 0,
        };
        assert!(validate_state(&state));
    }

    #[test]
    fn test_validate_state_invalid_wg_config_path_traversal() {
        let state = State {
            lock_active: true,
            wg_interface: String::new(),
            wg_config_path: "/run/airvpn-rs/../../../etc/passwd".to_string(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            pid: 12345,
            blocked_ipv6_ifaces: vec![],
            endpoint_ip: String::new(),
            nonce: 0,
        };
        assert!(!validate_state(&state));
    }

    #[test]
    fn test_validate_state_invalid_wg_config_path_wrong_dir() {
        let state = State {
            lock_active: true,
            wg_interface: String::new(),
            wg_config_path: "/tmp/evil.conf".to_string(),
            dns_ipv4: String::new(),
            dns_ipv6: String::new(),
            pid: 12345,
            blocked_ipv6_ifaces: vec![],
            endpoint_ip: String::new(),
            nonce: 0,
        };
        assert!(!validate_state(&state));
    }

}
