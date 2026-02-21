//! Crash recovery + signal handling for clean disconnect.
//!
//! Saves connection state to a JSON file so that if the process crashes or is
//! killed, a subsequent `airvpn recover` can clean up (tear down WireGuard,
//! restore DNS, remove nftables rules).
//!
//! Recovery sequence matches normal disconnect order (WireGuard → IPv6 → DNS → netlock):
//! 1. wireguard::disconnect(config_path) (wg-quick down)
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

use crate::{dns, ipv6, netlock, wireguard};

const PRIMARY_STATE_DIR: &str = "/run/airvpn-rs";
const PRIMARY_STATE_FILE: &str = "/run/airvpn-rs/state.json";
const FALLBACK_STATE_FILE: &str = "/tmp/airvpn-rs-state.json";

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
}

/// Determine the state file path. Prefers /run/airvpn-rs/ but falls back
/// to /tmp/ if /run is not writable.
fn state_path() -> PathBuf {
    let dir = Path::new(PRIMARY_STATE_DIR);
    if dir.exists() || fs::create_dir_all(dir).is_ok() {
        PathBuf::from(PRIMARY_STATE_FILE)
    } else {
        PathBuf::from(FALLBACK_STATE_FILE)
    }
}

/// Find an existing state file (check both locations).
fn find_state_file() -> Option<PathBuf> {
    let primary = PathBuf::from(PRIMARY_STATE_FILE);
    if primary.exists() {
        return Some(primary);
    }
    let fallback = PathBuf::from(FALLBACK_STATE_FILE);
    if fallback.exists() {
        return Some(fallback);
    }
    None
}

/// Save current connection state.
pub fn save(state: &State) -> Result<()> {
    let path = state_path();
    let json = serde_json::to_string_pretty(state).context("failed to serialize state")?;

    // Write to temp file then atomic rename (crash-safe)
    let dir = path.parent().unwrap_or(std::path::Path::new("/tmp"));

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
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read state file: {}", path.display()))?;
            match serde_json::from_str::<State>(&json) {
                Ok(state) => Ok(Some(state)),
                Err(e) => {
                    eprintln!("warning: corrupt state file ({}), removing it", e);
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

/// Check if a PID is still alive (using kill(pid, 0) signal probe).
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

/// Run the recovery cleanup sequence (matches normal disconnect order):
/// 1. wireguard::disconnect(config_path) (wg-quick down)
/// 2. ipv6::restore() (re-enable IPv6 on blocked interfaces)
/// 3. dns::deactivate() (restore resolv.conf)
/// 4. netlock::deactivate() (delete nft table — removed last to prevent leaks)
/// 5. Remove state file
fn recover_from_state(state: &State) -> Result<()> {
    let mut cleanup_failed = false;

    // 1. Disconnect WireGuard
    if !state.wg_config_path.is_empty() {
        if let Err(e) = wireguard::disconnect(&state.wg_config_path) {
            eprintln!("warning: failed to disconnect WireGuard: {}", e);
            cleanup_failed = true;
        }
    } else if !state.wg_interface.is_empty() {
        // Config path unknown (crash before state update) — delete interface directly
        if let Err(e) = std::process::Command::new("ip")
            .args(["link", "delete", &state.wg_interface])
            .output()
            .and_then(|o| if o.status.success() { Ok(()) } else {
                Err(std::io::Error::new(std::io::ErrorKind::Other,
                    String::from_utf8_lossy(&o.stderr).to_string()))
            })
        {
            eprintln!("warning: failed to delete WireGuard interface {}: {}", state.wg_interface, e);
            cleanup_failed = true;
        }
    }

    // 1b. Clean up any orphaned WireGuard config files (contain private keys)
    if let Ok(entries) = std::fs::read_dir("/tmp") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with("avpn-") && name.ends_with(".conf") {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    // 2. Restore IPv6 on previously blocked interfaces
    if !state.blocked_ipv6_ifaces.is_empty() {
        ipv6::restore(&state.blocked_ipv6_ifaces);
        eprintln!("restored IPv6 on {} interfaces", state.blocked_ipv6_ifaces.len());
    }

    // 3. Restore DNS
    if let Err(e) = dns::deactivate() {
        eprintln!("warning: failed to restore DNS: {}", e);
        cleanup_failed = true;
    }

    // 4. Deactivate network lock if it was active (last — prevents traffic leaks)
    if state.lock_active {
        if let Err(e) = netlock::deactivate() {
            eprintln!("warning: failed to deactivate network lock: {}", e);
            cleanup_failed = true;
        }
    }

    // 5. Only remove state file if all cleanup steps succeeded.
    // If any failed, keep it so next startup can retry recovery.
    if cleanup_failed {
        eprintln!("warning: some cleanup steps failed; keeping state file for next recovery attempt");
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

    if is_pid_alive(state.pid) {
        anyhow::bail!(
            "another airvpn-rs instance (PID {}) appears to be running",
            state.pid
        );
    }

    eprintln!("recovering from stale state (PID {} is dead)...", state.pid);
    recover_from_state(&state)
}

/// Force recovery regardless of PID status.
pub fn force_recover() -> Result<()> {
    let state = match load()? {
        Some(s) => s,
        None => {
            eprintln!("no state file found, nothing to recover");
            return Ok(());
        }
    };

    eprintln!("force recovering...");
    recover_from_state(&state)
}

/// Set up SIGINT/SIGTERM handler that sets a flag.
///
/// Returns an Arc<AtomicBool> that becomes true when a signal is received.
/// The caller should poll this flag in its main loop to trigger graceful shutdown.
pub fn setup_signal_handler() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));

    // SAFETY: signal_hook_registry style — we only set an atomic bool.
    // Using nix::sys::signal for the handler setup.
    unsafe {
        nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGINT,
            &nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::Handler(signal_handler),
                nix::sys::signal::SaFlags::SA_RESTART,
                nix::sys::signal::SigSet::empty(),
            ),
        )
        .context("failed to install SIGINT handler")?;

        nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGTERM,
            &nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::Handler(signal_handler),
                nix::sys::signal::SaFlags::SA_RESTART,
                nix::sys::signal::SigSet::empty(),
            ),
        )
        .context("failed to install SIGTERM handler")?;

        nix::sys::signal::sigaction(
            nix::sys::signal::Signal::SIGHUP,
            &nix::sys::signal::SigAction::new(
                nix::sys::signal::SigHandler::Handler(signal_handler),
                nix::sys::signal::SaFlags::SA_RESTART,
                nix::sys::signal::SigSet::empty(),
            ),
        )
        .context("failed to install SIGHUP handler")?;
    }

    // Store the flag in a global so the C-style handler can access it
    SHUTDOWN_FLAG
        .set(Arc::clone(&shutdown))
        .map_err(|_| anyhow::anyhow!("signal handler already initialized"))?;

    Ok(shutdown)
}

/// Global storage for the shutdown flag, accessed from the signal handler.
static SHUTDOWN_FLAG: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

/// C-compatible signal handler that sets the shutdown flag.
extern "C" fn signal_handler(_sig: nix::libc::c_int) {
    if let Some(flag) = SHUTDOWN_FLAG.get() {
        flag.store(true, Ordering::SeqCst);
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
            wg_interface: "airvpn-rs-abc123".to_string(),
            wg_config_path: "/tmp/airvpn-rs-abc123.conf".to_string(),
            dns_ipv4: "10.128.0.1".to_string(),
            dns_ipv6: "fd7d:76ee:3c49:9950::1".to_string(),
            pid: 12345,
            blocked_ipv6_ifaces: vec!["eth0".to_string(), "wlan0".to_string()],
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
    }

    #[test]
    fn test_state_json_format() {
        let state = State {
            lock_active: false,
            wg_interface: "wg0".to_string(),
            wg_config_path: "/tmp/wg0.conf".to_string(),
            dns_ipv4: "10.0.0.1".to_string(),
            dns_ipv6: "fd00::1".to_string(),
            pid: 99999,
            blocked_ipv6_ifaces: vec![],
        };

        let json = serde_json::to_string_pretty(&state).unwrap();

        // Verify JSON contains expected fields
        assert!(json.contains("\"lock_active\": false"));
        assert!(json.contains("\"wg_interface\": \"wg0\""));
        assert!(json.contains("\"wg_config_path\": \"/tmp/wg0.conf\""));
        assert!(json.contains("\"dns_ipv4\": \"10.0.0.1\""));
        assert!(json.contains("\"dns_ipv6\": \"fd00::1\""));
        assert!(json.contains("\"pid\": 99999"));
        assert!(json.contains("\"blocked_ipv6_ifaces\""));
    }

    #[test]
    fn test_state_deserialize_without_blocked_ipv6_ifaces() {
        // Old state files won't have the field — serde(default) should handle it
        let json = r#"{
            "lock_active": true,
            "wg_interface": "wg0",
            "wg_config_path": "/tmp/wg0.conf",
            "dns_ipv4": "10.0.0.1",
            "dns_ipv6": "fd00::1",
            "pid": 12345
        }"#;
        let state: State = serde_json::from_str(json).unwrap();
        assert!(state.blocked_ipv6_ifaces.is_empty());
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
    fn test_state_with_blocked_ipv6() {
        let state = State {
            lock_active: true,
            wg_interface: "wg0".to_string(),
            wg_config_path: "/tmp/wg0.conf".to_string(),
            dns_ipv4: "10.0.0.1".to_string(),
            dns_ipv6: "fd00::1".to_string(),
            pid: 12345,
            blocked_ipv6_ifaces: vec!["eth0".to_string(), "wlan0".to_string()],
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: State = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.blocked_ipv6_ifaces, vec!["eth0", "wlan0"]);
    }

    #[test]
    fn test_state_empty_blocked_ipv6_default() {
        // Old state files without blocked_ipv6_ifaces should deserialize with empty vec
        let json = r#"{"lock_active":true,"wg_interface":"wg0","wg_config_path":"/tmp/wg0.conf","dns_ipv4":"10.0.0.1","dns_ipv6":"fd00::1","pid":12345}"#;
        let state: State = serde_json::from_str(json).unwrap();
        assert!(state.blocked_ipv6_ifaces.is_empty());
    }

    #[test]
    fn test_load_no_state_file() {
        // If no state file exists at either location, load should return None.
        // This test depends on the test environment not having stale state files,
        // which is a reasonable assumption.
        // We can't reliably test this without mocking filesystem access,
        // so we just verify the function doesn't panic.
        let result = load();
        assert!(result.is_ok());
    }
}
