//! Crash recovery + signal handling for clean disconnect.
//!
//! Saves connection state to a JSON file so that if the process crashes or is
//! killed, a subsequent `airvpn recover` can clean up (tear down WireGuard,
//! restore DNS, remove nftables rules).
//!
//! Recovery sequence matches normal disconnect order (WireGuard → DNS → netlock):
//! 1. wireguard::disconnect(config_path) (wg-quick down)
//! 2. dns::deactivate() (restore resolv.conf)
//! 3. netlock::deactivate() (delete nft table — removed last to prevent leaks)
//! 4. Remove state file
//!
//! Reference: Eddie src/Lib.Core/Recovery.cs

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::{dns, netlock, wireguard};

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
    fs::write(&path, json).with_context(|| format!("failed to write state file: {}", path.display()))?;
    Ok(())
}

/// Load state from file. Returns None if no state file exists.
pub fn load() -> Result<Option<State>> {
    match find_state_file() {
        Some(path) => {
            let json = fs::read_to_string(&path)
                .with_context(|| format!("failed to read state file: {}", path.display()))?;
            let state: State =
                serde_json::from_str(&json).context("failed to parse state file")?;
            Ok(Some(state))
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
fn is_pid_alive(pid: u32) -> bool {
    use nix::sys::signal::kill;
    use nix::unistd::Pid;

    kill(Pid::from_raw(pid as i32), None).is_ok()
}

/// Run the recovery cleanup sequence (matches normal disconnect order):
/// 1. wireguard::disconnect(config_path) (wg-quick down)
/// 2. dns::deactivate() (restore resolv.conf)
/// 3. netlock::deactivate() (delete nft table — removed last to prevent leaks)
/// 4. Remove state file
fn recover_from_state(state: &State) -> Result<()> {
    // 1. Disconnect WireGuard
    if !state.wg_config_path.is_empty() {
        if let Err(e) = wireguard::disconnect(&state.wg_config_path) {
            eprintln!("warning: failed to disconnect WireGuard: {}", e);
        }
    }

    // 2. Restore DNS
    if let Err(e) = dns::deactivate() {
        eprintln!("warning: failed to restore DNS: {}", e);
    }

    // 3. Deactivate network lock if it was active (last — prevents traffic leaks)
    if state.lock_active {
        if let Err(e) = netlock::deactivate() {
            eprintln!("warning: failed to deactivate network lock: {}", e);
        }
    }

    // 4. Remove state file
    remove()?;

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
        };

        let json = serde_json::to_string_pretty(&state).unwrap();
        let parsed: State = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.lock_active, state.lock_active);
        assert_eq!(parsed.wg_interface, state.wg_interface);
        assert_eq!(parsed.wg_config_path, state.wg_config_path);
        assert_eq!(parsed.dns_ipv4, state.dns_ipv4);
        assert_eq!(parsed.dns_ipv6, state.dns_ipv6);
        assert_eq!(parsed.pid, state.pid);
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
        };

        let json = serde_json::to_string_pretty(&state).unwrap();

        // Verify JSON contains expected fields
        assert!(json.contains("\"lock_active\": false"));
        assert!(json.contains("\"wg_interface\": \"wg0\""));
        assert!(json.contains("\"wg_config_path\": \"/tmp/wg0.conf\""));
        assert!(json.contains("\"dns_ipv4\": \"10.0.0.1\""));
        assert!(json.contains("\"dns_ipv6\": \"fd00::1\""));
        assert!(json.contains("\"pid\": 99999"));
    }

    #[test]
    fn test_is_pid_alive_current_process() {
        let pid = std::process::id();
        assert!(is_pid_alive(pid), "current process should be alive");
    }

    #[test]
    fn test_is_pid_alive_dead_process() {
        // PID 2^31-1 (i32::MAX = 2147483647) is almost certainly not in use.
        // Note: u32::MAX wraps to -1 as i32, and kill(-1, 0) signals all
        // processes, so we avoid that.
        assert!(!is_pid_alive(i32::MAX as u32));
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
