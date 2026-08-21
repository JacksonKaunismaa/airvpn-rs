//! IPv6 management — disable/restore IPv6 on non-loopback interfaces.
//!
//! Eddie's default `network.ipv6.mode == "in-block"` disables IPv6 on all
//! interfaces (except all/lo/lo0) via sysctl to prevent IPv6 traffic leaking
//! outside the VPN tunnel.
//!
//! Reference: Eddie src/App.CLI.Linux.Elevated/src/impl.cpp

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use log::warn;

/// Disable IPv6 on all non-loopback interfaces, including `default`.
///
/// Returns the list of interfaces that were blocked (for restore on disconnect),
/// or an error if IPv6 could **not** be confirmed disabled on some live
/// interface. This is deliberately fail-closed: a silently-ignored write
/// failure would leave IPv6 enabled on a physical interface — exactly the leak
/// this function exists to prevent — so the caller must be able to see it and
/// refuse to connect (see `resolve_session`). This diverges from Eddie, which
/// best-efforts each interface and ignores failures (see known_divergences.md).
///
/// Setting `default` to `disable_ipv6=1` means newly created interfaces
/// (including the WireGuard tunnel) inherit disabled IPv6 automatically.
/// This matches Eddie's behavior (impl.cpp iterates all entries in
/// `/proc/sys/net/ipv6/conf/`, skipping only `all`, `lo`, `lo0`).
///
/// We no longer use wg-quick (which breaks with `default=1`), so this is safe.
/// The WireGuard interface is set up via direct `ip`/`wg` commands with IPv4 only.
///
/// Reference: Eddie src/App.CLI.Linux.Elevated/src/impl.cpp lines 478-510
pub fn block_all() -> Result<Vec<String>> {
    let mut blocked = Vec::new();
    let conf_dir = Path::new("/proc/sys/net/ipv6/conf");

    let entries = fs::read_dir(conf_dir)
        .with_context(|| format!("failed to enumerate {}", conf_dir.display()))?;

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();

        // Skip special pseudo-interfaces (matching Eddie impl.cpp:483-490).
        // "all" is skipped because setting it auto-cascades to all interfaces
        // (Eddie prefers per-interface control). "default" is NOT skipped —
        // it acts as a template for newly created interfaces.
        if matches!(name.as_str(), "all" | "lo" | "lo0") {
            continue;
        }

        // Validate interface name: alphanumeric + dash + underscore, max 15 chars.
        // Kernel-created names are safe, but defense-in-depth prevents path traversal
        // if /proc is ever somehow compromised or a FUSE overlay is mounted.
        if !crate::common::validate_interface_name(&name) {
            warn!("skipping invalid interface name in block_all: {:?}", name);
            continue;
        }

        let disable_path = conf_dir.join(&name).join("disable_ipv6");

        // Read the current state. If the knob vanished (interface removed between
        // the readdir and now), skip it — a gone interface can't leak. Any other
        // read error is fatal: we cannot confirm IPv6 is off, and treating an
        // unknown state as "already handled" is precisely the silent gap we're
        // removing.
        let current = match fs::read_to_string(&disable_path) {
            Ok(s) => s.trim().to_string(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => bail!(
                "cannot read {} to confirm IPv6 state: {}",
                disable_path.display(),
                e
            ),
        };

        // Already disabled (or otherwise not "0") — nothing to do, and we don't
        // track it for restore since we didn't change it.
        if current != "0" {
            continue;
        }

        // Disable, then read back to CONFIRM. A write that "succeeded" but left
        // IPv6 enabled (or a write that failed) must not be hidden.
        if let Err(e) = fs::write(&disable_path, "1") {
            if e.kind() == std::io::ErrorKind::NotFound {
                continue; // interface disappeared mid-write; can't leak
            }
            bail!("failed to disable IPv6 on {}: {}", name, e);
        }
        match fs::read_to_string(&disable_path) {
            Ok(s) if s.trim() == "1" => blocked.push(name),
            Ok(s) => bail!(
                "IPv6 still enabled on {} after write (state={:?})",
                name,
                s.trim()
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => bail!("cannot confirm IPv6 disabled on {}: {}", name, e),
        }
    }

    Ok(blocked)
}

/// Restore IPv6 on previously blocked interfaces.
///
/// Only restores interfaces that were explicitly tracked in `block_all()`.
/// We do NOT scan for untracked interfaces — re-enabling IPv6 on interfaces
/// we didn't disable (e.g., Docker, user-configured) could break their
/// intended configuration.
pub fn restore(interfaces: &[String]) {
    let conf_dir = Path::new("/proc/sys/net/ipv6/conf");
    for name in interfaces {
        // Validate interface name to prevent path traversal
        if !crate::common::validate_interface_name(name) {
            warn!("skipping invalid interface name in restore: {:?}", name);
            continue;
        }
        let disable_path = conf_dir.join(name).join("disable_ipv6");
        let _ = fs::write(&disable_path, "0");
    }
}
