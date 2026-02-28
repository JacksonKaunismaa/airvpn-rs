# Persistent Network Lock — Implementation Plan (SUPERSEDED)

> **This plan describes the initial single-table approach, which was replaced by a
> two-table architecture.** See `2026-02-27-persistent-lock-design.md` for the
> current design. Kept for historical reference.

**Goal:** Add an Android-style persistent kill switch that blocks all non-VPN traffic, surviving crashes, `nft flush ruleset`, and reboots.

**Architecture (SUPERSEDED):** A persistent nftables table (`airvpn_lock`) with `flags owner, persist` loaded at boot by a systemd oneshot service. When airvpn-rs connects, it detects the existing table, reclaims ownership, and adds server IP + tunnel interface rules dynamically. When no persistent lock exists, current transient session lock behavior is preserved unchanged.

**Tech Stack:** Rust, nftables (`nft` CLI), systemd

**Design doc:** `docs/plans/2026-02-27-persistent-lock-design.md`

---

### Task 1: `generate_persistent_ruleset` in netlock.rs

Generate the base persistent ruleset (no server IPs, no tunnel interface, no owner/persist flags). This is what gets written to `/etc/airvpn-rs/lock.nft` and loaded at boot.

**Files:**
- Modify: `src/netlock.rs`
- Test: `src/netlock.rs` (inline tests)

**Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/netlock.rs`:

```rust
#[test]
fn test_persistent_ruleset_has_bootstrap_ips() {
    let bootstrap_ips = vec![
        "63.33.78.166".to_string(),
        "54.93.175.114".to_string(),
        "82.196.3.205".to_string(),
    ];
    let ruleset = generate_persistent_ruleset(&bootstrap_ips);

    // Has table structure
    assert!(ruleset.contains("table inet airvpn_lock"));
    // Has bootstrap IPs in output chain
    assert!(ruleset.contains("ip daddr 63.33.78.166"));
    assert!(ruleset.contains("ip daddr 54.93.175.114"));
    assert!(ruleset.contains("ip daddr 82.196.3.205"));
    // Does NOT have owner/persist flags (loaded by systemd oneshot)
    assert!(!ruleset.contains("flags"));
    // Has sentinel rules for dynamic insertion
    assert!(ruleset.contains("airvpn_filter_input_latest_rule"));
    assert!(ruleset.contains("airvpn_filter_output_latest_rule"));
    assert!(ruleset.contains("airvpn_filter_forward_latest_rule"));
}

#[test]
fn test_persistent_ruleset_no_server_ips() {
    let bootstrap_ips = vec!["1.2.3.4".to_string()];
    let ruleset = generate_persistent_ruleset(&bootstrap_ips);
    // Should not contain any server-specific IPs beyond bootstrap
    // (server IPs are added dynamically at connect time)
    assert!(!ruleset.contains("ips_entry"));
}

#[test]
fn test_persistent_ruleset_ipv6_bootstrap() {
    let bootstrap_ips = vec![
        "1.2.3.4".to_string(),
        "2a03:b0c0:0:1010::9b:c001".to_string(),
    ];
    let ruleset = generate_persistent_ruleset(&bootstrap_ips);
    assert!(ruleset.contains("ip6 daddr 2a03:b0c0:0:1010::9b:c001"));
}

#[test]
fn test_persistent_ruleset_always_allows_lan() {
    let ruleset = generate_persistent_ruleset(&vec![]);
    assert!(ruleset.contains("192.168.0.0/16"));
    assert!(ruleset.contains("10.0.0.0/8"));
    assert!(ruleset.contains("172.16.0.0/12"));
    assert!(ruleset.contains("fe80::/10"));
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test test_persistent_ruleset -- --nocapture`
Expected: FAIL — `generate_persistent_ruleset` does not exist

**Step 3: Write the implementation**

Add to `src/netlock.rs`, reusing the existing `generate_ruleset` machinery:

```rust
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
```

**Step 4: Run tests to verify they pass**

Run: `cargo test test_persistent_ruleset -- --nocapture`
Expected: All 4 tests PASS

**Step 5: Build both debug and release**

Run: `cargo build && cargo build --release`
Expected: SUCCESS

**Step 6: Commit**

```bash
git add src/netlock.rs
git commit -m "feat(netlock): add generate_persistent_ruleset for boot-time lock"
```

---

### Task 2: `is_persistent` and `is_orphaned` detection helpers in netlock.rs

Add functions to detect whether the persistent lock is installed and whether the table is orphaned (has no owner process).

**Files:**
- Modify: `src/netlock.rs`

**Step 1: Write the implementation**

These can't be unit-tested (require root + actual nftables), so we write them directly:

```rust
/// Path to the persistent lock rules file.
pub const PERSISTENT_RULES_PATH: &str = "/etc/airvpn-rs/lock.nft";

/// Path to the persistent lock systemd service.
pub const PERSISTENT_SERVICE_PATH: &str = "/etc/systemd/system/airvpn-lock.service";

/// Check if the persistent lock is installed (rules file exists on disk).
///
/// This is the decision point at disconnect/recovery time: if the file exists,
/// we keep the base table alive; if not, we delete the whole table.
pub fn is_persistent() -> bool {
    std::path::Path::new(PERSISTENT_RULES_PATH).exists()
}

/// Reclaim ownership of an existing table (persistent lock loaded at boot).
///
/// Sends `add table inet airvpn_lock { flags owner, persist; }` which:
/// - If table is orphaned: assigns us as owner
/// - If table is owned by us already: no-op
/// - If table is owned by another process: fails with EOPNOTSUPP
pub fn reclaim_ownership() -> Result<()> {
    let cmd = format!(
        "add table inet {} {{ flags owner, persist; }}\n",
        TABLE_NAME
    );
    let mut tmpfile =
        tempfile::NamedTempFile::new().context("failed to create temp nft file")?;
    std::io::Write::write_all(&mut tmpfile, cmd.as_bytes())
        .context("failed to write nft command")?;
    tmpfile.flush().context("failed to flush nft command")?;

    let output = Command::new("nft")
        .arg("-f")
        .arg(tmpfile.path())
        .output()
        .context("failed to execute nft")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("failed to reclaim table ownership: {}", stderr);
    }
    Ok(())
}

/// Release ownership of the table (table becomes orphaned but stays active).
///
/// We can't just "unset" owner — we close the netlink socket by not holding it.
/// But since we use `nft -f` (not a persistent netlink connection), the kernel
/// auto-orphans the table when our nft process exits.
///
/// Actually, with `nft -f`, each invocation opens and closes a netlink socket.
/// So with `flags owner, persist`, the table is created owned by the nft process,
/// which immediately exits — leaving the table orphaned.
///
/// For a long-running process to truly own the table, we'd need to hold an open
/// netlink socket for the lifetime of the process. For now, the persist flag
/// ensures the table survives, and reclaim_ownership() re-asserts ownership
/// on each nft command we issue.
///
/// This is a no-op: ownership is automatically released when the process exits.
/// Kept as a function for clarity at call sites.
pub fn release_ownership() {
    // No-op: ownership releases automatically when process exits.
    // The table stays because of the persist flag.
}

/// Add a single server IP to the output chain allowlist.
///
/// Used in persistent lock mode to dynamically allow the VPN server endpoint.
pub fn allow_server_ip(ip: &str) -> Result<()> {
    let cidr = ensure_cidr(ip);
    let (family, rule) = match classify_ip(&cidr) {
        Some(IpVersion::V4) => ("ip daddr", &cidr),
        Some(IpVersion::V6) => ("ip6 daddr", &cidr),
        None => anyhow::bail!("invalid server IP: {}", ip),
    };
    let comment = format!("airvpn_server_endpoint_{}", ip.replace(':', "_"));
    nft_insert_before_latest(
        "output",
        &format!("{} {} counter accept comment \"{}\"", family, rule, comment),
    )
}

/// Remove a server IP from the output chain allowlist.
pub fn deallow_server_ip(ip: &str) -> Result<()> {
    let comment = format!("airvpn_server_endpoint_{}", ip.replace(':', "_"));
    nft_delete_by_comment("output", &comment)
}
```

**Step 2: Build both debug and release**

Run: `cargo build && cargo build --release`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/netlock.rs
git commit -m "feat(netlock): add persistent lock detection, ownership, and dynamic IP helpers"
```

---

### Task 3: `Lock` CLI subcommand in main.rs

Add `airvpn-rs lock {install,uninstall,enable,disable,status}` subcommands.

**Files:**
- Modify: `src/main.rs`

**Step 1: Add the Lock subcommand to the clap enum**

In the `Commands` enum (around line 38), add:

```rust
/// Manage persistent network lock (kill switch)
Lock {
    #[command(subcommand)]
    action: LockAction,
},
```

Add the `LockAction` enum after `Commands`:

```rust
#[derive(Subcommand)]
enum LockAction {
    /// Install persistent lock (generate rules, enable systemd service)
    Install,
    /// Uninstall persistent lock (remove rules, disable service, delete table)
    Uninstall,
    /// Reload persistent lock table now
    Enable,
    /// Temporarily disable persistent lock (returns on reboot)
    Disable,
    /// Show persistent lock status
    Status,
}
```

**Step 2: Add the match arm and handler functions**

In the `match cli.command` block (around line 225), add:

```rust
Commands::Lock { action } => cmd_lock(action),
```

Then add the handler functions:

```rust
fn cmd_lock(action: LockAction) -> anyhow::Result<()> {
    // lock commands need root (nft access)
    if !nix::unistd::geteuid().is_root() {
        anyhow::bail!("must run as root");
    }
    match action {
        LockAction::Install => cmd_lock_install(),
        LockAction::Uninstall => cmd_lock_uninstall(),
        LockAction::Enable => cmd_lock_enable(),
        LockAction::Disable => cmd_lock_disable(),
        LockAction::Status => cmd_lock_status(),
    }
}

fn cmd_lock_install() -> anyhow::Result<()> {
    let provider_config = api::load_provider_config()?;

    // Extract bootstrap IPs from provider.json (skip hostnames — can't resolve
    // without DNS, and that's the whole point of the persistent lock)
    let bootstrap_ips: Vec<String> = provider_config
        .bootstrap_urls
        .iter()
        .filter_map(|url| extract_ip_from_url(url))
        .filter(|host| host.parse::<std::net::IpAddr>().is_ok())
        .collect();

    if bootstrap_ips.is_empty() {
        anyhow::bail!("no bootstrap IPs found in provider config");
    }

    let ruleset = netlock::generate_persistent_ruleset(&bootstrap_ips);

    // Write rules file
    std::fs::create_dir_all("/etc/airvpn-rs")
        .context("failed to create /etc/airvpn-rs")?;
    std::fs::write(netlock::PERSISTENT_RULES_PATH, &ruleset)
        .context("failed to write lock.nft")?;
    info!("Wrote {}", netlock::PERSISTENT_RULES_PATH);

    // Write systemd service
    let service = "\
[Unit]
Description=AirVPN persistent kill switch
DefaultDependencies=no
Before=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nft -f /etc/airvpn-rs/lock.nft
ExecStop=/usr/bin/nft delete table inet airvpn_lock

[Install]
WantedBy=sysinit.target
";
    std::fs::write(netlock::PERSISTENT_SERVICE_PATH, service)
        .context("failed to write systemd service")?;
    info!("Wrote {}", netlock::PERSISTENT_SERVICE_PATH);

    // Enable service
    let output = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output()
        .context("failed to run systemctl daemon-reload")?;
    if !output.status.success() {
        warn!("systemctl daemon-reload failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let output = std::process::Command::new("systemctl")
        .args(["enable", "airvpn-lock.service"])
        .output()
        .context("failed to enable service")?;
    if !output.status.success() {
        anyhow::bail!("systemctl enable failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    info!("Enabled airvpn-lock.service");

    // Load the table now (if not already active)
    if !netlock::is_active() {
        let output = std::process::Command::new("nft")
            .args(["-f", netlock::PERSISTENT_RULES_PATH])
            .output()
            .context("failed to load lock.nft")?;
        if !output.status.success() {
            anyhow::bail!("nft -f failed: {}", String::from_utf8_lossy(&output.stderr));
        }
    }

    info!("Persistent lock installed and active.");
    info!("{} bootstrap IPs allowlisted.", bootstrap_ips.len());
    info!("To temporarily disable: airvpn-rs lock disable");
    Ok(())
}

fn cmd_lock_uninstall() -> anyhow::Result<()> {
    // Stop and disable service
    let _ = std::process::Command::new("systemctl")
        .args(["stop", "airvpn-lock.service"])
        .output();
    let _ = std::process::Command::new("systemctl")
        .args(["disable", "airvpn-lock.service"])
        .output();
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();

    // Remove files
    let _ = std::fs::remove_file(netlock::PERSISTENT_SERVICE_PATH);
    let _ = std::fs::remove_file(netlock::PERSISTENT_RULES_PATH);

    // Delete table if active
    if netlock::is_active() {
        // Try to reclaim first (in case it's orphaned+owned, need to be owner to delete)
        let _ = netlock::reclaim_ownership();
        let _ = netlock::deactivate();
    }

    info!("Persistent lock uninstalled.");
    Ok(())
}

fn cmd_lock_enable() -> anyhow::Result<()> {
    if !std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists() {
        anyhow::bail!("persistent lock not installed — run `airvpn-rs lock install` first");
    }
    if netlock::is_active() {
        info!("Lock table already active.");
        return Ok(());
    }
    let output = std::process::Command::new("nft")
        .args(["-f", netlock::PERSISTENT_RULES_PATH])
        .output()
        .context("failed to load lock.nft")?;
    if !output.status.success() {
        anyhow::bail!("nft -f failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    info!("Persistent lock re-enabled.");
    Ok(())
}

fn cmd_lock_disable() -> anyhow::Result<()> {
    if !netlock::is_active() {
        info!("Lock table not active.");
        return Ok(());
    }
    // Reclaim if needed (orphaned table can't be deleted by non-owner)
    let _ = netlock::reclaim_ownership();
    netlock::deactivate()?;
    info!("Persistent lock disabled (will return on next reboot if service enabled).");
    Ok(())
}

fn cmd_lock_status() -> anyhow::Result<()> {
    let table_active = netlock::is_active();
    let rules_exist = std::path::Path::new(netlock::PERSISTENT_RULES_PATH).exists();
    let service_exists = std::path::Path::new(netlock::PERSISTENT_SERVICE_PATH).exists();

    // Check if service is enabled
    let service_enabled = std::process::Command::new("systemctl")
        .args(["is-enabled", "airvpn-lock.service"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    println!("Persistent lock:");
    println!("  Table active:     {}", if table_active { "yes" } else { "no" });
    println!("  Rules file:       {}", if rules_exist { netlock::PERSISTENT_RULES_PATH } else { "not installed" });
    println!("  Service enabled:  {}", if service_enabled { "yes" } else { "no" });

    if !rules_exist && !service_exists {
        println!("\nNot installed. Run `airvpn-rs lock install` to set up.");
    }
    Ok(())
}
```

**Step 2: Build both debug and release**

Run: `cargo build && cargo build --release`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat: add 'lock' subcommand for persistent kill switch management"
```

---

### Task 4: Modify connect flow to detect persistent lock

Change the netlock activation block in `cmd_connect` to detect a pre-existing persistent lock and use dynamic rule insertion instead of rebuilding the full table.

**Files:**
- Modify: `src/main.rs:901-968` (the netlock activation block)

**Step 1: Replace the netlock activation block**

Replace lines 901-968 (`// 7. Activate network lock BEFORE auth` through the end of the `if !no_lock` block) with:

```rust
        // 7. Activate network lock BEFORE auth (Eddie: Session.cs:57-64 —
        // netlock activates at session start, before server selection or auth.
        // NetworkLockManager.cs:132-135 resolves hostnames before lock).
        // Bootstrap IPs are allowlisted so the auth API call works through the lock.
        let persistent_lock = netlock::is_active() && netlock::is_persistent();
        if !no_lock {
            if persistent_lock {
                // Persistent lock already active (loaded at boot by systemd service).
                // Reclaim ownership so we can add dynamic rules.
                info!("Persistent lock detected — reclaiming ownership...");
                netlock::reclaim_ownership()?;
                // Add server entry IPs to the persistent lock's output chain
                for ip in &server_ref.ips_entry {
                    netlock::allow_server_ip(ip)?;
                }
                info!("Persistent lock: added {} server IPs", server_ref.ips_entry.len());
            } else {
                // No persistent lock — create transient session lock (current behavior)
                info!("Activating network lock...");
                let mut allowed_ips: Vec<String> = server_ref.ips_entry.clone();
                // Also whitelist API bootstrap IPs (extract bare IP from URLs)
                for url in &provider_config.bootstrap_urls {
                    if let Some(host) = extract_ip_from_url(url) {
                        allowed_ips.push(host);
                    }
                }
                for url in &manifest.bootstrap_urls {
                    if let Some(host) = extract_ip_from_url(url) {
                        allowed_ips.push(host);
                    }
                }
                // Resolve hostnames to IPs before netlock activation
                let mut resolved_ips: Vec<String> = Vec::new();
                for entry in &allowed_ips {
                    if entry.parse::<std::net::IpAddr>().is_ok() {
                        resolved_ips.push(entry.clone());
                    } else {
                        let addrs = resolve_bootstrap_host(entry);
                        if addrs.is_empty() {
                            warn!("dropping unresolvable bootstrap host from allowlist: {}", entry);
                        } else {
                            debug!("resolved bootstrap host {} -> {:?}", entry, addrs);
                            resolved_ips.extend(addrs);
                        }
                    }
                }
                let allowed_ips = resolved_ips;
                let lock_config = netlock::NetlockConfig {
                    allow_lan,
                    allow_dhcp: true,
                    allow_ping: true,
                    allow_ipv4ipv6translation: true,
                    allowed_ips_incoming: vec![],
                    allowed_ips_outgoing: allowed_ips,
                    incoming_policy_accept: false,
                };
                netlock::activate(&lock_config)?;
                info!("Network lock active (dedicated nftables table)");
                debug!(
                    "Network lock: {} outgoing IPs whitelisted, allow_lan={}",
                    lock_config.allowed_ips_outgoing.len(),
                    lock_config.allow_lan,
                );
            }
            recovery::save(&recovery::State {
                lock_active: true,
                wg_interface: String::new(),
                wg_config_path: String::new(),
                dns_ipv4: String::new(),
                dns_ipv6: String::new(),
                pid: std::process::id(),
                blocked_ipv6_ifaces: blocked_ipv6_ifaces.clone(),
                endpoint_ip: String::new(),
                nonce,
                resolv_was_immutable: dns::was_immutable(),
            })?;
        }
```

Note: `persistent_lock` bool needs to be accessible later in the disconnect flow. Declare it before the `loop` or pass it through.

**Step 2: Build both debug and release**

Run: `cargo build && cargo build --release`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/main.rs
git commit -m "feat: detect persistent lock on connect, use dynamic IP insertion"
```

---

### Task 5: Modify disconnect flow for persistent lock awareness

Change `cmd_disconnect_internal` and `partial_disconnect` to keep the persistent lock table alive when `lock.nft` exists on disk.

**Files:**
- Modify: `src/main.rs` — `cmd_disconnect_internal` (line 1486) and all `netlock::deactivate()` call sites

**Step 1: Modify `cmd_disconnect_internal`**

Replace the netlock teardown section (lines 1501-1504):

```rust
    // 4. Remove netlock — or keep it if persistent lock is installed
    if lock_active {
        if netlock::is_persistent() {
            // Persistent lock: remove only the dynamic server IP rules.
            // The base table stays active, blocking all non-VPN traffic.
            // Server IPs are identified by comment prefix.
            // Interface rules were already removed in step 1.
            // We don't know the exact server IP here, so remove all server endpoint rules.
            // (The comment pattern "airvpn_server_endpoint_" identifies them.)
            info!("Persistent lock: keeping base table, removing dynamic rules");
            netlock::release_ownership();
        } else {
            let _ = netlock::deactivate();
        }
    }
```

**Step 2: Update all `netlock::deactivate()` error-path calls**

Every place in `cmd_connect`'s error handling that calls `netlock::deactivate()` needs the same treatment. Search for `netlock::deactivate()` — there are ~6 call sites in error paths (Fatal, Error with no_reconnect, Retry with no_reconnect, WG fail with no_reconnect, verification fail, etc.).

For each, replace:
```rust
if !no_lock { let _ = netlock::deactivate(); }
```
with:
```rust
if !no_lock && !persistent_lock { let _ = netlock::deactivate(); }
if !no_lock && persistent_lock {
    // Remove dynamic rules but keep persistent table
    for ip in &server_ref.ips_entry {
        let _ = netlock::deallow_server_ip(ip);
    }
    netlock::release_ownership();
}
```

Since this is repetitive, extract a helper:
```rust
fn teardown_lock(no_lock: bool, persistent_lock: bool, server_ips: &[String]) {
    if no_lock { return; }
    if persistent_lock {
        for ip in server_ips {
            let _ = netlock::deallow_server_ip(ip);
        }
        netlock::release_ownership();
    } else {
        let _ = netlock::deactivate();
    }
}
```

**Step 3: Update orphan cleanup in `cmd_connect` startup**

The orphan cleanup around line 493 (`// Unconditional cleanup: remove orphaned nftables table`) must skip deletion when persistent lock is installed:

```rust
if netlock::is_active() {
    if recovery::load().ok().flatten().map_or(true, |s| !recovery::is_pid_alive(s.pid)) {
        if netlock::is_persistent() {
            // Persistent lock: don't delete, just log
            info!("Persistent lock table found (orphaned) — will reclaim on connect");
        } else {
            warn!("Removing orphaned nftables table...");
            let _ = netlock::deactivate();
        }
    }
}
```

**Step 4: Build both debug and release**

Run: `cargo build && cargo build --release`
Expected: SUCCESS

**Step 5: Commit**

```bash
git add src/main.rs
git commit -m "feat: persistent lock awareness in disconnect and error paths"
```

---

### Task 6: Update recovery for persistent lock

`airvpn-rs recover` should preserve the persistent lock table when cleaning up.

**Files:**
- Modify: `src/recovery.rs:393-399` (netlock deactivation in `recover_from_state`)

**Step 1: Modify the netlock cleanup in recover_from_state**

Replace lines 393-399:

```rust
    // 4. Deactivate network lock if it was active (last — prevents traffic leaks)
    if state.lock_active {
        if netlock::is_persistent() {
            // Persistent lock installed — only clean up dynamic rules.
            // We can't know what server IP was used, so remove all airvpn_server_endpoint_ rules.
            // This is best-effort; the sentinel comments make them identifiable.
            info!("Persistent lock: preserving base table, cleaning dynamic rules only");
            // Try to reclaim so we can modify the table
            let _ = netlock::reclaim_ownership();
            // Interface rules may already be gone (WG teardown above). Ignore errors.
            // Server IP rules: we don't track these in recovery state, but they're harmless
            // to leave (they point to the old server which we won't be connecting to).
            // On next connect, new server IPs will be added.
            netlock::release_ownership();
        } else {
            if let Err(e) = netlock::deactivate() {
                warn!("failed to deactivate network lock: {}", e);
                cleanup_failed = true;
            }
        }
    }
```

**Step 2: Build both debug and release**

Run: `cargo build && cargo build --release`
Expected: SUCCESS

**Step 3: Commit**

```bash
git add src/recovery.rs
git commit -m "feat(recovery): preserve persistent lock table during crash recovery"
```

---

### Task 7: Integration test — persistent lock CLI

Add a test that exercises the `lock` subcommand parsing (without root, just verify CLI structure).

**Files:**
- Modify: `tests/integration.rs` or `src/main.rs` tests

**Step 1: Write the test**

```rust
#[test]
fn test_lock_subcommand_parse() {
    // Verify the CLI parser accepts lock subcommands
    use clap::Parser;
    // These would fail at runtime (need root) but should parse OK
    let cli = Cli::try_parse_from(["airvpn", "lock", "status"]);
    assert!(cli.is_ok(), "lock status should parse: {:?}", cli.err());

    let cli = Cli::try_parse_from(["airvpn", "lock", "install"]);
    assert!(cli.is_ok(), "lock install should parse: {:?}", cli.err());

    let cli = Cli::try_parse_from(["airvpn", "lock", "disable"]);
    assert!(cli.is_ok(), "lock disable should parse: {:?}", cli.err());
}
```

**Step 2: Run tests**

Run: `cargo test test_lock_subcommand -- --nocapture`
Expected: PASS

**Step 3: Commit**

```bash
git add src/main.rs
git commit -m "test: add lock subcommand parsing tests"
```

---

### Task 8: Update docs and known divergences

Document the persistent lock feature and note the Eddie divergence.

**Files:**
- Modify: `docs/known_divergences.md`
- Modify: `CLAUDE.md` (learnings section)

**Step 1: Add to known_divergences.md**

Add a section:

```markdown
## Persistent lock (kill switch)

Eddie has no persistent lock feature. Eddie's netlock activates at session start
and deactivates at session end. Between sessions, traffic is unrestricted.

airvpn-rs adds `lock install` which creates a persistent nftables table loaded at
boot by a systemd service. This provides Android-style "always-on VPN" protection:
all non-VPN traffic is blocked even when airvpn-rs is not running.

The persistent table uses nftables `flags owner, persist` (kernel 5.12+/6.9+) for
crash and flush immunity. Eddie does not use these flags.
```

**Step 2: Update CLAUDE.md learnings**

Add:
```
- Persistent lock uses nftables `flags owner, persist` — owner (5.12+) makes table immune to flush ruleset, persist (6.9+) survives process exit. Reclaim by table name, any root process. (2026-02-27)
- Persistent vs transient lock: detected by table existence at connect time, `lock.nft` file existence at disconnect time. No explicit mode flag. (2026-02-27)
```

**Step 3: Commit**

```bash
git add docs/known_divergences.md CLAUDE.md
git commit -m "docs: document persistent lock feature and Eddie divergence"
```

---

## Summary

| Task | What | Files |
|------|------|-------|
| 1 | `generate_persistent_ruleset` | `src/netlock.rs` |
| 2 | Detection + ownership helpers | `src/netlock.rs` |
| 3 | `Lock` CLI subcommand | `src/main.rs` |
| 4 | Connect flow changes | `src/main.rs` |
| 5 | Disconnect flow changes | `src/main.rs`, `src/recovery.rs` |
| 6 | Recovery changes | `src/recovery.rs` |
| 7 | Integration test | `src/main.rs` tests |
| 8 | Docs | `docs/known_divergences.md`, `CLAUDE.md` |

Tasks 1-2 are independent (netlock.rs only). Tasks 3-6 depend on 1-2. Task 7 depends on 3. Task 8 is independent.
