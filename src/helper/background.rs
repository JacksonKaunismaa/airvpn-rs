//! Background loops: pinger and manifest refresh.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use log::{debug, info, warn};
use zeroize::Zeroizing;

use crate::{api, config, manifest, netlock, options, pinger};
use super::{lock_state, State};

/// Background pinger loop — runs every 3 minutes, measures all server latencies.
///
/// Copies the server IP list out of SharedState (quick lock), pings without
/// holding the lock (~30-60s), then merges results back (quick lock).
pub(super) fn background_pinger_loop(state: State, shutdown: Arc<AtomicBool>) {
    const CYCLE_INTERVAL_SECS: u64 = 180; // 3 minutes
    // Resolve pinger options from profile
    let profile_opts = config::load_profile_options();
    let resolved = options::resolve(&profile_opts, &std::collections::HashMap::new());
    let ping_timeout_secs = options::get_u64(&resolved, options::PINGER_TIMEOUT);
    let pinger_enabled = options::get_bool(&resolved, options::PINGER_ENABLED);
    let pinger_jobs = options::get_u64(&resolved, options::PINGER_JOBS) as usize;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Wait until server IPs are available (manifest loop signals pinger_cv)
        {
            let guard = lock_state(&state);
            let _guard = state.1.pinger_cv.wait_while(guard, |st| {
                if shutdown.load(Ordering::Relaxed) {
                    return false; // unblock on shutdown
                }
                st.latency.server_ips().is_empty()
            }).unwrap_or_else(|e| e.into_inner());
        }

        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        debug!("Pinger woke: server IPs available, starting cycle");

        // When pinger is disabled, skip pinging but keep the loop alive
        // to avoid blocking the condvar chain (ready_cv must still fire).
        if !pinger_enabled {
            {
                let mut st = lock_state(&state);
                if !st.ready {
                    st.ready = true;
                    state.1.ready_cv.notify_all();
                }
            }
            debug!("Pinger disabled, skipping ping cycle");
            interruptible_sleep_secs(&shutdown, CYCLE_INTERVAL_SECS);
            continue;
        }

        // Copy IPs out of shared state (quick lock)
        let ips: Vec<(String, String)> = {
            let st = lock_state(&state);
            st.latency.server_ips()
                .iter()
                .map(|(n, ip)| (n.clone(), ip.clone()))
                .collect()
        };

        if ips.is_empty() {
            continue; // spurious wakeup
        }

        debug!("Starting ping cycle ({} servers, max {} concurrent)", ips.len(), pinger_jobs);

        // Ping all servers via host routes (direct, not through tunnel).
        // Each result merges under a brief per-result lock so /servers
        // reflects fresh values as they arrive, not in one bulk swap at
        // the end of the cycle.
        let total = ips.len();
        let mut measured: usize = 0;
        let mut failed: usize = 0;
        pinger::measure_all_from_ips(
            &ips,
            ping_timeout_secs,
            pinger_jobs,
            |name, latency| {
                let mut st = lock_state(&state);
                if latency >= 0 {
                    st.latency.update(name, latency);
                    measured += 1;
                } else {
                    st.latency.update_failed(name);
                    failed += 1;
                }
            },
        );

        // Flip ready (if first cycle) and persist to disk once per cycle.
        {
            let mut st = lock_state(&state);
            if !st.ready {
                st.ready = true;
                state.1.ready_cv.notify_all();
            }
            if let Err(e) = st.latency.save(pinger::LATENCY_CACHE_PATH) {
                warn!("Failed to persist latency cache: {e}");
            }
        }

        // One line per cycle: concise summary. Warn only if significant failures.
        {
            let st = lock_state(&state);
            if let Some((_count, min, avg, max)) = st.latency.summary() {
                if failed > total / 4 {
                    warn!(
                        "Ping: {}/{} measured ({} failed) — {}ms/{}ms/{}ms min/avg/max",
                        measured, total, failed, min, avg, max,
                    );
                } else {
                    info!(
                        "Ping: {}/{} — {}ms/{}ms/{}ms min/avg/max",
                        measured, total, min, avg, max,
                    );
                }
            } else {
                info!("Ping: {}/{} measured — no latency data yet", measured, total);
            }
        }

        // Sleep for 3 minutes (interruptible by shutdown)
        interruptible_sleep_secs(&shutdown, CYCLE_INTERVAL_SECS);
    }
}

/// Sleep for the given duration, checking shutdown flag every second.
pub(super) fn interruptible_sleep_secs(shutdown: &AtomicBool, seconds: u64) {
    for _ in 0..seconds {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }
}

/// Background manifest refresh loop — fetches manifest every 30 minutes.
///
/// On startup, waits for credentials (via manifest_cv) if none available.
/// After each successful fetch, populates server IPs and signals pinger_cv.
pub(super) fn background_manifest_loop(state: State, shutdown: Arc<AtomicBool>) {
    // Resolve from profile; falls back to registry defaults
    let profile_opts = config::load_profile_options();
    let resolved = options::resolve(&profile_opts, &std::collections::HashMap::new());
    let refresh_interval_secs = options::get_u64(&resolved, options::MANIFEST_REFRESH);
    let ip_layer = options::get_str(&resolved, options::NETWORK_ENTRY_IPLAYER).to_string();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Load credentials from profile
        let profile_options = config::load_profile_options();
        let username = Zeroizing::new(profile_options.get("login").cloned().unwrap_or_default());
        let password = Zeroizing::new(profile_options.get("password").cloned().unwrap_or_default());

        if username.is_empty() || password.is_empty() {
            // No creds yet — clear cached keys and wait for manifest_cv signal
            {
                let mut st = lock_state(&state);
                st.key_names.clear();
            }
            info!("No credentials available, manifest loop waiting for profile setup...");
            let guard = lock_state(&state);
            // wait_while blocks until the predicate returns false (i.e., creds available or shutdown)
            let _guard = state.1.manifest_cv.wait_while(guard, |_st| {
                if shutdown.load(Ordering::Relaxed) {
                    return false; // unblock on shutdown
                }
                let opts = config::load_profile_options();
                let u = opts.get("login").cloned().unwrap_or_default();
                let p = opts.get("password").cloned().unwrap_or_default();
                u.is_empty() || p.is_empty() // keep waiting while creds empty
            }).unwrap_or_else(|e| e.into_inner());
            continue; // re-check creds at top of loop
        }

        // Fetch manifest
        match api::load_provider_config() {
            Ok(provider_config) => {
                match api::fetch_manifest(&provider_config, &username, &password) {
                    Ok(manifest_xml) => {
                        match manifest::parse_manifest(&manifest_xml) {
                            Ok(new_manifest) => {
                                info!("Background manifest refresh: {} servers", new_manifest.servers.len());

                                if let Err(e) = manifest::save_manifest(&new_manifest, manifest::MANIFEST_CACHE_PATH) {
                                    warn!("Failed to persist manifest cache: {e}");
                                }

                                // Extract (name, preferred_entry_ip) pairs,
                                // respecting ip_layer preference with fallback.
                                let prefer_ipv6 = ip_layer == "ipv6";
                                let server_ip_pairs: Vec<(String, String)> = new_manifest.servers
                                    .iter()
                                    .filter_map(|s| {
                                        let ip = if prefer_ipv6 {
                                            s.ips_entry.iter()
                                                .find(|ip| ip.parse::<std::net::Ipv6Addr>().is_ok())
                                                .or_else(|| s.ips_entry.iter()
                                                    .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok()))
                                                .or_else(|| s.ips_entry.first())
                                        } else {
                                            s.ips_entry.iter()
                                                .find(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok())
                                                .or_else(|| s.ips_entry.first())
                                        };
                                        ip.map(|ip| (s.name.clone(), ip.clone()))
                                    })
                                    .collect();

                                // Update shared state
                                {
                                    let mut st = lock_state(&state);
                                    st.manifest = Some(new_manifest);
                                    if !server_ip_pairs.is_empty() {
                                        let ips: Vec<String> = server_ip_pairs.iter()
                                            .map(|(_, ip)| ip.clone()).collect();
                                        st.latency.set_server_ips(server_ip_pairs);
                                        drop(st);
                                        if let Err(e) = netlock::populate_ping_allow(&ips) {
                                            warn!("Failed to update ping_allow: {e}");
                                        }
                                    }
                                }

                                // Signal pinger that IPs are available
                                state.1.pinger_cv.notify_all();
                                // Signal ready_cv so warm-start connects unblock
                                // (ready=true from latency.json, was just waiting for manifest)
                                state.1.ready_cv.notify_all();
                            }
                            Err(e) => warn!("Failed to parse manifest: {:#}", e),
                        }
                    }
                    Err(e) => warn!("Failed to fetch manifest: {:#}", e),
                }

                // Fetch user info for key names (needed by GUI device dropdown).
                // Called outside the lock — network call can take 5-30s.
                match api::fetch_user(&provider_config, &username, &password) {
                    Ok(user_xml) => {
                        match manifest::parse_user(&user_xml) {
                            Ok(user_info) => {
                                let names: Vec<String> = user_info.keys.iter()
                                    .map(|k| k.name.clone())
                                    .collect();
                                debug!("Cached {} WireGuard key names", names.len());
                                let mut st = lock_state(&state);
                                st.key_names = names;
                            }
                            Err(e) => {
                                warn!("Failed to parse user info for keys: {:#}", e);
                                let mut st = lock_state(&state);
                                st.key_names.clear();
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to fetch user info for keys: {:#}", e);
                        let mut st = lock_state(&state);
                        st.key_names.clear();
                    }
                }
            }
            Err(e) => warn!("Failed to load provider config: {:#}", e),
        }

        let has_manifest = lock_state(&state).manifest.is_some();
        if has_manifest {
            interruptible_sleep_secs(&shutdown, refresh_interval_secs);
        } else {
            warn!("Manifest not yet loaded, retrying in 15s");
            interruptible_sleep_secs(&shutdown, 15);
        }
    }
}
