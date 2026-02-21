use std::collections::HashMap;
use std::time::Instant;

use anyhow::{bail, Context};

use crate::manifest::Server;
use crate::pinger::PingResults;

// ---------------------------------------------------------------------------
// Eddie-compatible scoring (ConnectionInfo.cs Score(), LoadPerc(), UsersPerc())
//
// Units:
//   Bandwidth (bw):     bytes/s  — converted to Mbit/s via 2*(bw*8)/(1000*1000)
//   BandwidthMax (bw_max): Mbit/s — used directly
//   ScoreBase:           raw score from manifest (lower = better)
//   Users / UsersMax:    current / max user counts
//
// We use "Speed" scoreType (Eddie default: servers.scoretype="Speed"):
//   All factors are 1.0 (ScoreBase *= 1, LoadPerc *= 1, UsersPerc *= 1)
// Penalty tracking via ServerPenalties (Eddie: Penality field on ConnectionInfo).
// Ping is always 0 (no ping data; we skip Eddie's Ping==-1 → 99995 path).
// Result is truncated to i64 to match Eddie's `(int)(sum)` cast.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Penalty tracking (Eddie: ConnectionInfo.Penality + advanced.penality_on_error)
//
// When a connection fails (ResetLevel::Error), the server receives an additive
// penalty (Eddie default: 30 via advanced.penality_on_error). Penalties
// accumulate: multiple failures add up. Decay is linear — the penalty
// decrements by 1 every 60 seconds (Eddie: Jobs/Penalities.cs).
// A single penalty of 30 takes 30 minutes to fully decay.
// Penalized servers sort lower in selection, causing automatic server rotation
// on reconnection.
// ---------------------------------------------------------------------------

/// Tracks per-server penalties with time-based linear decay.
///
/// Eddie stores `Penality` as a raw int on `ConnectionInfo` and multiplies by
/// `penality_factor` (default 1000) in `Score()`. Penalties accumulate
/// additively (`Penality += amount`) and decay by 1 every 60 seconds
/// (Eddie: `Jobs/Penalities.cs` runs every 60s, decrements by 1).
pub struct ServerPenalties {
    penalties: HashMap<String, (i64, Instant)>,
}

impl ServerPenalties {
    pub fn new() -> Self {
        Self {
            penalties: HashMap::new(),
        }
    }

    /// Apply a penalty to a server (Eddie: additive, default 30 per failure).
    pub fn penalize(&mut self, server_name: &str, amount: i64) {
        let entry = self
            .penalties
            .entry(server_name.to_string())
            .or_insert((0, Instant::now()));
        // Accumulate (Eddie: Penality += amount)
        entry.0 += amount;
        // Don't update timestamp — decay continues from first penalty (matches Eddie)
    }

    /// Get active penalty for a server with linear decay.
    /// Eddie: penalty decrements by 1 every 60 seconds.
    pub fn get(&self, server_name: &str) -> i64 {
        match self.penalties.get(server_name) {
            Some((base_penalty, when)) => {
                let elapsed_minutes = when.elapsed().as_secs() / 60;
                let decayed = base_penalty - elapsed_minutes as i64;
                if decayed > 0 {
                    decayed
                } else {
                    0
                }
            }
            None => 0,
        }
    }
}

/// Compute load as a percentage, matching Eddie's `LoadPerc()`.
///
/// `bwCur = 2 * (Bandwidth * 8) / (1_000_000)` (bytes/s → Mbit/s, with 2x factor)
/// `LoadPerc = (bwCur * 100) / BandwidthMax`
/// Returns 100 if BandwidthMax == 0.
fn load_perc(server: &Server) -> i64 {
    if server.bandwidth_max == 0 {
        return 100;
    }
    let bw_cur = 2 * (server.bandwidth * 8) / (1_000 * 1_000);
    (bw_cur * 100) / server.bandwidth_max
}

/// Compute user load as a percentage, matching Eddie's `UsersPerc()`.
///
/// `UsersPerc = (Users * 100) / UsersMax`
/// Returns 100 if UsersMax == 0.
fn users_perc(server: &Server) -> i64 {
    if server.users_max == 0 {
        return 100;
    }
    (server.users * 100) / server.users_max
}

/// Calculate server score (lower = better), matching Eddie's `ConnectionInfo.Score()`.
///
/// Special values:
/// - `warning_closed` non-empty -> 99998 (Error-level warning in Eddie)
/// - `warning_open` non-empty -> 99997 (Warning-level warning in Eddie)
///
/// Normal computation (Speed scoreType, no ping):
/// ```text
/// Score = PenalityB + PingB + LoadB + ScoreB + UsersB
/// ```
/// With Speed factors (all 1.0):
/// - PenalityB = 0 (base score excludes penalty; see `score_with_penalty()`)
/// - PingB = 0 (no ping data; see `score_with_ping()` for ping-aware scoring)
/// - LoadB = LoadPerc * 1
/// - ScoreB = ScoreBase * 1
/// - UsersB = UsersPerc * 1
///
/// Result is truncated to i64 to match Eddie's `(int)(sum)` cast.
///
/// NOTE: This treats ping as 0 (not measured). For ping-aware scoring, use
/// `score_with_ping()` which applies the Eddie sentinel (Ping==-1 -> 99995).
pub fn score(server: &Server) -> i64 {
    // warning_closed -> Error in Eddie -> HasWarningsErrors() -> 99998
    if !server.warning_closed.is_empty() {
        return 99998;
    }
    // warning_open -> Warning in Eddie -> HasWarnings() -> 99997
    if !server.warning_open.is_empty() {
        return 99997;
    }

    let penality_b = 0; // Base score excludes penalty; use score_with_penalty() for penalty-aware scoring
    let ping_b = 0; // No ping data; use score_with_ping() for ping-aware scoring

    let load = load_perc(server);
    let users = users_perc(server);
    let score_base = server.scorebase;

    // Speed scoreType (Eddie default: servers.scoretype="Speed")
    // All factors are 1.0 in speed mode
    let load_b = load;
    let score_b = score_base;
    let users_b = users;

    (penality_b + ping_b + load_b + score_b + users_b) as i64
}

/// Calculate server score with ICMP ping latency, matching Eddie's
/// `ConnectionInfo.Score()` with the Ping field populated.
///
/// Eddie behavior (ConnectionInfo.cs line 219-246):
/// - `ping_ms == -1` (not measured) -> return 99995 (sentinel)
/// - Otherwise: `PingB = ping_ms * ping_factor(1)` added to score sum
pub fn score_with_ping(server: &Server, ping_ms: i64) -> i64 {
    // warning_closed -> Error in Eddie -> HasWarningsErrors() -> 99998
    if !server.warning_closed.is_empty() {
        return 99998;
    }
    // warning_open -> Warning in Eddie -> HasWarnings() -> 99997
    if !server.warning_open.is_empty() {
        return 99997;
    }

    // Eddie: Ping == -1 means not yet measured -> return 99995
    if ping_ms == -1 {
        return 99995;
    }

    let penality_b = 0; // Base score excludes penalty; use score_with_penalty() for penalty-aware scoring
    let ping_b = ping_ms; // Eddie: Ping * ping_factor where ping_factor defaults to 1

    let load = load_perc(server);
    let users = users_perc(server);
    let score_base = server.scorebase;

    // Speed scoreType (Eddie default: servers.scoretype="Speed")
    // All factors are 1.0 in speed mode
    let load_b = load;
    let score_b = score_base;
    let users_b = users;

    (penality_b + ping_b + load_b + score_b + users_b) as i64
}

/// Compute server score including penalty, matching Eddie's `Score()` with
/// `Penality * penality_factor` (default factor = 1000).
///
/// Sentinel values (99995+) from warnings/unmeasured ping are not modified --
/// a closed server stays closed regardless of penalties.
pub fn score_with_penalty(server: &Server, penalties: &ServerPenalties, ping_ms: i64) -> i64 {
    let base = score_with_ping(server, ping_ms);
    // Don't inflate sentinel values (warnings/errors/unmeasured ping)
    if base >= 99995 {
        return base;
    }
    let penalty = penalties.get(&server.name);
    // Eddie: Penality * penality_factor where penality_factor defaults to 1000
    base + penalty * 1000
}

/// Filter servers by allowlist/denylist rules (matching Eddie's GetConnections filtering).
///
/// Rules:
/// - deny_server/deny_country always exclude
/// - If any allow_server/allow_country specified, only those are included
/// - Filtering is case-insensitive for server names and country codes
pub fn filter_servers<'a>(
    servers: &'a [Server],
    allow_servers: &[String],
    deny_servers: &[String],
    allow_countries: &[String],
    deny_countries: &[String],
) -> Vec<&'a Server> {
    servers
        .iter()
        .filter(|s| {
            // Denylist takes precedence
            if deny_servers
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&s.name))
            {
                return false;
            }
            if deny_countries
                .iter()
                .any(|d| d.eq_ignore_ascii_case(&s.country_code))
            {
                return false;
            }

            // If any allowlist specified, server must match at least one
            let has_allowlist = !allow_servers.is_empty() || !allow_countries.is_empty();
            if has_allowlist {
                let server_allowed = allow_servers
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&s.name));
                let country_allowed = allow_countries
                    .iter()
                    .any(|a| a.eq_ignore_ascii_case(&s.country_code));
                return server_allowed || country_allowed;
            }

            true
        })
        .collect()
}

/// Select best server: filter, score, sort, pick first.
/// If `server_name` is `Some`, find by exact name match instead.
pub fn select_server<'a>(
    servers: &'a [Server],
    server_name: Option<&str>,
) -> anyhow::Result<&'a Server> {
    if servers.is_empty() {
        bail!("no servers available");
    }

    if let Some(name) = server_name {
        return servers
            .iter()
            .find(|s| s.name == name)
            .with_context(|| format!("server '{name}' not found"));
    }

    // Score all servers and pick the one with the lowest score.
    servers
        .iter()
        .min_by(|a, b| score(a).cmp(&score(b)))
        .context("no servers available")
}

/// Select best server with penalty-aware and ping-aware scoring.
///
/// Like `select_server`, but uses `score_with_penalty` (which incorporates
/// ping latency) so that recently-failed and high-latency servers sort lower,
/// causing automatic rotation to a different server.
/// If `server_name` is `Some`, find by exact name match (bypasses scoring).
pub fn select_server_with_penalties<'a>(
    servers: &'a [Server],
    server_name: Option<&str>,
    penalties: &ServerPenalties,
    pings: &PingResults,
) -> anyhow::Result<&'a Server> {
    if servers.is_empty() {
        bail!("no servers available");
    }

    // Explicit server name bypasses penalty/ping scoring (user knows what they want)
    if let Some(name) = server_name {
        return servers
            .iter()
            .find(|s| s.name == name)
            .with_context(|| format!("server '{name}' not found"));
    }

    // Score all servers with penalties + ping and pick the lowest.
    servers
        .iter()
        .min_by(|a, b| {
            let sa = score_with_penalty(a, penalties, pings.get(&a.name));
            let sb = score_with_penalty(b, penalties, pings.get(&b.name));
            sa.cmp(&sb)
        })
        .context("no servers available")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::Server;

    /// Helper to build a test Server with the given fields, defaulting everything else.
    fn make_server(
        name: &str,
        bandwidth: i64,
        bandwidth_max: i64,
        users: i64,
        users_max: i64,
        scorebase: i64,
        warning_open: &str,
        warning_closed: &str,
    ) -> Server {
        Server {
            name: name.to_string(),
            group: String::new(),
            ips_entry: vec!["1.2.3.4".to_string()],
            ips_exit: vec!["5.6.7.8".to_string()],
            country_code: "XX".to_string(),
            location: "Test".to_string(),
            scorebase,
            bandwidth,
            bandwidth_max,
            users,
            users_max,
            support_ipv4: true,
            support_ipv6: true,
            warning_open: warning_open.to_string(),
            warning_closed: warning_closed.to_string(),
        }
    }

    #[test]
    fn test_score_normal_server() {
        // bandwidth = 500_000 bytes/s, bw_max = 1000 Mbit/s
        // users = 50, users_max = 250, scorebase = 10
        //
        // LoadPerc:
        //   bw_cur = 2 * (500_000 * 8) / 1_000_000 = 2 * 4_000_000 / 1_000_000 = 8
        //   load_perc = (8 * 100) / 1000 = 0  (integer division)
        //
        // UsersPerc:
        //   users_perc = (50 * 100) / 250 = 20
        //
        // Speed mode (all factors 1.0):
        //   LoadB = 0, ScoreB = 10, UsersB = 20
        //
        // Score = 0 + 0 + 0 + 10 + 20 = 30
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        let sc = score(&s);
        assert_eq!(sc, 30);
    }

    #[test]
    fn test_score_high_load_server() {
        // bandwidth = 50_000_000 bytes/s (50 MB/s), bw_max = 1000 Mbit/s
        // users = 200, users_max = 250, scorebase = 0
        //
        // LoadPerc:
        //   bw_cur = 2 * (50_000_000 * 8) / 1_000_000 = 800
        //   load_perc = (800 * 100) / 1000 = 80
        //
        // UsersPerc:
        //   users_perc = (200 * 100) / 250 = 80
        //
        // Speed mode (all factors 1.0):
        //   LoadB = 80, ScoreB = 0, UsersB = 80
        //
        // Score = 0 + 0 + 80 + 0 + 80 = 160
        let s = make_server("Bravo", 50_000_000, 1000, 200, 250, 0, "", "");
        let sc = score(&s);
        assert_eq!(sc, 160);
    }

    #[test]
    fn test_score_warning_closed() {
        let s = make_server("Closed", 500_000, 1000, 50, 250, 10, "", "Server maintenance");
        assert_eq!(score(&s), 99998);
    }

    #[test]
    fn test_score_warning_open() {
        let s = make_server("Open", 500_000, 1000, 50, 250, 10, "Degraded performance", "");
        assert_eq!(score(&s), 99997);
    }

    #[test]
    fn test_score_both_warnings_closed_takes_priority() {
        // When both are set, warning_closed (Error) is checked first → 99998
        let s = make_server("Both", 500_000, 1000, 50, 250, 10, "warning", "closed");
        assert_eq!(score(&s), 99998);
    }

    #[test]
    fn test_score_zero_bandwidth_max() {
        // BandwidthMax == 0 → LoadPerc returns 100
        // UsersPerc = (50 * 100) / 250 = 20
        // Speed mode: LoadB = 100, ScoreB = 0, UsersB = 20
        // Score = 0 + 0 + 100 + 0 + 20 = 120
        let s = make_server("Zero", 500_000, 0, 50, 250, 0, "", "");
        assert_eq!(score(&s), 120);
    }

    #[test]
    fn test_score_zero_users_max() {
        // UsersMax == 0 → UsersPerc returns 100
        // LoadPerc: bw_cur = 2*(500000*8)/1000000 = 8, (8*100)/1000 = 0
        // Speed mode: LoadB = 0, ScoreB = 0, UsersB = 100
        // Score = 0 + 0 + 0 + 0 + 100 = 100
        let s = make_server("NoMax", 500_000, 1000, 50, 0, 0, "", "");
        assert_eq!(score(&s), 100);
    }

    #[test]
    fn test_load_perc_integer_division() {
        // Verify integer truncation matches C# behavior.
        // bandwidth = 62_500 bytes/s, bw_max = 1000
        // bw_cur = 2 * (62500 * 8) / 1_000_000 = 1_000_000 / 1_000_000 = 1
        // load_perc = (1 * 100) / 1000 = 0  (truncated from 0.1)
        let s = make_server("Trunc", 62_500, 1000, 0, 100, 0, "", "");
        assert_eq!(load_perc(&s), 0);
    }

    #[test]
    fn test_select_server_picks_lowest_score() {
        let servers = vec![
            // Score: LoadB=80 + ScoreB=10 + UsersB=80 = 170
            make_server("Worse", 50_000_000, 1000, 200, 250, 10, "", ""),
            // Score: LoadB=0 + ScoreB=10 + UsersB=20 = 30
            make_server("Better", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let selected = select_server(&servers, None).unwrap();
        assert_eq!(selected.name, "Better");
    }

    #[test]
    fn test_select_server_by_name() {
        let servers = vec![
            make_server("Castor", 50_000_000, 1000, 200, 250, 10, "", ""),
            make_server("Pollux", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        // Castor has a worse score, but explicit name selection overrides scoring.
        let selected = select_server(&servers, Some("Castor")).unwrap();
        assert_eq!(selected.name, "Castor");
    }

    #[test]
    fn test_select_server_by_name_not_found() {
        let servers = vec![
            make_server("Alpha", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let err = select_server(&servers, Some("Nonexistent")).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "expected 'not found' error, got: {err}"
        );
    }

    #[test]
    fn test_select_server_empty_list() {
        let servers: Vec<Server> = vec![];
        let err = select_server(&servers, None).unwrap_err();
        assert!(
            err.to_string().contains("no servers available"),
            "expected 'no servers available' error, got: {err}"
        );
    }

    #[test]
    fn test_select_server_skips_warned_servers() {
        let servers = vec![
            make_server("Closed", 500_000, 1000, 50, 250, 0, "", "maintenance"),
            make_server("Open", 500_000, 1000, 50, 250, 0, "degraded", ""),
            make_server("Good", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let selected = select_server(&servers, None).unwrap();
        assert_eq!(selected.name, "Good");
    }

    // -------------------------------------------------------------------
    // Penalty tests
    // -------------------------------------------------------------------

    #[test]
    fn test_penalty_fresh_is_zero() {
        let penalties = ServerPenalties::new();
        assert_eq!(penalties.get("anything"), 0);
    }

    #[test]
    fn test_penalty_active() {
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        // Penalty was just applied — should be active
        assert_eq!(penalties.get("Alpha"), 30);
    }

    #[test]
    fn test_penalty_other_server_unaffected() {
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        assert_eq!(penalties.get("Beta"), 0);
    }

    #[test]
    fn test_score_with_penalty_normal() {
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        // Base score with ping=10ms: 10 + 0 + 10 + 20 = 40
        // Penalty contribution = 30 * 1000 = 30000
        assert_eq!(score_with_penalty(&s, &penalties, 10), 30040);
    }

    #[test]
    fn test_score_with_penalty_no_penalty() {
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        let penalties = ServerPenalties::new();
        // No penalty, ping=10 -> same as score_with_ping
        assert_eq!(score_with_penalty(&s, &penalties, 10), score_with_ping(&s, 10));
    }

    #[test]
    fn test_score_with_penalty_unmeasured_ping() {
        // ping == -1 -> sentinel 99995; penalty should NOT inflate it
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        assert_eq!(score_with_penalty(&s, &penalties, -1), 99995);
    }

    #[test]
    fn test_score_with_penalty_sentinel_unchanged() {
        // warning_closed -> base score 99998; penalty should NOT inflate it
        let s = make_server("Closed", 500_000, 1000, 50, 250, 10, "", "maintenance");
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Closed", 30);
        assert_eq!(score_with_penalty(&s, &penalties, 10), 99998);
    }

    // -------------------------------------------------------------------
    // Ping scoring tests
    // -------------------------------------------------------------------

    #[test]
    fn test_score_with_ping_unmeasured() {
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        assert_eq!(score_with_ping(&s, -1), 99995);
    }

    #[test]
    fn test_score_with_ping_measured() {
        // Base score without ping = 30 (LoadB=0 + ScoreB=10 + UsersB=20)
        // With ping=15ms: PingB=15, total = 15 + 0 + 10 + 20 = 45
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        assert_eq!(score_with_ping(&s, 15), 45);
    }

    #[test]
    fn test_score_with_ping_zero() {
        // ping=0ms (localhost-like): same as base score without ping
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        assert_eq!(score_with_ping(&s, 0), score(&s));
    }

    #[test]
    fn test_score_with_ping_warning_overrides() {
        let s = make_server("Closed", 500_000, 1000, 50, 250, 10, "", "maintenance");
        // Warning sentinel should take precedence over ping
        assert_eq!(score_with_ping(&s, 10), 99998);
    }

    #[test]
    fn test_select_server_with_penalties_rotates() {
        let servers = vec![
            // Score: 30 (best without penalty)
            make_server("Best", 500_000, 1000, 50, 250, 10, "", ""),
            // Score: 160
            make_server("Second", 50_000_000, 1000, 200, 250, 0, "", ""),
        ];
        let mut penalties = ServerPenalties::new();
        // Ping results: both measured with same low ping
        let mut pings = PingResults::new();
        pings.latencies.insert("Best".to_string(), 5);
        pings.latencies.insert("Second".to_string(), 5);

        // Without penalty, "Best" wins (score 35 vs 165)
        let selected = select_server_with_penalties(&servers, None, &penalties, &pings).unwrap();
        assert_eq!(selected.name, "Best");

        // Penalize "Best" -- now "Second" should win (35 + 30*1000 = 30035 > 165)
        penalties.penalize("Best", 30);
        let selected = select_server_with_penalties(&servers, None, &penalties, &pings).unwrap();
        assert_eq!(selected.name, "Second");
    }

    #[test]
    fn test_select_server_with_penalties_explicit_name_ignores_penalty() {
        let servers = vec![
            make_server("Alpha", 500_000, 1000, 50, 250, 10, "", ""),
            make_server("Beta", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        let pings = PingResults::new();
        // Explicit name should still find Alpha despite penalty
        let selected =
            select_server_with_penalties(&servers, Some("Alpha"), &penalties, &pings).unwrap();
        assert_eq!(selected.name, "Alpha");
    }

    #[test]
    fn test_select_server_with_ping_prefers_lower_latency() {
        let servers = vec![
            make_server("Far", 500_000, 1000, 50, 250, 10, "", ""),
            make_server("Near", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let penalties = ServerPenalties::new();
        let mut pings = PingResults::new();
        pings.latencies.insert("Far".to_string(), 200);
        pings.latencies.insert("Near".to_string(), 5);

        let selected = select_server_with_penalties(&servers, None, &penalties, &pings).unwrap();
        assert_eq!(selected.name, "Near");
    }

    #[test]
    fn test_select_server_unmeasured_ping_sorted_last() {
        let servers = vec![
            make_server("Unmeasured", 500_000, 1000, 50, 250, 10, "", ""),
            make_server("Measured", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let penalties = ServerPenalties::new();
        let mut pings = PingResults::new();
        // Only "Measured" has a ping result; "Unmeasured" defaults to -1
        pings.latencies.insert("Measured".to_string(), 50);

        let selected = select_server_with_penalties(&servers, None, &penalties, &pings).unwrap();
        assert_eq!(selected.name, "Measured");
    }

    // -------------------------------------------------------------------
    // filter_servers tests
    // -------------------------------------------------------------------

    /// Helper to build a test Server with a specific country code.
    fn make_server_cc(name: &str, country_code: &str) -> Server {
        Server {
            name: name.to_string(),
            group: String::new(),
            ips_entry: vec!["1.2.3.4".to_string()],
            ips_exit: vec!["5.6.7.8".to_string()],
            country_code: country_code.to_string(),
            location: "Test".to_string(),
            scorebase: 0,
            bandwidth: 500_000,
            bandwidth_max: 1000,
            users: 50,
            users_max: 250,
            support_ipv4: true,
            support_ipv6: true,
            warning_open: String::new(),
            warning_closed: String::new(),
        }
    }

    #[test]
    fn test_filter_no_rules_passes_all() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
            make_server_cc("Gamma", "DE"),
        ];
        let filtered = filter_servers(&servers, &[], &[], &[], &[]);
        assert_eq!(filtered.len(), 3);
    }

    #[test]
    fn test_filter_deny_server() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
            make_server_cc("Gamma", "DE"),
        ];
        let deny = vec!["Beta".to_string()];
        let filtered = filter_servers(&servers, &[], &deny, &[], &[]);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "Gamma"]);
    }

    #[test]
    fn test_filter_deny_country() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
            make_server_cc("Gamma", "IT"),
        ];
        let deny_cc = vec!["IT".to_string()];
        let filtered = filter_servers(&servers, &[], &[], &[], &deny_cc);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Beta"]);
    }

    #[test]
    fn test_filter_allow_server() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
            make_server_cc("Gamma", "DE"),
        ];
        let allow = vec!["Alpha".to_string(), "Gamma".to_string()];
        let filtered = filter_servers(&servers, &allow, &[], &[], &[]);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "Gamma"]);
    }

    #[test]
    fn test_filter_allow_country() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
            make_server_cc("Gamma", "IT"),
            make_server_cc("Delta", "DE"),
        ];
        let allow_cc = vec!["IT".to_string()];
        let filtered = filter_servers(&servers, &[], &[], &allow_cc, &[]);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "Gamma"]);
    }

    #[test]
    fn test_filter_deny_takes_precedence_over_allow() {
        // Alpha is in IT (allowed country) but also explicitly denied
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "IT"),
        ];
        let allow_cc = vec!["IT".to_string()];
        let deny = vec!["Alpha".to_string()];
        let filtered = filter_servers(&servers, &[], &deny, &allow_cc, &[]);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Beta"]);
    }

    #[test]
    fn test_filter_deny_country_takes_precedence_over_allow_server() {
        // Alpha is explicitly allowed by name but its country IT is denied
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
        ];
        let allow = vec!["Alpha".to_string()];
        let deny_cc = vec!["IT".to_string()];
        let filtered = filter_servers(&servers, &allow, &[], &[], &deny_cc);
        // Alpha is denied by country, Beta doesn't match allow_server
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_filter_case_insensitive_country() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
        ];
        let allow_cc = vec!["it".to_string()];
        let filtered = filter_servers(&servers, &[], &[], &allow_cc, &[]);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha"]);
    }

    #[test]
    fn test_filter_case_insensitive_server_name() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
        ];
        let deny = vec!["alpha".to_string()];
        let filtered = filter_servers(&servers, &[], &deny, &[], &[]);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Beta"]);
    }

    #[test]
    fn test_filter_allow_server_and_allow_country_union() {
        // allow_server=["Alpha"] + allow_country=["NL"] should include both
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
            make_server_cc("Gamma", "DE"),
        ];
        let allow = vec!["Alpha".to_string()];
        let allow_cc = vec!["NL".to_string()];
        let filtered = filter_servers(&servers, &allow, &[], &allow_cc, &[]);
        let names: Vec<&str> = filtered.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, vec!["Alpha", "Beta"]);
    }

    #[test]
    fn test_filter_all_denied_returns_empty() {
        let servers = vec![
            make_server_cc("Alpha", "IT"),
            make_server_cc("Beta", "NL"),
        ];
        let deny = vec!["Alpha".to_string(), "Beta".to_string()];
        let filtered = filter_servers(&servers, &[], &deny, &[], &[]);
        assert!(filtered.is_empty());
    }
}
