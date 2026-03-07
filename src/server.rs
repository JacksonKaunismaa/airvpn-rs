use std::collections::HashMap;
use std::time::Instant;

use anyhow::{bail, Context};

use crate::manifest::Server;
use crate::pinger::LatencyCache;

// ---------------------------------------------------------------------------
// Eddie-compatible scoring (ConnectionInfo.cs Score(), LoadPerc(), UsersPerc())
//
// Units:
//   Bandwidth (bw):     bytes/s  — converted to Mbit/s via 2*(bw*8)/(1000*1000)
//   BandwidthMax (bw_max): Mbit/s — used directly
//   ScoreBase:           raw score from manifest (lower = better)
//   Users / UsersMax:    current / max user counts
//
// ScoreType (Eddie: servers.scoretype, default "Speed"):
//   Speed:   all factors 1.0 — balanced scoring
//   Latency: ScoreB /= 500, LoadB /= 10, UsersB /= 10 — ping dominates
//
// Factor values confirmed from AirVPN manifest (2026-03-07):
//   speed_factor=1, latency_factor=500, load_factor=1, users_factor=1,
//   ping_factor=1, penality_factor=1000, speed_load_factor=1 (default),
//   latency_load_factor=10 (default), speed_users_factor=1 (default),
//   latency_users_factor=10 (default)
//
// Penalty tracking via ServerPenalties (Eddie: Penality field on ConnectionInfo).
// Unmeasured ping (Ping==-1) contributes 0 instead of Eddie's 99995 sentinel,
// so that load/users/scorebase/penalties still differentiate servers.
// Result is truncated to i64 to match Eddie's `(int)(sum)` cast.
// ---------------------------------------------------------------------------

/// Scoring mode (Eddie: `servers.scoretype`).
///
/// Speed (default): balanced — load, users, scorebase, and ping all contribute equally.
/// Latency: ping dominates — load and users divided by 10, scorebase divided by 500.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum ScoreType {
    #[default]
    Speed,
    Latency,
}

impl ScoreType {
    /// Parse from profile option string (case-insensitive, defaults to Speed).
    pub fn from_profile(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "latency" => ScoreType::Latency,
            _ => ScoreType::Speed,
        }
    }
}

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
#[derive(Default)]
pub struct ServerPenalties {
    penalties: HashMap<String, (i64, Instant)>,
}

impl ServerPenalties {
    pub fn new() -> Self {
        Self::default()
    }

    /// Maximum penalty value (2 hours of decay at 1/minute).
    /// Prevents unbounded accumulation from repeated failures.
    const MAX_PENALTY: i64 = 120;

    /// Apply a penalty to a server (Eddie: additive, default 30 per failure).
    pub fn penalize(&mut self, server_name: &str, amount: i64) {
        let entry = self
            .penalties
            .entry(server_name.to_string())
            .or_insert((0, Instant::now()));
        // Accumulate with cap (Eddie: Penality += amount)
        entry.0 = (entry.0 + amount).min(Self::MAX_PENALTY);
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
pub fn load_perc(server: &Server) -> i64 {
    if server.bandwidth_max == 0 {
        return 100;
    }
    let bw_cur = 2_i64.saturating_mul(server.bandwidth.saturating_mul(8)) / (1_000 * 1_000);
    bw_cur.saturating_mul(100) / server.bandwidth_max
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
/// Normal computation (no ping):
/// ```text
/// Score = PenalityB + PingB + LoadB + ScoreB + UsersB
/// ```
/// Speed mode (all 1.0): LoadB = LoadPerc, ScoreB = ScoreBase, UsersB = UsersPerc
/// Latency mode: ScoreB /= 500, LoadB /= 10, UsersB /= 10 (ping dominates)
///
/// Result is truncated to i64 to match Eddie's `(int)(sum)` cast.
///
/// NOTE: This treats ping as 0 (not measured). For ping-aware scoring, use
/// `score_with_ping()`.
pub fn score(server: &Server, score_type: ScoreType) -> i64 {
    score_with_ping(server, -1, score_type)
}

/// Calculate server score with ICMP ping latency, matching Eddie's
/// `ConnectionInfo.Score()` with the Ping field populated.
///
/// Eddie behavior (ConnectionInfo.cs line 219-246):
/// - `ping_ms == -1` (not measured) -> fall back to base score (load + scorebase + users)
/// - Otherwise: `PingB = ping_ms * ping_factor(1)` added to score sum
///
/// Score type determines factor divisors (Eddie: `servers.scoretype`):
/// - Speed (default): all factors 1.0
/// - Latency: ScoreB /= 500, LoadB /= 10, UsersB /= 10
///
/// NOTE: Eddie returns 99995 sentinel for unmeasured ping, which makes all
/// unmeasured servers score identically and breaks penalty-based rotation
/// (score_with_penalty skips penalties for sentinels >= 99995). We diverge
/// from Eddie here: unmeasured ping contributes 0 instead of a sentinel,
/// so that load/users/scorebase/penalties still differentiate servers.
pub fn score_with_ping(server: &Server, ping_ms: i64, score_type: ScoreType) -> i64 {
    // warning_closed -> Error in Eddie -> HasWarningsErrors() -> 99998
    if !server.warning_closed.is_empty() {
        return 99998;
    }
    // warning_open -> Warning in Eddie -> HasWarnings() -> 99997
    if !server.warning_open.is_empty() {
        return 99997;
    }

    // Unmeasured ping: fall back to base score (ping contributes 0).
    // Eddie returns 99995 here, but that makes all unmeasured servers
    // score identically, breaking penalty rotation and degenerating
    // selection to manifest order (alphabetically first server always wins).
    let ping_b = if ping_ms == -1 { 0 } else { ping_ms };

    let penality_b = 0; // Base score excludes penalty; use score_with_penalty() for penalty-aware scoring

    let mut load_b = load_perc(server);
    let mut score_b = server.scorebase;
    let mut users_b = users_perc(server);

    // Apply score type divisors (Eddie: ConnectionInfo.cs lines 233-244)
    match score_type {
        ScoreType::Speed => {} // All factors 1.0, no adjustment needed
        ScoreType::Latency => {
            score_b /= 500;
            load_b /= 10;
            users_b /= 10;
        }
    }

    penality_b + ping_b + load_b + score_b + users_b
}

/// Compute server score including penalty, matching Eddie's `Score()` with
/// `Penality * penality_factor` (default factor = 1000).
///
/// Sentinel values (99995+) from warnings/unmeasured ping are not modified --
/// a closed server stays closed regardless of penalties.
pub fn score_with_penalty(
    server: &Server,
    penalties: &ServerPenalties,
    ping_ms: i64,
    score_type: ScoreType,
) -> i64 {
    let base = score_with_ping(server, ping_ms, score_type);
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
    score_type: ScoreType,
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
        .min_by(|a, b| score(a, score_type).cmp(&score(b, score_type)))
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
    pings: &LatencyCache,
    score_type: ScoreType,
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
            let sa = score_with_penalty(a, penalties, pings.get(&a.name), score_type);
            let sb = score_with_penalty(b, penalties, pings.get(&b.name), score_type);
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
        let sc = score(&s, ScoreType::Speed);
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
        let sc = score(&s, ScoreType::Speed);
        assert_eq!(sc, 160);
    }

    #[test]
    fn test_score_warning_closed() {
        let s = make_server("Closed", 500_000, 1000, 50, 250, 10, "", "Server maintenance");
        assert_eq!(score(&s, ScoreType::Speed), 99998);
    }

    #[test]
    fn test_score_warning_open() {
        let s = make_server("Open", 500_000, 1000, 50, 250, 10, "Degraded performance", "");
        assert_eq!(score(&s, ScoreType::Speed), 99997);
    }

    #[test]
    fn test_score_both_warnings_closed_takes_priority() {
        // When both are set, warning_closed (Error) is checked first → 99998
        let s = make_server("Both", 500_000, 1000, 50, 250, 10, "warning", "closed");
        assert_eq!(score(&s, ScoreType::Speed), 99998);
    }

    #[test]
    fn test_score_zero_bandwidth_max() {
        // BandwidthMax == 0 → LoadPerc returns 100
        // UsersPerc = (50 * 100) / 250 = 20
        // Speed mode: LoadB = 100, ScoreB = 0, UsersB = 20
        // Score = 0 + 0 + 100 + 0 + 20 = 120
        let s = make_server("Zero", 500_000, 0, 50, 250, 0, "", "");
        assert_eq!(score(&s, ScoreType::Speed), 120);
    }

    #[test]
    fn test_score_zero_users_max() {
        // UsersMax == 0 → UsersPerc returns 100
        // LoadPerc: bw_cur = 2*(500000*8)/1000000 = 8, (8*100)/1000 = 0
        // Speed mode: LoadB = 0, ScoreB = 0, UsersB = 100
        // Score = 0 + 0 + 0 + 0 + 100 = 100
        let s = make_server("NoMax", 500_000, 1000, 50, 0, 0, "", "");
        assert_eq!(score(&s, ScoreType::Speed), 100);
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
        let selected = select_server(&servers, None, ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Better");
    }

    #[test]
    fn test_select_server_by_name() {
        let servers = vec![
            make_server("Castor", 50_000_000, 1000, 200, 250, 10, "", ""),
            make_server("Pollux", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        // Castor has a worse score, but explicit name selection overrides scoring.
        let selected = select_server(&servers, Some("Castor"), ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Castor");
    }

    #[test]
    fn test_select_server_by_name_not_found() {
        let servers = vec![
            make_server("Alpha", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let err = select_server(&servers, Some("Nonexistent"), ScoreType::Speed).unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "expected 'not found' error, got: {err}"
        );
    }

    #[test]
    fn test_select_server_empty_list() {
        let servers: Vec<Server> = vec![];
        let err = select_server(&servers, None, ScoreType::Speed).unwrap_err();
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
        let selected = select_server(&servers, None, ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Good");
    }

    // -------------------------------------------------------------------
    // Penalty tests
    // -------------------------------------------------------------------

    #[test]
    fn test_penalty_active() {
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        // Penalty was just applied — should be active
        assert_eq!(penalties.get("Alpha"), 30);
    }

    #[test]
    fn test_score_with_penalty_normal() {
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        // Base score with ping=10ms: 10 + 0 + 10 + 20 = 40
        // Penalty contribution = 30 * 1000 = 30000
        assert_eq!(score_with_penalty(&s, &penalties, 10, ScoreType::Speed), 30040);
    }

    #[test]
    fn test_score_with_penalty_unmeasured_ping() {
        // ping == -1 falls back to base score; penalty should still apply.
        // Base: LoadB=0 + ScoreB=10 + UsersB=20 = 30
        // Penalty: 30 * 1000 = 30000
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        assert_eq!(score_with_penalty(&s, &penalties, -1, ScoreType::Speed), 30030);
    }

    #[test]
    fn test_score_with_penalty_sentinel_unchanged() {
        // warning_closed -> base score 99998; penalty should NOT inflate it
        let s = make_server("Closed", 500_000, 1000, 50, 250, 10, "", "maintenance");
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Closed", 30);
        assert_eq!(score_with_penalty(&s, &penalties, 10, ScoreType::Speed), 99998);
    }

    // -------------------------------------------------------------------
    // Ping scoring tests
    // -------------------------------------------------------------------

    #[test]
    fn test_score_with_ping_unmeasured() {
        // Unmeasured ping (-1) falls back to base score (ping contributes 0).
        // Base: LoadB=0 + ScoreB=10 + UsersB=20 = 30
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        assert_eq!(score_with_ping(&s, -1, ScoreType::Speed), score(&s, ScoreType::Speed));
    }

    #[test]
    fn test_score_with_ping_measured() {
        // Base score without ping = 30 (LoadB=0 + ScoreB=10 + UsersB=20)
        // With ping=15ms: PingB=15, total = 15 + 0 + 10 + 20 = 45
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        assert_eq!(score_with_ping(&s, 15, ScoreType::Speed), 45);
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
        let mut pings = LatencyCache::new();
        pings.update("Best", 5);
        pings.update("Second", 5);

        // Without penalty, "Best" wins (score 35 vs 165)
        let selected = select_server_with_penalties(&servers, None, &penalties, &pings, ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Best");

        // Penalize "Best" -- now "Second" should win (35 + 30*1000 = 30035 > 165)
        penalties.penalize("Best", 30);
        let selected = select_server_with_penalties(&servers, None, &penalties, &pings, ScoreType::Speed).unwrap();
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
        let pings = LatencyCache::new();
        // Explicit name should still find Alpha despite penalty
        let selected =
            select_server_with_penalties(&servers, Some("Alpha"), &penalties, &pings, ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Alpha");
    }

    #[test]
    fn test_select_server_with_ping_prefers_lower_latency() {
        let servers = vec![
            make_server("Far", 500_000, 1000, 50, 250, 10, "", ""),
            make_server("Near", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let penalties = ServerPenalties::new();
        let mut pings = LatencyCache::new();
        pings.update("Far", 200);
        pings.update("Near", 5);

        let selected = select_server_with_penalties(&servers, None, &penalties, &pings, ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Near");
    }

    #[test]
    fn test_select_server_unmeasured_ping_not_penalized() {
        // Unmeasured ping falls back to base score (30), which is lower than
        // a measured server with high ping (30 + 50 = 80). The unmeasured
        // server should win since its base score is better.
        let servers = vec![
            make_server("Unmeasured", 500_000, 1000, 50, 250, 10, "", ""),
            make_server("Measured", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let penalties = ServerPenalties::new();
        let mut pings = LatencyCache::new();
        // Only "Measured" has a ping result; "Unmeasured" defaults to -1 (→ 0 contribution)
        pings.update("Measured", 50);

        let selected = select_server_with_penalties(&servers, None, &penalties, &pings, ScoreType::Speed).unwrap();
        // Unmeasured: base 30 + ping 0 = 30
        // Measured: base 30 + ping 50 = 80
        assert_eq!(selected.name, "Unmeasured");
    }

    #[test]
    fn test_select_server_penalty_works_without_ping() {
        // Core regression test: penalties must differentiate servers even when
        // all pings are unmeasured (--skip-ping). Previously all servers scored
        // sentinel 99995 and penalties were skipped, degenerating to manifest order.
        let servers = vec![
            make_server("Achernar", 500_000, 1000, 50, 250, 10, "", ""),
            make_server("Geminorum", 500_000, 1000, 50, 250, 10, "", ""),
        ];
        let mut penalties = ServerPenalties::new();
        let pings = LatencyCache::new(); // No pings (--skip-ping)

        // Without penalty, both score 30; min_by picks first (Achernar)
        let selected = select_server_with_penalties(&servers, None, &penalties, &pings, ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Achernar");

        // Penalize Achernar — Geminorum should now win
        penalties.penalize("Achernar", 30);
        let selected = select_server_with_penalties(&servers, None, &penalties, &pings, ScoreType::Speed).unwrap();
        assert_eq!(selected.name, "Geminorum");
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

    // -------------------------------------------------------------------
    // ServerPenalties::get() after long elapsed time (penalty fully decayed)
    // -------------------------------------------------------------------

    #[test]
    fn test_penalty_decay_over_time() {
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);

        // Manually set the timestamp to 60 minutes ago so penalty is fully decayed
        // We need to adjust the stored timestamp to simulate time passage
        if let Some(entry) = penalties.penalties.get_mut("Alpha") {
            // Set timestamp to 60 minutes ago: penalty 30, decays 1/min, so 30 min decays it to 0
            entry.1 = Instant::now() - std::time::Duration::from_secs(60 * 60);
        }

        // After 60 minutes, a penalty of 30 should be fully decayed (30 - 60 = negative → 0)
        assert_eq!(penalties.get("Alpha"), 0, "penalty should be fully decayed after 60 minutes");
    }

    #[test]
    fn test_penalty_partial_decay() {
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);

        // Set timestamp to 10 minutes ago: penalty 30 - 10 = 20
        if let Some(entry) = penalties.penalties.get_mut("Alpha") {
            entry.1 = Instant::now() - std::time::Duration::from_secs(10 * 60);
        }

        assert_eq!(penalties.get("Alpha"), 20, "penalty should decay by 1 per minute");
    }

    #[test]
    fn test_penalty_accumulation() {
        let mut penalties = ServerPenalties::new();
        penalties.penalize("Alpha", 30);
        penalties.penalize("Alpha", 30);
        // Penalty should accumulate: 30 + 30 = 60
        assert_eq!(penalties.get("Alpha"), 60);
    }

    #[test]
    fn test_penalty_accumulation_capped_at_max() {
        let mut penalties = ServerPenalties::new();
        // Apply 5 penalties of 30 each: 150 total, but capped at MAX_PENALTY (120)
        for _ in 0..5 {
            penalties.penalize("Alpha", 30);
        }
        assert_eq!(
            penalties.get("Alpha"),
            ServerPenalties::MAX_PENALTY,
            "penalty should be capped at MAX_PENALTY ({})",
            ServerPenalties::MAX_PENALTY,
        );
    }

    // -------------------------------------------------------------------
    // Latency score type tests
    // -------------------------------------------------------------------

    #[test]
    fn test_score_latency_mode() {
        // Same server as test_score_normal_server:
        // LoadPerc = 0, ScoreBase = 10, UsersPerc = 20
        //
        // Latency mode: ScoreB /= 500, LoadB /= 10, UsersB /= 10
        //   ScoreB = 10 / 500 = 0 (integer division)
        //   LoadB = 0 / 10 = 0
        //   UsersB = 20 / 10 = 2
        //   PingB = 0 (no ping)
        //
        // Score = 0 + 0 + 0 + 2 = 2
        let s = make_server("Alpha", 500_000, 1000, 50, 250, 10, "", "");
        assert_eq!(score(&s, ScoreType::Latency), 2);
    }

    #[test]
    fn test_score_latency_ping_dominates() {
        // Two servers with identical load/users but different pings.
        // In Speed mode, 50ms difference is meaningful but load matters equally.
        // In Latency mode, load is divided by 10 so ping dominates.
        let low_load = make_server("LowLoad", 500_000, 1000, 50, 250, 0, "", "");
        let high_load = make_server("HighLoad", 50_000_000, 1000, 200, 250, 0, "", "");

        // Speed mode: LowLoad=0+20=20, HighLoad=80+80=160
        // With ping 100ms: LowLoad=120, HighLoad=260
        assert_eq!(score_with_ping(&low_load, 100, ScoreType::Speed), 120);
        assert_eq!(score_with_ping(&high_load, 100, ScoreType::Speed), 260);

        // Latency mode: LowLoad load=0/10=0, users=20/10=2 → 2+100=102
        //               HighLoad load=80/10=8, users=80/10=8 → 16+100=116
        // Difference shrinks from 140 (speed) to 14 (latency) — ping dominates
        assert_eq!(score_with_ping(&low_load, 100, ScoreType::Latency), 102);
        assert_eq!(score_with_ping(&high_load, 100, ScoreType::Latency), 116);
    }

    #[test]
    fn test_latency_mode_prefers_low_ping_over_low_load() {
        // Server A: low load, high ping (200ms)
        // Server B: high load, low ping (10ms)
        // In Latency mode, B should win despite high load.
        let servers = vec![
            make_server("LowLoad", 500_000, 1000, 50, 250, 0, "", ""),
            make_server("LowPing", 50_000_000, 1000, 200, 250, 0, "", ""),
        ];
        let penalties = ServerPenalties::new();
        let mut pings = LatencyCache::new();
        pings.update("LowLoad", 200);
        pings.update("LowPing", 10);

        // Speed mode: LowLoad wins (20+200=220 vs 160+10=170) — actually LowPing wins
        // Latency mode: LowPing definitely wins (8+8+10=26 vs 0+2+200=202)
        let selected = select_server_with_penalties(
            &servers, None, &penalties, &pings, ScoreType::Latency,
        ).unwrap();
        assert_eq!(selected.name, "LowPing");
    }

    #[test]
    fn test_score_type_from_profile() {
        assert_eq!(ScoreType::from_profile("Speed"), ScoreType::Speed);
        assert_eq!(ScoreType::from_profile("speed"), ScoreType::Speed);
        assert_eq!(ScoreType::from_profile("Latency"), ScoreType::Latency);
        assert_eq!(ScoreType::from_profile("latency"), ScoreType::Latency);
        assert_eq!(ScoreType::from_profile(""), ScoreType::Speed);
        assert_eq!(ScoreType::from_profile("unknown"), ScoreType::Speed);
    }

}
