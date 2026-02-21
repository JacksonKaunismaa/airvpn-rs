use anyhow::{bail, Context};

use crate::manifest::Server;

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
// Penality is always 0 (we don't track it).
// Ping is always 0 (no ping data; we skip Eddie's Ping==-1 → 99995 path).
// Result is truncated to i64 to match Eddie's `(int)(sum)` cast.
// ---------------------------------------------------------------------------

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
/// - `warning_closed` non-empty → 99998 (Error-level warning in Eddie)
/// - `warning_open` non-empty → 99997 (Warning-level warning in Eddie)
///
/// Normal computation (Speed scoreType, no ping):
/// ```text
/// Score = PenalityB + PingB + LoadB + ScoreB + UsersB
/// ```
/// With Speed factors (all 1.0):
/// - PenalityB = 0 (penality always 0)
/// - PingB = 0 (no ping data)
/// - LoadB = LoadPerc * 1
/// - ScoreB = ScoreBase * 1
/// - UsersB = UsersPerc * 1
///
/// Result is truncated to i64 to match Eddie's `(int)(sum)` cast.
pub fn score(server: &Server) -> i64 {
    // warning_closed → Error in Eddie → HasWarningsErrors() → 99998
    if !server.warning_closed.is_empty() {
        return 99998;
    }
    // warning_open → Warning in Eddie → HasWarnings() → 99997
    if !server.warning_open.is_empty() {
        return 99997;
    }

    let penality_b = 0; // Penality * 1000; penality always 0
    let ping_b = 0; // Ping * 1; no ping data, use 0

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
}
