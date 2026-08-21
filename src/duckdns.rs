//! DuckDNS updater: client-owned DNS record for a stable remote-access endpoint.
//!
//! AirDNS's record is written by AirVPN's backend as an opaque side effect of
//! session lifecycle — no client-callable update path, no ack. Every wedge in
//! 2026-07/08 (3h38m, 9h36m, 7h32m+) was "the backend didn't write and nothing
//! client-side could make it" (same-server corrective reconnects went 0-for-6
//! lifetime). DuckDNS inverts the ownership: WE write the record over an acked
//! HTTPS API, so keeping it fresh is one idempotent GET per check interval
//! instead of a corrective-reconnect state machine.
//!
//! Protocol: `GET https://www.duckdns.org/update?domains=<d>&token=<t>&ip=<ip>`
//! answers a bare `OK` or `KO` body. `KO` means the token is wrong or the
//! domain isn't in the token's account — permanent until the config or the
//! DuckDNS account changes. An empty `ip=` makes DuckDNS use the request's
//! source address (useful for `airvpn ddns test-duckdns`; the monitor loop
//! always passes the exit IP explicitly).
//!
//! The update URL embeds the token — never log the URL. Errors are logged by
//! callers from the `Failed` payload, which contains no secrets.

use std::net::Ipv4Addr;
use std::time::Duration;

/// How often the monitor loop re-sends the record while connected (seconds).
/// Unconditional idempotent rewrite — the standard DuckDNS cron cadence; no
/// drift detection needed when every write is acked.
pub const WRITE_INTERVAL_SECS: u64 = 300;

/// Consecutive transport failures before the pager fires (~15 min at
/// `WRITE_INTERVAL_SECS`): long enough to skip API blips, far faster than the
/// hours-scale staleness that motivated all of this.
pub const FAILURES_BEFORE_PAGE: u32 = 3;

/// One record write's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOutcome {
    /// DuckDNS acked the write (body `OK`).
    Accepted,
    /// DuckDNS refused it (body `KO`): wrong token, or domain not in the
    /// token's account. Permanent until config/account changes.
    Rejected,
    /// Transport-level failure (DNS, TCP, TLS, timeout, non-2xx, unexpected
    /// body). Retryable. The payload is a human-readable cause, secret-free.
    Failed(String),
}

/// Strip an optional `.duckdns.org` suffix so users can configure either the
/// bare subdomain (`myhost`) or the fully-qualified form.
pub fn normalize_domain(domain: &str) -> &str {
    domain.strip_suffix(".duckdns.org").unwrap_or(domain)
}

/// Validate the option pair at connect time — misconfiguration must be a loud
/// startup error, not a silent no-op or a page at 4am (the notify-URL lesson).
/// Both empty = feature deliberately off = fine.
pub fn validate_config(domain: &str, token: &str) -> Result<(), String> {
    if domain.is_empty() && token.is_empty() {
        return Ok(());
    }
    if domain.is_empty() || token.is_empty() {
        return Err(
            "ddns.duckdns_domain and ddns.duckdns_token must be set together".to_string(),
        );
    }
    let sub = normalize_domain(domain);
    if sub.is_empty() || !sub.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!(
            "ddns.duckdns_domain '{}' is not a DuckDNS subdomain (letters, digits, '-'; \
             optionally suffixed .duckdns.org)",
            domain,
        ));
    }
    // DuckDNS tokens are UUIDs. The token is interpolated raw into the update
    // URL, so reserved characters (`& # ?` — or whitespace from a bad paste)
    // would mangle the query; a `#` even fails SILENTLY (drops `&ip=`,
    // source-detect masks it). Reject anything but alnum + '-'.
    if token.is_empty() || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(
            "ddns.duckdns_token is not a DuckDNS token (UUID: letters, digits, '-') — \
             re-set it with `airvpn config set ddns.duckdns_token --stdin`"
                .to_string(),
        );
    }
    Ok(())
}

/// The full record name for logging and for the flight recorder.
pub fn record_name(domain: &str) -> String {
    format!("{}.duckdns.org", normalize_domain(domain))
}

/// A connected server's exit IPs — the record value comes from here.
///
/// Exits, NOT entries: the port forward listens on the exit; comparing or
/// publishing an entry IP is the exact measurement error that manufactured
/// the original June 2026 "drift" diagnosis ("I compared apples to oranges",
/// 2026-07-01 post-mortem).
pub fn exit_ips(server: &crate::manifest::Server) -> Vec<Ipv4Addr> {
    server
        .ips_exit
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Build the update URL. `ip: None` leaves `ip=` empty (source-detect).
fn build_update_url(domain: &str, token: &str, ip: Option<Ipv4Addr>) -> String {
    format!(
        "https://www.duckdns.org/update?domains={}&token={}&ip={}",
        normalize_domain(domain),
        token,
        ip.map(|i| i.to_string()).unwrap_or_default(),
    )
}

/// Map an HTTP result onto `WriteOutcome`. DuckDNS's protocol is a bare
/// `OK`/`KO` body; anything else means we didn't talk to the real endpoint
/// (captive portal, proxy error page) and counts as a transport failure.
/// Bodies are clipped to a short snippet: they feed log lines and pager
/// texts, and a portal's HTML can be arbitrarily large.
fn classify(status_2xx: bool, body: &str) -> WriteOutcome {
    let snippet: String = body.trim().chars().take(120).collect();
    if !status_2xx {
        return WriteOutcome::Failed(format!("HTTP error, body {:?}", snippet));
    }
    match body.trim() {
        "OK" => WriteOutcome::Accepted,
        "KO" => WriteOutcome::Rejected,
        _ => WriteOutcome::Failed(format!("unexpected response body {:?}", snippet)),
    }
}

/// Write the record: one GET, 10s timeout, no retries here (the caller's
/// interval loop IS the retry policy).
pub fn update(domain: &str, token: &str, ip: Option<Ipv4Addr>) -> WriteOutcome {
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        // Terminal OK/KO API — never follow redirects. The default policy
        // follows up to 10 hops with a Referer carrying the token-bearing
        // URL, would follow downgrades to http://, and hands the root
        // daemon a blind-GET SSRF primitive if DuckDNS or its CDN ever
        // serves a hostile redirect (2026-08-20 security review).
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(c) => c,
        Err(e) => return WriteOutcome::Failed(crate::ddns::error_chain(&e)),
    };
    // reqwest::Error's Display includes the request URL — which embeds the
    // token here. `without_url()` strips it before the message reaches logs,
    // the flight recorder, or a pager body.
    match client.get(build_update_url(domain, token, ip)).send() {
        Ok(resp) => {
            let status = resp.status();
            // Bounded read: the real protocol body is 2 bytes; a captive
            // portal can serve megabytes, and this runs in the root helper.
            use std::io::Read;
            let mut buf = Vec::with_capacity(64);
            match resp.take(4096).read_to_end(&mut buf) {
                Ok(_) => {
                    // Reflected-URL defense: proxy/WAF error pages commonly
                    // echo the request URI — token included — so scrub any
                    // response-derived text before it can reach logs or
                    // pager bodies (without_url() only covers reqwest's own
                    // error Display).
                    let body = redact_token(&String::from_utf8_lossy(&buf), token);
                    match classify(status.is_success(), &body) {
                        WriteOutcome::Failed(f) if !status.is_success() => {
                            WriteOutcome::Failed(format!("HTTP {}: {}", status, f))
                        }
                        other => other,
                    }
                }
                Err(e) => {
                    WriteOutcome::Failed(redact_token(&crate::ddns::error_chain(&e), token))
                }
            }
        }
        Err(e) => WriteOutcome::Failed(redact_token(
            &crate::ddns::error_chain(&e.without_url()),
            token,
        )),
    }
}

/// Scrub the token from text derived from network responses or errors.
fn redact_token(text: &str, token: &str) -> String {
    if token.is_empty() {
        text.to_string()
    } else {
        text.replace(token, "[token]")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_normalization() {
        assert_eq!(normalize_domain("myhost"), "myhost");
        assert_eq!(normalize_domain("myhost.duckdns.org"), "myhost");
        // Only the exact suffix is stripped — a different zone is left alone
        // (and will then fail charset validation, loudly).
        assert_eq!(normalize_domain("myhost.example.org"), "myhost.example.org");
    }

    #[test]
    fn config_validation() {
        // Both empty = feature off, not an error.
        assert!(validate_config("", "").is_ok());
        // One without the other is a config mistake.
        assert!(validate_config("myhost", "").is_err());
        assert!(validate_config("", "sometoken").is_err());
        // Good pairs, bare and suffixed.
        assert!(validate_config("myhost", "aaaa-bbbb").is_ok());
        assert!(validate_config("myhost.duckdns.org", "aaaa-bbbb").is_ok());
        // Bad subdomains: wrong zone, embedded dot, spaces, empty after strip.
        assert!(validate_config("myhost.example.org", "t").is_err());
        assert!(validate_config("a b", "t").is_err());
        assert!(validate_config(".duckdns.org", "t").is_err());
        // Tokens are UUIDs; whitespace is a paste artifact and reserved URL
        // chars would mangle the query (a `#` even fails silently) — reject
        // anything but alnum + '-'.
        assert!(validate_config("myhost", "tok en").is_err());
        assert!(validate_config("myhost", "token\n").is_err());
        assert!(validate_config("myhost", "tok&en").is_err());
        assert!(validate_config("myhost", "tok#en").is_err());
        assert!(validate_config("myhost", "01234567-89ab-4cde-8f01-234567890abc").is_ok());
    }

    #[test]
    fn record_name_is_fully_qualified() {
        assert_eq!(record_name("myhost"), "myhost.duckdns.org");
        assert_eq!(record_name("myhost.duckdns.org"), "myhost.duckdns.org");
    }

    #[test]
    fn update_url_shape() {
        let url = build_update_url("myhost.duckdns.org", "tok123", Some(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(
            url,
            "https://www.duckdns.org/update?domains=myhost&token=tok123&ip=1.2.3.4"
        );
        // No IP = source-detect: the param stays, empty.
        let url = build_update_url("myhost", "tok123", None);
        assert_eq!(url, "https://www.duckdns.org/update?domains=myhost&token=tok123&ip=");
    }

    #[test]
    fn token_redaction() {
        // A WAF/proxy error page echoing the request URI must not carry the
        // token into logs or pager bodies.
        assert_eq!(
            redact_token("GET /update?domains=x&token=sekret-123&ip= rejected", "sekret-123"),
            "GET /update?domains=x&token=[token]&ip= rejected"
        );
        assert_eq!(redact_token("no token here", "sekret-123"), "no token here");
        assert_eq!(redact_token("anything", ""), "anything");
    }

    #[test]
    fn response_classification() {
        assert_eq!(classify(true, "OK"), WriteOutcome::Accepted);
        assert_eq!(classify(true, "OK\n"), WriteOutcome::Accepted);
        assert_eq!(classify(true, "KO"), WriteOutcome::Rejected);
        // Non-OK/KO 2xx body = we didn't reach the real API.
        assert!(matches!(classify(true, "<html>portal</html>"), WriteOutcome::Failed(_)));
        // A 2xx-shaped body on a non-2xx status is still a failure.
        assert!(matches!(classify(false, "OK"), WriteOutcome::Failed(_)));
        // Huge bodies (portal HTML) are clipped — these strings feed log
        // lines and pager texts.
        let huge = "x".repeat(10_000);
        if let WriteOutcome::Failed(msg) = classify(true, &huge) {
            assert!(msg.len() < 200, "unclipped body in failure message");
        } else {
            panic!("huge non-OK/KO body must classify as Failed");
        }
    }
}
