//! Shared dynamic-DNS infrastructure: the ntfy pager and the observation
//! flight recorder.
//!
//! This is what remains of the AirDNS self-heal (v1 reverted 2026-07-01; v2
//! removed 2026-08-20 after its corrective-reconnect lever went 0-for-6
//! lifetime — AirVPN's backend writes the AirDNS record as an unacked side
//! effect of session lifecycle, and no client-side connect pattern reliably
//! rewrites it; see docs/known_divergences.md #17). The record the phone
//! depends on is now owned client-side by the DuckDNS writer (`duckdns.rs`),
//! which reports through the pager and recorder here.

use std::net::Ipv4Addr;
use std::time::Duration;

use log::warn;

// ---------------------------------------------------------------------------
// Observation logging (flight recorder)
// ---------------------------------------------------------------------------

/// Append-only JSONL log of every record observation, so the next incident has
/// a timeline instead of a multi-hour blind spot. ~288 lines/day at the 300s
/// cadence — negligible. Failures are log-only; the recorder must never affect
/// the tunnel.
pub const OBSERVATIONS_PATH: &str = "/var/lib/airvpn-rs/ddns-observations.jsonl";

/// Append one observation line. `action` is the short verdict string.
pub fn log_observation(
    hostname: &str,
    looked_up: Option<Ipv4Addr>,
    expected: &[Ipv4Addr],
    since_connect_secs: u64,
    action: &str,
) {
    let line = serde_json::json!({
        "ts": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        "hostname": hostname,
        "record": looked_up.map(|ip| ip.to_string()),
        "expected": expected.iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        "since_connect_secs": since_connect_secs,
        "action": action,
    });
    if let Err(e) = append_line(OBSERVATIONS_PATH, &line.to_string()) {
        warn!("ddns: failed to append observation log: {}", e);
    }
}

fn append_line(path: &str, line: &str) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(dir) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    writeln!(f, "{}", line)
}

// ---------------------------------------------------------------------------
// Pager (ntfy-style POST)
// ---------------------------------------------------------------------------

/// Check that a notify URL is usable: parseable AND credential-free. Empty =
/// pager deliberately disabled = fine. user:pass@ userinfo is rejected — the
/// only supported credential form is ddns.notify_user/notify_password (an
/// unencoded `\ / ? #` in a URL-embedded password shifts the authority
/// boundary and killed every page on 2026-08-15). Call at connect time so a
/// broken URL is a loud config error, not a silent drop when a page is needed.
pub fn validate_notify_url(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Ok(());
    }
    let parsed = reqwest::Url::parse(url).map_err(|e| error_chain(&e))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "ddns.notify_url must be credential-free — move user/password to \
             ddns.notify_user/ddns.notify_password"
                .to_string(),
        );
    }
    Ok(())
}

/// Fire-and-forget ntfy notification (plain POST; title via X-Title header).
/// Empty URL = disabled. Non-empty `user` = Basic auth with the password used
/// verbatim (the reason these are separate options: URL-embedded passwords
/// need percent-encoding and failed silently on 2026-08-15). All failures are
/// log-only. Returns whether the server accepted the page (2xx) so
/// `airvpn ddns test-notify` can report; loop callers ignore it.
pub fn notify(url: &str, user: &str, password: &str, title: &str, body: &str) -> bool {
    if url.is_empty() {
        return false;
    }
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("ddns: notify client build failed: {}", error_chain(&e));
            return false;
        }
    };
    let mut req = client
        .post(url)
        .header("X-Title", title)
        .body(body.to_string());
    if !user.is_empty() {
        req = req.basic_auth(user, Some(password));
    }
    match req.send() {
        Ok(resp) if resp.status().is_success() => true,
        Ok(resp) => {
            warn!("ddns: notify returned HTTP {}", resp.status());
            false
        }
        Err(e) => {
            warn!("ddns: notify failed: {}", error_chain(&e));
            false
        }
    }
}

/// Render an error with its full source chain ("builder error" alone is
/// useless; "builder error: invalid port number" names the cause — learned
/// from the 2026-08-15 silent-pager incident).
pub(crate) fn error_chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    msg
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The 2026-08-15 silent-pager incident: a reserved character (`/ ? #`) in
    /// the URL's embedded password makes Url::parse fail ("invalid port
    /// number"), so every notify() died as an opaque "builder error". The
    /// validation must catch that at connect time and name the real cause.
    #[test]
    fn notify_url_validation() {
        // Empty = pager disabled, not an error; credential-free URL = the
        // only accepted live form.
        assert!(validate_notify_url("").is_ok());
        assert!(validate_notify_url("https://host.example/alerts-topic").is_ok());
        // Reserved chars that shift the authority boundary — the real bug.
        // `\` is the one that actually bit (WHATWG treats it as `/` in
        // special schemes), and the one the first repro matrix missed.
        for bad in [
            "https://user:pa/ss@host.example/topic",
            "https://user:pa?ss@host.example/topic",
            "https://user:pa#ss@host.example/topic",
            r"https://user:pa\ss@host.example/topic",
        ] {
            let err = validate_notify_url(bad).unwrap_err();
            assert!(err.contains("invalid port number"), "err was: {err}");
        }
        // Userinfo is rejected outright, however well-encoded — the only
        // supported credential form is the dedicated options.
        for cred in [
            "https://user:pa%2F%3F%23%5Css@host.example/topic",
            "https://user:simple@host.example/topic",
            "https://user@host.example/topic",
        ] {
            let err = validate_notify_url(cred).unwrap_err();
            assert!(err.contains("credential-free"), "err was: {err}");
        }
    }

    /// The explicit-credentials path must send the password VERBATIM as Basic
    /// auth even when it contains characters that would break URL userinfo —
    /// that's the whole point of ddns.notify_user/notify_password.
    #[test]
    fn notify_sends_verbatim_basic_auth() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut req = Vec::new();
            let mut buf = [0u8; 1024];
            // Empty body (content-length: 0), so headers are the whole request.
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = sock.read(&mut buf).unwrap();
                assert!(n > 0, "connection closed before headers finished");
                req.extend_from_slice(&buf[..n]);
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n")
                .unwrap();
            String::from_utf8_lossy(&req).into_owned()
        });

        let url = format!("http://127.0.0.1:{port}/alerts-test");
        // base64("usr:pa/ss") — reserved char in the raw password.
        let delivered = notify(&url, "usr", "pa/ss", "test title", "");
        assert!(delivered, "notify() should report 2xx as success");
        let req = server.join().unwrap();
        assert!(
            req.contains("authorization: Basic dXNyOnBhL3Nz")
                || req.contains("Authorization: Basic dXNyOnBhL3Nz"),
            "missing/wrong basic-auth header in request:\n{req}"
        );
        assert!(req.contains("x-title: test title") || req.contains("X-Title: test title"));
    }
}
