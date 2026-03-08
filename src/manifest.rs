use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{bail, Context};
use log::{debug, warn};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct Message {
    pub kind: String,
    pub text: String,
    pub url: String,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub servers: Vec<Server>,
    pub modes: Vec<Mode>,
    pub bootstrap_urls: Vec<String>,
    pub force_reauth_ts: i64,
    pub messages: Vec<Message>,
    pub check_domain: String,
    pub check_dns_query: String,
    pub check_protocol: String,  // "https" or "http" (Eddie default: "https")
    /// RSA modulus from `auth_rsa_modulus` attribute on `<manifest>` element.
    /// When present, subsequent API calls should use this key instead of the
    /// provider.json key. This allows AirVPN to rotate their RSA key without
    /// requiring a software update. The manifest is received encrypted with
    /// the CURRENT key, so the new key is authenticated.
    /// (Eddie: Service.cs:924-932)
    pub rsa_modulus: Option<String>,
    /// RSA exponent from `auth_rsa_exponent` attribute on `<manifest>` element.
    pub rsa_exponent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Server {
    pub name: String,
    pub group: String,
    pub ips_entry: Vec<String>,
    pub ips_exit: Vec<String>,
    pub country_code: String,
    pub location: String,
    pub scorebase: i64,
    pub bandwidth: i64,
    pub bandwidth_max: i64,
    pub users: i64,
    pub users_max: i64,
    pub support_ipv4: bool,
    pub support_ipv6: bool,
    pub warning_open: String,
    pub warning_closed: String,
}

#[derive(Debug, Clone)]
pub struct Mode {
    pub title: String,
    pub protocol: String,
    pub port: u16,
    pub entry_index: usize,
}

#[derive(Debug)]
pub struct UserInfo {
    pub login: String,
    pub wg_public_key: String,
    pub keys: Vec<WireGuardKey>,
}

#[derive(Debug)]
pub struct WireGuardKey {
    pub name: String,
    pub wg_private_key: Zeroizing<String>,
    pub wg_ipv4: String,
    pub wg_ipv6: String,
    pub wg_dns_ipv4: String,
    pub wg_dns_ipv6: String,
    pub wg_preshared: Zeroizing<String>,
}

struct ServerGroupAttrs {
    ips_entry: String,
    ips_exit: String,
    country_code: String,
    location: String,
    scorebase: String,
    bw: String,
    bw_max: String,
    users: String,
    users_max: String,
    support_ipv4: String,
    support_ipv6: String,
    warning_open: String,
    warning_closed: String,
}

struct RawServerAttrs {
    name: String,
    group: String,
    ips_entry: Option<String>,
    ips_exit: Option<String>,
    country_code: Option<String>,
    location: Option<String>,
    scorebase: Option<String>,
    bw: Option<String>,
    bw_max: Option<String>,
    users: Option<String>,
    users_max: Option<String>,
    support_ipv4: Option<String>,
    support_ipv6: Option<String>,
    warning_open: Option<String>,
    warning_closed: Option<String>,
}

const MAX_ERROR_MSG_LEN: usize = 200;
const MAX_MANIFEST_SIZE: usize = 50 * 1024 * 1024;
const MAX_SERVERS: usize = 10_000;
const MAX_MODES: usize = 100;
const MAX_BOOTSTRAP_URLS: usize = 50;


pub fn sanitize_server_message(msg: &str) -> String {
    let mut result = String::with_capacity(msg.len());
    let mut in_tag = false;
    for ch in msg.chars() {
        match ch {
            '<' => { in_tag = true; }
            '>' => { in_tag = false; }
            _ if !in_tag && ch.is_ascii() && !ch.is_ascii_control() => {
                result.push(ch);
            }
            _ => {}
        }
    }
    if result.len() > MAX_ERROR_MSG_LEN {
        result.truncate(MAX_ERROR_MSG_LEN);
        result.push_str("...");
    }
    result
}

pub fn attr_opt(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == name {
            return String::from_utf8(attr.value.to_vec()).ok();
        }
    }
    None
}

fn attr_req(e: &quick_xml::events::BytesStart<'_>, name: &str) -> anyhow::Result<String> {
    attr_opt(e, name.as_bytes())
        .with_context(|| format!("missing required attribute '{name}' on <{}>", elem_name(e)))
}

fn elem_name(e: &quick_xml::events::BytesStart<'_>) -> String {
    String::from_utf8_lossy(e.name().as_ref()).into_owned()
}

fn split_ips(s: &str) -> Vec<String> {
    s.split([',', ';'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|ip_str| {
            // Strip CIDR prefix if present (e.g. "10.0.0.1/24" -> "10.0.0.1")
            let bare = ip_str.split('/').next().unwrap_or(ip_str);
            match bare.parse::<IpAddr>() {
                Ok(_) => true,
                Err(_) => {
                    warn!("Skipping invalid IP '{}' in server entry/exit list", ip_str);
                    false
                }
            }
        })
        .map(String::from)
        .collect()
}

fn check_api_error(xml: &str) -> anyhow::Result<()> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                if let Some(err_msg) = attr_opt(e, b"error") {
                    if !err_msg.is_empty() {
                        bail!("{}", sanitize_server_message(&err_msg));
                    }
                }
                return Ok(());
            }
            Ok(Event::Eof) => return Ok(()),
            Err(e) => bail!("XML parse error: {e}"),
            _ => {}
        }
    }
}

/// Maximum length for a server name.
const MAX_SERVER_NAME_LEN: usize = 64;

/// Validate that a server name contains only safe characters.
///
/// Server names are used in hostname construction (e.g. `{name}_exit.{domain}`),
/// so they must only contain [a-zA-Z0-9_-] to prevent hostname injection.
fn validate_server_name(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        bail!("server name is empty");
    }
    if name.len() > MAX_SERVER_NAME_LEN {
        bail!(
            "server name '{}' exceeds maximum length ({} > {})",
            name,
            name.len(),
            MAX_SERVER_NAME_LEN,
        );
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        bail!(
            "server name '{}' contains invalid characters (only [a-zA-Z0-9_-] allowed)",
            name,
        );
    }
    Ok(())
}

// NOTE: Eddie does NOT validate check_domain or bootstrap URL domains against
// an allowlist. The manifest is received over an authenticated channel (RSA+AES
// envelope). If an attacker can compromise the API response, they already control
// everything. Domain allowlists were previously added here but broke real
// functionality (airservers.org, HTTP bootstrap IPs) because they couldn't
// anticipate every legitimate domain AirVPN uses. Removed to match Eddie's
// approach.

fn validate_ip(s: &str, context: &str) -> anyhow::Result<()> {
    let ip_str = s.split('/').next().unwrap_or(s);
    ip_str.parse::<IpAddr>()
        .with_context(|| format!("invalid IP address '{}' in {}", s, context))?;
    Ok(())
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

fn parse_i64(s: &str) -> i64 {
    s.parse().unwrap_or(0)
}

/// Parse an integer for score fields. Unparseable values default to i64::MAX
/// so malicious/corrupt servers are penalized rather than favored (scorebase 0
/// is the best possible score).
fn parse_i64_score(s: &str) -> i64 {
    match s.parse() {
        Ok(v) => v,
        Err(_) => {
            if !s.is_empty() {
                warn!("failed to parse manifest score integer: {:?}, defaulting to i64::MAX", s);
            }
            i64::MAX
        }
    }
}

fn resolve_str(server_val: &Option<String>, group: Option<&ServerGroupAttrs>, getter: fn(&ServerGroupAttrs) -> &str) -> String {
    if let Some(v) = server_val {
        if !v.is_empty() {
            return v.clone();
        }
    }
    group.map_or_else(String::new, |g| getter(g).to_owned())
}

fn resolve_server(raw: RawServerAttrs, groups: &HashMap<String, ServerGroupAttrs>) -> Server {
    let grp = groups.get(&raw.group);
    let ips_entry_str = resolve_str(&raw.ips_entry, grp, |g| &g.ips_entry);
    let ips_exit_str = resolve_str(&raw.ips_exit, grp, |g| &g.ips_exit);
    let country_code = resolve_str(&raw.country_code, grp, |g| &g.country_code);
    let location = resolve_str(&raw.location, grp, |g| &g.location);
    let scorebase = resolve_str(&raw.scorebase, grp, |g| &g.scorebase);
    let bw = resolve_str(&raw.bw, grp, |g| &g.bw);
    let bw_max = resolve_str(&raw.bw_max, grp, |g| &g.bw_max);
    let users = resolve_str(&raw.users, grp, |g| &g.users);
    let users_max = resolve_str(&raw.users_max, grp, |g| &g.users_max);
    let support_ipv4 = resolve_str(&raw.support_ipv4, grp, |g| &g.support_ipv4);
    let support_ipv6 = resolve_str(&raw.support_ipv6, grp, |g| &g.support_ipv6);
    let warning_open = resolve_str(&raw.warning_open, grp, |g| &g.warning_open);
    let warning_closed = resolve_str(&raw.warning_closed, grp, |g| &g.warning_closed);
    Server {
        name: raw.name,
        group: raw.group,
        ips_entry: split_ips(&ips_entry_str),
        ips_exit: split_ips(&ips_exit_str),
        country_code,
        location,
        scorebase: parse_i64_score(&scorebase),
        bandwidth: parse_i64(&bw),
        bandwidth_max: { let v = parse_i64(&bw_max); if v == 0 { 1 } else { v } },
        users: parse_i64(&users),
        users_max: { let v = parse_i64(&users_max); if v == 0 { 100 } else { v } },
        support_ipv4: parse_bool(&support_ipv4),
        support_ipv6: parse_bool(&support_ipv6),
        warning_open,
        warning_closed,
    }
}

pub fn parse_manifest(xml: &str) -> anyhow::Result<Manifest> {
    if xml.len() > MAX_MANIFEST_SIZE {
        bail!("manifest too large: {} bytes exceeds {} byte limit", xml.len(), MAX_MANIFEST_SIZE);
    }
    check_api_error(xml)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut groups: HashMap<String, ServerGroupAttrs> = HashMap::new();
    let mut raw_servers: Vec<RawServerAttrs> = Vec::new();
    let mut modes: Vec<Mode> = Vec::new();
    let mut bootstrap_urls: Vec<String> = Vec::new();
    let mut messages: Vec<Message> = Vec::new();
    let mut force_reauth_ts: i64 = 0;
    let mut check_domain = String::new();
    let mut check_dns_query = String::new();
    let mut check_protocol = String::from("https");
    let mut rsa_modulus: Option<String> = None;
    let mut rsa_exponent: Option<String> = None;
    loop {
        match reader.read_event() {
            Err(e) => bail!("XML parse error at position {}: {e}", reader.error_position()),
            Ok(Event::Eof) => break,
            Ok(Event::Empty(ref e)) => {
                match e.name().as_ref() {
                    b"server" => {
                        if raw_servers.len() >= MAX_SERVERS {
                            bail!("manifest exceeds maximum server count ({})", MAX_SERVERS);
                        }
                        let name = attr_req(e, "name")?;
                        validate_server_name(&name)?;
                        let group = attr_opt(e, b"group").unwrap_or_default();
                        raw_servers.push(RawServerAttrs {
                            name, group,
                            ips_entry: attr_opt(e, b"ips_entry"),
                            ips_exit: attr_opt(e, b"ips_exit"),
                            country_code: attr_opt(e, b"country_code"),
                            location: attr_opt(e, b"location"),
                            scorebase: attr_opt(e, b"scorebase"),
                            bw: attr_opt(e, b"bw"),
                            bw_max: attr_opt(e, b"bw_max"),
                            users: attr_opt(e, b"users"),
                            users_max: attr_opt(e, b"users_max"),
                            support_ipv4: attr_opt(e, b"support_ipv4"),
                            support_ipv6: attr_opt(e, b"support_ipv6"),
                            warning_open: attr_opt(e, b"warning_open"),
                            warning_closed: attr_opt(e, b"warning_closed"),
                        });
                    }
                    b"servers_group" => {
                        let group = attr_req(e, "group")?;
                        groups.insert(group.clone(), ServerGroupAttrs {
                            ips_entry: attr_opt(e, b"ips_entry").unwrap_or_default(),
                            ips_exit: attr_opt(e, b"ips_exit").unwrap_or_default(),
                            country_code: attr_opt(e, b"country_code").unwrap_or_default(),
                            location: attr_opt(e, b"location").unwrap_or_default(),
                            scorebase: attr_opt(e, b"scorebase").unwrap_or_default(),
                            bw: attr_opt(e, b"bw").unwrap_or_default(),
                            bw_max: attr_opt(e, b"bw_max").unwrap_or_default(),
                            users: attr_opt(e, b"users").unwrap_or_default(),
                            users_max: attr_opt(e, b"users_max").unwrap_or_default(),
                            support_ipv4: attr_opt(e, b"support_ipv4").unwrap_or_default(),
                            support_ipv6: attr_opt(e, b"support_ipv6").unwrap_or_default(),
                            warning_open: attr_opt(e, b"warning_open").unwrap_or_default(),
                            warning_closed: attr_opt(e, b"warning_closed").unwrap_or_default(),
                        });
                    }
                    b"mode" => {
                        let mode_type = attr_opt(e, b"type").unwrap_or_default();
                        if mode_type == "wireguard" {
                            if modes.len() >= MAX_MODES {
                                bail!("manifest exceeds maximum mode count ({})", MAX_MODES);
                            }
                            modes.push(Mode {
                                title: attr_opt(e, b"title").unwrap_or_default(),
                                protocol: attr_opt(e, b"protocol").unwrap_or_default(),
                                port: attr_opt(e, b"port").unwrap_or_default().parse().unwrap_or(0),
                                entry_index: attr_opt(e, b"entry_index").unwrap_or_default().parse().unwrap_or(0),
                            });
                        }
                    }
                    b"url" => {
                        if let Some(addr) = attr_opt(e, b"address") {
                            if !addr.is_empty() {
                                if bootstrap_urls.len() >= MAX_BOOTSTRAP_URLS {
                                    bail!("manifest exceeds maximum bootstrap URL count ({})", MAX_BOOTSTRAP_URLS);
                                }
                                if !addr.starts_with("http://") && !addr.starts_with("https://") {
                                    warn!("Skipping bootstrap URL with unknown scheme: {}", sanitize_server_message(&addr));
                                } else {
                                    bootstrap_urls.push(addr);
                                }
                            }
                        }
                    }
                    b"message" => {
                        let kind = attr_opt(e, b"kind").unwrap_or_default();
                        let raw_text = attr_opt(e, b"text").unwrap_or_default();
                        let text = sanitize_server_message(&raw_text);
                        let url = attr_opt(e, b"url").unwrap_or_default();
                        if !text.is_empty() {
                            messages.push(Message { kind, text, url });
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Start(ref e)) => {
                if e.name().as_ref() == b"manifest" {
                    force_reauth_ts = attr_opt(e, b"force_reauth_ts")
                        .and_then(|s| s.parse::<i64>().ok())
                        .unwrap_or(0);
                    if let Some(cd) = attr_opt(e, b"check_domain") {
                        if !cd.is_empty() { check_domain = cd; }
                    }
                    if let Some(dq) = attr_opt(e, b"check_dns_query") {
                        if !dq.is_empty() { check_dns_query = dq; }
                    }
                    if let Some(cp) = attr_opt(e, b"check_protocol") {
                        if !cp.is_empty() { check_protocol = cp; }
                    }
                    // Eddie (Service.cs:924-932): read RSA key from manifest
                    // for use in subsequent API calls. This allows AirVPN to
                    // rotate their RSA key without requiring a software update.
                    // The manifest itself was received encrypted with the current
                    // (provider.json) key, so the new key is authenticated.
                    if let Some(modulus) = attr_opt(e, b"auth_rsa_modulus") {
                        if !modulus.is_empty() {
                            debug!("Manifest contains auth_rsa_modulus ({} chars)", modulus.len());
                            rsa_modulus = Some(modulus);
                        }
                    }
                    if let Some(exponent) = attr_opt(e, b"auth_rsa_exponent") {
                        if !exponent.is_empty() {
                            debug!("Manifest contains auth_rsa_exponent ({} chars)", exponent.len());
                            rsa_exponent = Some(exponent);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let servers: Vec<Server> = raw_servers.into_iter().map(|raw| resolve_server(raw, &groups)).collect();
    Ok(Manifest { servers, modes, bootstrap_urls, force_reauth_ts, messages, check_domain, check_dns_query, check_protocol, rsa_modulus, rsa_exponent })
}

pub fn parse_user(xml: &str) -> anyhow::Result<UserInfo> {
    check_api_error(xml)?;
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut user: Option<UserInfo> = None;
    let mut in_user = false;
    let mut login = String::new();
    let mut wg_public_key = String::new();
    let mut keys: Vec<WireGuardKey> = Vec::new();
    loop {
        match reader.read_event() {
            Err(e) => bail!("XML parse error at position {}: {e}", reader.error_position()),
            Ok(Event::Eof) => break,
            Ok(Event::Empty(ref e)) => {
                if e.name().as_ref() == b"key" && in_user {
                    let wg_ipv4 = attr_opt(e, b"wg_ipv4").unwrap_or_default();
                    let wg_ipv6 = attr_opt(e, b"wg_ipv6").unwrap_or_default();
                    let wg_dns_ipv4 = attr_opt(e, b"wg_dns_ipv4").unwrap_or_default();
                    let wg_dns_ipv6 = attr_opt(e, b"wg_dns_ipv6").unwrap_or_default();
                    if !wg_ipv4.is_empty() { validate_ip(&wg_ipv4, "wg_ipv4")?; }
                    if !wg_ipv6.is_empty() { validate_ip(&wg_ipv6, "wg_ipv6")?; }
                    if !wg_dns_ipv4.is_empty() { validate_ip(&wg_dns_ipv4, "wg_dns_ipv4")?; }
                    if !wg_dns_ipv6.is_empty() { validate_ip(&wg_dns_ipv6, "wg_dns_ipv6")?; }
                    keys.push(WireGuardKey {
                        name: attr_opt(e, b"name").unwrap_or_default(),
                        wg_private_key: Zeroizing::new(attr_opt(e, b"wg_private_key").unwrap_or_default()),
                        wg_ipv4, wg_ipv6,
                        wg_dns_ipv4, wg_dns_ipv6,
                        wg_preshared: Zeroizing::new(attr_opt(e, b"wg_preshared").unwrap_or_default()),
                    });
                }
            }
            Ok(Event::Start(ref e)) => {
                match e.name().as_ref() {
                    b"user" => {
                        in_user = true;
                        if let Some(msg) = attr_opt(e, b"message") {
                            if !msg.is_empty() {
                                bail!("server message: {}", sanitize_server_message(&msg));
                            }
                        }
                        login = attr_opt(e, b"login").unwrap_or_default();
                        wg_public_key = attr_opt(e, b"wg_public_key").unwrap_or_default();
                        keys.clear();
                    }
                    b"key" if in_user => {
                        let wg_ipv4 = attr_opt(e, b"wg_ipv4").unwrap_or_default();
                        let wg_ipv6 = attr_opt(e, b"wg_ipv6").unwrap_or_default();
                        let wg_dns_ipv4 = attr_opt(e, b"wg_dns_ipv4").unwrap_or_default();
                        let wg_dns_ipv6 = attr_opt(e, b"wg_dns_ipv6").unwrap_or_default();
                        if !wg_ipv4.is_empty() { validate_ip(&wg_ipv4, "wg_ipv4")?; }
                        if !wg_ipv6.is_empty() { validate_ip(&wg_ipv6, "wg_ipv6")?; }
                        if !wg_dns_ipv4.is_empty() { validate_ip(&wg_dns_ipv4, "wg_dns_ipv4")?; }
                        if !wg_dns_ipv6.is_empty() { validate_ip(&wg_dns_ipv6, "wg_dns_ipv6")?; }
                        keys.push(WireGuardKey {
                            name: attr_opt(e, b"name").unwrap_or_default(),
                            wg_private_key: Zeroizing::new(attr_opt(e, b"wg_private_key").unwrap_or_default()),
                            wg_ipv4, wg_ipv6,
                            wg_dns_ipv4, wg_dns_ipv6,
                            wg_preshared: Zeroizing::new(attr_opt(e, b"wg_preshared").unwrap_or_default()),
                        });
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                if e.name().as_ref() == b"user" && in_user {
                    in_user = false;
                    user = Some(UserInfo {
                        login: std::mem::take(&mut login),
                        wg_public_key: std::mem::take(&mut wg_public_key),
                        keys: std::mem::take(&mut keys),
                    });
                }
            }
            _ => {}
        }
    }
    user.context("user response missing <user> element")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest time="1708444800" next_update="3600" force_reauth_ts="0" check_domain="airvpn.org" check_dns_query="{hash}.airvpn.org">
  <rsa><RSAParameters><Modulus>base64modulus==</Modulus><Exponent>AQAB</Exponent></RSAParameters></rsa>
  <servers>
    <server name="Alchiba" group="eu-it" ips_entry="185.32.12.1,185.32.12.2" ips_exit="185.32.12.10" country_code="IT" location="Milan" scorebase="0" bw="500000" bw_max="1000000" users="42" users_max="250" support_ipv4="true" support_ipv6="true" warning_open="" warning_closed="" />
  </servers>
  <servers_groups>
    <servers_group group="eu-it" ips_entry="185.32.12.1" ips_exit="185.32.12.10" country_code="IT" location="Milan" scorebase="0" bw="500000" bw_max="1000000" users="42" users_max="250" />
  </servers_groups>
  <modes>
    <mode title="WireGuard UDP 1637" type="wireguard" protocol="UDP" port="1637" entry_index="0" />
    <mode title="OpenVPN UDP 443" type="openvpn" protocol="UDP" port="443" entry_index="0" />
  </modes>
  <urls>
    <url address="https://api.airvpn.org/api/" />
  </urls>
</manifest>"#;

    #[test]
    fn test_parse_basic_manifest() {
        let m = parse_manifest(FULL_MANIFEST).unwrap();
        assert_eq!(m.servers.len(), 1);
        assert_eq!(m.modes.len(), 1);
        assert_eq!(m.bootstrap_urls.len(), 1);
        assert_eq!(m.check_domain, "airvpn.org");
    }

    #[test]
    fn test_parse_manifest_error() {
        let err = parse_manifest(r#"<manifest error="Invalid credentials"/>"#).unwrap_err();
        assert!(err.to_string().contains("Invalid credentials"));
    }

    #[test]
    fn test_parse_user() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="testuser" wg_public_key="PubKey==">
  <keys>
    <key name="default" wg_private_key="Priv==" wg_ipv4="10.0.0.1" wg_ipv6="fd00::1" wg_dns_ipv4="10.0.0.1" wg_dns_ipv6="fd00::53" wg_preshared="" />
  </keys>
</user>"#;
        let user = parse_user(xml).unwrap();
        assert_eq!(user.login, "testuser");
        assert_eq!(user.keys.len(), 1);
    }

    #[test]
    fn test_sanitize_strips_html() {
        assert_eq!(sanitize_server_message("<b>bold</b> text"), "bold text");
    }

    #[test]
    fn test_sanitize_truncates() {
        let long = "x".repeat(300);
        let result = sanitize_server_message(&long);
        assert!(result.len() <= 203);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn test_validate_ip_valid() {
        assert!(validate_ip("10.128.0.1", "test").is_ok());
        assert!(validate_ip("fd7d:76ee:3c49:9950::1", "test").is_ok());
    }

    #[test]
    fn test_validate_ip_invalid() {
        assert!(validate_ip("not-an-ip", "test").is_err());
    }

    #[test]
    fn test_parse_user_invalid_dns_ip() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="t" wg_public_key="P">
  <keys><key name="d" wg_private_key="P" wg_ipv4="10.0.0.1" wg_ipv6="fd00::1" wg_dns_ipv4="not-an-ip" wg_dns_ipv6="fd00::53" wg_preshared="" /></keys>
</user>"#;
        assert!(parse_user(xml).is_err());
    }

    #[test]
    fn test_manifest_size_limit() {
        let huge = "x".repeat(MAX_MANIFEST_SIZE + 1);
        assert!(parse_manifest(&huge).is_err());
    }

    #[test]
    fn test_split_ips() {
        assert_eq!(split_ips("1.2.3.4,5.6.7.8"), vec!["1.2.3.4", "5.6.7.8"]);
        assert_eq!(split_ips("1.2.3.4;5.6.7.8"), vec!["1.2.3.4", "5.6.7.8"]);
        assert!(split_ips("").is_empty());
    }

    #[test]
    fn test_split_ips_filters_invalid() {
        // Valid IPs kept, invalid ones dropped
        assert_eq!(split_ips("1.2.3.4,not-an-ip,5.6.7.8"), vec!["1.2.3.4", "5.6.7.8"]);
        // All invalid -> empty
        assert!(split_ips("garbage,also-bad").is_empty());
        // IPv6 works
        assert_eq!(split_ips("fd00::1,1.2.3.4"), vec!["fd00::1", "1.2.3.4"]);
    }

    #[test]
    fn test_message_text_sanitized() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest time="0" next_update="0" force_reauth_ts="0" check_domain="" check_dns_query="">
  <message kind="info" text="Hello &lt;script&gt;alert(1)&lt;/script&gt; world" url="" />
</manifest>"#;
        let m = parse_manifest(xml).unwrap();
        assert_eq!(m.messages.len(), 1);
        // HTML tags should be stripped by sanitize_server_message
        assert!(!m.messages[0].text.contains("<script>"));
        assert!(m.messages[0].text.contains("Hello"));
        assert!(m.messages[0].text.contains("world"));
    }

    #[test]
    fn test_parse_bool() {
        assert!(parse_bool("true"));
        assert!(parse_bool("1"));
        assert!(!parse_bool("false"));
        assert!(!parse_bool(""));
    }

    #[test]
    fn test_parse_user_with_message_bails() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="t" wg_public_key="P" message="expired"><keys /></user>"#;
        assert!(parse_user(xml).is_err());
    }

    #[test]
    fn test_check_api_error_empty() {
        assert!(check_api_error("").is_ok());
        assert!(check_api_error(r#"<manifest error="" />"#).is_ok());
    }

    // --- Server name validation ---

    #[test]
    fn test_validate_server_name_valid() {
        assert!(validate_server_name("Alchiba").is_ok());
        assert!(validate_server_name("server-1").is_ok());
        assert!(validate_server_name("server_2").is_ok());
        assert!(validate_server_name("A").is_ok());
    }

    #[test]
    fn test_validate_server_name_invalid() {
        assert!(validate_server_name("").is_err());
        assert!(validate_server_name("server.evil.com").is_err());
        assert!(validate_server_name("server name").is_err());
        assert!(validate_server_name("server/path").is_err());
        assert!(validate_server_name(&"a".repeat(65)).is_err());
    }

    #[test]
    fn test_manifest_rejects_bad_server_name() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest time="0" next_update="0" force_reauth_ts="0" check_domain="" check_dns_query="">
  <servers>
    <server name="evil.server.com" group="eu" ips_entry="1.2.3.4" ips_exit="1.2.3.5" />
  </servers>
</manifest>"#;
        assert!(parse_manifest(xml).is_err());
    }

    // --- Fix 5: wg_ipv4/wg_ipv6 validated at parse time ---

    #[test]
    fn test_parse_user_invalid_wg_ipv4() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="t" wg_public_key="P">
  <keys><key name="d" wg_private_key="P" wg_ipv4="not-an-ip" wg_ipv6="fd00::1" wg_dns_ipv4="10.0.0.1" wg_dns_ipv6="fd00::53" wg_preshared="" /></keys>
</user>"#;
        assert!(parse_user(xml).is_err());
    }

    #[test]
    fn test_parse_user_invalid_wg_ipv6() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="t" wg_public_key="P">
  <keys><key name="d" wg_private_key="P" wg_ipv4="10.0.0.1" wg_ipv6="not-an-ip" wg_dns_ipv4="10.0.0.1" wg_dns_ipv6="fd00::53" wg_preshared="" /></keys>
</user>"#;
        assert!(parse_user(xml).is_err());
    }

    #[test]
    fn test_parse_user_valid_wg_ips_with_cidr() {
        // wg_ipv4 often has /32 CIDR suffix -- validate_ip handles this
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="t" wg_public_key="P">
  <keys><key name="d" wg_private_key="P" wg_ipv4="10.0.0.1/32" wg_ipv6="fd00::1/128" wg_dns_ipv4="10.0.0.1" wg_dns_ipv6="fd00::53" wg_preshared="" /></keys>
</user>"#;
        assert!(parse_user(xml).is_ok());
    }
}
