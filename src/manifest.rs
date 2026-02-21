use std::collections::HashMap;

use anyhow::{bail, Context};
use quick_xml::events::Event;
use quick_xml::reader::Reader;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

pub struct Manifest {
    pub servers: Vec<Server>,
    pub modes: Vec<Mode>,
    pub bootstrap_urls: Vec<String>,
}

// UserInfo and WireGuardKey are parsed separately via parse_user() from the act=user response.

#[derive(Debug)]
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

pub struct Mode {
    pub title: String,
    pub protocol: String,
    pub port: u16,
    pub entry_index: usize,
}

pub struct UserInfo {
    pub login: String,
    pub wg_public_key: String,
    pub keys: Vec<WireGuardKey>,
}

pub struct WireGuardKey {
    pub name: String,
    pub wg_private_key: String,
    pub wg_ipv4: String,
    pub wg_ipv6: String,
    pub wg_dns_ipv4: String,
    pub wg_dns_ipv6: String,
    pub wg_preshared: String,
}

// ---------------------------------------------------------------------------
// Intermediate structs for collecting group attributes
// ---------------------------------------------------------------------------

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

/// Raw attributes read from a `<server>` element before group inheritance.
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Get a decoded attribute value from an XML element. Returns None if absent.
fn attr_opt(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == name {
            return String::from_utf8(attr.value.to_vec()).ok();
        }
    }
    None
}

/// Get a required attribute, returning an error if absent.
fn attr_req(e: &quick_xml::events::BytesStart<'_>, name: &str) -> anyhow::Result<String> {
    attr_opt(e, name.as_bytes())
        .with_context(|| format!("missing required attribute '{name}' on <{}>", elem_name(e)))
}

fn elem_name(e: &quick_xml::events::BytesStart<'_>) -> String {
    String::from_utf8_lossy(e.name().as_ref()).into_owned()
}

/// Split a semicolon-separated IP list into a Vec, filtering empty strings.
fn split_ips(s: &str) -> Vec<String> {
    s.split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_ascii_lowercase().as_str(), "true" | "1" | "yes")
}

fn parse_i64(s: &str) -> i64 {
    s.parse().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Resolve a server attribute with group fallback (mirrors Eddie's
// XmlGetServerAttribute: try server first, fall back to group).
// ---------------------------------------------------------------------------

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
        scorebase: parse_i64(&scorebase),
        bandwidth: parse_i64(&bw),
        bandwidth_max: parse_i64(&bw_max),
        users: parse_i64(&users),
        users_max: parse_i64(&users_max),
        support_ipv4: parse_bool(&support_ipv4),
        support_ipv6: parse_bool(&support_ipv6),
        warning_open,
        warning_closed,
    }
}

// ---------------------------------------------------------------------------
// Main parser
// ---------------------------------------------------------------------------

pub fn parse_manifest(xml: &str) -> anyhow::Result<Manifest> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    let mut groups: HashMap<String, ServerGroupAttrs> = HashMap::new();
    let mut raw_servers: Vec<RawServerAttrs> = Vec::new();
    let mut modes: Vec<Mode> = Vec::new();
    let mut bootstrap_urls: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Err(e) => bail!("XML parse error at position {}: {e}", reader.error_position()),
            Ok(Event::Eof) => break,

            // ---------- Empty elements (<tag ... />) ----------
            Ok(Event::Empty(ref e)) => {
                match e.name().as_ref() {
                    b"server" => {
                        let name = attr_req(e, "name")?;
                        let group = attr_opt(e, b"group").unwrap_or_default();
                        raw_servers.push(RawServerAttrs {
                            name,
                            group,
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
                        // Only keep WireGuard modes
                        if mode_type == "wireguard" {
                            modes.push(Mode {
                                title: attr_opt(e, b"title").unwrap_or_default(),
                                protocol: attr_opt(e, b"protocol").unwrap_or_default(),
                                port: attr_opt(e, b"port")
                                    .unwrap_or_default()
                                    .parse()
                                    .unwrap_or(0),
                                entry_index: attr_opt(e, b"entry_index")
                                    .unwrap_or_default()
                                    .parse()
                                    .unwrap_or(0),
                            });
                        }
                    }
                    b"url" => {
                        if let Some(addr) = attr_opt(e, b"address") {
                            if !addr.is_empty() {
                                bootstrap_urls.push(addr);
                            }
                        }
                    }
                    _ => {}
                }
            }

            // ---------- Start / End elements — nothing to track ----------
            Ok(Event::Start(_)) | Ok(Event::End(_)) => {}
            _ => {}
        }
    }

    // Resolve server attributes with group inheritance
    let servers: Vec<Server> = raw_servers
        .into_iter()
        .map(|raw| resolve_server(raw, &groups))
        .collect();

    Ok(Manifest {
        servers,
        modes,
        bootstrap_urls,
    })
}

// ---------------------------------------------------------------------------
// User parser (act=user response)
// ---------------------------------------------------------------------------

/// Parse the `act=user` API response into a [`UserInfo`].
///
/// The root element is `<user login="..." wg_public_key="...">` with
/// `<keys><key .../></keys>` children containing WireGuard device keys.
pub fn parse_user(xml: &str) -> anyhow::Result<UserInfo> {
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
                    keys.push(WireGuardKey {
                        name: attr_opt(e, b"name").unwrap_or_default(),
                        wg_private_key: attr_opt(e, b"wg_private_key").unwrap_or_default(),
                        wg_ipv4: attr_opt(e, b"wg_ipv4").unwrap_or_default(),
                        wg_ipv6: attr_opt(e, b"wg_ipv6").unwrap_or_default(),
                        wg_dns_ipv4: attr_opt(e, b"wg_dns_ipv4").unwrap_or_default(),
                        wg_dns_ipv6: attr_opt(e, b"wg_dns_ipv6").unwrap_or_default(),
                        wg_preshared: attr_opt(e, b"wg_preshared").unwrap_or_default(),
                    });
                }
            }

            Ok(Event::Start(ref e)) => {
                match e.name().as_ref() {
                    b"user" => {
                        in_user = true;
                        login = attr_opt(e, b"login").unwrap_or_default();
                        wg_public_key = attr_opt(e, b"wg_public_key").unwrap_or_default();
                        keys.clear();
                    }
                    // Handle <key> as a Start element too (in case it has children)
                    b"key" if in_user => {
                        keys.push(WireGuardKey {
                            name: attr_opt(e, b"name").unwrap_or_default(),
                            wg_private_key: attr_opt(e, b"wg_private_key").unwrap_or_default(),
                            wg_ipv4: attr_opt(e, b"wg_ipv4").unwrap_or_default(),
                            wg_ipv6: attr_opt(e, b"wg_ipv6").unwrap_or_default(),
                            wg_dns_ipv4: attr_opt(e, b"wg_dns_ipv4").unwrap_or_default(),
                            wg_dns_ipv6: attr_opt(e, b"wg_dns_ipv6").unwrap_or_default(),
                            wg_preshared: attr_opt(e, b"wg_preshared").unwrap_or_default(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest time="1708444800" next_update="3600" force_reauth_ts="0">
  <rsa><RSAParameters><Modulus>base64modulus==</Modulus><Exponent>AQAB</Exponent></RSAParameters></rsa>

  <servers>
    <server name="Alchiba" group="eu-it"
            ips_entry="185.32.12.1;185.32.12.2" ips_exit="185.32.12.10"
            country_code="IT" location="Milan"
            scorebase="0" bw="500000" bw_max="1000000"
            users="42" users_max="250"
            support_ipv4="true" support_ipv6="true"
            warning_open="" warning_closed="" />
    <server name="Castor" group="eu-nl"
            ips_entry="31.171.152.9" ips_exit="31.171.152.100"
            country_code="NL" location="Amsterdam"
            scorebase="10" bw="750000" bw_max="2000000"
            users="100" users_max="500"
            support_ipv4="true" support_ipv6="false"
            warning_open="Maintenance scheduled" warning_closed="" />
  </servers>

  <servers_groups>
    <servers_group group="eu-it"
                   ips_entry="185.32.12.1" ips_exit="185.32.12.10"
                   country_code="IT" location="Milan"
                   scorebase="0" bw="500000" bw_max="1000000"
                   users="42" users_max="250" />
    <servers_group group="eu-nl"
                   ips_entry="31.171.152.9" ips_exit="31.171.152.100"
                   country_code="NL" location="Amsterdam"
                   scorebase="10" bw="750000" bw_max="2000000"
                   users="100" users_max="500" />
  </servers_groups>

  <modes>
    <mode title="WireGuard UDP 1637" type="wireguard"
          protocol="UDP" port="1637" entry_index="0" />
    <mode title="OpenVPN UDP 443" type="openvpn"
          protocol="UDP" port="443" entry_index="0" />
    <mode title="OpenVPN TCP 443" type="openvpn"
          protocol="TCP" port="443" entry_index="0" />
  </modes>

  <urls>
    <url address="http://eddie.website/api/" />
    <url address="http://185.60.40.11:8080/" />
  </urls>
</manifest>"#;

    #[test]
    fn test_parse_basic_manifest() {
        let manifest = parse_manifest(FULL_MANIFEST).expect("failed to parse manifest");

        // --- Servers ---
        assert_eq!(manifest.servers.len(), 2);

        let alchiba = &manifest.servers[0];
        assert_eq!(alchiba.name, "Alchiba");
        assert_eq!(alchiba.group, "eu-it");
        assert_eq!(alchiba.ips_entry, vec!["185.32.12.1", "185.32.12.2"]);
        assert_eq!(alchiba.ips_exit, vec!["185.32.12.10"]);
        assert_eq!(alchiba.country_code, "IT");
        assert_eq!(alchiba.location, "Milan");
        assert_eq!(alchiba.scorebase, 0);
        assert_eq!(alchiba.bandwidth, 500_000);
        assert_eq!(alchiba.bandwidth_max, 1_000_000);
        assert_eq!(alchiba.users, 42);
        assert_eq!(alchiba.users_max, 250);
        assert!(alchiba.support_ipv4);
        assert!(alchiba.support_ipv6);
        assert_eq!(alchiba.warning_open, "");
        assert_eq!(alchiba.warning_closed, "");

        let castor = &manifest.servers[1];
        assert_eq!(castor.name, "Castor");
        assert_eq!(castor.group, "eu-nl");
        assert_eq!(castor.country_code, "NL");
        assert_eq!(castor.location, "Amsterdam");
        assert_eq!(castor.scorebase, 10);
        assert_eq!(castor.bandwidth, 750_000);
        assert_eq!(castor.bandwidth_max, 2_000_000);
        assert_eq!(castor.users, 100);
        assert_eq!(castor.users_max, 500);
        assert!(castor.support_ipv4);
        assert!(!castor.support_ipv6);
        assert_eq!(castor.warning_open, "Maintenance scheduled");

        // --- Modes: only WireGuard kept ---
        assert_eq!(manifest.modes.len(), 1);
        let wg_mode = &manifest.modes[0];
        assert_eq!(wg_mode.title, "WireGuard UDP 1637");
        assert_eq!(wg_mode.protocol, "UDP");
        assert_eq!(wg_mode.port, 1637);
        assert_eq!(wg_mode.entry_index, 0);

        // --- Bootstrap URLs ---
        assert_eq!(manifest.bootstrap_urls.len(), 2);
        assert_eq!(manifest.bootstrap_urls[0], "http://eddie.website/api/");
        assert_eq!(manifest.bootstrap_urls[1], "http://185.60.40.11:8080/");
    }

    #[test]
    fn test_server_group_inheritance() {
        // Server "Mizar" is missing country_code, location, bw, bw_max — should
        // inherit from its group "eu-de".
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest time="1708444800">
  <servers>
    <server name="Mizar" group="eu-de"
            ips_entry="91.207.56.1" ips_exit="91.207.56.10"
            scorebase="5"
            users="30" users_max="200"
            support_ipv4="true" support_ipv6="true"
            warning_open="" warning_closed="" />
  </servers>

  <servers_groups>
    <servers_group group="eu-de"
                   ips_entry="91.207.56.1" ips_exit="91.207.56.10"
                   country_code="DE" location="Frankfurt"
                   scorebase="0" bw="600000" bw_max="1500000"
                   users="30" users_max="200" />
  </servers_groups>

  <modes>
    <mode title="WireGuard UDP 1637" type="wireguard"
          protocol="UDP" port="1637" entry_index="0" />
  </modes>

  <urls />
</manifest>"#;

        let manifest = parse_manifest(xml).expect("failed to parse manifest");
        assert_eq!(manifest.servers.len(), 1);

        let mizar = &manifest.servers[0];
        assert_eq!(mizar.name, "Mizar");
        // Inherited from group:
        assert_eq!(mizar.country_code, "DE");
        assert_eq!(mizar.location, "Frankfurt");
        assert_eq!(mizar.bandwidth, 600_000);
        assert_eq!(mizar.bandwidth_max, 1_500_000);
        // Kept from server element:
        assert_eq!(mizar.scorebase, 5);
        assert_eq!(mizar.users, 30);
        assert_eq!(mizar.users_max, 200);
        assert!(mizar.support_ipv4);
        assert!(mizar.support_ipv6);
    }

    #[test]
    fn test_ips_entry_semicolon_split() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<manifest time="1708444800">
  <servers>
    <server name="Vega" group="us-east"
            ips_entry="1.2.3.4;5.6.7.8" ips_exit="9.10.11.12;13.14.15.16"
            country_code="US" location="New York"
            scorebase="0" bw="1000000" bw_max="5000000"
            users="10" users_max="100"
            support_ipv4="true" support_ipv6="false"
            warning_open="" warning_closed="" />
  </servers>

  <servers_groups />
  <modes>
    <mode title="WireGuard UDP 1637" type="wireguard"
          protocol="UDP" port="1637" entry_index="0" />
  </modes>
  <urls />
</manifest>"#;

        let manifest = parse_manifest(xml).expect("failed to parse manifest");
        let vega = &manifest.servers[0];
        assert_eq!(vega.ips_entry, vec!["1.2.3.4", "5.6.7.8"]);
        assert_eq!(vega.ips_exit, vec!["9.10.11.12", "13.14.15.16"]);
    }

    #[test]
    fn test_parse_user() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="testuser" wg_public_key="PublicKeyBase64==">
  <keys>
    <key name="default"
         wg_private_key="PrivateKeyBase64=="
         wg_ipv4="10.128.0.42"
         wg_ipv6="fd7d:76ee:3c49:9950::42"
         wg_dns_ipv4="10.128.0.1"
         wg_dns_ipv6="fd7d:76ee:3c49:9950::1"
         wg_preshared="PresharedKeyBase64==" />
  </keys>
</user>"#;

        let user = parse_user(xml).expect("failed to parse user");
        assert_eq!(user.login, "testuser");
        assert_eq!(user.wg_public_key, "PublicKeyBase64==");
        assert_eq!(user.keys.len(), 1);

        let key = &user.keys[0];
        assert_eq!(key.name, "default");
        assert_eq!(key.wg_private_key, "PrivateKeyBase64==");
        assert_eq!(key.wg_ipv4, "10.128.0.42");
        assert_eq!(key.wg_ipv6, "fd7d:76ee:3c49:9950::42");
        assert_eq!(key.wg_dns_ipv4, "10.128.0.1");
        assert_eq!(key.wg_dns_ipv6, "fd7d:76ee:3c49:9950::1");
        assert_eq!(key.wg_preshared, "PresharedKeyBase64==");
    }

    #[test]
    fn test_parse_user_multiple_keys() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<user login="multi" wg_public_key="PubMulti==">
  <keys>
    <key name="laptop"
         wg_private_key="PrivLaptop=="
         wg_ipv4="10.128.0.1" wg_ipv6="fd00::1"
         wg_dns_ipv4="10.128.0.1" wg_dns_ipv6="fd00::53"
         wg_preshared="PSK1==" />
    <key name="phone"
         wg_private_key="PrivPhone=="
         wg_ipv4="10.128.0.2" wg_ipv6="fd00::2"
         wg_dns_ipv4="10.128.0.1" wg_dns_ipv6="fd00::53"
         wg_preshared="PSK2==" />
  </keys>
</user>"#;

        let user = parse_user(xml).expect("failed to parse user");
        assert_eq!(user.login, "multi");
        assert_eq!(user.keys.len(), 2);
        assert_eq!(user.keys[0].name, "laptop");
        assert_eq!(user.keys[1].name, "phone");
    }
}
