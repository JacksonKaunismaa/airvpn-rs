//! Config and credential resolution using Eddie-compatible XML profile format.
//!
//! Resolution chain:
//! 1. CLI flags (highest priority)
//! 2. Saved profile file (`/etc/airvpn-rs/default.profile`, root-owned)
//! 3. Eddie profile (`~user/.config/eddie/default.profile`) as one-time import
//! 4. Interactive stdin prompt (lowest priority)
//!
//! Profile format matches Eddie: encrypted XML with `<option name="..." value="..." />`
//! elements. Our profile uses v2n (file permissions provide security since
//! the file is root:root 0600 in /etc/). Eddie's profile is read via the
//! appropriate format (v2n/v2s/v2p).
//!
//! Eddie reference: Storage.cs (Save/Load), ProfileOptions.cs (defaults)

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use log::{debug, info, warn};
use quick_xml::events::Event;
use quick_xml::reader::Reader;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::profile::{generate_id, load_profile, save_profile, ProfileFormat};

const PROFILE_PATH: &str = "/etc/airvpn-rs/default.profile";

/// Get the profile file path.
fn profile_path() -> PathBuf {
    PathBuf::from(PROFILE_PATH)
}

/// Get the Eddie profile path for the actual (non-root) user.
///
/// When running via sudo, we need the invoking user's home directory
/// (where Eddie stores its profile), not /root. `$SUDO_USER` gives us
/// the original username, and we look up their home via /etc/passwd.
fn eddie_profile_path() -> Option<PathBuf> {
    let home = if nix::unistd::getuid().is_root() {
        // Running as root (probably via sudo) — find the real user's home
        if let Some(sudo_user) = std::env::var_os("SUDO_USER") {
            let username = sudo_user.to_string_lossy().to_string();
            let user = nix::unistd::User::from_name(&username).ok()??;
            user.dir
        } else {
            // Running as root without sudo — no user Eddie profile to find
            return None;
        }
    } else {
        // Running as regular user
        std::env::var_os("HOME").map(PathBuf::from)?
    };

    let path = home.join(".config/eddie/default.profile");
    if path.exists() { Some(path) } else { None }
}

/// Find Eddie profile for a specific user by UID (for helper daemon use).
/// Resolves the user's home directory from /etc/passwd via the UID.
pub fn eddie_profile_path_for_uid(uid: u32) -> Option<PathBuf> {
    let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid)).ok()??;
    let path = user.dir.join(".config/eddie/default.profile");
    if path.exists() { Some(path) } else { None }
}

/// Warn if a profile uses v2n format on a non-root-owned file.
///
/// v2n uses a hardcoded password (no real encryption). This is fine for
/// root-owned files in /etc/ (file permissions are the security), but
/// insecure for user-owned files where any process running as that user
/// can decrypt the profile.
fn warn_if_insecure_v2n(path: &Path, format: ProfileFormat) {
    if format != ProfileFormat::V2N {
        return;
    }
    if let Ok(metadata) = std::fs::metadata(path) {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() == 0 {
            // Root-owned v2n is fine — file perms are the security
            debug!(
                "Profile {} uses v2n format (root-owned, secured by file permissions).",
                path.display()
            );
        } else {
            warn!(
                "Profile {} uses v2n format (no real encryption) and is owned by uid {}. \
                 Your credentials are readable by any process running as that user. \
                 Consider switching to 'Linux secret-tool' or 'Password' protection.",
                path.display(),
                metadata.uid()
            );
        }
    }
}

/// Expand `~` to the user's home directory.
///
/// When running as root (uid 0), uses /root instead of trusting `$HOME`.
#[cfg(test)]
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = if nix::unistd::getuid().is_root() {
            PathBuf::from("/root")
        } else if let Some(h) = std::env::var_os("HOME") {
            PathBuf::from(h)
        } else {
            return PathBuf::from(path);
        };
        return home.join(rest);
    }
    PathBuf::from(path)
}

/// SHA256 hex digest of a string (Eddie: Crypto.Manager.HashSHA256).
/// Used for `servers.last` which stores SHA256(server_name).
pub fn sha256_hex(input: &str) -> String {
    hex::encode(Sha256::digest(input.as_bytes()))
}

/// Reverse-lookup a servers.last SHA256 hash against server names.
/// Returns the matching server name, or None if no match.
pub fn reverse_server_hash(hash: &str, server_names: &[&str]) -> Option<String> {
    server_names
        .iter()
        .find(|name| sha256_hex(name) == hash)
        .map(|s| s.to_string())
}

// ---------------------------------------------------------------------------
// Profile XML parsing (Eddie: Storage.cs Save/Load)
// ---------------------------------------------------------------------------

/// Extract an XML attribute value with entity unescaping (e.g., `&amp;` → `&`).
///
/// Unlike `manifest::attr_opt` (which returns raw bytes), this properly
/// unescapes XML entities for profile values that may contain special characters.
fn attr_unescaped(e: &quick_xml::events::BytesStart<'_>, name: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == name {
            return attr.unescape_value().ok().map(|s| s.into_owned());
        }
    }
    None
}

/// Parse Eddie-format XML profile data into a HashMap of option name→value.
///
/// Expected format:
/// ```xml
/// <eddie>
///   <options>
///     <option name="login" value="..." />
///     <option name="servers.locklast" value="True" />
///   </options>
///   <providers>...</providers>  <!-- ignored -->
/// </eddie>
/// ```
fn parse_xml_options(data: &[u8]) -> Result<HashMap<String, String>> {
    let mut options = HashMap::new();
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);

    let mut in_options = false;
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if tag == "options" {
                    in_options = true;
                } else if tag == "option" && in_options {
                    let name = attr_unescaped(e, b"name");
                    let value = attr_unescaped(e, b"value");
                    if let (Some(n), Some(v)) = (name, value) {
                        options.insert(n, v);
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                let tag = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if tag == "options" {
                    in_options = false;
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(anyhow::anyhow!("XML parse error: {}", e)),
            _ => {}
        }
        buf.clear();
    }

    Ok(options)
}

/// Parse legacy JSON profile data (pre-XML migration) into options HashMap.
fn parse_json_options(data: &[u8]) -> Result<HashMap<String, String>> {
    let json: serde_json::Value =
        serde_json::from_slice(data).context("failed to parse profile JSON")?;
    let mut options = HashMap::new();

    if let Some(login) = json.get("login").and_then(|v| v.as_str()) {
        options.insert("login".to_string(), login.to_string());
    }
    if let Some(password) = json.get("password").and_then(|v| v.as_str()) {
        options.insert("password".to_string(), password.to_string());
    }

    Ok(options)
}

/// Serialize options HashMap to Eddie-format XML.
fn serialize_xml_options(options: &HashMap<String, String>) -> Vec<u8> {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<eddie>\n  <options>\n");
    // Sort keys for deterministic output
    let mut keys: Vec<&String> = options.keys().collect();
    keys.sort();
    for key in keys {
        let value = &options[key];
        // XML-escape name and value (minimal: & < > ")
        let name_esc = xml_escape(key);
        let value_esc = xml_escape(value);
        xml.push_str(&format!(
            "    <option name=\"{}\" value=\"{}\" />\n",
            name_esc, value_esc
        ));
    }
    xml.push_str("  </options>\n</eddie>\n");
    xml.into_bytes()
}

/// Minimal XML attribute value escaping.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Load all profile options from our profile, falling back to Eddie's profile.
///
/// Returns an empty HashMap if no profile exists (caller uses defaults).
pub fn load_profile_options() -> HashMap<String, String> {
    // Try our profile first (/etc/airvpn-rs/default.profile)
    let path = profile_path();
    match std::fs::metadata(&path) {
        Ok(_) => {
            match load_options_from_path(&path) {
                Ok(opts) => return opts,
                Err(e) => warn!("failed to load profile: {:#}", e),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // Can't read profile directory (non-root). The helper (root) will
            // handle credential resolution from its own profile.
            return HashMap::new();
        }
        Err(_) => {} // File doesn't exist, fall through to Eddie import
    }

    // Offer to import Eddie's profile (~user/.config/eddie/default.profile).
    // Only prompt if we don't have our own profile yet (i.e., first run).
    if let Some(eddie_path) = eddie_profile_path() {
        eprint!(
            "Eddie profile detected at {}. Import settings? [Y/n] ",
            eddie_path.display()
        );
        let mut answer = String::new();
        let import = match std::io::stdin().read_line(&mut answer) {
            Ok(_) => {
                let trimmed = answer.trim().to_lowercase();
                trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
            }
            Err(_) => false,
        };
        if import {
            match load_eddie_profile(&eddie_path) {
                Ok(opts) => {
                    eprintln!("Imported {} settings from Eddie profile.", opts.len());
                    // Save to our profile so we don't re-prompt next time.
                    if let Err(e) = save_options(&path, &opts) {
                        warn!("Could not save imported profile: {:#} (will re-prompt next time)", e);
                    }
                    return opts;
                }
                Err(e) => warn!("Could not import Eddie profile: {:#}", e),
            }
        } else {
            info!("Skipping Eddie profile import.");
        }
    }

    HashMap::new()
}

/// Load options from Eddie's profile, handling Eddie's v2s keyring format.
///
/// Eddie stores keyring passwords under attribute `"Eddie Profile" = "<profile_id>"`
/// instead of our `application=airvpn-rs, profile-id=<id>`.
pub fn load_eddie_profile(path: &Path) -> Result<HashMap<String, String>> {
    let password_provider = || {
        rpassword::prompt_password("Eddie profile password: ")
            .context("failed to read profile password from stdin")
    };

    let (format, _id, data) = crate::profile::load_profile_with_keyring(
        path,
        password_provider,
        crate::profile::eddie_keyring_read,
    )?;

    warn_if_insecure_v2n(path, format);

    let trimmed = data.iter().position(|&b| !b.is_ascii_whitespace());
    let is_xml = trimmed.is_some_and(|i| data[i] == b'<');

    if is_xml {
        parse_xml_options(&data)
    } else {
        parse_json_options(&data)
    }
}

/// Load Eddie profile using a specific UID for keyring access (helper daemon use).
/// Returns (options, is_v2n) where is_v2n indicates the profile uses fake encryption.
pub fn load_eddie_profile_for_uid(path: &Path, uid: u32) -> Result<(HashMap<String, String>, bool)> {
    let keyring_reader = move |id: &str| crate::profile::eddie_keyring_read_for_uid(id, uid);

    let (format, _id, data) = crate::profile::load_profile_with_keyring(
        path,
        || anyhow::bail!("Eddie profile requires a password (v2p format) — run sudo airvpn connect"),
        keyring_reader,
    )?;

    let is_v2n = format == crate::profile::ProfileFormat::V2N;
    warn_if_insecure_v2n(path, format);

    let trimmed = data.iter().position(|&b| !b.is_ascii_whitespace());
    let is_xml = trimmed.is_some_and(|i| data[i] == b'<');

    let opts = if is_xml {
        parse_xml_options(&data)?
    } else {
        parse_json_options(&data)?
    };
    Ok((opts, is_v2n))
}

/// Load options from a specific profile path.
fn load_options_from_path(path: &Path) -> Result<HashMap<String, String>> {
    let password_provider = || {
        rpassword::prompt_password("Profile password: ")
            .context("failed to read profile password from stdin")
    };

    let (format, _id, data) = load_profile(path, password_provider)?;

    warn_if_insecure_v2n(path, format);

    // Detect format: XML starts with '<' (possibly after BOM/whitespace)
    let trimmed = data.iter().position(|&b| !b.is_ascii_whitespace());
    let is_xml = trimmed.is_some_and(|i| data[i] == b'<');

    if is_xml {
        parse_xml_options(&data)
    } else {
        parse_json_options(&data)
    }
}

/// Save a single option to the profile (read-modify-write).
///
/// Loads existing options, patches the key, writes back as Eddie XML.
pub fn save_profile_option(key: &str, value: &str) -> Result<()> {
    let path = profile_path();

    // Load existing options (or start fresh)
    let mut options = if path.exists() {
        load_options_from_path(&path).unwrap_or_default()
    } else {
        HashMap::new()
    };

    options.insert(key.to_string(), value.to_string());
    save_options(&path, &options)
}

/// Save multiple options to the profile in a single read-modify-write cycle.
///
/// Unlike calling `save_profile_option` in a loop (which does N full
/// read-decrypt-modify-encrypt-write-rename cycles), this loads once,
/// patches all keys, and saves once — atomic and crash-safe.
pub fn save_profile_options(updates: &HashMap<String, String>) -> Result<()> {
    let path = profile_path();

    let mut options = if path.exists() {
        load_options_from_path(&path).unwrap_or_default()
    } else {
        HashMap::new()
    };

    for (key, value) in updates {
        options.insert(key.clone(), value.clone());
    }

    save_options(&path, &options)
}

/// Save credentials and optionally other options to the profile.
///
/// Preserves existing options (e.g., servers.last) while updating credentials.
pub fn save_credentials(username: &str, password: &str) -> Result<()> {
    let path = profile_path();

    // Load existing options to preserve non-credential fields
    let mut options = if path.exists() {
        load_options_from_path(&path).unwrap_or_default()
    } else {
        HashMap::new()
    };

    options.insert("login".to_string(), username.to_string());
    options.insert("password".to_string(), password.to_string());

    save_options(&path, &options)
}

/// Write options to profile as Eddie XML.
///
/// Always uses V2N format — the profile lives at /etc/airvpn-rs/ (root:root 0600),
/// so file permissions provide security. The user's keyring is not accessible
/// when running as root via sudo.
fn save_options(path: &Path, options: &HashMap<String, String>) -> Result<()> {
    let data = serialize_xml_options(options);

    // Reuse existing profile ID
    let id = if path.exists() {
        match load_profile(path, || Ok(String::new())) {
            Ok((_fmt, existing_id, _data)) => existing_id,
            Err(_) => generate_id(),
        }
    } else {
        generate_id()
    };

    save_profile(path, ProfileFormat::V2N, &id, &data, "")?;
    Ok(())
}

/// Resolve credentials from: CLI flags -> profile options -> stdin prompt.
///
/// Takes pre-loaded profile options to avoid redundant loading/prompting.
/// Returns `(username, password)` wrapped in `Zeroizing` for secure cleanup.
pub fn resolve_credentials(
    cli_username: Option<&str>,
    cli_password: Option<&str>,
    profile_options: &HashMap<String, String>,
) -> Result<(Zeroizing<String>, Zeroizing<String>)> {
    // Error if only one of username/password provided via CLI/stdin
    if cli_username.is_some() != cli_password.is_some() {
        bail!("--username and password (via --password-stdin or profile) must be provided together");
    }

    // 1. CLI flags take priority
    if let (Some(user), Some(pass)) = (cli_username, cli_password) {
        return Ok((Zeroizing::new(user.to_string()), Zeroizing::new(pass.to_string())));
    }

    // 2. Try credentials from profile options
    if let (Some(login), Some(password)) = (profile_options.get("login"), profile_options.get("password")) {
        if !login.is_empty() && !password.is_empty() {
            return Ok((Zeroizing::new(login.clone()), Zeroizing::new(password.clone())));
        }
    }

    // 3. Prompt on stdin
    use std::io::Write;
    print!("AirVPN username: ");
    std::io::stdout().flush().context("failed to flush stdout")?;
    let mut username = String::new();
    std::io::stdin()
        .read_line(&mut username)
        .context("failed to read username from stdin")?;
    let username = username.trim().to_string();
    if username.is_empty() {
        bail!("username cannot be empty");
    }

    let password =
        rpassword::prompt_password("AirVPN password: ").context("failed to read password from stdin")?;
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    Ok((Zeroizing::new(username), Zeroizing::new(password)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_from_cli_flags() {
        let (user, pass) = resolve_credentials(Some("alice"), Some("s3cret"), &HashMap::new()).unwrap();
        assert_eq!(&*user, "alice");
        assert_eq!(&*pass, "s3cret");
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/.config/airvpn-rs/default.profile");
        assert!(!expanded.to_str().unwrap().starts_with('~'));
        assert!(expanded
            .to_str()
            .unwrap()
            .ends_with(".config/airvpn-rs/default.profile"));
    }

    #[test]
    fn test_expand_tilde_no_tilde() {
        let expanded = expand_tilde("/tmp/test.profile");
        assert_eq!(expanded, PathBuf::from("/tmp/test.profile"));
    }

    #[test]
    fn test_expand_tilde_relative_path() {
        let expanded = expand_tilde("relative/path");
        assert_eq!(expanded, PathBuf::from("relative/path"));
    }

    #[test]
    fn test_expand_tilde_empty_string() {
        let expanded = expand_tilde("");
        assert_eq!(expanded, PathBuf::from(""));
    }

    #[test]
    fn test_expand_tilde_just_tilde_slash() {
        let expanded = expand_tilde("~/");
        assert!(!expanded.to_str().unwrap().starts_with('~'));
    }

    #[test]
    fn test_expand_tilde_bare_tilde() {
        let expanded = expand_tilde("~");
        assert_eq!(expanded, PathBuf::from("~"));
    }

    #[test]
    fn test_expand_tilde_nested_tilde() {
        let expanded = expand_tilde("/foo/~/bar");
        assert_eq!(expanded, PathBuf::from("/foo/~/bar"));
    }

    #[test]
    fn test_resolve_credentials_only_username_errors() {
        let result = resolve_credentials(Some("alice"), None, &HashMap::new());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("--username and password"),
            "should mention both flags are required"
        );
    }

    #[test]
    fn test_resolve_credentials_only_password_errors() {
        let result = resolve_credentials(None, Some("s3cret"), &HashMap::new());
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("--username and password"),
            "should mention both flags are required"
        );
    }

    // -------------------------------------------------------------------
    // XML parsing tests
    // -------------------------------------------------------------------

    #[test]
    fn test_parse_xml_options_basic() {
        let xml = br#"<?xml version="1.0" encoding="utf-8"?>
<eddie>
  <options>
    <option name="login" value="alice" />
    <option name="password" value="s3cret" />
    <option name="servers.locklast" value="True" />
  </options>
</eddie>"#;
        let opts = parse_xml_options(xml).unwrap();
        assert_eq!(opts.get("login").unwrap(), "alice");
        assert_eq!(opts.get("password").unwrap(), "s3cret");
        assert_eq!(opts.get("servers.locklast").unwrap(), "True");
    }

    #[test]
    fn test_parse_xml_options_ignores_providers() {
        let xml = br#"<eddie>
  <options>
    <option name="login" value="bob" />
  </options>
  <providers>
    <option name="should_be_ignored" value="yes" />
  </providers>
</eddie>"#;
        let opts = parse_xml_options(xml).unwrap();
        assert_eq!(opts.len(), 1);
        assert_eq!(opts.get("login").unwrap(), "bob");
    }

    #[test]
    fn test_parse_xml_options_empty() {
        let xml = b"<eddie><options></options></eddie>";
        let opts = parse_xml_options(xml).unwrap();
        assert!(opts.is_empty());
    }

    #[test]
    fn test_parse_json_options_legacy() {
        let json = br#"{"login":"alice","password":"pass123","remember":true}"#;
        let opts = parse_json_options(json).unwrap();
        assert_eq!(opts.get("login").unwrap(), "alice");
        assert_eq!(opts.get("password").unwrap(), "pass123");
        // "remember" is not mapped (not an Eddie option name)
        assert!(!opts.contains_key("remember"));
    }

    #[test]
    fn test_serialize_xml_options_roundtrip() {
        let mut options = HashMap::new();
        options.insert("login".to_string(), "alice".to_string());
        options.insert("password".to_string(), "s3cret".to_string());
        options.insert("servers.locklast".to_string(), "True".to_string());

        let xml = serialize_xml_options(&options);
        let parsed = parse_xml_options(&xml).unwrap();

        assert_eq!(parsed.get("login").unwrap(), "alice");
        assert_eq!(parsed.get("password").unwrap(), "s3cret");
        assert_eq!(parsed.get("servers.locklast").unwrap(), "True");
    }

    #[test]
    fn test_serialize_xml_options_escaping() {
        let mut options = HashMap::new();
        options.insert("key".to_string(), "value with \"quotes\" & <brackets>".to_string());

        let xml = serialize_xml_options(&options);
        let xml_str = String::from_utf8(xml.clone()).unwrap();
        assert!(xml_str.contains("&quot;"));
        assert!(xml_str.contains("&amp;"));
        assert!(xml_str.contains("&lt;"));
        assert!(xml_str.contains("&gt;"));

        // Roundtrip: quick-xml should unescape back
        let parsed = parse_xml_options(&xml).unwrap();
        assert_eq!(
            parsed.get("key").unwrap(),
            "value with \"quotes\" & <brackets>"
        );
    }

    #[test]
    fn test_sha256_hex_matches_eddie() {
        // Eddie: Crypto.Manager.HashSHA256("Carinae")
        // Verified from user's actual Eddie profile
        assert_eq!(
            sha256_hex("Carinae"),
            "600bb65180381071c7d4e7e6f472233b6d0caeaabddf5ca2690a978fb59111dc"
        );
    }

    #[test]
    fn test_reverse_server_hash() {
        let names = vec!["Achernar", "Carinae", "Geminorum"];
        let hash = sha256_hex("Carinae");
        assert_eq!(
            reverse_server_hash(&hash, &names),
            Some("Carinae".to_string())
        );
    }

    #[test]
    fn test_reverse_server_hash_not_found() {
        let names = vec!["Achernar", "Geminorum"];
        assert_eq!(reverse_server_hash("deadbeef", &names), None);
    }

}
