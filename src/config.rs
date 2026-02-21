//! Config and credential resolution.
//!
//! Resolution chain:
//! 1. CLI flags (highest priority)
//! 2. Saved profile file
//! 3. Interactive stdin prompt (lowest priority)

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use crate::profile::{default_format, generate_id, load_profile, save_profile, ProfileFormat};

const PROFILE_PATH: &str = "~/.config/airvpn-rs/default.profile";

/// Expand `~` to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(path)
}

/// Get the expanded profile file path.
fn profile_path() -> PathBuf {
    expand_tilde(PROFILE_PATH)
}

/// Resolve credentials from: CLI flags -> saved profile -> stdin prompt.
///
/// Returns `(username, password)`.
pub fn resolve_credentials(
    cli_username: Option<&str>,
    cli_password: Option<&str>,
) -> Result<(String, String)> {
    // Error if only one CLI flag provided
    if cli_username.is_some() != cli_password.is_some() {
        bail!("both --username and --password must be provided together");
    }

    // 1. CLI flags take priority
    if let (Some(user), Some(pass)) = (cli_username, cli_password) {
        return Ok((user.to_string(), pass.to_string()));
    }

    // 2. Try loading from saved profile
    let path = profile_path();
    if path.exists() {
        let password_provider = || {
            rpassword::prompt_password("Profile password: ")
                .context("failed to read profile password from stdin")
        };

        match load_profile(&path, password_provider) {
            Ok((_format, _id, data)) => {
                let profile: serde_json::Value = serde_json::from_slice(&data)
                    .context("failed to parse profile JSON")?;

                let login = profile
                    .get("login")
                    .and_then(|v| v.as_str())
                    .context("profile missing 'login' field")?
                    .to_string();

                let password = profile
                    .get("password")
                    .and_then(|v| v.as_str())
                    .context("profile missing 'password' field")?
                    .to_string();

                return Ok((login, password));
            }
            Err(e) => {
                eprintln!("warning: failed to load profile: {:#}", e);
                // Fall through to stdin prompt
            }
        }
    }

    // 3. Prompt on stdin
    use std::io::Write;
    print!("AirVPN username: ");
    std::io::stdout().flush().context("failed to flush stdout")?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username).context("failed to read username from stdin")?;
    let username = username.trim().to_string();
    if username.is_empty() {
        bail!("username cannot be empty");
    }

    let password = rpassword::prompt_password("AirVPN password: ")
        .context("failed to read password from stdin")?;
    if password.is_empty() {
        bail!("password cannot be empty");
    }

    Ok((username, password))
}

/// Save credentials to profile (respecting the default format).
pub fn save_credentials(username: &str, password: &str) -> Result<()> {
    let profile_data = serde_json::json!({
        "login": username,
        "password": password,
        "remember": true,
    });
    let data = serde_json::to_vec(&profile_data).context("failed to serialize profile data")?;

    let path = profile_path();
    let format = default_format();

    // Reuse existing profile ID to avoid orphaning keyring entries
    let id = if path.exists() {
        match crate::profile::load_profile(&path, || Ok(String::new())) {
            Ok((_fmt, existing_id, _data)) => existing_id,
            Err(_) => generate_id(),
        }
    } else {
        generate_id()
    };

    // For V2S, generate a random password for the keyring
    // For V2N, password is ignored (uses constant)
    // For V2P, we'd need a user-provided password — but save_credentials uses default format
    let profile_password = match format {
        ProfileFormat::V2S => {
            // Generate a random password to store in keyring
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
            hex::encode(bytes)
        }
        ProfileFormat::V2N => String::new(), // Will be replaced by constant
        ProfileFormat::V2P => {
            // Shouldn't happen via save_credentials (default_format returns V2S or V2N)
            bail!("V2P format requires explicit password — use save_profile directly");
        }
    };

    save_profile(&path, format, &id, &data, &profile_password)?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_from_cli_flags() {
        let (user, pass) = resolve_credentials(Some("alice"), Some("s3cret")).unwrap();
        assert_eq!(user, "alice");
        assert_eq!(pass, "s3cret");
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/.config/airvpn-rs/default.profile");
        // Should not start with ~ anymore
        assert!(!expanded.to_str().unwrap().starts_with('~'));
        assert!(expanded.to_str().unwrap().ends_with(".config/airvpn-rs/default.profile"));
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
        // "~/" should expand to home dir
        let expanded = expand_tilde("~/");
        assert!(!expanded.to_str().unwrap().starts_with('~'));
    }

    #[test]
    fn test_expand_tilde_bare_tilde() {
        // Just "~" without "/" does NOT match the strip_prefix("~/") pattern
        // so it should be returned as-is
        let expanded = expand_tilde("~");
        assert_eq!(expanded, PathBuf::from("~"));
    }

    #[test]
    fn test_expand_tilde_nested_tilde() {
        // Tilde not at start should be left alone
        let expanded = expand_tilde("/foo/~/bar");
        assert_eq!(expanded, PathBuf::from("/foo/~/bar"));
    }

    #[test]
    fn test_expand_tilde_deep_path() {
        let expanded = expand_tilde("~/a/b/c/d/e.txt");
        assert!(expanded.to_str().unwrap().ends_with("a/b/c/d/e.txt"));
        assert!(!expanded.to_str().unwrap().starts_with('~'));
    }

    // -------------------------------------------------------------------
    // resolve_credentials with partial flags should error
    // -------------------------------------------------------------------

    #[test]
    fn test_resolve_credentials_only_username_errors() {
        let result = resolve_credentials(Some("alice"), None);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("both --username and --password"),
            "should mention both flags are required"
        );
    }

    #[test]
    fn test_resolve_credentials_only_password_errors() {
        let result = resolve_credentials(None, Some("s3cret"));
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("both --username and --password"),
            "should mention both flags are required"
        );
    }

    #[test]
    fn test_resolve_credentials_both_cli_flags() {
        let (user, pass) = resolve_credentials(Some("bob"), Some("pass123")).unwrap();
        assert_eq!(user, "bob");
        assert_eq!(pass, "pass123");
    }

    #[test]
    fn test_expand_tilde_home_set() {
        // Ensure expand_tilde produces a path that contains the HOME dir
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() {
            let expanded = expand_tilde("~/.config/test");
            assert!(
                expanded.to_str().unwrap().starts_with(&home),
                "expanded path should start with HOME: {}",
                expanded.display()
            );
        }
    }
}
