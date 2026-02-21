//! Profile storage matching Eddie's exact format (Storage.cs + AESThenHMAC.cs).
//!
//! File format: `[3-byte ASCII header][64-byte ASCII ID][AES-encrypted data]`
//!
//! Headers:
//! - `v2n` = no real encryption (uses `Constants.PasswordIfEmpty` as password)
//! - `v2s` = password stored in system keyring (libsecret/Secret Service)
//! - `v2p` = user-provided password
//!
//! The encrypted data uses Eddie's AESThenHMAC scheme:
//! - PBKDF2-HMAC-SHA1 key derivation (10000 iterations, 8-byte salts)
//! - AES-256-CBC encryption with PKCS7 padding
//! - HMAC-SHA256 authentication (Encrypt-then-MAC)
//!
//! Wire format of encrypted blob:
//! `[NotSecretPayload (40 bytes)][cryptSalt (8 bytes)][authSalt (8 bytes)][IV (16 bytes)][ciphertext][HMAC-SHA256 tag (32 bytes)]`
//!
//! Reference: Eddie src/Lib.Core/Storage.cs, src/Lib.Core/Crypto/AESThenHMAC.cs,
//!            src/Lib.Core/Crypto/Manager.cs, src/Lib.Core/Constants.cs

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::Sha256;
use std::path::Path;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

// ---------------------------------------------------------------------------
// Eddie constants (from Constants.cs)
// ---------------------------------------------------------------------------

/// Eddie's `Constants.NotSecretPayload` — prepended to the encrypted blob as non-secret payload.
/// Value: UTF-8 bytes of "4af85e84255b077ad890dba297e811b7d016add1"
const NOT_SECRET_PAYLOAD: &[u8] = b"4af85e84255b077ad890dba297e811b7d016add1";

/// Eddie's `Constants.PasswordIfEmpty` — used as password for v2n (no encryption) mode.
const PASSWORD_IF_EMPTY: &str = "e6552ddf3ac5c8755a82870d91273a63eab0da1e";

// ---------------------------------------------------------------------------
// AESThenHMAC parameters (from AESThenHMAC.cs)
// ---------------------------------------------------------------------------

const KEY_BIT_SIZE: usize = 256;
const BLOCK_BIT_SIZE: usize = 128;
const SALT_BIT_SIZE: usize = 64;
const PBKDF2_ITERATIONS: u32 = 10000;

const KEY_BYTE_SIZE: usize = KEY_BIT_SIZE / 8; // 32
const BLOCK_BYTE_SIZE: usize = BLOCK_BIT_SIZE / 8; // 16
const SALT_BYTE_SIZE: usize = SALT_BIT_SIZE / 8; // 8
const HMAC_TAG_SIZE: usize = 32; // SHA-256 output

// ---------------------------------------------------------------------------
// Profile format
// ---------------------------------------------------------------------------

const HEADER_LEN: usize = 3;
const ID_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileFormat {
    V2N,
    V2S,
    V2P,
}

impl ProfileFormat {
    fn header(&self) -> &'static [u8; 3] {
        match self {
            ProfileFormat::V2N => b"v2n",
            ProfileFormat::V2S => b"v2s",
            ProfileFormat::V2P => b"v2p",
        }
    }

    fn from_header(header: &[u8]) -> Result<Self> {
        match header {
            b"v2n" => Ok(ProfileFormat::V2N),
            b"v2s" => Ok(ProfileFormat::V2S),
            b"v2p" => Ok(ProfileFormat::V2P),
            _ => bail!(
                "unknown profile header: {:?}",
                std::str::from_utf8(header).unwrap_or("<invalid utf8>")
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// AESThenHMAC — Eddie-compatible Encrypt-then-MAC
// ---------------------------------------------------------------------------

/// Derive a key from password + salt using PBKDF2-HMAC-SHA1, matching Eddie's
/// `Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA1)`.
fn pbkdf2_derive_key(password: &str, salt: &[u8]) -> [u8; KEY_BYTE_SIZE] {
    let mut key = [0u8; KEY_BYTE_SIZE];
    pbkdf2::pbkdf2::<Hmac<Sha1>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key)
        .expect("HMAC can be initialized with any key length");
    key
}

/// Eddie's `SimpleEncrypt` — AES-256-CBC then HMAC-SHA256.
///
/// Wire format: `[nonSecretPayload][IV (16 bytes)][ciphertext][HMAC-SHA256 tag (32 bytes)]`
///
/// The HMAC is computed over `[nonSecretPayload][IV][ciphertext]`, then appended.
fn simple_encrypt(
    plaintext: &[u8],
    crypt_key: &[u8; KEY_BYTE_SIZE],
    auth_key: &[u8; KEY_BYTE_SIZE],
    non_secret_payload: &[u8],
) -> Vec<u8> {
    // Generate random IV
    let mut iv = [0u8; BLOCK_BYTE_SIZE];
    rand::thread_rng().fill_bytes(&mut iv);

    // AES-256-CBC encrypt with PKCS7 padding
    let ciphertext =
        Aes256CbcEnc::new(crypt_key.into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // Build authenticated message: [payload][IV][ciphertext]
    let mut message = Vec::with_capacity(
        non_secret_payload.len() + BLOCK_BYTE_SIZE + ciphertext.len() + HMAC_TAG_SIZE,
    );
    message.extend_from_slice(non_secret_payload);
    message.extend_from_slice(&iv);
    message.extend_from_slice(&ciphertext);

    // Compute HMAC-SHA256 over the message so far
    let mut mac =
        HmacSha256::new_from_slice(auth_key).expect("HMAC can be initialized with any key length");
    mac.update(&message);
    let tag = mac.finalize().into_bytes();

    // Append tag
    message.extend_from_slice(&tag);
    message
}

/// Eddie's `SimpleDecrypt` — verify HMAC-SHA256 then AES-256-CBC decrypt.
///
/// Returns `None` if authentication fails (constant-time comparison).
fn simple_decrypt(
    encrypted: &[u8],
    crypt_key: &[u8; KEY_BYTE_SIZE],
    auth_key: &[u8; KEY_BYTE_SIZE],
    non_secret_payload_length: usize,
) -> Option<Vec<u8>> {
    let iv_length = BLOCK_BYTE_SIZE;

    // Check minimum length
    if encrypted.len() < HMAC_TAG_SIZE + non_secret_payload_length + iv_length {
        return None;
    }

    // Compute expected HMAC over everything except the trailing tag
    let message_len = encrypted.len() - HMAC_TAG_SIZE;
    let mut mac =
        HmacSha256::new_from_slice(auth_key).expect("HMAC can be initialized with any key length");
    mac.update(&encrypted[..message_len]);
    let calc_tag = mac.finalize().into_bytes();

    // Grab the sent tag (last 32 bytes)
    let sent_tag = &encrypted[message_len..];

    // Constant-time comparison
    let mut compare = 0u8;
    for i in 0..HMAC_TAG_SIZE {
        compare |= sent_tag[i] ^ calc_tag[i];
    }
    if compare != 0 {
        return None;
    }

    // Extract IV from after the non-secret payload
    let iv_start = non_secret_payload_length;
    let mut iv = [0u8; BLOCK_BYTE_SIZE];
    iv.copy_from_slice(&encrypted[iv_start..iv_start + iv_length]);

    // Extract ciphertext (between IV and HMAC tag)
    let ct_start = iv_start + iv_length;
    let ct_end = message_len;
    let ciphertext = &encrypted[ct_start..ct_end];

    // Decrypt
    Aes256CbcDec::new(crypt_key.into(), &iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .ok()
}

/// Eddie's `SimpleEncryptWithPassword` — PBKDF2 key derivation then encrypt.
///
/// Creates the non-secret payload as: `[externalPayload][cryptSalt (8)][authSalt (8)]`
/// then calls `simple_encrypt`.
fn encrypt_with_password(plaintext: &[u8], password: &str, external_payload: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();

    // Generate random salts
    let mut crypt_salt = [0u8; SALT_BYTE_SIZE];
    rng.fill_bytes(&mut crypt_salt);

    let mut auth_salt = [0u8; SALT_BYTE_SIZE];
    rng.fill_bytes(&mut auth_salt);

    // Derive keys
    let crypt_key = pbkdf2_derive_key(password, &crypt_salt);
    let auth_key = pbkdf2_derive_key(password, &auth_salt);

    // Build combined non-secret payload: [externalPayload][cryptSalt][authSalt]
    let mut payload =
        Vec::with_capacity(external_payload.len() + SALT_BYTE_SIZE + SALT_BYTE_SIZE);
    payload.extend_from_slice(external_payload);
    payload.extend_from_slice(&crypt_salt);
    payload.extend_from_slice(&auth_salt);

    simple_encrypt(plaintext, &crypt_key, &auth_key, &payload)
}

/// Eddie's `SimpleDecryptWithPassword` — extract salts, derive keys, then decrypt.
///
/// Returns `None` if decryption/authentication fails.
fn decrypt_with_password(
    encrypted: &[u8],
    password: &str,
    external_payload_length: usize,
) -> Option<Vec<u8>> {
    if encrypted.len() < external_payload_length + SALT_BYTE_SIZE + SALT_BYTE_SIZE {
        return None;
    }

    // Extract salts from after the external payload
    let mut crypt_salt = [0u8; SALT_BYTE_SIZE];
    crypt_salt.copy_from_slice(
        &encrypted[external_payload_length..external_payload_length + SALT_BYTE_SIZE],
    );

    let mut auth_salt = [0u8; SALT_BYTE_SIZE];
    auth_salt.copy_from_slice(
        &encrypted[external_payload_length + SALT_BYTE_SIZE
            ..external_payload_length + SALT_BYTE_SIZE + SALT_BYTE_SIZE],
    );

    // Derive keys
    let crypt_key = pbkdf2_derive_key(password, &crypt_salt);
    let auth_key = pbkdf2_derive_key(password, &auth_salt);

    // Total non-secret payload length = external + both salts
    let total_payload_len = external_payload_length + SALT_BYTE_SIZE + SALT_BYTE_SIZE;
    simple_decrypt(encrypted, &crypt_key, &auth_key, total_payload_len)
}

// ---------------------------------------------------------------------------
// Eddie-compatible profile encrypt/decrypt (Manager.cs wrappers)
// ---------------------------------------------------------------------------

/// Encrypt profile data matching Eddie's `Crypto.Manager.WriteBytesEncrypted`.
///
/// Uses `Constants.NotSecretPayload` as the external non-secret payload.
fn profile_encrypt(data: &[u8], password: &str) -> Vec<u8> {
    encrypt_with_password(data, password, NOT_SECRET_PAYLOAD)
}

/// Decrypt profile data matching Eddie's `Crypto.Manager.ReadBytesEncrypted`.
///
/// Returns `None` if decryption fails (wrong password or corrupt data).
fn profile_decrypt(encrypted: &[u8], password: &str) -> Option<Vec<u8>> {
    decrypt_with_password(encrypted, password, NOT_SECRET_PAYLOAD.len())
}

// ---------------------------------------------------------------------------
// File I/O — Eddie's Storage.EncodeFormat / DecodeFormat
// ---------------------------------------------------------------------------

/// Save profile data to file in Eddie's format.
///
/// File format: `[3-byte header][64-byte ASCII ID][encrypted blob]`
pub fn save_profile(
    path: &Path,
    format: ProfileFormat,
    id: &str,
    data: &[u8],
    password: &str,
) -> Result<()> {
    if id.len() != ID_LEN {
        bail!("profile ID must be exactly {} ASCII characters, got {}", ID_LEN, id.len());
    }

    // Determine effective password
    let effective_password = match format {
        ProfileFormat::V2N => PASSWORD_IF_EMPTY.to_string(),
        ProfileFormat::V2S => {
            keyring_write(id, password)?;
            password.to_string()
        }
        ProfileFormat::V2P => password.to_string(),
    };

    let encrypted = profile_encrypt(data, &effective_password);

    // Build file: [header (3)][id (64)][encrypted]
    let mut file_data = Vec::with_capacity(HEADER_LEN + ID_LEN + encrypted.len());
    file_data.extend_from_slice(format.header());
    file_data.extend_from_slice(id.as_bytes());
    file_data.extend_from_slice(&encrypted);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create profile directory: {}", parent.display()))?;
    }

    // Write with correct permissions atomically (no world-readable window)
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to create profile: {}", path.display()))?;
        f.write_all(&file_data)
            .with_context(|| format!("failed to write profile: {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, &file_data)
            .with_context(|| format!("failed to write profile: {}", path.display()))?;
    }

    Ok(())
}

/// Load profile from file. Returns `(format, id, decrypted_data)`.
///
/// For V2P format, calls `password_provider` to get the decryption password.
/// For V2S, reads the password from the system keyring.
/// For V2N, uses the constant password.
pub fn load_profile(
    path: &Path,
    password_provider: impl Fn() -> Result<String>,
) -> Result<(ProfileFormat, String, Vec<u8>)> {
    let file_data = std::fs::read(path)
        .with_context(|| format!("failed to read profile: {}", path.display()))?;

    if file_data.len() < HEADER_LEN + ID_LEN {
        bail!("profile file too small: {} bytes", file_data.len());
    }

    // Parse header
    let format = ProfileFormat::from_header(&file_data[..HEADER_LEN])?;

    // Parse ID
    let id = std::str::from_utf8(&file_data[HEADER_LEN..HEADER_LEN + ID_LEN])
        .context("profile ID is not valid ASCII")?
        .to_string();

    // Extract encrypted blob
    let encrypted = &file_data[HEADER_LEN + ID_LEN..];

    // Determine password
    let password = match format {
        ProfileFormat::V2N => PASSWORD_IF_EMPTY.to_string(),
        ProfileFormat::V2S => {
            keyring_read(&id)?
                .context("keyring entry not found for this profile; cannot decrypt V2S profile")?
        }
        ProfileFormat::V2P => password_provider()?,
    };

    // Decrypt
    let decrypted = profile_decrypt(encrypted, &password)
        .context("profile decryption failed — wrong password or corrupt data")?;

    Ok((format, id, decrypted))
}

/// Default format: V2S if keyring is available, else V2N.
pub fn default_format() -> ProfileFormat {
    if keyring_available() {
        ProfileFormat::V2S
    } else {
        ProfileFormat::V2N
    }
}

// ---------------------------------------------------------------------------
// Generate random profile ID (64 hex chars, matching Eddie's RandomGenerator.GetRandomId64)
// ---------------------------------------------------------------------------

/// Generate a random 64-character hex ID, matching Eddie's `RandomGenerator.GetRandomId64()`.
pub fn generate_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Keyring operations (for V2S mode) — uses libsecret via Secret Service D-Bus API
// ---------------------------------------------------------------------------

/// Check if the system keyring (Secret Service) is available.
pub fn keyring_available() -> bool {
    // Try to connect to Secret Service. On systems without a keyring daemon
    // (e.g., headless servers, containers), this will fail.
    std::process::Command::new("dbus-send")
        .args([
            "--session",
            "--dest=org.freedesktop.secrets",
            "--type=method_call",
            "--print-reply",
            "/org/freedesktop/secrets",
            "org.freedesktop.DBus.Peer.Ping",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Read a password from the system keyring for the given profile ID.
pub fn keyring_read(id: &str) -> Result<Option<String>> {
    // Use secret-tool CLI which talks to Secret Service (libsecret)
    let output = std::process::Command::new("secret-tool")
        .args(["lookup", "application", "airvpn-rs", "profile-id", id])
        .output()
        .context("failed to run secret-tool for keyring lookup")?;

    if output.status.success() {
        let password = String::from_utf8(output.stdout)
            .context("keyring value is not valid UTF-8")?
            .trim_end()
            .to_string();
        if password.is_empty() {
            Ok(None)
        } else {
            Ok(Some(password))
        }
    } else {
        // secret-tool returns non-zero if key not found
        Ok(None)
    }
}

/// Write a password to the system keyring for the given profile ID.
pub fn keyring_write(id: &str, password: &str) -> Result<()> {
    use std::io::Write;

    let mut child = std::process::Command::new("secret-tool")
        .args([
            "store",
            "--label",
            "AirVPN-RS Profile",
            "application",
            "airvpn-rs",
            "profile-id",
            id,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("failed to run secret-tool for keyring store")?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(password.as_bytes())
            .context("failed to write password to secret-tool stdin")?;
    }

    let status = child.wait().context("failed to wait for secret-tool")?;
    if !status.success() {
        bail!("secret-tool store failed with exit code {:?}", status.code());
    }

    Ok(())
}

/// Delete a password from the system keyring for the given profile ID.
pub fn keyring_delete(id: &str) -> Result<()> {
    let status = std::process::Command::new("secret-tool")
        .args(["clear", "application", "airvpn-rs", "profile-id", id])
        .status()
        .context("failed to run secret-tool for keyring delete")?;

    if !status.success() {
        bail!(
            "secret-tool clear failed with exit code {:?}",
            status.code()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_v2n_roundtrip() {
        let data = br#"{"login":"testuser","password":"testpass","remember":true}"#;
        let id = generate_id();
        assert_eq!(id.len(), 64);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.profile");

        // Save with V2N (password is ignored, uses constant)
        save_profile(&path, ProfileFormat::V2N, &id, data, "").unwrap();

        // Load back — password_provider should not be called for V2N
        let (fmt, loaded_id, decrypted) =
            load_profile(&path, || bail!("should not be called")).unwrap();

        assert_eq!(fmt, ProfileFormat::V2N);
        assert_eq!(loaded_id, id);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_v2p_roundtrip() {
        let data = br#"{"login":"alice","password":"s3cret!","remember":true}"#;
        let id = generate_id();
        let user_password = "my-strong-passphrase-for-profile";

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.profile");

        // Save with V2P
        save_profile(&path, ProfileFormat::V2P, &id, data, user_password).unwrap();

        // Load back — provide the same password
        let (fmt, loaded_id, decrypted) =
            load_profile(&path, || Ok(user_password.to_string())).unwrap();

        assert_eq!(fmt, ProfileFormat::V2P);
        assert_eq!(loaded_id, id);
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_v2p_wrong_password_fails() {
        let data = b"secret data";
        let id = generate_id();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.profile");

        save_profile(&path, ProfileFormat::V2P, &id, data, "correct-password").unwrap();

        // Try loading with wrong password — should fail
        let result = load_profile(&path, || Ok("wrong-password".to_string()));
        assert!(result.is_err(), "decryption with wrong password should fail");
    }

    #[test]
    fn test_file_format_header() {
        let data = b"test";
        let id = generate_id();

        let dir = tempfile::tempdir().unwrap();

        // Test V2N header
        let path_n = dir.path().join("v2n.profile");
        save_profile(&path_n, ProfileFormat::V2N, &id, data, "").unwrap();
        let bytes_n = std::fs::read(&path_n).unwrap();
        assert_eq!(&bytes_n[..3], b"v2n");
        assert_eq!(
            std::str::from_utf8(&bytes_n[3..67]).unwrap(),
            id
        );

        // Test V2P header
        let path_p = dir.path().join("v2p.profile");
        save_profile(&path_p, ProfileFormat::V2P, &id, data, "pass").unwrap();
        let bytes_p = std::fs::read(&path_p).unwrap();
        assert_eq!(&bytes_p[..3], b"v2p");
        assert_eq!(
            std::str::from_utf8(&bytes_p[3..67]).unwrap(),
            id
        );
    }

    #[test]
    fn test_aes_then_hmac_roundtrip() {
        // Directly test the encrypt/decrypt cycle with known password
        let plaintext = b"Hello, Eddie compatibility!";
        let password = "test-password-12chars";

        let encrypted = encrypt_with_password(plaintext, password, NOT_SECRET_PAYLOAD);
        let decrypted = decrypt_with_password(&encrypted, password, NOT_SECRET_PAYLOAD.len());

        assert_eq!(decrypted.as_deref(), Some(plaintext.as_slice()));
    }

    #[test]
    fn test_aes_then_hmac_tampered_fails() {
        let plaintext = b"sensitive data";
        let password = "test-password-12chars";

        let mut encrypted = encrypt_with_password(plaintext, password, NOT_SECRET_PAYLOAD);

        // Tamper with the ciphertext (somewhere in the middle)
        let mid = encrypted.len() / 2;
        encrypted[mid] ^= 0xFF;

        let result = decrypt_with_password(&encrypted, password, NOT_SECRET_PAYLOAD.len());
        assert!(result.is_none(), "tampered ciphertext should fail HMAC verification");
    }

    #[test]
    fn test_encrypted_blob_structure() {
        // Verify the wire format matches Eddie's expected layout:
        // [NotSecretPayload (40)][cryptSalt (8)][authSalt (8)][IV (16)][ciphertext][HMAC (32)]
        let plaintext = b"test";
        let password = "test-password-12chars";

        let encrypted = encrypt_with_password(plaintext, password, NOT_SECRET_PAYLOAD);

        // Minimum size: 40 + 8 + 8 + 16 + 16 (one AES block) + 32 = 120
        assert!(
            encrypted.len() >= 40 + 8 + 8 + 16 + 16 + 32,
            "encrypted blob too small: {} bytes",
            encrypted.len()
        );

        // First 40 bytes should be the NotSecretPayload
        assert_eq!(&encrypted[..40], NOT_SECRET_PAYLOAD);

        // Total non-secret payload = 40 + 8 + 8 = 56 bytes (before IV)
        // After that comes IV (16), ciphertext, HMAC (32)
        // Ciphertext for 4 bytes with PKCS7 → 16 bytes (one block)
        let expected_len = 40 + 8 + 8 + 16 + 16 + 32;
        assert_eq!(encrypted.len(), expected_len);
    }

    #[test]
    fn test_generate_id_length() {
        let id = generate_id();
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_profile_format_from_header() {
        assert_eq!(ProfileFormat::from_header(b"v2n").unwrap(), ProfileFormat::V2N);
        assert_eq!(ProfileFormat::from_header(b"v2s").unwrap(), ProfileFormat::V2S);
        assert_eq!(ProfileFormat::from_header(b"v2p").unwrap(), ProfileFormat::V2P);
        assert!(ProfileFormat::from_header(b"v1n").is_err());
        assert!(ProfileFormat::from_header(b"xyz").is_err());
    }
}
