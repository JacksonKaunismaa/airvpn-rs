//! Crypto module matching Eddie's exact API envelope protocol.
//!
//! Eddie's protocol:
//! - `s` param = RSA-4096 encrypted session key envelope (AES key + IV in assoc format)
//! - `d` param = AES-256-CBC encrypted request data (params in assoc format)
//! - Response = AES-256-CBC encrypted XML, decrypted with the same session key
//!
//! Reference: Eddie src/Lib.Core/Providers/Service.cs FetchUrl()

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;

/// Re-export for api.rs to use when base64-encoding/decoding.
pub use base64::engine::general_purpose::STANDARD as BASE64;

// ---------------------------------------------------------------------------
// Assoc encoding — Eddie's key:value wire format
// ---------------------------------------------------------------------------

/// Encode string key-value pairs in Eddie's assoc format.
///
/// Format: `base64(utf8(key)):base64(utf8(value))\n` per entry.
/// Used for request parameters (the `d` payload before AES encryption).
///
/// Reference: Eddie Service.AssocToUtf8Bytes(Dictionary<string, string>)
pub fn assoc_encode_strings(params: &[(String, String)]) -> Vec<u8> {
    let mut output = String::new();
    for (k, v) in params {
        output.push_str(&B64.encode(k.as_bytes()));
        output.push(':');
        output.push_str(&B64.encode(v.as_bytes()));
        output.push('\n');
    }
    output.into_bytes()
}

/// Encode byte-valued key-value pairs in Eddie's assoc format.
///
/// Format: `base64(utf8(key)):base64(value)\n` per entry.
/// Used for the session key envelope (key + IV sent via RSA).
///
/// Reference: Eddie Service.AssocToUtf8Bytes(Dictionary<string, byte[]>)
pub fn assoc_encode_bytes(params: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = String::new();
    for (k, v) in params {
        output.push_str(&B64.encode(k.as_bytes()));
        output.push(':');
        output.push_str(&B64.encode(v));
        output.push('\n');
    }
    output.into_bytes()
}

// ---------------------------------------------------------------------------
// AES-256-CBC with PKCS7 padding
// ---------------------------------------------------------------------------

/// AES-256-CBC encrypt with PKCS7 padding.
///
/// Matches .NET `Aes.Create()` defaults:
/// - Mode: CBC
/// - Padding: PKCS7
/// - KeySize: 256 (32 bytes)
/// - BlockSize: 128 (16 bytes)
///
/// Reference: Eddie Service.FetchUrl() — `aes.CreateEncryptor()`
pub fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Vec<u8> {
    Aes256CbcEnc::new(key.into(), iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext)
}

/// AES-256-CBC decrypt with PKCS7 unpadding.
///
/// Reference: Eddie Service.FetchUrl() — `aes.CreateDecryptor()`
pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<Vec<u8>> {
    Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-CBC decryption failed: {}", e))
}

// ---------------------------------------------------------------------------
// RSA-4096 PKCS#1 v1.5
// ---------------------------------------------------------------------------

/// Build an RSA public key from base64-encoded modulus and exponent.
///
/// Eddie stores these in the manifest as `auth_rsa_modulus` and `auth_rsa_exponent`,
/// both base64-encoded big-endian unsigned integers.
///
/// Reference: Eddie Service.FetchUrl() — `RSAParameters` construction
pub fn build_rsa_public_key(modulus_b64: &str, exponent_b64: &str) -> Result<RsaPublicKey> {
    let n_bytes = B64
        .decode(modulus_b64)
        .context("failed to decode RSA modulus from base64")?;
    let e_bytes = B64
        .decode(exponent_b64)
        .context("failed to decode RSA exponent from base64")?;

    let n = BigUint::from_bytes_be(&n_bytes);
    let e = BigUint::from_bytes_be(&e_bytes);

    RsaPublicKey::new(n, e).context("failed to construct RSA public key")
}

/// RSA-encrypt with PKCS#1 v1.5 padding.
///
/// Eddie uses `RSACryptoServiceProvider.Encrypt(data, false)` where `false` means
/// PKCS#1 v1.5 (NOT OAEP). This is critical — OAEP would produce ciphertext the
/// server cannot decrypt.
///
/// Reference: Eddie Service.FetchUrl() — `csp.Encrypt(AssocToUtf8Bytes(assocParamS), false)`
pub fn rsa_encrypt(public_key: &RsaPublicKey, plaintext: &[u8]) -> Result<Vec<u8>> {
    let mut rng = rand::thread_rng();
    public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, plaintext)
        .context("RSA PKCS1v15 encryption failed")
}

// ---------------------------------------------------------------------------
// Envelope construction
// ---------------------------------------------------------------------------

/// Session key material returned alongside the envelope for response decryption.
/// Key and IV are wrapped in `Zeroizing` to ensure they are zeroed on drop.
pub struct SessionKey {
    pub key: Zeroizing<[u8; 32]>,
    pub iv: Zeroizing<[u8; 16]>,
}

/// Build the encrypted API envelope matching Eddie's FetchUrl() protocol.
///
/// Returns `(s_b64, d_b64, session_key)` where:
/// - `s_b64`: base64(RSA-encrypt(assoc("key"=aes_key, "iv"=aes_iv)))
/// - `d_b64`: base64(AES-CBC-encrypt(assoc(params)))
/// - `session_key`: the raw AES key+IV needed to decrypt the server response
///
/// Reference: Eddie src/Lib.Core/Providers/Service.cs FetchUrl()
pub fn build_envelope(
    public_key: &RsaPublicKey,
    params: &[(String, String)],
) -> Result<(String, String, SessionKey)> {
    // 1. Generate random AES-256 key (32 bytes) + IV (16 bytes)
    let mut key = Zeroizing::new([0u8; 32]);
    let mut iv = Zeroizing::new([0u8; 16]);
    rand::thread_rng().fill_bytes(&mut *key);
    rand::thread_rng().fill_bytes(&mut *iv);

    // 2. Build session key envelope: assoc with "key" and "iv"
    let session_assoc = assoc_encode_bytes(&[("key", &key[..]), ("iv", &iv[..])]);

    // 3. RSA-encrypt the envelope
    let s_encrypted = rsa_encrypt(public_key, &session_assoc)?;
    let s_b64 = B64.encode(&s_encrypted);

    // 4. Build request data: assoc-encode all params
    let d_plaintext = assoc_encode_strings(params);

    // 5. AES-CBC encrypt the request data
    let d_encrypted = aes_cbc_encrypt(&d_plaintext, &*key, &*iv);
    let d_b64 = B64.encode(&d_encrypted);

    Ok((s_b64, d_b64, SessionKey { key, iv }))
}

// ---------------------------------------------------------------------------
// Response decryption
// ---------------------------------------------------------------------------

/// Decrypt the server's AES-CBC encrypted response body.
///
/// The server responds with raw AES-CBC ciphertext (not base64).
/// Decrypted content is UTF-8 XML.
///
/// Reference: Eddie Service.FetchUrl() — response decryption block
pub fn decrypt_response(body: &[u8], key: &[u8; 32], iv: &[u8; 16]) -> Result<String> {
    let plaintext = aes_cbc_decrypt(body, key, iv).context("failed to decrypt API response")?;
    String::from_utf8(plaintext).context("decrypted response is not valid UTF-8")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::traits::PublicKeyParts;

    #[test]
    fn test_assoc_string_serialization() {
        let params = vec![
            ("login".to_string(), "testuser".to_string()),
            ("password".to_string(), "testpass".to_string()),
        ];
        let encoded = assoc_encode_strings(&params);
        let text = std::str::from_utf8(&encoded).expect("assoc output should be valid UTF-8");

        // Each line is base64(key):base64(value)\n
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);

        for (i, (key, value)) in params.iter().enumerate() {
            let parts: Vec<&str> = lines[i].splitn(2, ':').collect();
            assert_eq!(parts.len(), 2, "line should have exactly one colon separator");

            let decoded_key = B64.decode(parts[0]).expect("key should be valid base64");
            let decoded_value = B64.decode(parts[1]).expect("value should be valid base64");

            assert_eq!(
                std::str::from_utf8(&decoded_key).unwrap(),
                key,
                "round-trip key mismatch"
            );
            assert_eq!(
                std::str::from_utf8(&decoded_value).unwrap(),
                value,
                "round-trip value mismatch"
            );
        }
    }

    #[test]
    fn test_aes_cbc_round_trip() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext = b"Hello, AirVPN API! This is a test message.";

        let ciphertext = aes_cbc_encrypt(plaintext, &key, &iv);
        let decrypted = aes_cbc_decrypt(&ciphertext, &key, &iv).expect("decryption should succeed");

        assert_eq!(&decrypted, plaintext, "round-trip plaintext mismatch");
    }

    #[test]
    fn test_aes_cbc_pkcs7_padding() {
        let key: [u8; 32] = [0xAA; 32];
        let iv: [u8; 16] = [0xBB; 16];

        // 13 bytes — not block-aligned (block size = 16)
        let plaintext = b"Hello, World!";
        assert_eq!(plaintext.len(), 13);

        let ciphertext = aes_cbc_encrypt(plaintext, &key, &iv);

        // PKCS7 pads to next block boundary: ceil(13/16)*16 = 16
        assert_eq!(
            ciphertext.len() % 16,
            0,
            "ciphertext must be block-aligned"
        );
        assert_eq!(ciphertext.len(), 16, "13 bytes should pad to one 16-byte block");

        let decrypted = aes_cbc_decrypt(&ciphertext, &key, &iv).expect("decryption should succeed");
        assert_eq!(&decrypted, plaintext, "round-trip plaintext mismatch");

        // Also test exact block-size input (16 bytes) — PKCS7 adds a full padding block
        let plaintext_16 = b"0123456789abcdef";
        assert_eq!(plaintext_16.len(), 16);
        let ct_16 = aes_cbc_encrypt(plaintext_16, &key, &iv);
        assert_eq!(ct_16.len(), 32, "16-byte input should produce 32-byte ciphertext with PKCS7");
        let dec_16 = aes_cbc_decrypt(&ct_16, &key, &iv).expect("decryption should succeed");
        assert_eq!(&dec_16, plaintext_16);
    }

    /// Shared RSA-4096 test keypair (generated once, reused across tests).
    /// Key generation is expensive in debug mode (~55s), so we cache it.
    struct TestRsaKeypair {
        public_key: RsaPublicKey,
        modulus_b64: String,
        exponent_b64: String,
    }

    static TEST_RSA: std::sync::LazyLock<TestRsaKeypair> = std::sync::LazyLock::new(|| {
        use rsa::RsaPrivateKey;
        let mut rng = rand::thread_rng();
        let private_key =
            RsaPrivateKey::new(&mut rng, 4096).expect("should generate RSA-4096 key");
        let public_key = RsaPublicKey::from(&private_key);
        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();
        TestRsaKeypair {
            modulus_b64: B64.encode(&n_bytes),
            exponent_b64: B64.encode(&e_bytes),
            public_key,
        }
    });

    #[test]
    fn test_rsa_public_key_construction() {
        let kp = &*TEST_RSA;

        // Round-trip: reconstruct from base64
        let reconstructed = build_rsa_public_key(&kp.modulus_b64, &kp.exponent_b64)
            .expect("should build RSA key from base64 modulus+exponent");

        // Verify it's a 4096-bit key (512 bytes)
        assert_eq!(
            reconstructed.size(),
            512,
            "RSA-4096 key should have 512-byte modulus"
        );
    }

    #[test]
    fn test_rsa_encrypt_produces_correct_length() {
        let kp = &*TEST_RSA;

        let plaintext = b"test data for RSA encryption";
        let ciphertext =
            rsa_encrypt(&kp.public_key, plaintext).expect("RSA encryption should succeed");

        // RSA-4096 produces 512-byte ciphertext (4096 bits / 8)
        assert_eq!(
            ciphertext.len(),
            512,
            "RSA-4096 ciphertext should be 512 bytes"
        );
    }

    #[test]
    fn test_build_envelope_format() {
        let kp = &*TEST_RSA;
        let key = build_rsa_public_key(&kp.modulus_b64, &kp.exponent_b64)
            .expect("should build RSA key");

        let params = vec![
            ("login".to_string(), "testuser".to_string()),
            ("password".to_string(), "testpass".to_string()),
        ];

        let (s_b64, d_b64, session) =
            build_envelope(&key, &params).expect("build_envelope should succeed");

        // Both s and d should be valid base64
        let s_bytes = B64
            .decode(&s_b64)
            .expect("s param should be valid base64");
        let d_bytes = B64
            .decode(&d_b64)
            .expect("d param should be valid base64");

        // s should be RSA-4096 ciphertext (512 bytes)
        assert_eq!(s_bytes.len(), 512, "s should be 512-byte RSA ciphertext");

        // d should be AES-CBC ciphertext (block-aligned)
        assert_eq!(
            d_bytes.len() % 16,
            0,
            "d should be block-aligned AES ciphertext"
        );

        // Decrypt d back with the session key and verify it contains our params
        let d_decrypted =
            aes_cbc_decrypt(&d_bytes, &session.key, &session.iv).expect("d should decrypt");
        let d_text = std::str::from_utf8(&d_decrypted).expect("decrypted d should be UTF-8");

        // Verify it's the assoc-encoded params
        let expected = assoc_encode_strings(&params);
        let expected_text = std::str::from_utf8(&expected).unwrap();
        assert_eq!(d_text, expected_text, "decrypted d should match assoc-encoded params");
    }
}
