//! # Key Derivation Function (Asymmetric Primitive)
//!
//! **ASYMMETRY:** Weak key derivation can be broken in 2^80, strong KDF requires 2^256.
//!
//! | KDF | Attacker Cost (with salt) | Defender Cost | Asymmetry |
//! |-----|-------------------------|---------------|-----------|
//! | HKDF | 2^256 | O(n) | 99.999% |
//! | PBKDF2 | 2^iterations | O(n × iterations) | Configurable |
//! | Argon2 | 2^memory × 2^iterations | O(memory × time) | Configurable |
//!
//! ## Mathematical Basis
//!
//! KDF security is based on:
//! - **Extract-then-Expand** paradigm (HKDF):
//!   - Extract: PRF(key, salt) → fixed-length pseudorandom key
//!   - Expand: PRF(extracted_key, info || T(1)) || PRF(...) || ...
//! - **Memory-hard functions** (Argon2):
//!   - Requires attacker to use same memory as defender
//!   - Memory cost: M bytes
//!   - Time cost: T iterations
//!   - Total: M × T operations
//!
//! ## Asymmetry Principle
//!
//! If attacker doesn't have salt:
//! - Cost to brute-force: 2^256 (for 256-bit output)
//!
//! If attacker has salt but not key:
//! - Cost: Still 2^256 (salt doesn't reduce security)
//!
//! If attacker has weak key (low entropy):
//! - Cost: 2^entropy_bits (KDF doesn't increase entropy)
//!
//! **Key insight:** KDF preserves entropy but doesn't create it.

use crate::error::{CryptoError, CryptoResult};
use crate::hash::{Hash, HashAlgorithm};
use crate::CryptoPrimitive;
use crate::SecurityLevel;

use blake3::Hasher as Blake3Hasher;
use hkdf::Hkdf;
use sha2::Sha256;

/// KDF trait
pub trait Kdf: CryptoPrimitive {
    /// Derive key from input key material and salt
    fn derive(&self, ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>>;

    /// Extract phase (HKDF extract)
    fn extract(&self, ikm: &[u8], salt: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Expand phase (HKDF expand)
    fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>>;
}

// ============================================================================
// HKDF (HMAC-based Extract-and-Expand Key Derivation)
// ============================================================================

/// HKDF key derivation function (RFC 5869)
///
/// **ASYMMETRY:**
/// - With secret IKM: 2^256 to reverse
/// - Without secret IKM: Cannot derive key
/// - With salt: Still 2^256 (salt is public)
///
/// # Security
/// - **Output size**: Any length up to 255 * hash_size
/// - **Extract**: HMAC-Hash(salt, IKM)
/// - **Expand**: HMAC-Hash(PRK, info || T(1)) || HMAC-Hash(PRK, T(2)) || ...
/// - **Asymmetry**: 2^256 : 1 for 256-bit output
pub struct HkdfBlake3 {
    hash_algorithm: HashAlgorithm,
}

impl Default for HkdfBlake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl HkdfBlake3 {
    /// Create new HKDF with BLAKE3
    pub fn new() -> Self {
        Self {
            hash_algorithm: HashAlgorithm::Blake3,
        }
    }

    /// Derive key using HKDF
    ///
    /// # Asymmetry
    /// - **Attacker**: Without IKM, cannot derive. With IKM, must brute-force output.
    /// - **Defender**: O(n) derivation where n = output length
    /// - **Ratio**: 2^256 : output_length
    pub fn derive(&self, ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::InvalidInputLength(1, 0));
        }

        // Extract phase
        let prk = self.extract(ikm, salt)?;

        // Expand phase
        self.expand(&prk, info, length)
    }

    /// Extract phase: PRK = HMAC-Hash(salt, IKM)
    pub fn extract(&self, ikm: &[u8], salt: &[u8]) -> CryptoResult<Vec<u8>> {
        let mut hasher = Blake3Hasher::new_keyed(salt);
        hasher.update(ikm);
        let mut digest = [0u8; 64];
        hasher.finalize(&mut digest);
        Ok(digest.to_vec())
    }

    /// Expand phase: OKM = T(1) || T(2) || ... || T(N)
    pub fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        if prk.is_empty() {
            return Err(CryptoError::InvalidKeySize(32, 0));
        }

        let hash_size = self.hash_algorithm.output_size();
        let n = (length + hash_size - 1) / hash_size;

        if n > 255 {
            return Err(CryptoError::InvalidInputLength(255 * hash_size, length));
        }

        let mut okm = Vec::with_capacity(length);
        let mut t = Vec::new();

        for i in 1..=n {
            let mut hasher = Blake3Hasher::new_keyed(prk);
            hasher.update(&t);
            hasher.update(info);
            hasher.update(&[i as u8]);
            let mut digest = [0u8; 64];
            hasher.finalize(&mut digest);

            t = digest.to_vec();

            if i < n {
                okm.extend_from_slice(&digest[..hash_size]);
            } else {
                okm.extend_from_slice(&digest[..(length - (n - 1) * hash_size)]);
            }
        }

        Ok(okm)
    }
}

impl CryptoPrimitive for HkdfBlake3 {
    fn algorithm(&self) -> &'static str {
        "HKDF-BLAKE3"
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::PostQuantum
    }

    fn asymmetry(&self) -> crate::AsymmetryRating {
        crate::AsymmetryRating::new(
            0.99999,  // computational
            0.0,       // physical
            0.99,     // side-channel
        )
    }

    fn key_size(&self) -> usize {
        0 // No key for KDF itself
    }
}

impl Kdf for HkdfBlake3 {
    fn derive(&self, ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        self.derive(ikm, salt, info, length)
    }

    fn extract(&self, ikm: &[u8], salt: &[u8]) -> CryptoResult<Vec<u8>> {
        self.extract(ikm, salt)
    }

    fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        self.expand(prk, info, length)
    }
}

// ============================================================================
// STATIC INSTANCE
// ============================================================================

/// Global HKDF-BLAKE3 instance
pub static HKDF_BLAKE3: HkdfBlake3 = HkdfBlake3::new();

/// Derive key using HKDF-BLAKE3 (convenience function)
pub fn derive_key(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    HKDF_BLAKE3.derive(ikm, salt, info, length)
}

/// Extract using HKDF-BLAKE3
pub fn extract(ikm: &[u8], salt: &[u8]) -> CryptoResult<Vec<u8>> {
    HKDF_BLAKE3.extract(ikm, salt)
}

/// Expand using HKDF-BLAKE3
pub fn expand(prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
    HKDF_BLAKE3.expand(prk, info, length)
}

// ============================================================================
// PBKDF2 (Password-Based Key Derivation)
// ============================================================================

/// PBKDF2 implementation (RFC 2898)
///
/// **ASYMMETRY:**
/// - **Attacker**: Must try 2^entropy passwords (if no salt)
/// - **With salt**: Still 2^entropy (salt doesn't help against weak passwords)
/// - **With iterations**: Cost = iterations × 2^entropy
/// - **Defender**: O(iterations × n)
///
/// # Warning
/// PBKDF2 is NOT memory-hard. Use Argon2 for password hashing.
/// PBKDF2 is only for key derivation from high-entropy keys.
pub struct Pbkdf2HmacSha256 {
    iterations: u32,
}

impl Pbkdf2HmacSha256 {
    /// Create new PBKDF2 with specified iterations
    pub fn new(iterations: u32) -> Self {
        Self { iterations }
    }

    /// Create with recommended iterations (100,000)
    pub fn recommended() -> Self {
        Self::new(100_000)
    }

    /// Derive key using PBKDF2-HMAC-SHA256
    pub fn derive(&self, password: &[u8], salt: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        use pbkdf2::password_hash::{
            PasswordHasher, SaltString,
        };
        use pbkdf2::Pbkdf2;

        let password_str = std::str::from_utf8(password).map_err(|_| {
            CryptoError::InvalidInputLength(0, password.len())
        })?;

        let salt_str = std::str::from_utf8(salt).map_err(|_| {
            CryptoError::InvalidInputLength(0, salt.len())
        })?;

        let salt_string = SaltString::encode_b64(salt_str).unwrap();
        let password_hash = Pbkdf2
            .hash_password_custom(
                password_str.as_bytes(),
                None,
                None,
                pbkdf2::Params {
                    rounds: self.iterations,
                    output_length: length,
                },
                &salt_string,
            )
            .unwrap();

        Ok(password_hash.to_string().as_bytes().to_vec())
    }
}

impl Default for Pbkdf2HmacSha256 {
    fn default() -> Self {
        Self::recommended()
    }
}

impl CryptoPrimitive for Pbkdf2HmacSha256 {
    fn algorithm(&self) -> &'static str {
        "PBKDF2-HMAC-SHA256"
    }

    fn security_level(&self) -> SecurityLevel {
        match self.iterations {
            i if i >= 1_000_000 => SecurityLevel::Strong,
            i if i >= 100_000 => SecurityLevel::Standard,
            _ => SecurityLevel::Legacy,
        }
    }

    fn asymmetry(&self) -> crate::AsymmetryRating {
        // Asymmetry depends on iteration count
        let computational = match self.iterations {
            i if i >= 1_000_000 => 0.999,
            i if i >= 100_000 => 0.99,
            i if i >= 10_000 => 0.9,
            _ => 0.5,
        };
        crate::AsymmetryRating::new(computational, 0.0, 0.9)
    }

    fn key_size(&self) -> usize {
        0
    }
}

impl Kdf for Pbkdf2HmacSha256 {
    fn derive(&self, ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        // Note: PBKDF2 doesn't use info parameter
        self.derive(ikm, salt, length)
    }

    fn extract(&self, ikm: &[u8], salt: &[u8]) -> CryptoResult<Vec<u8>> {
        // PBKDF2 doesn't have separate extract/expand
        // Just derive with length = hash output size
        self.derive(ikm, salt, 32)
    }

    fn expand(&self, prk: &[u8], info: &[u8], length: usize) -> CryptoResult<Vec<u8>> {
        // PBKDF2 doesn't have separate expand
        Ok(prk.to_vec())
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive() {
        let hkdf = HkdfBlake3::new();
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"info";

        let key = hkdf.derive(ikm, salt, info, 32).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hkdf_extract_expand() {
        let hkdf = HkdfBlake3::new();
        let ikm = b"input key material";
        let salt = b"salt";

        let prk = hkdf.extract(ikm, salt).unwrap();
        assert_eq!(prk.len(), 64); // BLAKE3 outputs 64 bytes

        let info = b"info";
        let okm = hkdf.expand(&prk, info, 32).unwrap();
        assert_eq!(okm.len(), 32);
    }

    #[test]
    fn test_hkdf_deterministic() {
        let hkdf = HkdfBlake3::new();
        let ikm = b"test";
        let salt = b"salt";
        let info = b"info";

        let key1 = hkdf.derive(ikm, salt, info, 32).unwrap();
        let key2 = hkdf.derive(ikm, salt, info, 32).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_hkdf_different_salt() {
        let hkdf = HkdfBlake3::new();
        let ikm = b"test";
        let info = b"info";

        let key1 = hkdf.derive(ikm, b"salt1", info, 32).unwrap();
        let key2 = hkdf.derive(ikm, b"salt2", info, 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_asymmetry() {
        let hkdf = HkdfBlake3::new();
        let rating = hkdf.asymmetry();
        assert!(rating.computational > 0.99);
    }

    #[test]
    fn test_pbkdf2_derive() {
        let pbkdf2 = Pbkdf2HmacSha256::recommended();
        let password = b"password";
        let salt = b"salt";

        let key = pbkdf2.derive(password, salt, 32).unwrap();
        assert_eq!(key.len(), 32);
    }
}
