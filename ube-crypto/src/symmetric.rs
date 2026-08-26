//! # Symmetric Encryption (Asymmetric Primitive)
//!
//! **ASYMMETRY:** Key holder can encrypt/decrypt in O(n), attacker must try 2^256 keys.
//!
//! | Operation | Attacker Cost | Defender Cost | Asymmetry |
//! |-----------|---------------|---------------|-----------|
//! | AES-256-GCM | 2^256 brute force | O(n) encrypt | 99.999% |
//! | ChaCha20-Poly1305 | 2^256 brute force | O(n) encrypt | 99.999% |
//!
//! ## Mathematical Basis
//!
//! Symmetric encryption security is based on:
//! - **AES**: 10-14 rounds of substitution-permutation network
//!   - Confusion: Each bit affects many output bits
//!   - Diffusion: Each input bit affects many output bits
//! - **ChaCha20**: 20 rounds of quarter-rounds
//!   - ARX construction: Addition, Rotation, XOR
//! - **Key size**: 256 bits = 2^256 possible keys
//! - **Brute force**: 2^256 operations to try all keys
//!
//! ##Asymmetry Calculation
//!
//! For AES-256:
//! - Attacker: 2^256 operations
//! - Defender: 14 * (n/16) operations (for n-byte message)
//! - Ratio: 2^256 / (14 * n/16)
//! - For n=1KB: ~10^77 / 1000 = 10^74 : 1
//!
//! This is **computationally impossible** for any known attacker.

use crate::error::{CryptoError, CryptoResult};
use crate::CryptoPrimitive;
use crate::SecurityLevel;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::{
    aead::{Aead as ChaChaAead, KeyInit as ChaChaKeyInit},
    ChaCha20Poly1305, Nonce as ChaChaNonce,
};

/// Cipher trait for symmetric encryption
pub trait Cipher: CryptoPrimitive {
    /// Encrypt data
    fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Decrypt data
    fn decrypt(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>>;

    /// Get nonce size
    fn nonce_size(&self) -> usize;

    /// Get key size
    fn key_size(&self) -> usize;
}

/// Encryption result with nonce
#[derive(Debug, Clone)]
pub struct EncryptionResult {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl EncryptionResult {
    pub fn new(ciphertext: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self { ciphertext, nonce }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.nonce.len() + self.ciphertext.len());
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    pub fn from_bytes(data: &[u8], nonce_size: usize) -> CryptoResult<Self> {
        if data.len() < nonce_size {
            return Err(CryptoError::InvalidInputLength(
                nonce_size,
                data.len(),
            ));
        }
        Ok(Self {
            nonce: data[..nonce_size].to_vec(),
            ciphertext: data[nonce_size..].to_vec(),
        })
    }
}

// ============================================================================
// AES-256-GCM
// ============================================================================

/// AES-256-GCM symmetric cipher
///
/// **ASYMMETRY:** 2^256 to break, O(n) to use
///
/// # Security
/// - **Key size**: 256 bits
/// - **Nonce size**: 96 bits (12 bytes)
/// - **Tag size**: 128 bits (16 bytes)
/// - **Brute force**: 2^256 operations
/// - **Defender cost**: ~1 cycle/byte (AES-NI hardware)
/// - **Asymmetry ratio**: 2^256 / n
pub struct Aes256GcmCipher {
    cipher: Aes256Gcm,
}

impl Aes256GcmCipher {
    /// Create new AES-256-GCM cipher with given key
    pub fn new(key: &[u32; 8]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key.as_slice()).unwrap();
        Self { cipher }
    }

    /// Generate random key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt with AES-256-GCM (ASYMMETRIC: 2^256 to break key, O(n) to use)
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<EncryptionResult> {
        let nonce = Aes256Gcm::<Aes256Gcm>::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(EncryptionResult::new(ciphertext, nonce.to_vec()))
    }

    /// Decrypt with AES-256-GCM
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

impl Cipher for Aes256GcmCipher {
    fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let result = self.encrypt(plaintext)?;
        Ok(result.to_bytes())
    }

    fn decrypt(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let result = EncryptionResult::from_bytes(data, 12)?;
        self.decrypt(&result.ciphertext, &result.nonce)
    }

    fn nonce_size(&self) -> usize {
        12 // 96 bits
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }
}

impl CryptoPrimitive for Aes256GcmCipher {
    fn algorithm(&self) -> &'static str {
        "AES-256-GCM"
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::PostQuantum // AES-256 is quantum-resistant (Grover reduces to 2^128)
    }

    fn asymmetry(&self) -> crate::AsymmetryRating {
        crate::AsymmetryRating::new(
            0.999999999, // computational (2^128 quantum)
            0.0,           // physical
            0.95,          // side-channel (AES-NI is mostly constant-time)
        )
    }

    fn key_size(&self) -> usize {
        32
    }
}

// ============================================================================
// ChaCha20-Poly1305
// ============================================================================

/// ChaCha20-Poly1305 symmetric cipher
///
/// **ASYMMETRY:** 2^256 to break key, O(n) to use
///
/// # Security
/// - **Key size**: 256 bits
/// - **Nonce size**: 96 bits (12 bytes)
/// - **Tag size**: 128 bits (16 bytes)
/// - **Brute force**: 2^256 operations
/// - **Defender cost**: ~10 cycles/byte (software)
/// - **Asymmetry ratio**: 2^256 / n
///
/// # Advantages over AES-GCM
/// - Software-optimized (no hardware acceleration needed)
/// - Constant-time by design
/// - Resistant to timing attacks
pub struct ChaCha20Poly1305Cipher {
    cipher: ChaCha20Poly1305,
}

impl ChaCha20Poly1305Cipher {
    /// Create new ChaCha20-Poly1305 cipher with given key
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new_from_slice(key.as_slice()).unwrap();
        Self { cipher }
    }

    /// Generate random key
    pub fn generate_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Encrypt with ChaCha20-Poly1305 (ASYMMETRIC: 2^256 to break, O(n) to use)
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<EncryptionResult> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(EncryptionResult::new(ciphertext, nonce.to_vec()))
    }

    /// Decrypt with ChaCha20-Poly1305
    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> CryptoResult<Vec<u8>> {
        let nonce = ChaChaNonce::from_slice(nonce);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}

impl Cipher for ChaCha20Poly1305Cipher {
    fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<Vec<u8>> {
        let result = self.encrypt(plaintext)?;
        Ok(result.to_bytes())
    }

    fn decrypt(&self, data: &[u8]) -> CryptoResult<Vec<u8>> {
        let result = EncryptionResult::from_bytes(data, 12)?;
        self.decrypt(&result.ciphertext, &result.nonce)
    }

    fn nonce_size(&self) -> usize {
        12 // 96 bits
    }

    fn key_size(&self) -> usize {
        32 // 256 bits
    }
}

impl CryptoPrimitive for ChaCha20Poly1305Cipher {
    fn algorithm(&self) -> &'static str {
        "ChaCha20-Poly1305"
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::PostQuantum
    }

    fn asymmetry(&self) -> crate::AsymmetryRating {
        crate::AsymmetryRating::new(
            0.999999999, // computational (2^128 quantum)
            0.0,           // physical
            0.99,          // side-channel (constant-time by design)
        )
    }

    fn key_size(&self) -> usize {
        32
    }
}

// ============================================================================
// Cipher Enum (for easy selection)
// ============================================================================

/// Available cipher types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Aes256Gcm,
    ChaCha20Poly1305,
}

/// Create cipher from type
pub fn cipher_from_type(cipher_type: CipherType, key: &[u8; 32]) -> Box<dyn Cipher> {
    match cipher_type {
        CipherType::Aes256Gcm => Box::new(Aes256GcmCipher::new(key)),
        CipherType::ChaCha20Poly1305 => Box::new(ChaCha20Poly1305Cipher::new(key)),
    }
}

// ============================================================================
// STATIC INSTANCES
// ============================================================================

/// Generate random AES-256-GCM key
pub fn generate_aes256_key() -> [u8; 32] {
    Aes256GcmCipher::generate_key()
}

/// Generate random ChaCha20-Poly1305 key
pub fn generate_chacha20_key() -> [u8; 32] {
    ChaCha20Poly1305Cipher::generate_key()
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes256_encrypt_decrypt() {
        let key = Aes256GcmCipher::generate_key();
        let cipher = Aes256GcmCipher::new(&key);

        let plaintext = b"Hello, world!";
        let result = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&result.ciphertext, &result.nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = ChaCha20Poly1305Cipher::generate_key();
        let cipher = ChaCha20Poly1305Cipher::new(&key);

        let plaintext = b"Hello, world!";
        let result = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&result.ciphertext, &result.nonce).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_aes256_wrong_key() {
        let key1 = Aes256GcmCipher::generate_key();
        let key2 = Aes256GcmCipher::generate_key();

        let cipher1 = Aes256GcmCipher::new(&key1);
        let cipher2 = Aes256GcmCipher::new(&key2);

        let plaintext = b"Secret";
        let result = cipher1.encrypt(plaintext).unwrap();

        let decrypted = cipher2.decrypt(&result.ciphertext, &result.nonce);
        assert!(decrypted.is_err()); // Should fail with wrong key
    }

    #[test]
    fn test_cipher_asymmetry() {
        let key = Aes256GcmCipher::generate_key();
        let cipher = Aes256GcmCipher::new(&key);

        let rating = cipher.asymmetry();
        assert!(rating.computational > 0.999);
    }
}
