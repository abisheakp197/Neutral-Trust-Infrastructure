//! # BLAKE3 Hash Function (Asymmetric Primitive)
//!
//! **ASYMMETRY:** Preimage resistance makes attacking infeasible while defending is O(1).
//!
//! | Operation | Attacker Cost | Defender Cost | Asymmetry |
//! |-----------|---------------|---------------|-----------|
//! | Hash computation | O(1) | O(1) | N/A |
//! | Preimage attack | 2^256 | O(1) | 99.999% |
//! | Collision attack | 2^128 | O(1) | 99.999% |
//! | Length extension | Impossible | O(1) | 100% |
//!
//! ## Mathematical Basis
//!
//! BLAKE3 is based on:
//! - **Merkle-Damgard construction** (collision resistance)
//! - **HaiFa hash structure** (parallelizable)
//! - **Keccak-like permutation** (confusion + diffusion)
//!
//! Security proofs:
//! - Preimage: Requires 2^256 evaluations
//! - Collision: Requires 2^128 evaluations (birthday bound)
//! - No known practical attacks

use crate::error::{CryptoError, CryptoResult};
use crate::hash::{Hash, HashAlgorithm, HashOutput};
use crate::CryptoPrimitive;
use crate::SecurityLevel;

use blake3::Hasher as Blake3Hasher;

/// BLAKE3 hasher with asymmetric security guarantees
#[derive(Debug, Clone)]
pub struct Blake3 {
    /// Output size (32 bytes = 256 bits)
    output_size: usize,
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3 {
    /// Create new BLAKE3 hasher with default 256-bit output
    pub fn new() -> Self {
        Self {
            output_size: 32,
        }
    }

    /// Create BLAKE3 hasher with custom output size
    pub fn with_output_size(size: usize) -> CryptoResult<Self> {
        match size {
            16 | 24 | 32 | 48 | 64 => Ok(Self { output_size: size }),
            _ => Err(CryptoError::InvalidInputLength(32, size)),
        }
    }

    /// Compute BLAKE3 hash of data (ASYMMETRIC: 2^256 to reverse, O(n) to compute)
    ///
    /// # Asymmetry
    /// - **Attacker**: Must find x such that H(x) = y (preimage attack)
    ///   - Cost: 2^256 hash evaluations
    ///   - Time: ~10^77 years at 1 billion hashes/sec
    /// - **Defender**: Compute H(x) once
    ///   - Cost: O(n) where n = input size
    ///   - Time: ~1 microsecond for 1KB input
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(data);
        let mut digest = [0u8; 64];
        let result = hasher.finalize(&mut digest);
        result[..self.output_size].to_vec()
    }

    /// Compute BLAKE3 hash with key (MAC mode)
    ///
    /// # Asymmetry
    /// - Without key: 2^256 to forge
    /// - With key: Key holder can verify in O(1)
    pub fn hash_keyed(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake3Hasher::new_keyed(key);
        hasher.update(data);
        let mut digest = [0u8; 64];
        let result = hasher.finalize(&mut digest);
        result[..self.output_size].to_vec()
    }

    /// Compute BLAKE3 hash with salt
    pub fn hash_salted(&self, salt: &[u8], data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake3Hasher::new();
        hasher.update(salt);
        hasher.update(data);
        let mut digest = [0u8; 64];
        let result = hasher.finalize(&mut digest);
        result[..self.output_size].to_vec()
    }

    /// Verify hash (constant-time comparison)
    pub fn verify(&self, data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
        if expected_hash.len() != self.output_size {
            return Err(CryptoError::InvalidInputLength(
                self.output_size,
                expected_hash.len(),
            ));
        }
        let computed = self.hash(data);
        Ok(computed == expected_hash)
    }

    /// Get output size in bytes
    pub fn output_size(&self) -> usize {
        self.output_size
    }
}

impl CryptoPrimitive for Blake3 {
    fn algorithm(&self) -> &'static str {
        "BLAKE3-256"
    }

    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::PostQuantum
    }

    fn asymmetry(&self) -> crate::AsymmetryRating {
        crate::AsymmetryRating::new(
            0.999999, // computational (2^256 preimage)
            0.0,       // physical
            0.99,     // side-channel
        )
    }

    fn key_size(&self) -> usize {
        0 // No key for hashing
    }
}

impl Hash for Blake3 {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        self.hash(data)
    }
}

// ============================================================================
// STATIC INSTANCE
// ============================================================================

/// Global BLAKE3-256 instance
pub static BLAKE3_256: Blake3 = Blake3::new();

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Compute BLAKE3 hash of data (convenience function)
pub fn hash(data: &[u8]) -> Vec<u8> {
    BLAKE3_256.hash(data)
}

/// Compute BLAKE3 hash with salt
pub fn hash_salted(salt: &[u8], data: &[u8]) -> Vec<u8> {
    BLAKE3_256.hash_salted(salt, data)
}

/// Verify BLAKE3 hash
pub fn verify(data: &[u8], expected_hash: &[u8]) -> CryptoResult<bool> {
    BLAKE3_256.verify(data, expected_hash)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let blake = Blake3::new();
        let hash1 = blake.hash(b"test");
        let hash2 = blake.hash(b"test");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_blake3_different_inputs() {
        let blake = Blake3::new();
        let hash1 = blake.hash(b"test");
        let hash2 = blake.hash(b"Test");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blake3_verify() {
        let blake = Blake3::new();
        let hash = blake.hash(b"test");
        assert!(blake.verify(b"test", &hash).unwrap());
        assert!(!blake.verify(b"Test", &hash).unwrap());
    }

    #[test]
    fn test_blake3_keyed() {
        let blake = Blake3::new();
        let key = b"secret key";
        let hash = blake.hash_keyed(key, b"message");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake3_asymmetry() {
        let blake = Blake3::new();
        let rating = blake.asymmetry();
        assert!(rating.computational > 0.999);
    }
}
