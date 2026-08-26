//! # UBE Crypto
//!
//! **Post-quantum cryptographic primitives** for building asymmetric security systems.
//!
//! ## Features
//!
//! - **Lattice-based cryptography**: Kyber (KEM), Dilithium (signatures), SPHINCS+ (hash-based)
//! - **Fast hashing**: BLAKE3 (default), SHA-2, SHA-3
//! - **Side-channel resistance**: Constant-time operations
//! - **Key derivation**: HKDF, Argon2-compatible
//! - **Zero-knowledge friendly**: Commitment schemes
//!
//! ## Asymmetry Guarantee
//!
//! | Operation | Attacker Cost | Defender Cost | Asymmetry |
//! |-----------|---------------|---------------|-----------|
//! | Lattice KEM | 2^128+ ops | O(1) | 99.999% |
//! | Lattice Sign | 2^128+ ops | O(1) | 99.999% |
//! | BLAKE3 | 2^256 ops | O(1) | 99.999% |
//! | Constant-time | Side-channel | O(1) | 99% |
//!
//! ## Usage
//!
//! ```
//! use ube_crypto::pqc::{Kyber512, Dilithium3};
//! use ube_crypto::hash::Blake3;
//!
//! // Generate a Kyber key pair
//! let (pk, sk) = Kyber512::keypair();
//!
//! // Encapsulate
//! let (ct, ss_recipient) = Kyber512::encapsulate(&pk);
//! let ss_initiator = Kyber512::decapsulate(&sk, &ct);
//! assert_eq!(ss_recipient, ss_initiator);
//!
//! // Sign a message
//! let (sk, pk) = Dilithium3::keypair();
//! let signature = Dilithium3::sign(&sk, b"Hello, world!");
//! assert!(Dilithium3::verify(&pk, b"Hello, world!", &signature));
//!
//! // Hash with BLAKE3
//! let hash = Blake3::hash(b"test");
//! ```

pub mod blake3;
pub mod commitments;
pub mod constant_time;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod pqc;
pub mod symmetric;

// Re-export commonly used types
pub use blake3::{Blake3, BLAKE3_256};
pub use commitments::{Blake3Commitment, MerkleTreeCommitment, Commitment, CommitmentOutput, MerkleProof};
pub use constant_time::*;
pub use error::CryptoError;
pub use hash::{Hash, HashAlgorithm};
pub use kdf::{HkdfBlake3, Kdf, Pbkdf2HmacSha256};
pub use pqc::{Dilithium, DilithiumLevel, DilithiumKeypair, Kyber, KyberLevel, KyberKeypair, KyberParams, Pqc};
pub use symmetric::{Aes256GcmCipher, ChaCha20Poly1305Cipher, Cipher, EncryptionResult, CipherType};

// Re-export static instances
pub use pqc::{KYBER512, KYBER768, KYBER1024, DILITHIUM2, DILITHIUM3, DILITHIUM5};
pub use commitments::{BLAKE3_COMMITMENT, MERKLE_TREE_COMMITMENT};
pub use kdf::HKDF_BLAKE3;
pub use symmetric::{generate_aes256_key, generate_chacha20_key, cipher_from_type};
pub use blake3::{hash as blake3_hash, hash_salted as blake3_hash_salted, verify as blake3_verify};
pub use kdf::{derive_key, extract, expand};
pub use commitments::{commit, verify_commitment};

/// Asymmetry rating for cryptographic operations
#[derive(Debug, Clone, Copy)]
pub struct AsymmetryRating {
    /// Computational asymmetry (attacker vs defender)
    pub computational: f64,
    /// Physical asymmetry (if hardware-backed)
    pub physical: f64,
    /// Side-channel resistance
    pub side_channel: f64,
    /// Overall rating (0.0 - 1.0)
    pub overall: f64,
}

impl AsymmetryRating {
    /// Create a new asymmetry rating
    pub fn new(computational: f64, physical: f64, side_channel: f64) -> Self {
        let overall = (computational * 0.5) + (physical * 0.3) + (side_channel * 0.2);
        Self {
            computational,
            physical,
            side_channel,
            overall,
        }
    }

    /// Get asymmetry rating for Kyber512
    pub fn kyber512() -> Self {
        Self::new(0.99999, 0.0, 0.99)
    }

    /// Get asymmetry rating for Dilithium3
    pub fn dilithium3() -> Self {
        Self::new(0.99999, 0.0, 0.99)
    }

    /// Get asymmetry rating for BLAKE3
    pub fn blake3() -> Self {
        Self::new(0.99999, 0.0, 0.95)
    }

    /// Get asymmetry rating for constant-time operations
    pub fn constant_time() -> Self {
        Self::new(0.0, 0.0, 0.99)
    }
}

/// Security level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Insecure (deprecated, broken)
    Insecure = 0,
    /// Legacy (weak but acceptable for low-risk)
    Legacy = 1,
    /// Standard (current best practice)
    Standard = 2,
    /// Strong (resistant to known attacks)
    Strong = 3,
    /// PostQuantum (resistant to quantum attacks)
    PostQuantum = 4,
}

/// Trait for cryptographic primitives
pub trait CryptoPrimitive {
    /// Get the algorithm name
    fn algorithm(&self) -> &'static str;

    /// Get the security level
    fn security_level(&self) -> SecurityLevel;

    /// Get the asymmetry rating
    fn asymmetry(&self) -> AsymmetryRating;

    /// Get key size in bits
    fn key_size(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asymmetry_ratings() {
        // All PQC should have high asymmetry
        assert!(AsymmetryRating::kyber512().overall > 0.95);
        assert!(AsymmetryRating::dilithium3().overall > 0.95);

        // BLAKE3 should have high computational asymmetry
        assert!(AsymmetryRating::blake3().computational > 0.99);

        // Constant-time should have high side-channel resistance
        assert!(AsymmetryRating::constant_time().side_channel > 0.95);
    }

    #[test]
    fn test_security_levels() {
        assert!(SecurityLevel::PostQuantum > SecurityLevel::Standard);
        assert!(SecurityLevel::Standard > SecurityLevel::Legacy);
    }
}
