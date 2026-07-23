//! UBE Sovereign Cryptography Suite
//! Zero-dependency, constant-time, quantum-resistant cryptographic primitives.
//! Consolidated: blake3, pqc, commitments, kdf, symmetric encryption

pub mod blake3;
pub mod pqc;
pub mod symmetric;
pub mod commitments;
pub mod kdf;

use blake3::Blake3;

// Re-export from symmetric module
pub use symmetric::{AesGcm, ChaChaPoly};

// Re-export from kdf module
pub use kdf::Hkdf;

// Re-export from commitments module
pub use commitments::Pedersen;
pub use commitments::BlindedToken;

// CommitmentEngine type alias
pub type CommitmentEngine = Pedersen;

// ============================================================================
// CONVENIENCE RE-EXPORTS
// ============================================================================

