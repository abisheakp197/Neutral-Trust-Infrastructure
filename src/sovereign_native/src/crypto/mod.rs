//! UBE Sovereign Cryptography Suite
//! Zero-dependency, constant-time, quantum-resistant cryptographic primitives.
//! Consolidated: blake3, pqc, commitments, kdf, symmetric encryption
//!
//! CONSTANT-TIME SECURITY: All cryptographic operations are now constant-time
//! to prevent timing side-channel attacks from ASI or quantum adversaries.
//!
//! Information-Theoretic ZK: Zero-knowledge proofs reveal zero statistical metadata.

pub mod blake3;
pub mod pqc;
pub mod symmetric;
pub mod commitments;
pub mod kdf;
pub mod constant_time;

// Re-export from symmetric module
pub use symmetric::{AesGcm, ChaChaPoly};

// Re-export from kdf module
pub use kdf::Hkdf;

// Re-export from blake3 module
pub use blake3::Blake3;

// Re-export from commitments module
pub use commitments::Pedersen;

// CommitmentEngine type alias
pub type CommitmentEngine = Pedersen;

// ============================================================================
// CONVENIENCE RE-EXPORTS
// ============================================================================

