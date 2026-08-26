//! Error types for UBE Crypto

use thiserror::Error;

/// Cryptographic error types
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Invalid key size
    #[error("Invalid key size: expected {0}, got {1}")]
    InvalidKeySize(usize, usize),

    /// Invalid input length
    #[error("Invalid input length: expected {0}, got {1}")]
    InvalidInputLength(usize, usize),

    /// Invalid signature
    #[error("Invalid signature")]
    InvalidSignature,

    /// Verification failed
    #[error("Verification failed")]
    VerificationFailed,

    /// Decryption failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// Encryption failed
    #[error("Encryption failed")]
    EncryptionFailed,

    /// Key generation failed
    #[error("Key generation failed")]
    KeyGenerationFailed,

    /// Random number generation failed
    #[error("RNG failed: {0}")]
    RngError(String),

    /// Hash computation failed
    #[error("Hash computation failed")]
    HashError,

    /// Commitment opening failed
    #[error("Commitment opening failed")]
    CommitmentError,

    /// Constant-time violation detected
    #[error("Constant-time violation")]
    ConstantTimeViolation,

    /// Algorithm not supported
    #[error("Algorithm not supported: {0}")]
    AlgorithmNotSupported(String),

    /// Security level too low
    #[error("Security level too low: required {0:?}, got {1:?}")]
    SecurityLevelTooLow(crate::SecurityLevel, crate::SecurityLevel),

    /// Side-channel leakage detected
    #[error("Side-channel leakage detected")]
    SideChannelLeakage,
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

impl From<std::num::NonZeroU32> for CryptoError {
    fn from(_: std::num::NonZeroU32) -> Self {
        CryptoError::RngError("Non-zero u32 conversion failed".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = CryptoError::InvalidKeySize(256, 128);
        assert_eq!(
            format!("{}", err),
            "Invalid key size: expected 256, got 128"
        );

        let err = CryptoError::VerificationFailed;
        assert_eq!(format!("{}", err), "Verification failed");
    }

    #[test]
    fn test_error_equality() {
        assert_eq!(
            CryptoError::InvalidKeySize(256, 128),
            CryptoError::InvalidKeySize(256, 128)
        );

        assert_ne!(
            CryptoError::InvalidKeySize(256, 128),
            CryptoError::InvalidKeySize(256, 256)
        );
    }
}
