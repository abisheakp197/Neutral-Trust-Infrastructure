//! Hash algorithms for UBE Crypto

use crate::error::CryptoResult;
use crate::CryptoPrimitive;
use serde::{Serialize, Deserialize};

/// Hash algorithm types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// BLAKE3 (default, recommended)
    Blake3,
    /// SHA-256
    Sha256,
    /// SHA-384
    Sha384,
    /// SHA-512
    Sha512,
    /// SHA3-256
    Sha3_256,
    /// SHA3-384
    Sha3_384,
    /// SHA3-512
    Sha3_512,
}

impl HashAlgorithm {
    /// Get the output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            HashAlgorithm::Blake3 => 32,
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Sha3_256 => 32,
            HashAlgorithm::Sha3_384 => 48,
            HashAlgorithm::Sha3_512 => 64,
        }
    }

    /// Get the algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            HashAlgorithm::Blake3 => "BLAKE3",
            HashAlgorithm::Sha256 => "SHA-256",
            HashAlgorithm::Sha384 => "SHA-384",
            HashAlgorithm::Sha512 => "SHA-512",
            HashAlgorithm::Sha3_256 => "SHA3-256",
            HashAlgorithm::Sha3_384 => "SHA3-384",
            HashAlgorithm::Sha3_512 => "SHA3-512",
        }
    }
}

/// Trait for hash functions
pub trait Hash: CryptoPrimitive {
    /// Compute hash of data
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Compute hash with salt/pepper
    fn hash_with_salt(&self, data: &[u8], salt: &[u8]) -> Vec<u8> {
        let mut combined = Vec::with_capacity(data.len() + salt.len());
        combined.extend_from_slice(salt);
        combined.extend_from_slice(data);
        self.hash(&combined)
    }
}

/// Hash output structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashOutput {
    pub algorithm: HashAlgorithm,
    pub digest: Vec<u8>,
}

impl HashOutput {
    pub fn new(algorithm: HashAlgorithm, digest: Vec<u8>) -> Self {
        Self { algorithm, digest }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_sizes() {
        assert_eq!(HashAlgorithm::Blake3.output_size(), 32);
        assert_eq!(HashAlgorithm::Sha256.output_size(), 32);
        assert_eq!(HashAlgorithm::Sha512.output_size(), 64);
    }

    #[test]
    fn test_algorithm_names() {
        assert_eq!(HashAlgorithm::Blake3.name(), "BLAKE3");
        assert_eq!(HashAlgorithm::Sha256.name(), "SHA-256");
    }
}
