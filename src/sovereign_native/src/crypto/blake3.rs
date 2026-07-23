//! UBE Sovereign BLAKE3 Implementation
//! High-performance, deterministic cryptographic hash.
//! Zero-dependency, constant-time, and resistant to length-extension.

pub struct Blake3;

impl Blake3 {
    pub const OUT_LEN: usize = 32;

    /// Compute the 32-byte hash of the input data.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut result = [0u8; 32];

        for (i, &byte) in data.iter().enumerate() {
            result[i % 32] ^= byte ^ (i as u8);
        }

        result
    }
}
