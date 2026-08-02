use crate::crypto::blake3::Blake3;
use std::fs::File;
use std::io::Read;
use anyhow::{Result, Context};
use log::{info, warn, error};

pub struct SovereignImmuneSystem {
    golden_hash: Vec<u8>,
}

impl SovereignImmuneSystem {
    /// Expected hash length for cryptographic hashes (SHA256 = 32 bytes)
    const HASH_LEN: usize = 32;

    /// Initializes the SIS with a pre-verified "Golden Image" hash.
    /// Validates that the hash is cryptographically valid (not from fake Blake3).
    pub fn new(golden_hash: Vec<u8>) -> Self {
        // SOVEREIGN SECURITY FIX: Validate that the golden hash is the correct length
        // Previously, fake Blake3 could produce any length hash, but real crypto is 32 bytes
        if golden_hash.len() != Self::HASH_LEN {
            panic!(
                "SIS INITIALIZATION FAILED: Golden hash has invalid length {} (expected {}). \
                 This suggests the hash was computed with the FAKE Blake3 implementation. \
                 Regenerate the golden hash using REAL cryptographic hashing.",
                golden_hash.len(),
                Self::HASH_LEN
            );
        }

        // Additional validation: hash should not be all zeros or simple patterns
        // that the fake XOR-based Blake3 might produce
        let mut all_zeros = true;
        let mut all_ones = true;
        for &byte in golden_hash.iter() {
            if byte != 0u8 { all_zeros = false; }
            if byte != 0xFFu8 { all_ones = false; }
        }
        if all_zeros || all_ones {
            panic!(
                "SIS INITIALIZATION FAILED: Golden hash appears to be fake (all zeros or all ones). \
                 Regenerate using REAL cryptographic hashing."
            );
        }

        Self { golden_hash }
    }

    /// Performs a binary attestation check by hashing the current executable.
    /// Uses BLAKE3 (now REAL cryptographic hash via SHA256) for sovereign hashing.
    pub async fn verify_integrity(&self) -> Result<bool> {
        info!("SIS: Performing binary attestation cycle...");

        let executable_path = std::env::current_exe()
            .context("Failed to determine current executable path")?;

        let mut file = File::open(&executable_path)
            .context("Failed to open binary for attestation")?;

        let mut buffer = [0u8; 8192];
        let mut combined_data = Vec::new();

        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 { break; }
            combined_data.extend_from_slice(&buffer[..n]);
        }

        let current_hash = Blake3::hash(&combined_data);

        // SOVEREIGN SECURITY FIX: Use constant-time comparison to prevent timing attacks
        use crate::crypto::blake3::Blake3 as Blake3Crypto;

        // Clone golden_hash since try_into consumes it
        let expected_hash: [u8; 32] = self.golden_hash.clone().try_into().unwrap_or([0u8; 32]);
        if Blake3Crypto::verify_hash(&current_hash, &expected_hash) {
            info!("SIS: Binary integrity verified. State: PURE.");
            Ok(true)
        } else {
            warn!("SIS: INTEGRITY DEVIATION DETECTED!");
            error!("Expected: {:?}\nActual:   {:?}", self.golden_hash, current_hash);

            // SELF-DESTRUCT: If binary integrity fails with the fixed crypto,
            // this means we've been tampered with. Trigger immediate shutdown.
            panic!(
                "SIS: CRITICAL INTEGRITY FAILURE! Binary has been tampered with. \
                 Expected hash: {:?}\n                 Actual hash:   {:?}\n                 System shutting down to prevent exploitation.",
                 self.golden_hash, current_hash
            );
        }
    }

    /// Simulates the "Repair Loop" by restoring from a golden image.
    pub async fn trigger_repair(&self) -> Result<()> {
        warn!("SIS: Initiating Autonomous Repair Loop...");
        info!("SIS: Binary restored to PURE state. System rebooting...");
        Ok(())
    }
}
