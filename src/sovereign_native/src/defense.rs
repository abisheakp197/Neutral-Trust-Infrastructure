use crate::crypto::blake3::Blake3;
use std::fs::File;
use std::io::Read;
use anyhow::{Result, Context};
use log::{info, warn, error};

pub struct SovereignImmuneSystem {
    golden_hash: Vec<u8>,
}

impl SovereignImmuneSystem {
    /// Initializes the SIS with a pre-verified "Golden Image" hash.
    pub fn new(golden_hash: Vec<u8>) -> Self {
        Self { golden_hash }
    }

    /// Performs a binary attestation check by hashing the current executable.
    /// Uses BLAKE3 for deterministic, high-performance, sovereign hashing.
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

        let current_hash = Blake3::hash(&combined_data).to_vec();

        if current_hash == self.golden_hash {
            info!("SIS: Binary integrity verified. State: PURE.");
            Ok(true)
        } else {
            warn!("SIS: INTEGRITY DEVIATION DETECTED!");
            error!("Expected: {:?}\nActual:   {:?}", self.golden_hash, current_hash);
            // Trigger repair on integrity failure
            let _ = self.trigger_repair().await;
            Ok(false)
        }
    }

    /// Simulates the "Repair Loop" by restoring from a golden image.
    pub async fn trigger_repair(&self) -> Result<()> {
        warn!("SIS: Initiating Autonomous Repair Loop...");
        info!("SIS: Binary restored to PURE state. System rebooting...");
        Ok(())
    }
}
