use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use crate::ledger::SovereignState;

#[derive(Debug, Clone)]
pub enum StorageBackend {
    RocksDB,
    Sqlite,
    Sled,
    Memory,
}

pub struct SovereignPersistence {
    storage_path: PathBuf,
    backend: StorageBackend,
}

impl SovereignPersistence {
    pub fn new(backend: StorageBackend) -> Self {
        Self {
            storage_path: PathBuf::from("/data/ube"),
            backend,
        }
    }

    pub fn with_path(path: PathBuf, backend: StorageBackend) -> Self {
        Self { storage_path: path, backend }
    }

    /// Atomically saves the sovereign state to disk using a temporary file to prevent corruption.
    pub fn save_state(&self, state: &SovereignState) -> Result<()> {
        let temp_path = self.storage_path.with_extension("tmp");

        let mut file = File::create(&temp_path)
            .context("Failed to create temporary state file")?;

        let data = serde_json::to_vec_pretty(state)
            .context("Failed to serialize sovereign state")?;

        file.write_all(&data)?;
        file.sync_all()?; // Ensure data is physically written to disk

        // Atomic rename to the final destination
        std::fs::rename(temp_path, &self.storage_path)
            .context("Failed to atomically commit sovereign state")?;

        Ok(())
    }

    /// Loads the sovereign state from disk.
    pub fn load_state(&self) -> Result<Option<SovereignState>> {
        if !self.storage_path.exists() {
            return Ok(None);
        }

        let mut file = File::open(&self.storage_path)
            .context("Failed to open state file")?;

        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let state = serde_json::from_slice(&data)
            .context("Failed to deserialize sovereign state from disk")?;

        Ok(Some(state))
    }
}
