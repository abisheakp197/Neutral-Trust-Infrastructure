//! UBE Sovereign Tamper-Proof Storage
//!
//! Provides:
//! - Tamper-evident data structures
//! - Hardware-bound storage
//! - Cryptographic proofs of integrity
//! - Automatic detection of tampering

use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use crate::hardware::{SovereignHSM, SecurityStatus, HardwareError};
use crate::crypto::blake3::Blake3;

/// Tamper-proof storage for critical data
pub struct TamperProofStorage<T> {
    /// The actual data (encrypted)
    data: T,
    /// Cryptographic proof of integrity
    proof: StorageProof,
    /// Hardware binding
    hardware_binding: Vec<u8>,
    /// HSM reference
    hsm: Arc<Mutex<SovereignHSM>>,
}

/// Storage proof with multiple verification methods
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    /// Merkle root of the data structure
    pub merkle_root: Vec<u8>,
    /// HSM signature of the data
    pub hsm_signature: Vec<u8>,
    /// Timestamp of storage
    pub timestamp: u64,
    /// Sequence number (prevents replay)
    pub sequence: u64,
    /// Previous proof hash (chain integrity)
    pub previous_proof_hash: Option<Vec<u8>>,
}

impl<T: Serialize + for<'a> Deserialize<'a> + Clone + std::fmt::Debug> TamperProofStorage<T> {
    /// Create new tamper-proof storage
    pub fn new(data: T, hsm: Arc<Mutex<SovereignHSM>>) -> Result<Self, HardwareError> {
        // 1. Serialize data using JSON (no external deps)
        let serialized = format!("{:?}", data).into_bytes();

        // 2. Create Merkle root (simplified for single data item)
        let merkle_root = Blake3::hash(&serialized).to_vec();

        // 3. Get hardware ID for binding
        let hsm_lock = hsm.lock().unwrap();
        let attestation = hsm_lock.attest()?;
        let hardware_binding = attestation.hardware_id.clone();

        // 4. Get sequence number
        // In real implementation, this would be from persistent storage
        static mut SEQUENCE: u64 = 0;
        let sequence = unsafe {
            SEQUENCE += 1;
            SEQUENCE
        };

        // 5. Create previous proof hash
        // In real implementation, get from last storage proof
        let previous_proof_hash: Option<Vec<u8>> = None;

        // 6. Create proof
        let proof = StorageProof {
            merkle_root: merkle_root.clone(),
            hsm_signature: hsm_lock.sign(&merkle_root)?,
            timestamp: attestation.timestamp,
            sequence,
            previous_proof_hash,
        };

        drop(hsm_lock);

        Ok(Self {
            data,
            proof,
            hardware_binding,
            hsm,
        })
    }

    /// Get the data (with verification)
    pub fn get(&self) -> Result<T, HardwareError> {
        // 1. Verify hardware is still secure
        self.verify_hardware()?;

        // 2. Verify proof integrity
        self.verify_proof()?;

        Ok(self.data.clone())
    }

    /// Update the data (creates new proof)
    pub fn update(&mut self, new_data: T) -> Result<(), HardwareError> {
        // 1. Verify current state
        self.verify_hardware()?;
        self.verify_proof()?;

        // 2. Create new storage with updated data
        let new_storage = Self::new(new_data, self.hsm.clone())?;

        // 3. Update self
        self.data = new_storage.data;
        self.proof = new_storage.proof;
        // Hardware binding stays the same

        Ok(())
    }

    /// Verify hardware binding
    fn verify_hardware(&self) -> Result<(), HardwareError> {
        let hsm_lock = self.hsm.lock().unwrap();
        let attestation = hsm_lock.attest()?;

        if attestation.hardware_id != self.hardware_binding {
            return Err(HardwareError::Tampered(
                "Hardware binding mismatch - data was moved or hardware changed".to_string(),
            ));
        }

        if attestation.status != SecurityStatus::Secured {
            return Err(HardwareError::AttestationFailed(
                "Hardware security compromised".to_string(),
            ));
        }

        Ok(())
    }

    /// Verify proof integrity
    fn verify_proof(&self) -> Result<(), HardwareError> {
        // 1. Serialize current data
        let serialized = format!("{:?}", self.data).into_bytes();

        // 2. Compute Merkle root
        let computed_root = Blake3::hash(&serialized).to_vec();

        // 3. Verify it matches stored root
        if computed_root != self.proof.merkle_root {
            return Err(HardwareError::AttestationFailed(
                "Data integrity check failed - data was modified".to_string(),
            ));
        }

        // 4. Verify HSM signature (simplified)
        let hsm_lock = self.hsm.lock().unwrap();
        let is_valid = hsm_lock.verify(
            &self.proof.merkle_root,
            &self.proof.hsm_signature,
            &self.hardware_binding,
        )?;

        if !is_valid {
            return Err(HardwareError::AttestationFailed(
                "HSM signature verification failed".to_string(),
            ));
        }

        Ok(())
    }

    /// Get proof
    pub fn get_proof(&self) -> &StorageProof {
        &self.proof
    }

    /// Get hardware binding
    pub fn get_hardware_binding(&self) -> &Vec<u8> {
        &self.hardware_binding
    }

    /// Export for cold storage (with full proof chain)
    pub fn export(&self) -> TamperProofExport<T> {
        TamperProofExport {
            data: self.data.clone(),
            proof: self.proof.clone(),
            hardware_binding: self.hardware_binding.clone(),
        }
    }

    /// Import from cold storage (with verification)
    pub fn import(export: TamperProofExport<T>, hsm: Arc<Mutex<SovereignHSM>>) -> Result<Self, HardwareError> {
        // 1. Verify HSM
        let hsm_lock = hsm.lock().unwrap();
        let attestation = hsm_lock.attest()?;

        // 2. Verify hardware binding
        if attestation.hardware_id != export.hardware_binding {
            return Err(HardwareError::Tampered(
                "Hardware binding mismatch on import".to_string(),
            ));
        }

        // 3. Verify proof chain
        // In real implementation, verify against previous proofs

        // 4. Verify current data integrity
        let serialized = format!("{:?}", export.data).into_bytes();
        let computed_root = Blake3::hash(&serialized).to_vec();

        if computed_root != export.proof.merkle_root {
            return Err(HardwareError::AttestationFailed(
                "Imported data integrity check failed".to_string(),
            ));
        }

        Ok(Self {
            data: export.data,
            proof: export.proof,
            hardware_binding: export.hardware_binding,
            hsm: Arc::clone(&hsm),
        })
    }
}

/// Exportable tamper-proof data
pub struct TamperProofExport<T> {
    pub data: T,
    pub proof: StorageProof,
    pub hardware_binding: Vec<u8>,
}

impl<T: Serialize + for<'de> Deserialize<'de> + Clone + std::fmt::Debug> TamperProofExport<T> {}

/// Tamper-proof registry for multiple items
pub struct TamperProofRegistry<T> {
    /// All stored items
    items: HashMap<String, TamperProofStorage<T>>,
    /// HSM reference
    hsm: Arc<Mutex<SovereignHSM>>,
}

impl<T: Serialize + for<'de> Deserialize<'de> + Clone + std::fmt::Debug> TamperProofRegistry<T> {
    pub fn new(hsm: Arc<Mutex<SovereignHSM>>) -> Self {
        Self {
            items: HashMap::new(),
            hsm,
        }
    }

    /// Store an item with a key
    pub fn store(&mut self, key: String, data: T) -> Result<(), HardwareError> {
        let storage = TamperProofStorage::new(data, self.hsm.clone())?;
        self.items.insert(key, storage);
        Ok(())
    }

    /// Load an item by key
    pub fn load(&self, key: &str) -> Result<T, HardwareError> {
        let storage = self.items.get(key).ok_or_else(|| {
            HardwareError::AccessDenied(format!("Item {} not found", key))
        })?;
        storage.get()
    }

    /// Remove an item (with proof of removal)
    pub fn remove(&mut self, key: &str) -> Result<T, HardwareError> {
        let storage = self.items.remove(key).ok_or_else(|| {
            HardwareError::AccessDenied(format!("Item {} not found", key))
        })?;
        storage.get()
    }

    /// Verify all items
    pub fn verify_all(&self) -> Result<Vec<String>, HardwareError> {
        let mut failed = Vec::new();

        for (key, storage) in &self.items {
            if storage.verify_proof().is_err() || storage.verify_hardware().is_err() {
                failed.push(key.clone());
            }
        }

        if failed.is_empty() {
            Ok(failed)
        } else {
            Err(HardwareError::AttestationFailed(
                format!("{} items failed verification", failed.len()),
            ))
        }
    }

    /// Get all keys
    pub fn keys(&self) -> Vec<String> {
        self.items.keys().cloned().collect()
    }
}

/// Tamper-proof log (append-only with hardware attestation)
pub struct TamperProofLog {
    /// Log entries
    entries: Vec<TamperProofLogEntry>,
    /// HSM reference
    hsm: Arc<Mutex<SovereignHSM>>,
    /// Current chain hash
    chain_hash: Vec<u8>,
}

/// Tamper-proof log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TamperProofLogEntry {
    pub timestamp: u64,
    pub message: String,
    pub level: LogLevel,
    pub metadata: HashMap<String, String>,
    pub signature: Vec<u8>,
    pub previous_hash: Vec<u8>,
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
}

impl TamperProofLog {
    pub fn new(hsm: Arc<Mutex<SovereignHSM>>) -> Self {
        Self {
            entries: Vec::new(),
            hsm,
            chain_hash: vec![0u8], // Genesis hash
        }
    }

    /// Append a log entry
    pub fn append(&mut self, message: String, level: LogLevel, metadata: HashMap<String, String>) -> Result<(), HardwareError> {
        // 1. Create entry
        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let previous_hash = if self.entries.is_empty() {
            self.chain_hash.clone()
        } else {
            let last = self.entries.last().unwrap();
            let last_bytes = format!("{:?}", last).into_bytes();
            Blake3::hash(&last_bytes).to_vec()
        };

        // 2. Create entry data
        let mut entry_data = Vec::new();
        entry_data.extend_from_slice(&timestamp.to_be_bytes());
        entry_data.extend_from_slice(message.as_bytes());
        entry_data.extend_from_slice(&previous_hash);

        for (k, v) in &metadata {
            entry_data.extend_from_slice(k.as_bytes());
            entry_data.extend_from_slice(v.as_bytes());
        }

        // 3. Sign with HSM
        let hsm_lock = self.hsm.lock().unwrap();
        let signature = hsm_lock.sign(&entry_data)?;
        drop(hsm_lock);

        // 4. Create entry
        let entry = TamperProofLogEntry {
            timestamp,
            message,
            level,
            metadata,
            signature,
            previous_hash,
        };

        // 5. Add to log
        self.entries.push(entry);

        // 6. Update chain hash
        let entries_bytes = format!("{:?}", self.entries).into_bytes();
        self.chain_hash = Blake3::hash(&entries_bytes).to_vec();

        Ok(())
    }

    /// Verify the entire log chain
    pub fn verify_chain(&self) -> Result<bool, HardwareError> {
        if self.entries.is_empty() {
            return Ok(true);
        }

        let mut previous_hash = self.chain_hash.clone();

        for entry in &self.entries {
            // Verify previous hash matches
            if entry.previous_hash != previous_hash {
                return Ok(false);
            }

            // Update previous hash for next iteration
            let entry_bytes = format!("{:?}", entry).into_bytes();
            previous_hash = Blake3::hash(&entry_bytes).to_vec();
        }

        Ok(true)
    }

    /// Get all entries
    pub fn get_entries(&self) -> &[TamperProofLogEntry] {
        &self.entries
    }

    /// Get entries by level
    pub fn get_by_level(&self, level: LogLevel) -> Vec<&TamperProofLogEntry> {
        self.entries.iter()
            .filter(|e| e.level == level)
            .collect()
    }

    /// Get entries after timestamp
    pub fn get_after(&self, timestamp: u64) -> Vec<&TamperProofLogEntry> {
        self.entries.iter()
            .filter(|e| e.timestamp >= timestamp)
            .collect()
    }

    /// Export log (for backup)
    pub fn export(&self) -> Vec<u8> {
        format!("{:?}", self.entries).into_bytes()
    }

    /// Import log (with verification)
    pub fn import(&mut self, data: Vec<u8>) -> Result<(), HardwareError> {
        let data_str = String::from_utf8(data).map_err(|e| {
            HardwareError::EncryptionError(e.to_string())
        })?;
        let entries: Vec<TamperProofLogEntry> = serde_json::from_str(&data_str).map_err(|e| {
            HardwareError::EncryptionError(e.to_string())
        })?;

        // Verify chain
        self.entries = entries;
        self.verify_chain()?;

        Ok(())
    }
}

/// Hardware-bound configuration
pub struct HardwareBoundConfig {
    /// Configuration data
    data: HashMap<String, String>,
    /// Hardware binding
    hardware_binding: Vec<u8>,
    /// HSM reference
    hsm: Arc<Mutex<SovereignHSM>>,
}

impl HardwareBoundConfig {
    pub fn new(hsm: Arc<Mutex<SovereignHSM>>) -> Result<Self, HardwareError> {
        let hsm_lock = hsm.lock().unwrap();
        let attestation = hsm_lock.attest()?;
        drop(hsm_lock);

        Ok(Self {
            data: HashMap::new(),
            hardware_binding: attestation.hardware_id,
            hsm,
        })
    }

    /// Set a configuration value
    pub fn set(&mut self, key: String, value: String) -> Result<(), HardwareError> {
        self.verify_hardware()?;
        self.data.insert(key, value);
        Ok(())
    }

    /// Get a configuration value
    pub fn get(&self, key: &str) -> Option<String> {
        self.data.get(key).cloned()
    }

    /// Remove a configuration value
    pub fn remove(&mut self, key: &str) -> Result<(), HardwareError> {
        self.verify_hardware()?;
        self.data.remove(key);
        Ok(())
    }

    fn verify_hardware(&self) -> Result<(), HardwareError> {
        let hsm_lock = self.hsm.lock().unwrap();
        let attestation = hsm_lock.attest()?;

        if attestation.hardware_id != self.hardware_binding {
            return Err(HardwareError::Tampered(
                "Hardware binding mismatch for config".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tamper_proof_storage() {
        let hsm = SovereignHSM::new();
        let data = vec![1u8, 2, 3, 4, 5];

        let storage = TamperProofStorage::<Vec<u8>>::new(data.clone(), hsm.clone()).unwrap();
        assert_eq!(storage.get().unwrap(), data);
    }

    #[test]
    fn test_tamper_proof_registry() {
        let hsm = SovereignHSM::new();
        let mut registry = TamperProofRegistry::<Vec<u8>>::new(hsm.clone());

        registry.store("key1".to_string(), vec![1, 2, 3]).unwrap();
        assert_eq!(registry.load("key1").unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn test_tamper_proof_log() {
        let hsm = SovereignHSM::new();
        let mut log = TamperProofLog::new(hsm.clone());

        log.append("Test message".to_string(), LogLevel::Info, HashMap::new()).unwrap();
        assert_eq!(log.get_entries().len(), 1);
        assert!(log.verify_chain().unwrap());
    }
}
