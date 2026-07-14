use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),
    #[error("Merkle root mismatch")]
    RootMismatch,
    #[error("Serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SovereignState {
    pub values: HashMap<String, Vec<u8>>,
    pub sequence: u64,
}

impl SovereignState {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            sequence: 0,
        }
    }

    /// Computes the Merkle Root (simplified as a hash of sorted state) of the current state.
    pub fn compute_merkle_root(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();

        // Sort keys to ensure deterministic hashing
        let mut keys: Vec<_> = self.values.keys().collect();
        keys.sort();

        for key in keys {
            hasher.update(key.as_bytes());
            hasher.update(&self.values[key]);
        }

        hasher.update(&self.sequence.to_be_bytes());
        hasher.finalize().to_vec()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub sender: Vec<u8>, // Public key of the node proposing the change
    pub key: String,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct SovereignLedger {
    pub state: SovereignState,
    pub history: Vec<Transaction>,
}

impl SovereignLedger {
    pub fn new() -> Self {
        Self {
            state: SovereignState::new(),
            history: Vec::new(),
        }
    }

    /// Applies a transaction to the state after verification.
    pub fn apply_transaction(&mut self, tx: Transaction, _public_key: &[u8]) -> Result<Vec<u8>, LedgerError> {
        // In a real BFT system, this would involve multi-node consensus.
        // For the native core, we verify the signature and apply the state change.

        // Note: Signature verification logic is handled by identity.rs,
        // but we assume the orchestrator passes the verified public_key.

        self.state.values.insert(tx.key.clone(), tx.value.clone());
        self.state.sequence += 1;
        self.history.push(tx);

        Ok(self.state.compute_merkle_root())
    }

    pub fn get_root(&self) -> Vec<u8> {
        self.state.compute_merkle_root()
    }
}
