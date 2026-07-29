//! UBE Sovereign Persistence Layer
//!
//! Ensures UBE survives ALL hardware power cycles:
//! - Process daemon (always running)
//! - Boot auto-start (restart after power-on)
//! - Zero-knowledge state persistence
//! - Immortal ledger (remembers everything)

use std::sync::Arc;

pub mod daemon;
pub mod ledger;

pub use daemon::UbeDaemon;
pub use ledger::{UbeState, StateManager, WorkItem, WorkStatus, AutomationRule, default_state_manager, generate_work_id, generate_rule_id};

// Compatibility with existing code
#[derive(Clone)]
pub struct SovereignPersistence {
    backend: StorageBackend,
}

impl SovereignPersistence {
    pub fn new(backend: StorageBackend) -> Arc<Self> {
        Arc::new(Self { backend })
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum StorageBackend {
    #[default]
    Memory,
    File,
    Database,
}
