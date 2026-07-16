//! UBE Sovereign Intelligence Layer
//! Deterministic AI, anomaly detection, and self-healing for the Sovereign Fabric.
//! Zero-dependency, constant-time, and memory-safe.

pub mod stats;
pub mod anomaly;
pub mod learning;
pub mod memory;
pub mod healing;
pub mod policy;
pub mod core;

pub use core::{ModuleIntelligence, IntelligenceHub, IntelligenceSystem};
