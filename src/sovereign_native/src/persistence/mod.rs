//! UBE Sovereign Persistence Layer
//!
//! Ensures UBE survives ALL hardware power cycles:
//! - Process daemon (always running)
//! - Boot auto-start (restart after power-on)
//! - Zero-knowledge state persistence

pub mod daemon;

pub use daemon::UbeDaemon;
