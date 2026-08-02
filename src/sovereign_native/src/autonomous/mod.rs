//! UBE Unified Autonomous Self-Healing System
//!
//! Single point for all autonomous/self-healing functionality:
//! - Code optimization (code_optimizer.rs)
//! - Service monitoring and restart (self_healing.rs)
//! - Combined access to hardware healing modules

pub mod code_optimizer;
pub mod self_healing;

pub use code_optimizer::*;
pub use self_healing::*;
