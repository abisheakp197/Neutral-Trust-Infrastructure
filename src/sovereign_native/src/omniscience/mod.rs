//! UBE Omniscience Layer
//!
//! This is the SELF-LEARNING + SELF-AUTOMATING system.
//!
//! Design Principle:
//! - WATCH everything the user does
//! - DETECT repetitive patterns
//! - CREATE universal laws from patterns
//! - ENFORCE laws automatically (no human setup)
//!
//! This is what you built UBE for: Omniscience = All-knowing + Self-acting

pub mod observer;
pub mod auto_executor;

pub use observer::{
    OmniscienceObserver,
    OmniEvent,
    OmniPattern,
    UniversalLaw,
    LawCondition,
    LawEnforcement,
    EnforcementMode,
    OmniStats,
    OMNI_OBSERVER,
    observe_event,
    check_automation,
};

pub use auto_executor::{
    AutoExecutor,
    start_auto_executor,
    AUTO_EXECUTOR,
    hook_file_operation,
};
