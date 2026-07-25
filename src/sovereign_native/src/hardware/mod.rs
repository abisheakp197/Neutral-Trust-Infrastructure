//! UBE Sovereign Hardware Security Module
//!
//! Main hardware security module that provides:
//! - Hardware Security Module (HSM) integration
//! - Anti-tampering system
//! - Intrusion detection system
//! - Tamper-proof storage
//! - Secure healing engine

pub mod core;
pub mod anti_tamper;
pub mod intrusion_detection;
pub mod tamper_proof;

// Re-export all types from core
pub use core::{
    HardwareSecurityModule,
    SovereignHSM,
    SecurityLevel,
    SecurityStatus,
    AttestationReport,
    SecureMemory,
    MemoryAccessPolicy,
    HardwareError,
    SoftwareFallbackHSM,
    TamperEvidentStorage,
    SecureRng,
};

// Re-export anti-tamper types
pub use anti_tamper::{
    AntiTamperSystem,
    TamperStatus,
    TamperEvent,
    TamperMethod,
    CodeIntegrityChecker,
    MemoryIntegrityMonitor,
    RuntimeMonitor,
    PhysicalTamperDetector,
    SelfDestruct,
    DestructCondition,
    SecureMemoryZeroizer,
};

// Re-export intrusion detection types
pub use intrusion_detection::{
    IntrusionDetectionSystem,
    IntrusionEvent,
    IntrusionEventType,
    IntrusionAction,
    ConnectionTracker,
    ConnectionState,
    ConnectionRecord,
    PayloadAnalyzer,
    BehaviorAnalyzer,
    BehaviorSession,
    IntrusionDetectionConfig,
    IdsStatus,
};

// Re-export tamper-proof types
pub use tamper_proof::{
    TamperProofStorage,
    StorageProof,
    TamperProofExport,
    TamperProofRegistry,
    TamperProofLog,
    TamperProofLogEntry,
    LogLevel,
    HardwareBoundConfig,
};

// Re-export secure healing types
pub mod secure_healing;

// Re-export absolute security types
pub mod absolute_security;
pub use absolute_security::{AbsoluteSecurity, AbsoluteSecurityState};

// Re-export zero-knowledge types
pub mod zero_knowledge;
pub use zero_knowledge::{
    ZkPrivacyLevel,
    ZkProof,
    ZkProofType,
    ZkTransaction,
    ZkDataVault,
    ZkNode,
    ZkNetwork,
};

// Re-export omni-healing types
pub mod omni_healing;
pub use omni_healing::{
    OmniHealingEngine,
    OmniHealingAction,
    OmniHealingRecord,
    HealingLayer,
    OmniHealer,
};

// Re-export data black box types
pub mod data_blackbox;
pub use data_blackbox::{
    DataBlackBox,
    PhysicalDataDestructor,
};

// Re-export developer immutability types
pub mod developer_immutability;
pub use developer_immutability::{
    DeveloperImmutabilityEngine,
    DeveloperIdentity,
    ModuleSecurityLevel,
    ImmutableCodeSeal,
    UpdatePolicyEngine,
    ChangeType,
    IMMUTABLE_MODULES,
};
pub use secure_healing::{
    SecureHealingEngine,
    SecureHealingState,
    SecureHealingAction,
    HealingCertificate,
    SecureHealingPlaybook,
    HealingCondition,
    ConditionType,
    HardwareFaultDetector,
    FaultType,
    FaultDetection,
    FaultDetectionSummary,
    HealingSnapshot,
};
