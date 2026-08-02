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
pub mod dual_core_lockstep;

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
    SecureSoftwareHSM,
    TamperEvidentStorage,
    SecureRng,
};

#[cfg(test)]
pub use core::TestHSM;

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

// Re-export dual-core lockstep types
pub use dual_core_lockstep::{
    DualCoreLockstep,
    DualCoreConfig,
    LockstepError,
    LockstepResult,
    SecureBootChain,
};

// Re-export quantum security types from crate root (commented out to avoid conflicts with crypto::QRNGType)
// Notes: Some types conflict with existing types in crypto module

// Re-export threshold crypto types from crate root (commented out temporarily)

// Re-export PUF types from crate root (commented out temporarily)

// Re-export ORAM types from crate root (commented out temporarily)

// Re-export QRNG types from crate root (commented out temporarily)

// Re-export side-channel types from crate root (commented out temporarily)

// Re-export secure healing types
pub mod secure_healing;

// Re-export absolute security types
pub mod absolute_security;
pub use absolute_security::{AbsoluteSecurity, AbsoluteSecurityState};

// Re-export zero-knowledge types
pub mod zero_knowledge;

// Re-export universal hardware access types
pub mod access;
pub use access::{UniversalHardwareAccessor, HardwareAccessError, HardwareResult, FileInfo, ProcessInfo, MemoryInfo, CpuInfo, DiskInfo, BatteryInfo, SystemInfo, HardwareAccessor};
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

// Re-export attack matrix types
pub mod attack_matrix;
pub use attack_matrix::{
    AttackMatrix,
    AttackMatrixEntry,
    AttackMatrixIntegrator,
    AttackTactic,
    AttackEvent,
    AttackStats,
    ASIAttackSimulator,
    HumanAttackPrevention,
    MisconfigDetector,
    PhysicalAttackDetector,
    SecurityDomain,
    UniversalPillar,
    EnforcementStatus,
    VerificationReport,
    VerificationEntry,
    VerificationSummary,
    TacticStats,
    PillarStats,
    create_attack_matrix,
    create_asi_simulator,
    create_human_prevention,
};
