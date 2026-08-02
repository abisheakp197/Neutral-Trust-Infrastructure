//! Sovereign Guardian - Zero-Error Enforcement
//!
//! 5-Layer Validation:
//! 1. Schema Validation
//! 2. Type Safety Validation
//! 3. Bounds Validation
//! 4. Consensus Voting (3 validators)
//! 5. Final Decision

use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use crate::ledger::SovereignLedger;
use crate::proxy_types::ProxyWorkOrder;
use crate::types::Value;

/// Validation context
#[derive(Debug, Clone)]
pub struct ValidationContext {
    pub timestamp: u64,
    pub entity_id: String,
    pub session_id: String,
    pub current_state: Value,
    pub historical_patterns: Vec<()>, // Placeholder for pattern matching
    pub threat_level: f64,
}

/// Final decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalDecision {
    Approved, Rejected, Quarantined, RequiresHumanReview,
}

impl FinalDecision {
    pub fn display_reason(&self) -> &'static str {
        match self {
            FinalDecision::Approved => "All validations passed",
            FinalDecision::Rejected => "Critical validation failed",
            FinalDecision::Quarantined => "High risk detected",
            FinalDecision::RequiresHumanReview => "Review required",
        }
    }
}

/// Individual validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub validator_id: String,
    pub is_valid: bool,
    pub risk_score: f64,
    pub reason: String,
}

/// Vote from consensus validator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vote { Approve, Reject, Abstain }

/// Vote record
#[derive(Debug, Clone)]
pub struct VoteRecord {
    pub validator_id: String,
    pub vote: Vote,
}

/// Guard result
#[derive(Debug, Clone)]
pub struct GuardResult {
    pub decision: FinalDecision,
    pub validation_results: Vec<ValidationResult>,
    pub consensus_votes: Vec<VoteRecord>,
    pub risk_score: f64,
}

impl GuardResult {
    pub fn display_reason(&self) -> String {
        self.decision.display_reason().to_string()
    }
}

/// Pre-validator trait
pub trait PreValidator: Send + Sync {
    fn validate(&self, work: &ProxyWorkOrder, ctx: &ValidationContext) -> ValidationResult;
    fn id(&self) -> &str;
}

/// Consensus validator trait
pub trait ConsensusValidator: Send + Sync {
    fn vote(&self, work: &ProxyWorkOrder, pre_results: &[ValidationResult]) -> Vote;
    fn id(&self) -> &str;
}

/// Sovereign Guardian
pub struct SovereignGuardian {
    guardian_id: String,
    ledger: Arc<RwLock<SovereignLedger>>,
    pre_validators: Arc<RwLock<Vec<Arc<dyn PreValidator + Send + Sync>>>>,
    consensus_validators: Arc<RwLock<Vec<Arc<dyn ConsensusValidator + Send + Sync>>>>,
}

impl SovereignGuardian {
    pub fn new(ledger: Arc<RwLock<SovereignLedger>>) -> Self {
        Self {
            guardian_id: format!("guardian:{}", now()),
            ledger,
            pre_validators: Arc::new(RwLock::new(Self::make_pre_validators())),
            consensus_validators: Arc::new(RwLock::new(Self::make_consensus_validators())),
        }
    }

    fn make_pre_validators() -> Vec<Arc<dyn PreValidator + Send + Sync>> {
        vec![
            Arc::new(SchemaValidator),
            Arc::new(BoundsValidator),
            Arc::new(TypeValidator),
        ]
    }

    fn make_consensus_validators() -> Vec<Arc<dyn ConsensusValidator + Send + Sync>> {
        vec![
            Arc::new(SecurityConsensus),
            Arc::new(RiskConsensus),
            Arc::new(LogicConsensus),
        ]
    }

    pub async fn validate(&self, work: &ProxyWorkOrder, ctx: ValidationContext) -> GuardResult {
        let pre_results = self.run_pre_validation(work, &ctx);
        let votes = self.run_consensus(work, &pre_results);
        let (decision, risk_score) = self.make_decision(work, &pre_results, &votes);
        self.log_validation(work, &pre_results, &votes, decision);
        GuardResult { decision, validation_results: pre_results, consensus_votes: votes, risk_score }
    }

    fn run_pre_validation(&self, work: &ProxyWorkOrder, ctx: &ValidationContext) -> Vec<ValidationResult> {
        self.pre_validators.read().unwrap().iter().map(|v| v.validate(work, ctx)).collect()
    }

    fn run_consensus(&self, work: &ProxyWorkOrder, pre_results: &[ValidationResult]) -> Vec<VoteRecord> {
        self.consensus_validators.read().unwrap().iter()
            .map(|v| VoteRecord { validator_id: v.id().to_string(), vote: v.vote(work, pre_results) })
            .collect()
    }

    fn make_decision(&self, work: &ProxyWorkOrder, pre: &[ValidationResult], votes: &[VoteRecord]) -> (FinalDecision, f64) {
        let max_risk = pre.iter().map(|r| r.risk_score).fold(0.0_f64, f64::max);
        if pre.iter().any(|r| !r.is_valid) { return (FinalDecision::Rejected, max_risk); }
        let approve = votes.iter().filter(|v| v.vote == Vote::Approve).count();
        let reject = votes.iter().filter(|v| v.vote == Vote::Reject).count();

        if work.irreversible && work.source.is_outer_world() && approve < 2 {
            return (FinalDecision::Rejected, max_risk);
        }
        if max_risk > 0.5 && reject > 0 { return (FinalDecision::Quarantined, max_risk); }
        if reject > 0 { return (FinalDecision::RequiresHumanReview, max_risk); }
        (FinalDecision::Approved, max_risk)
    }

    fn log_validation(&self, work: &ProxyWorkOrder, pre: &[ValidationResult], _votes: &[VoteRecord], decision: FinalDecision) {
        let mut ledger = self.ledger.write().unwrap();
        let mut record = Value::Object(serde_json::Map::new());
        record["type"] = Value::String("guardian_validation".to_string());
        record["order_id"] = Value::String(work.order_id.clone());
        record["entity_id"] = Value::String(work.source.entity_id());
        record["decision"] = Value::String(format!("{:?}", decision));
        record["risk_score"] = Value::Number(serde_json::Number::from_f64(pre.iter().map(|r| r.risk_score).fold(f64::NEG_INFINITY, |a, b| a.max(b))).unwrap_or(serde_json::Number::from_f64(0.0).unwrap()));
        record["timestamp"] = Value::Number(now().into());
        record["guardian"] = Value::String(self.guardian_id.clone());
        ledger.append(record);
    }
}

// Pre-Validators
struct SchemaValidator;
impl PreValidator for SchemaValidator {
    fn validate(&self, work: &ProxyWorkOrder, _: &ValidationContext) -> ValidationResult {
        let (valid, risk, reason) = match &work.request {
            Value::Object(_) => (true, 0.0, "Valid JSON object"),
            _ => (false, 0.5, "Request must be JSON object"),
        };
        ValidationResult { validator_id: "schema".into(), is_valid: valid, risk_score: risk, reason: reason.into() }
    }
    fn id(&self) -> &str { "schema" }
}

struct BoundsValidator;
impl PreValidator for BoundsValidator {
    fn validate(&self, work: &ProxyWorkOrder, _: &ValidationContext) -> ValidationResult {
        let size = match &work.request {
            Value::Object(m) => m.len(), Value::Array(a) => a.len(), _ => 0,
        };
        if size > 1000 {
            ValidationResult { validator_id: "bounds".into(), is_valid: false, risk_score: 0.4, reason: "Request too large".into() }
        } else {
            ValidationResult { validator_id: "bounds".into(), is_valid: true, risk_score: 0.0, reason: "Within bounds".into() }
        }
    }
    fn id(&self) -> &str { "bounds" }
}

struct TypeValidator;
impl PreValidator for TypeValidator {
    fn validate(&self, work: &ProxyWorkOrder, _: &ValidationContext) -> ValidationResult {
        // SOVEREIGN SECURITY FIX: Actually validate the work order structure
        // instead of always approving. Checks for required fields and consistency.

        // Check that work order has a valid ID
        if work.order_id.is_empty() {
            return ValidationResult {
                validator_id: "type".into(),
                is_valid: false,
                risk_score: 0.5,
                reason: "Work order has empty ID".into(),
            };
        }

        // Check that request is not null or empty
        if work.request.is_null() {
            return ValidationResult {
                validator_id: "type".into(),
                is_valid: false,
                risk_score: 0.7,
                reason: "Work order has null request".into(),
            };
        }

        // Check for outer world operations
        if work.source.is_outer_world() {
            // Outer world operations cannot be undone - verify undo_token is absent
            if work.undo_token.is_some() {
                return ValidationResult {
                    validator_id: "type".into(),
                    is_valid: false,
                    risk_score: 0.9,
                    reason: "Outer world operation cannot have undo_token".into(),
                };
            }
        }

        // Check timeout is reasonable
        if let Some(timeout) = work.timeout {
            if timeout.as_secs() == 0 {
                return ValidationResult {
                    validator_id: "type".into(),
                    is_valid: false,
                    risk_score: 0.6,
                    reason: "Work order has zero timeout".into(),
                };
            }
            // Timeout should be reasonable (less than 24 hours)
            if timeout.as_secs() > 86400 {
                return ValidationResult {
                    validator_id: "type".into(),
                    is_valid: false,
                    risk_score: 0.4,
                    reason: format!("Work order timeout too long: {} seconds", timeout.as_secs()),
                };
            }
        }

        ValidationResult { validator_id: "type".into(), is_valid: true, risk_score: 0.0, reason: "All structural validations passed".into() }
    }
    fn id(&self) -> &str { "type" }
}

// Consensus Validators
struct SecurityConsensus;
impl ConsensusValidator for SecurityConsensus {
    fn vote(&self, _work: &ProxyWorkOrder, pre: &[ValidationResult]) -> Vote {
        if pre.iter().any(|r| !r.is_valid) { Vote::Reject } else { Vote::Approve }
    }
    fn id(&self) -> &str { "security" }
}

struct RiskConsensus;
impl ConsensusValidator for RiskConsensus {
    fn vote(&self, _: &ProxyWorkOrder, pre: &[ValidationResult]) -> Vote {
        let max_risk = pre.iter().map(|r| r.risk_score).fold(0.0, f64::max);
        if max_risk > 0.3 { Vote::Reject } else { Vote::Approve }
    }
    fn id(&self) -> &str { "risk" }
}

struct LogicConsensus;
impl ConsensusValidator for LogicConsensus {
    fn vote(&self, work: &ProxyWorkOrder, pre: &[ValidationResult]) -> Vote {
        // SOVEREIGN SECURITY FIX: Actually analyze the logic of the work order
        // Instead of always approving, we check for logical consistency

        // Rule 1: If pre-validation failed, reject
        if pre.iter().any(|r| !r.is_valid) {
            return Vote::Reject;
        }

        // Rule 2: Check for circular dependencies
        if Self::has_circular_dependencies(work) {
            return Vote::Reject;
        }

        // Rule 3: Check for invalid state transitions
        if Self::has_invalid_transitions(work) {
            return Vote::Reject;
        }

        // Rule 4: Check for empty work orders
        if work.request.is_null() && work.order_id.is_empty() {
            return Vote::Reject;
        }

        // Rule 5: Check risk scores from pre-validation
        if !pre.is_empty() {
            let avg_risk: f64 = pre.iter().map(|r| r.risk_score).sum::<f64>() / pre.len() as f64;
            if avg_risk > 0.5 {
                return Vote::Reject;
            }
        }

        // Rule 6: Inner world operations should have undo_token
        if work.source.is_inner_world() && work.undo_token.is_none() {
            return Vote::Reject;
        }

        // Only approve if all checks pass
        Vote::Approve
    }
    fn id(&self) -> &str { "logic" }
}

impl LogicConsensus {
    fn has_circular_dependencies(_work: &ProxyWorkOrder) -> bool {
        // In a full implementation, this would check for circular
        // dependencies between work orders. For now, we return false
        false
    }

    fn has_invalid_transitions(_work: &ProxyWorkOrder) -> bool {
        // In production, check against resource permissions
        false
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
}
