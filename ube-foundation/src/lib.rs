pub mod network;

use ed25519_dalek::{Signature, Verifier, VerifyingKey, SigningKey, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaveatType {
    Expires(String),         // ISO 8601 timestamp
    MaxExecutions(u64),      // Maximum number of times this token can be used
    ValueLimit(u64, String), // (amount, currency) e.g., (50, "USD")
    PathRestricted(String),  // Required prefix for path-based actions
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Caveat {
    pub location: Option<String>,
    pub condition: CaveatType,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    pub id: String,
    pub root_actor: String,
    pub capability: String,
    pub caveats: Vec<Caveat>,
    pub signature: Vec<u8>,
}

impl CapabilityToken {
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.id,
            &self.root_actor,
            &self.capability,
            &self.caveats,
        );
        serde_json::to_vec(&data).expect("serialization for token signing")
    }

    pub fn verify(&self, public_key_bytes: &[u8]) -> bool {
        let Ok(bytes) = public_key_bytes.try_into() else {
            return false;
        };
        let Ok(public_key) = VerifyingKey::from_bytes(bytes) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        public_key.verify(&self.message_to_sign(), &signature).is_ok()
    }
}

impl TrustEngine {
    pub fn verify_consensus(&self, proposal: &ConsensusProposal, threshold: usize) -> bool {
        let mut valid_votes = 0;
        let mut hash_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut seen_voters: BTreeSet<String> = BTreeSet::new();

        for vote in &proposal.votes {
            // Verify vote signature against payload
            if !vote.verify() {
                continue;
            }

            // If voter key is registered in TrustEngine, enforce key binding to voter_id
            if let Some(registered_key) = self.voter_keys.get(&vote.voter_id) {
                if registered_key != &vote.public_key {
                    continue;
                }
            }

            // Prevent duplicate votes from the same voter identity
            if !seen_voters.insert(vote.voter_id.clone()) {
                continue;
            }

            if vote.decision.as_ref().map(|d| d.decision == Decision::Allow).unwrap_or(false) {
                valid_votes += 1;
                *hash_counts.entry(vote.outcome_hash.clone()).or_insert(0) += 1;
            }
        }

        // Must meet threshold AND have agreement on outcome hash
        valid_votes >= threshold && hash_counts.values().any(|&count| count >= threshold)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeIdentity {
    pub version: String,
    pub source_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityClaim {
    pub agent_id: String,
    pub code_identity: CodeIdentity,
    pub provider: String,
    pub claim_type: String,
    pub value: String,
    pub proof: Vec<u8>,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl IdentityClaim {
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.agent_id,
            &self.code_identity.version,
            &self.code_identity.source_hash,
            &self.provider,
            &self.claim_type,
            &self.value,
        );
        serde_json::to_vec(&data).expect("serialization for identity claim")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRequest {
    pub id: String,
    pub actor: String,
    pub capability: String,
    pub action: String,
    pub input: serde_json::Value,
    pub signature: Option<Vec<u8>>,
    pub pqc_signature: Option<PqcSignature>,
    pub public_key: Option<Vec<u8>>,
    pub pqc_public_key: Option<Vec<u8>>,
    pub token: Option<CapabilityToken>,
    pub identity_claim: Option<IdentityClaim>,
}

impl ActionRequest {
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.id,
            &self.actor,
            &self.capability,
            &self.action,
            &self.input,
        );
        serde_json::to_vec(&data).expect("serialization for action request")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    InProgress,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVote {
    pub voter_id: String,
    pub request_id: String,
    pub decision: Option<PolicyDecision>,
    pub outcome_hash: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ConsensusVote {
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.voter_id,
            &self.request_id,
            &self.decision,
            &self.outcome_hash,
        );
        serde_json::to_vec(&data).expect("serialization for vote signing")
    }

    pub fn verify(&self) -> bool {
        if self.public_key.is_empty() || self.signature.is_empty() {
            return false;
        }
        let Ok(bytes) = self.public_key.as_slice().try_into() else {
            return false;
        };
        let Ok(public_key) = VerifyingKey::from_bytes(bytes) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        public_key.verify(&self.message_to_sign(), &signature).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    pub request_id: String,
    pub votes: Vec<ConsensusVote>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub request: ActionRequest,
    pub decision: PolicyDecision,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBatch {
    pub events: Vec<AuditEvent>,
    pub merkle_root: String,
    pub prev_batch_hash: String,
}

#[derive(Debug, Default)]
pub struct TrustEngine {
    capabilities: BTreeMap<String, BTreeSet<String>>,
    expected_code_hashes: BTreeMap<String, String>,
    voter_keys: BTreeMap<String, Vec<u8>>,
    revocation_list: BTreeSet<String>,
    events: Vec<AuditEvent>,
    batches: Vec<AuditBatch>,
    last_batch_hash: String,
}

pub struct CaveatInterpreter;

impl CaveatInterpreter {
    pub fn verify_all(caveats: &[Caveat], request: &ActionRequest, engine: &TrustEngine) -> OutcomeVerdict {
        for caveat in caveats {
            match &caveat.condition {
                CaveatType::MaxExecutions(max) => {
                    let count = engine.events.iter()
                        .filter(|e| e.request.token.as_ref().map(|t| &t.id) == request.token.as_ref().map(|t| &t.id))
                        .count();
                    if count as u64 >= *max {
                        return OutcomeVerdict::Invalid(format!("Execution limit reached: {}", max));
                    }
                }
                CaveatType::ValueLimit(max_val, _curr) => {
                    let val = request.input["amount"].as_u64().unwrap_or(0);
                    if val > *max_val {
                        return OutcomeVerdict::Invalid(format!("Value limit exceeded: {} > {}", val, max_val));
                    }
                }
                CaveatType::PathRestricted(prefix) => {
                    let path = request.input["path"].as_str().unwrap_or("");
                    if !path.starts_with(prefix) {
                        return OutcomeVerdict::Invalid(format!("Path restricted: {} must start with {}", path, prefix));
                    }
                }
                CaveatType::Expires(timestamp) => {
                    if let Ok(expiry) = timestamp.parse::<chrono::DateTime<chrono::Utc>>().or_else(|_| chrono::DateTime::parse_from_rfc3339(timestamp).map(|dt| dt.with_timezone(&chrono::Utc))) {
                        if chrono::Utc::now() > expiry {
                            return OutcomeVerdict::Invalid(format!("Token expired at {}", timestamp));
                        }
                    } else {
                        return OutcomeVerdict::Invalid(format!("Invalid expiry format: {}", timestamp));
                    }
                }
            }
        }
        OutcomeVerdict::Valid
    }
}

impl TrustEngine {
    pub fn new() -> Self {
        Self {
            capabilities: BTreeMap::new(),
            expected_code_hashes: BTreeMap::new(),
            voter_keys: BTreeMap::new(),
            revocation_list: BTreeSet::new(),
            events: Vec::new(),
            batches: Vec::new(),
            last_batch_hash: "".into(),
        }
    }

    pub fn register_voter_key(&mut self, voter_id: impl Into<String>, public_key: Vec<u8>) {
        self.voter_keys.insert(voter_id.into(), public_key);
    }
    pub fn revoke_token(&mut self, token_id: impl Into<String>) {
        self.revocation_list.insert(token_id.into());
    }

    pub fn register_expected_hash(&mut self, agent_id: impl Into<String>, hash: impl Into<String>) {
        self.expected_code_hashes.insert(agent_id.into(), hash.into());
    }

    pub fn grant(&mut self, actor: impl Into<String>, capability: impl Into<String>) {
        self.capabilities
            .entry(actor.into())
            .or_default()
            .insert(capability.into());
    }

    fn compute_merkle_root(events: &[AuditEvent]) -> String {
        if events.is_empty() { return "".into(); }
        let mut hashes: Vec<String> = events.iter().map(|e| e.hash.clone()).collect();
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..hashes.len()).step_by(2) {
                let mut hasher = Sha256::new();
                hasher.update(&hashes[i]);
                if i + 1 < hashes.len() { hasher.update(&hashes[i + 1]); }
                else { hasher.update(&hashes[i]); }
                next_level.push(hex::encode(hasher.finalize()));
            }
            hashes = next_level;
        }
        hashes[0].clone()
    }

    pub fn commit_batch(&mut self) -> Option<String> {
        if self.events.is_empty() { return None; }
        let merkle_root = Self::compute_merkle_root(&self.events);
        let events = std::mem::take(&mut self.events);
        let batch = AuditBatch { events, merkle_root, prev_batch_hash: self.last_batch_hash.clone() };
        let body = serde_json::to_vec(&batch).expect("batch serialization");
        let batch_hash = hex::encode(Sha256::digest(body));
        self.last_batch_hash = batch_hash.clone();
        self.batches.push(batch);
        Some(batch_hash)
    }

    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecision {
        // PQC Verification (Post-Quantum Durability)
        if let Some(pqc_sig) = &request.pqc_signature {
            if let Some(_pqc_pk) = &request.pqc_public_key {
                 // Placeholder for actual Dilithium/Kyber verification logic
                 // This proves the structural readiness for Global Trust
                 if pqc_sig.algorithm != "Dilithium5" {
                     return PolicyDecision { decision: Decision::Deny, reason: "unsupported pqc algorithm".into() };
                 }
            }
        }

        if let Some(claim) = &request.identity_claim {
            let Ok(pk) = VerifyingKey::from_bytes(claim.public_key.as_slice().try_into().unwrap_or(&[0;32])) else {
                return PolicyDecision { decision: Decision::Deny, reason: "invalid identity pk".into() };
            };
            let Ok(sig) = Signature::from_slice(&claim.signature) else {
                return PolicyDecision { decision: Decision::Deny, reason: "invalid identity sig".into() };
            };
            if pk.verify(&claim.message_to_sign(), &sig).is_err() {
                return PolicyDecision { decision: Decision::Deny, reason: "identity sig mismatch".into() };
            }
            if let Some(expected) = self.expected_code_hashes.get(&claim.agent_id) {
                if &claim.code_identity.source_hash != expected {
                    return PolicyDecision { decision: Decision::Deny, reason: "code hash mismatch".into() };
                }
            }
        }

        if let (Some(sig_bytes), Some(pk_bytes)) = (&request.signature, &request.public_key) {
            let Ok(pk) = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0;32])) else {
                return PolicyDecision { decision: Decision::Deny, reason: "invalid pk".into() };
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                return PolicyDecision { decision: Decision::Deny, reason: "invalid sig".into() };
            };
            if pk.verify(&request.message_to_sign(), &sig).is_err() {
                return PolicyDecision { decision: Decision::Deny, reason: "sig mismatch".into() };
            }
        }

        if let Some(token) = &request.token {
            if self.revocation_list.contains(&token.id) {
                return PolicyDecision { decision: Decision::Deny, reason: "token revoked".into() };
            }
            if token.capability != request.capability {
                 return PolicyDecision { decision: Decision::Deny, reason: "token cap mismatch".into() };
            }
            if let OutcomeVerdict::Invalid(reason) = CaveatInterpreter::verify_all(&token.caveats, request, self) {
                return PolicyDecision { decision: Decision::Deny, reason: format!("caveat violation: {}", reason) };
            }
            return PolicyDecision { decision: Decision::Allow, reason: "token verified".into() };
        }

        let allowed = self.capabilities.get(&request.actor).is_some_and(|caps| caps.contains(&request.capability));
        if allowed { PolicyDecision { decision: Decision::Allow, reason: "granted".into() } }
        else { PolicyDecision { decision: Decision::Deny, reason: "no cap".into() } }
    }

    pub fn record(&mut self, request: ActionRequest) -> PolicyDecision {
        let decision = self.evaluate(&request);
        let previous_hash = self.events.last().map(|e| e.hash.clone()).unwrap_or_else(|| self.last_batch_hash.clone());
        let sequence = self.events.len() as u64;
        let body = serde_json::to_vec(&(sequence, &request, &decision, &previous_hash)).expect("audit serialization");
        let hash = hex::encode(Sha256::digest(body));
        self.events.push(AuditEvent { sequence, request, decision: decision.clone(), previous_hash, hash });
        if self.events.len() >= 10 { self.commit_batch(); }
        decision
    }

    pub fn verify_history(&self) -> bool {
        let mut prev_hash = "".to_string();
        for batch in &self.batches {
            if batch.prev_batch_hash != prev_hash { return false; }
            let mut event_prev = batch.prev_batch_hash.clone();
            for event in &batch.events {
                if event.previous_hash != event_prev { return false; }
                let body = serde_json::to_vec(&(event.sequence, &event.request, &event.decision, &event.previous_hash)).expect("audit serialization");
                if event.hash != hex::encode(Sha256::digest(body)) { return false; }
                event_prev = event.hash.clone();
            }
            if Self::compute_merkle_root(&batch.events) != batch.merkle_root { return false; }
            let body = serde_json::to_vec(&batch).expect("batch serialization");
            prev_hash = hex::encode(Sha256::digest(body));
        }
        let mut event_prev = if self.batches.is_empty() { "".to_string() } else { self.last_batch_hash.clone() };
        for event in &self.events {
            if event.previous_hash != event_prev { return false; }
            let body = serde_json::to_vec(&(event.sequence, &event.request, &event.decision, &event.previous_hash)).expect("audit serialization");
            if event.hash != hex::encode(Sha256::digest(body)) { return false; }
            event_prev = event.hash.clone();
        }
        true
    }
}

#[async_trait::async_trait]
pub trait Module: Send + Sync {
    fn name(&self) -> &str;
    fn capabilities(&self) -> Vec<String>;
    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, String>;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStandard {
    SOC2,
    Uptime(u8),
    LegalCompliance,
    AirGapped,
    FormalVerification,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndependentCredential {
    pub verifier_id: String,
    pub standard: VerificationStandard,
    pub evidence_hash: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProfile {
    pub provider_id: String,
    pub service_metadata: serde_json::Value,
    pub credentials: Vec<IndependentCredential>,
    pub reputation_score: f64,
    pub total_outcomes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionLogic {
    pub required_standards: Vec<VerificationStandard>,
    pub min_reputation: f64,
}

impl SelectionLogic {
    pub fn is_eligible(&self, profile: &ProviderProfile, layer: &RecommendationLayer) -> bool {
        if profile.reputation_score < self.min_reputation {
            return false;
        }

        for req in &self.required_standards {
            let has_valid = profile.credentials.iter().any(|cred| {
                cred.standard == *req &&
                cred.expires_at > chrono::Utc::now() &&
                layer.verify_credential(cred)
            });
            if !has_valid { return false; }
        }
        true
    }

    pub fn tie_break<'a>(&self, eligible: Vec<&'a ProviderProfile>) -> Option<&'a ProviderProfile> {
        if eligible.is_empty() { return None; }

        let unproven: Vec<&&ProviderProfile> = eligible.iter()
            .filter(|p| p.total_outcomes < 10)
            .collect();

        if !unproven.is_empty() {
            let mut rng = rand::thread_rng();
            if rand::Rng::gen_bool(&mut rng, 0.1) {
                let idx = rand::Rng::gen_range(&mut rng, 0..unproven.len());
                return Some(*unproven[idx]);
            }
        }

        eligible.into_iter()
            .max_by(|a, b| a.reputation_score.partial_cmp(&b.reputation_score).unwrap_or(std::cmp::Ordering::Equal))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOutcome {
    pub provider_id: String,
    pub request_id: String,
    pub success: bool,
    pub user_feedback: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifierTier {
    Foundational,
    Community,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierProfile {
    pub id: String,
    pub tier: VerifierTier,
    pub public_key: Vec<u8>,
    pub reputation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationNotice {
    pub credential_hash: String,
    pub reason: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRecord {
    pub provider_id: String,
    pub verifier_id: String,
    pub claim: String,
    pub evidence: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationFee {
    pub provider_id: String,
    pub verifier_id: String,
    pub amount: u64,
    pub currency: String,
    pub fee_type: FeeType,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeeType {
    InitialVerification,
    Renewal,
    TransactionCommission(f64),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionAudit {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub request_id: String,
    pub logic: SelectionLogic,
    pub eligible_providers: Vec<String>,
    pub selected_provider: Option<String>,
    pub reasoning: String,
}

pub struct RecommendationLayer {
    pub verifiers: BTreeMap<String, VerifierProfile>,
    pub providers: BTreeMap<String, ProviderProfile>,
    pub revocations: BTreeMap<String, RevocationNotice>,
    pub disputes: Vec<DisputeRecord>,
}

impl RecommendationLayer {
    pub fn new() -> Self {
        Self {
            verifiers: BTreeMap::new(),
            providers: BTreeMap::new(),
            revocations: BTreeMap::new(),
            disputes: Vec::new(),
        }
    }

    pub fn add_dispute(&mut self, record: DisputeRecord) {
        self.disputes.push(record);
    }

    pub fn process_fee(&self, fee: &VerificationFee) {
        println!("FEE LOG: Provider {} paid {} {} for {:?} to Verifier {}",
            fee.provider_id, fee.amount, fee.currency, fee.fee_type, fee.verifier_id);
    }

    pub fn verify_credential(&self, cred: &IndependentCredential) -> bool {
        if let Some(notice) = self.revocations.get(&cred.evidence_hash) {
            let msg = serde_json::json!({
                "credential_hash": notice.credential_hash,
                "reason": notice.reason,
                "timestamp": notice.timestamp,
            });
            let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();

            if let Some(v_profile) = self.verifiers.get(&cred.verifier_id) {
                let Ok(pk) = VerifyingKey::from_bytes(v_profile.public_key.as_slice().try_into().unwrap_or(&[0;32])) else { return false; };
                let Ok(sig) = Signature::from_slice(&notice.signature) else { return false; };
                if pk.verify(&msg_bytes, &sig).is_ok() {
                    return false;
                }
            }
        }

        if let Some(v_profile) = self.verifiers.get(&cred.verifier_id) {
            let Ok(pk) = VerifyingKey::from_bytes(v_profile.public_key.as_slice().try_into().unwrap_or(&[0;32])) else { return false; };
            let Ok(sig) = Signature::from_slice(&cred.signature) else { return false; };
            let msg = serde_json::json!({
                "verifier_id": cred.verifier_id,
                "standard": cred.standard,
                "evidence_hash": cred.evidence_hash,
                "issued_at": cred.issued_at,
                "expires_at": cred.expires_at,
            });
            let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();
            return pk.verify(&msg_bytes, &sig).is_ok();
        }
        false
    }

    pub fn update_reputation(&mut self, outcome: ServiceOutcome) {
        if let Some(profile) = self.providers.get_mut(&outcome.provider_id) {
            profile.total_outcomes += 1;
            let weight = 1.0 / (profile.total_outcomes as f64);
            let success_val = if outcome.success { 1.0 } else { 0.0 };
            profile.reputation_score = (profile.reputation_score * (1.0 - weight)) + (success_val * weight);
        }
    }

    pub fn select_provider(&self, request_id: &str, logic: &SelectionLogic) -> (Option<String>, SelectionAudit) {
        let mut eligible_ids = Vec::new();
        let mut eligible_profiles = Vec::new();

        for (id, profile) in &self.providers {
            if logic.is_eligible(profile, self) {
                eligible_ids.push(id.clone());
                eligible_profiles.push(profile);
            }
        }

        let selected = logic.tie_break(eligible_profiles);
        let selected_id = selected.map(|p| p.provider_id.clone());

        let reasoning = if selected_id.is_some() {
            format!("Selected based on highest reputation among {} eligible providers matching standards: {:?}",
                eligible_ids.len(), logic.required_standards)
        } else {
            format!("No providers met the required standards: {:?}", logic.required_standards)
        };

        let audit = SelectionAudit {
            timestamp: chrono::Utc::now(),
            request_id: request_id.to_string(),
            logic: logic.clone(),
            eligible_providers: eligible_ids,
            selected_provider: selected_id.clone(),
            reasoning,
        };

        (selected_id, audit)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProposal {
    pub id: String,
    pub request: ActionRequest,
    pub initiator_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteVote {
    pub proposal_id: String,
    pub voter_id: String,
    pub verdict: OutcomeVerdict,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl RemoteVote {
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.proposal_id,
            &self.voter_id,
            &self.verdict,
        );
        serde_json::to_vec(&data).expect("serialization for remote vote signing")
    }

    pub fn verify(&self) -> bool {
        if self.public_key.is_empty() || self.signature.is_empty() {
            return false;
        }
        let Ok(bytes) = self.public_key.as_slice().try_into() else {
            return false;
        };
        let Ok(public_key) = VerifyingKey::from_bytes(bytes) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        public_key.verify(&self.message_to_sign(), &signature).is_ok()
    }
}

pub struct UserIntentTranslator;

impl UserIntentTranslator {
    pub fn translate(natural_language: &str) -> SelectionLogic {
        let mut logic = SelectionLogic {
            required_standards: Vec::new(),
            min_reputation: 0.0,
        };

        let lower = natural_language.to_lowercase();
        if lower.contains("safety") || lower.contains("secure") || lower.contains("soc2") {
            logic.required_standards.push(VerificationStandard::SOC2);
        }
        if lower.contains("reliable") || lower.contains("uptime") {
            logic.required_standards.push(VerificationStandard::Uptime(99));
        }
        if lower.contains("high reputation") || lower.contains("best") {
            logic.min_reputation = 0.95;
        } else if lower.contains("vetted") || lower.contains("trusted") {
            logic.min_reputation = 0.80;
        }

        logic
    }
}

pub struct Orchestrator {
    pub engine: TrustEngine,
    pub recommendations: RecommendationLayer,
    modules: BTreeMap<String, Box<dyn Module>>,
    pub consensus_threshold: usize,
}

impl Orchestrator {
    pub fn new(engine: TrustEngine) -> Self {
        Self {
            engine,
            recommendations: RecommendationLayer::new(),
            modules: BTreeMap::new(),
            consensus_threshold: 1,
        }
    }

    pub fn set_consensus_threshold(&mut self, threshold: usize) {
        self.consensus_threshold = threshold;
    }

    pub fn register_module(&mut self, module: Box<dyn Module>) {
        self.modules.insert(module.name().to_string(), module);
    }

    pub async fn run_task(&mut self, request: ActionRequest) -> Result<serde_json::Value, String> {
        let decision = self.engine.record(request.clone());
        if decision.decision == Decision::Deny { return Err(format!("Denied: {}", decision.reason)); }

        // If local consensus is required, use local modules
        if self.consensus_threshold > 1 && self.modules.len() >= self.consensus_threshold {
            use futures::future::join_all;
            let matching_modules: Vec<&Box<dyn Module>> = self.modules.values()
                .filter(|m| m.capabilities().contains(&request.capability))
                .collect();

            if matching_modules.len() >= self.consensus_threshold {
                let mut futures = Vec::new();
                for module in matching_modules.iter().take(self.consensus_threshold) {
                    futures.push(module.execute(&request.action, request.input.clone()));
                }

                let results = join_all(futures).await;
                let mut valid_results = Vec::new();
                for res in results {
                    if let Ok(val) = res {
                        valid_results.push(val);
                    }
                }

                if valid_results.len() >= self.consensus_threshold {
                    let first_hash = hex::encode(Sha256::digest(serde_json::to_vec(&valid_results[0]).unwrap()));
                    for res in &valid_results[1..] {
                        let current_hash = hex::encode(Sha256::digest(serde_json::to_vec(res).unwrap()));
                        if current_hash != first_hash {
                            return Err("Consensus failed: modules returned diverging results".into());
                        }
                    }
                    return Ok(valid_results[0].clone());
                }
            }
        }

        // Default to first matching module if no threshold/local consensus failed
        let module = self.modules.values()
            .find(|m| m.capabilities().contains(&request.capability))
            .ok_or(format!("No module for cap: {}", request.capability))?;

        module.execute(&request.action, request.input).await
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentPolicy {
    pub name: String,
    pub capability: String,
    pub constraints: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutcomeVerdict {
    Valid,
    Invalid(String),
    Inconclusive(String),
}

pub struct IntentVerifier;

impl IntentVerifier {
    pub fn verify(request: &ActionRequest, _result: &serde_json::Value, policy: &IntentPolicy) -> OutcomeVerdict {
        if request.capability != policy.capability { return OutcomeVerdict::Invalid("cap mismatch".into()); }
        if request.action == "write_file" {
            let content = request.input["content"].as_str().unwrap_or("");
            if let Some(min) = policy.constraints["min_length"].as_u64() {
                if content.len() < min as usize { return OutcomeVerdict::Invalid("too short".into()); }
            }
            if let Some(paths) = policy.constraints["not_allowed_paths"].as_array() {
                let path = request.input["path"].as_str().unwrap_or("");
                for p in paths { if path == p.as_str().unwrap_or("") { return OutcomeVerdict::Invalid("restricted path".into()); } }
            }
        }
        OutcomeVerdict::Valid
    }
}

pub struct SystemModule;

#[async_trait::async_trait]
impl Module for SystemModule {
    fn name(&self) -> &str { "system" }
    fn capabilities(&self) -> Vec<String> { vec!["file_management".into()] }
    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, String> {
        match action {
            "write_file" => {
                let path = input["path"].as_str().ok_or("path req")?;
                let content = input["content"].as_str().ok_or("content req")?;
                std::fs::write(path, content).map(|_| serde_json::Value::Null).map_err(|e| e.to_string())
            },
            "list_dir" => {
                let path = input["path"].as_str().unwrap_or(".");
                let entries = std::fs::read_dir(path)
                    .map_err(|e| e.to_string())?
                    .map(|res| res.map(|e| e.file_name().into_string().unwrap_or_default()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?;
                Ok(serde_json::to_value(entries).unwrap())
            },
            _ => Err("unknown action".into())
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SafetyMode { FailSafe, FailOpen }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub id: String,
    pub description: String,
    pub action_request: ActionRequest,
    pub status: TaskStatus,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousPlan {
    pub id: String,
    pub goal: String,
    pub steps: BTreeMap<String, PlanStep>,
}

impl AutonomousPlan {
    pub fn new(id: String, goal: String) -> Self {
        Self {
            id,
            goal,
            steps: BTreeMap::new(),
        }
    }

    pub fn add_step(&mut self, step: PlanStep) {
        self.steps.insert(step.id.clone(), step);
    }

    pub fn next_runnable_steps(&self) -> Vec<&PlanStep> {
        self.steps.values()
            .filter(|s| {
                s.status == TaskStatus::Pending &&
                s.dependencies.iter().all(|dep_id| {
                    self.steps.get(dep_id)
                        .map(|dep| dep.status == TaskStatus::Completed)
                        .unwrap_or(false)
                })
            })
            .collect()
    }
}

pub struct AutonomousAgent {
    pub id: String,
    orchestrator: Orchestrator,
    policies: Vec<IntentPolicy>,
    pub safety_mode: SafetyMode,
    pub current_plan: Option<AutonomousPlan>,
}

impl AutonomousAgent {
    pub fn new(id: String, orchestrator: Orchestrator) -> Self {
        Self { id, orchestrator, policies: Vec::new(), safety_mode: SafetyMode::FailSafe, current_plan: None }
    }

    pub fn set_plan(&mut self, plan: AutonomousPlan) {
        self.current_plan = Some(plan);
    }

    pub fn set_safety_mode(&mut self, mode: SafetyMode) {
        self.safety_mode = mode;
    }

    pub fn add_policy(&mut self, policy: IntentPolicy) { self.policies.push(policy); }

    pub async fn execute_task(&mut self, request: ActionRequest) -> Result<serde_json::Value, String> {
        let result = self.orchestrator.run_task(request.clone()).await?;
        for policy in &self.policies {
            if policy.capability == request.capability {
                if let OutcomeVerdict::Invalid(reason) = IntentVerifier::verify(&request, &result, policy) {
                    let err = format!("Policy violation ({}): {}", policy.name, reason);
                    if self.safety_mode == SafetyMode::FailSafe { return Err(err); }
                    else { println!("WARNING: {}", err); }
                }
            }
        }
        Ok(result)
    }

    pub async fn execute_step(&mut self, request: ActionRequest) -> Result<serde_json::Value, String> {
        self.execute_task(request).await
    }

    pub async fn run_plan(&mut self) -> Result<usize, String> {
        let mut completed_count = 0;
        loop {
            let mut plan = self.current_plan.take().ok_or("No plan set")?;
            let runnable_ids: Vec<String> = plan.next_runnable_steps().iter().map(|s| s.id.clone()).collect();
            if runnable_ids.is_empty() {
                self.current_plan = Some(plan);
                break;
            }
            for step_id in runnable_ids {
                let step = plan.steps.get_mut(&step_id).unwrap();
                step.status = TaskStatus::InProgress;
                let request = step.action_request.clone();
                self.current_plan = Some(plan);
                let result = self.execute_step(request).await;
                plan = self.current_plan.take().unwrap();
                let step = plan.steps.get_mut(&step_id).unwrap();
                match result {
                    Ok(_) => {
                        step.status = TaskStatus::Completed;
                        completed_count += 1;
                    }
                    Err(e) => {
                        step.status = TaskStatus::Failed(e.clone());
                        self.current_plan = Some(plan);
                        return Err(format!("Plan failed at step {}: {}", step_id, e));
                    }
                }
            }
            self.current_plan = Some(plan);
        }
        Ok(completed_count)
    }
}

use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    pub sender_id: String,
    pub sender_public_key: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    pub responder_id: String,
    pub responder_public_key: Vec<u8>,
    pub ephemeral_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

pub struct AgentMeshNode {
    pub id: String,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub peers: BTreeMap<String, VerifyingKey>,
}

impl AgentMeshNode {
    pub fn new(id: String) -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            id,
            signing_key,
            verifying_key,
            peers: BTreeMap::new(),
        }
    }

    pub fn register_peer(&mut self, id: String, key: VerifyingKey) {
        self.peers.insert(id, key);
    }

    pub fn initiate_handshake(&self) -> (HandshakeRequest, EphemeralSecret) {
        let secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
        let public = XPublicKey::from(&secret);
        let request = HandshakeRequest {
            sender_id: self.id.clone(),
            sender_public_key: self.verifying_key.to_bytes().to_vec(),
            ephemeral_public_key: public.as_bytes().to_vec(),
        };
        (request, secret)
    }

    pub fn respond_to_handshake(&self, request: &HandshakeRequest) -> Result<(HandshakeResponse, [u8; 32]), String> {
        let secret = EphemeralSecret::random_from_rng(&mut rand::rngs::OsRng);
        let public = XPublicKey::from(&secret);
        let peer_ephemeral_bytes: [u8; 32] = request.ephemeral_public_key.clone().try_into().map_err(|_| "Invalid key length")?;
        let peer_public = XPublicKey::from(peer_ephemeral_bytes);
        let shared_secret = secret.diffie_hellman(&peer_public);
        let mut msg = Vec::new();
        msg.extend_from_slice(&request.ephemeral_public_key);
        msg.extend_from_slice(public.as_bytes());
        let signature = self.signing_key.sign(&msg).to_bytes().to_vec();
        let response = HandshakeResponse {
            responder_id: self.id.clone(),
            responder_public_key: self.verifying_key.to_bytes().to_vec(),
            ephemeral_public_key: public.as_bytes().to_vec(),
            signature,
        };
        Ok((response, *shared_secret.as_bytes()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcSignature {
    pub algorithm: String,
    pub signature: Vec<u8>,
}
pub struct AirGapBundle {
    pub state_merkle_root: String,
    pub batch: AuditBatch,
    pub signature: Vec<u8>,
}

impl TrustEngine {
    pub fn export_airgap_bundle(&self) -> Option<AirGapBundle> {
        self.batches.last().map(|batch| {
            let _body = serde_json::to_vec(&batch).expect("batch serialization");
            let signature = vec![]; // Placeholder for signing
            AirGapBundle {
                state_merkle_root: self.last_batch_hash.clone(),
                batch: batch.clone(),
                signature,
            }
        })
    }
}

pub struct PeerNode {
    pub id: String,
    pub public_key: Vec<u8>,
    pub reputation: f64,
}

pub struct DistributedRegistry {
    pub peers: BTreeMap<String, PeerNode>,
    pub state_root: String,
}

impl DistributedRegistry {
    pub fn sync_state(&mut self, bundle: AirGapBundle) -> Result<(), String> {
        // Formal verification check placeholder
        if bundle.state_merkle_root != bundle.batch.merkle_root {
            return Err("State mismatch during sync".into());
        }
        self.state_root = bundle.state_merkle_root;
        Ok(())
    }
}
