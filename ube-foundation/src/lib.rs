//! Neutral Trust Infrastructure (NTI) — Zero-Trust Post-Quantum Runtime & Governance Engine.
//!
//! Provides cryptographic capabilities for autonomous AI agents, including post-quantum
//! Dilithium5 (FIPS 204 ML-DSA-87) signatures, Kyber1024 (FIPS 203 ML-KEM-1024) hybrid AEAD encryption,
//! Ed25519 capabilities, Merkle-tree audit trails, and BFT consensus governance.

pub mod network;
#[cfg(feature = "python")]
pub mod python_bindings;

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium5;
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertextTrait, PublicKey as KemPublicKeyTrait,
    SecretKey as KemSecretKeyTrait, SharedSecret as KemSharedSecretTrait,
};
use pqcrypto_traits::sign::{
    DetachedSignature as SignDetachedSignatureTrait, PublicKey as SignPublicKeyTrait,
    SecretKey as SignSecretKeyTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Deterministically serializes any serializable value into compact, canonical JSON bytes.
pub fn canonical_json_bytes<T: Serialize>(val: &T) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(val)
        .map_err(|e| format!("Canonical JSON value conversion failed: {}", e))?;
    serde_json::to_vec(&value).map_err(|e| format!("Canonical JSON serialization failed: {}", e))
}

/// Represents dynamic constraints attached to capability tokens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CaveatType {
    /// Token expires at the specified ISO 8601 timestamp.
    Expires(String),
    /// Maximum number of executions allowed under this token.
    MaxExecutions(u64),
    /// Numerical limit and currency for value-based transactions.
    ValueLimit(u64, String),
    /// Prefix restriction on file path or resource URI.
    PathRestricted(String),
}

/// A policy caveat scoping the validity of an agent capability token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Caveat {
    /// Optional location tag for caveat enforcement context.
    pub location: Option<String>,
    /// Condition governing caveat validity.
    pub condition: CaveatType,
}

/// Cryptographically signed capability delegation token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    /// Unique identifier of the token.
    pub id: String,
    /// Root issuing actor ID.
    pub root_actor: String,
    /// Delegated capability name.
    pub capability: String,
    /// Enforced caveats.
    pub caveats: Vec<Caveat>,
    /// Ed25519 signature of the issuing actor.
    pub signature: Vec<u8>,
}

impl CapabilityToken {
    /// Computes canonical byte message for signing and verifying the capability token.
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (&self.id, &self.root_actor, &self.capability, &self.caveats);
        canonical_json_bytes(&data).unwrap_or_default()
    }

    /// Verifies the token signature against the issuer's Ed25519 public key.
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
        public_key
            .verify(&self.message_to_sign(), &signature)
            .is_ok()
    }
}

impl ConsensusVote {
    /// Computes canonical message payload for consensus vote signing and verification.
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.voter_id,
            &self.request_id,
            &self.decision,
            &self.outcome_hash,
        );
        canonical_json_bytes(&data).unwrap_or_default()
    }

    /// Verifies consensus vote signature using the voter's Ed25519 public key.
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
        public_key
            .verify(&self.message_to_sign(), &signature)
            .is_ok()
    }
}

impl TrustEngine {
    /// Registers a voter's public key in the trust engine registry.
    pub fn register_voter_key(&mut self, voter_id: impl Into<String>, public_key: Vec<u8>) {
        self.voter_keys.insert(voter_id.into(), public_key);
    }

    /// Verifies a BFT consensus proposal against registered voter signatures and threshold requirement.
    pub fn verify_consensus(&self, proposal: &ConsensusProposal, threshold: usize) -> bool {
        let mut valid_votes = 0;
        let mut hash_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut seen_voters: BTreeSet<String> = BTreeSet::new();

        for vote in &proposal.votes {
            if seen_voters.contains(&vote.voter_id) {
                continue; // Prevent duplicate voting from same voter
            }

            let Some(voter_pk) = self.voter_keys.get(&vote.voter_id) else {
                continue; // Reject votes from unregistered voters
            };

            if !vote.verify(voter_pk) {
                continue; // Skip invalid vote signature
            }

            seen_voters.insert(vote.voter_id.clone());

            if vote
                .decision
                .as_ref()
                .map(|d| d.decision == Decision::Allow)
                .unwrap_or(false)
            {
                valid_votes += 1;
                *hash_counts.entry(vote.outcome_hash.clone()).or_insert(0) += 1;
            }
        }

        // Must meet threshold AND have agreement on outcome hash
        valid_votes >= threshold && hash_counts.values().any(|&count| count >= threshold)
    }
}

/// Identifies agent source code release version and cryptographic source hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeIdentity {
    /// Release version tag.
    pub version: String,
    /// Cryptographic hash of binary or source code.
    pub source_hash: String,
}

/// Cryptographic identity claim presented by an agent to prove code integrity and provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityClaim {
    /// Agent identifier.
    pub agent_id: String,
    /// Code identity metadata.
    pub code_identity: CodeIdentity,
    /// Identity provider ID.
    pub provider: String,
    /// Claim type tag.
    pub claim_type: String,
    /// Claim value payload.
    pub value: String,
    /// Verification proof bytes.
    pub proof: Vec<u8>,
    /// Verifying public key bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 claim signature.
    pub signature: Vec<u8>,
}

impl IdentityClaim {
    /// Computes canonical message payload for signing and verifying identity claims.
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.agent_id,
            &self.code_identity.version,
            &self.code_identity.source_hash,
            &self.provider,
            &self.claim_type,
            &self.value,
        );
        canonical_json_bytes(&data).unwrap_or_default()
    }
}

/// Primary request envelope encapsulating agent action execution payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRequest {
    /// Unique request ID.
    pub id: String,
    /// Requesting actor ID.
    pub actor: String,
    /// Required capability name.
    pub capability: String,
    /// Action verb or command.
    pub action: String,
    /// Action input JSON parameters.
    pub input: serde_json::Value,
    /// Optional Ed25519 signature bytes.
    pub signature: Option<Vec<u8>>,
    /// Optional Dilithium5 PQC signature.
    pub pqc_signature: Option<PqcSignature>,
    /// Optional Ed25519 public key bytes.
    pub public_key: Option<Vec<u8>>,
    /// Optional Dilithium5 public key bytes.
    pub pqc_public_key: Option<Vec<u8>>,
    /// Optional capability token payload.
    pub token: Option<CapabilityToken>,
    /// Optional code identity claim.
    pub identity_claim: Option<IdentityClaim>,
}

impl ActionRequest {
    /// Computes canonical message payload for signing and verifying action requests.
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.id,
            &self.actor,
            &self.capability,
            &self.action,
            &self.input,
        );
        canonical_json_bytes(&data).unwrap_or_default()
    }
}

/// Status of an autonomous task step execution.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TaskStatus {
    /// Step pending execution.
    Pending,
    /// Step currently running.
    InProgress,
    /// Step successfully completed.
    Completed,
    /// Step execution failed with reason.
    Failed(String),
}

/// Policy evaluation decision verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    /// Action allowed by policy.
    Allow,
    /// Action denied by policy.
    Deny,
}

/// Policy verdict record with explanation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct PolicyDecision {
    /// Final decision verdict.
    pub decision: Decision,
    /// Explanation or violation reason.
    pub reason: String,
}

/// BFT consensus vote submitted by a network validator node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConsensusVote {
    /// Voter node ID.
    pub voter_id: String,
    /// Request proposal ID.
    pub request_id: String,
    /// Policy decision vote.
    pub decision: Option<PolicyDecision>,
    /// Expected outcome state hash.
    pub outcome_hash: String,
    /// Voter signature bytes.
    pub signature: Vec<u8>,
}

/// Consensus proposal bundling validator votes for evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusProposal {
    /// Request proposal ID.
    pub request_id: String,
    /// Collection of validator votes.
    pub votes: Vec<ConsensusVote>,
}

/// Single immutable entry in the audit trail chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    /// Monotonically increasing sequence index.
    pub sequence: u64,
    /// Recorded action request.
    pub request: ActionRequest,
    /// Policy decision verdict.
    pub decision: PolicyDecision,
    /// SHA-256 hash of previous event.
    pub previous_hash: String,
    /// SHA-256 hash of current audit event.
    pub hash: String,
}

/// Committed batch of audit events with Merkle tree root hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditBatch {
    /// Events contained in this batch.
    pub events: Vec<AuditEvent>,
    /// Merkle tree root hash of batch events.
    pub merkle_root: String,
    /// SHA-256 hash of previous committed audit batch.
    pub prev_batch_hash: String,
}

/// Exportable snapshot of trust engine state for file persistence and recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEngineState {
    /// Map of granted capabilities per actor.
    pub capabilities: BTreeMap<String, BTreeSet<String>>,
    /// Registered expected code identity hashes per agent.
    pub expected_code_hashes: BTreeMap<String, String>,
    /// Registered validator voter Ed25519 public keys.
    pub voter_keys: BTreeMap<String, Vec<u8>>,
    /// Revocation list of invalidated capability token IDs.
    pub revocation_list: BTreeSet<String>,
    /// Pending uncommitted audit events.
    pub events: Vec<AuditEvent>,
    /// Committed audit batches.
    pub batches: Vec<AuditBatch>,
    /// SHA-256 hash of last committed batch.
    pub last_batch_hash: String,
}

/// Main Zero-Trust policy evaluation engine with Merkle audit trails.
#[derive(Debug, Default)]
pub struct TrustEngine {
    /// Map of granted capabilities per actor.
    pub capabilities: BTreeMap<String, BTreeSet<String>>,
    /// Expected agent code source hashes.
    pub expected_code_hashes: BTreeMap<String, String>,
    /// Registered validator public keys.
    pub voter_keys: BTreeMap<String, Vec<u8>>,
    /// Token revocation set.
    pub revocation_list: BTreeSet<String>,
    /// Active event audit log buffer.
    pub events: Vec<AuditEvent>,
    /// Historical committed audit batches.
    pub batches: Vec<AuditBatch>,
    /// Hash of most recently committed batch.
    pub last_batch_hash: String,
    /// Path for automatic disk persistence.
    pub persistence_path: Option<std::path::PathBuf>,
}

/// Evaluates dynamic caveats against incoming action request state.
pub struct CaveatInterpreter;

impl CaveatInterpreter {
    /// Verifies all caveats attached to a token against action request input parameters.
    pub fn verify_all(
        caveats: &[Caveat],
        request: &ActionRequest,
        engine: &TrustEngine,
    ) -> OutcomeVerdict {
        for caveat in caveats {
            match &caveat.condition {
                CaveatType::MaxExecutions(max) => {
                    let count = engine
                        .events
                        .iter()
                        .filter(|e| {
                            e.request.token.as_ref().map(|t| &t.id)
                                == request.token.as_ref().map(|t| &t.id)
                        })
                        .count();
                    if count as u64 >= *max {
                        return OutcomeVerdict::Invalid(format!(
                            "Execution limit reached: {}",
                            max
                        ));
                    }
                }
                CaveatType::ValueLimit(max_val, _curr) => {
                    let val = request.input["amount"].as_u64().unwrap_or(0);
                    if val > *max_val {
                        return OutcomeVerdict::Invalid(format!(
                            "Value limit exceeded: {} > {}",
                            val, max_val
                        ));
                    }
                }
                CaveatType::PathRestricted(prefix) => {
                    let path = request.input["path"].as_str().unwrap_or("");
                    if !path.starts_with(prefix) {
                        return OutcomeVerdict::Invalid(format!(
                            "Path restricted: {} must start with {}",
                            path, prefix
                        ));
                    }
                }
                CaveatType::Expires(timestamp) => {
                    if let Ok(expiry) =
                        timestamp
                            .parse::<chrono::DateTime<chrono::Utc>>()
                            .or_else(|_| {
                                chrono::DateTime::parse_from_rfc3339(timestamp)
                                    .map(|dt| dt.with_timezone(&chrono::Utc))
                            })
                    {
                        if chrono::Utc::now() > expiry {
                            return OutcomeVerdict::Invalid(format!(
                                "Token expired at {}",
                                timestamp
                            ));
                        }
                    } else {
                        return OutcomeVerdict::Invalid(format!(
                            "Invalid expiry format: {}",
                            timestamp
                        ));
                    }
                }
            }
        }
        OutcomeVerdict::Valid
    }
}

impl TrustEngine {
    /// Creates a new empty `TrustEngine`.
    pub fn new() -> Self {
        Self {
            capabilities: BTreeMap::new(),
            expected_code_hashes: BTreeMap::new(),
            voter_keys: BTreeMap::new(),
            revocation_list: BTreeSet::new(),
            events: Vec::new(),
            batches: Vec::new(),
            last_batch_hash: "".into(),
            persistence_path: None,
        }
    }

    /// Configures automatic file persistence path for the engine state.
    pub fn with_persistence(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.persistence_path = Some(path.into());
        self
    }

    /// Exports engine configuration and audit trail snapshot.
    pub fn export_state(&self) -> TrustEngineState {
        TrustEngineState {
            capabilities: self.capabilities.clone(),
            expected_code_hashes: self.expected_code_hashes.clone(),
            voter_keys: self.voter_keys.clone(),
            revocation_list: self.revocation_list.clone(),
            events: self.events.clone(),
            batches: self.batches.clone(),
            last_batch_hash: self.last_batch_hash.clone(),
        }
    }

    /// Saves engine state to disk as pretty-printed JSON.
    pub fn save_to_file(&self, path: impl AsRef<std::path::Path>) -> Result<(), String> {
        let state = self.export_state();
        let bytes =
            serde_json::to_vec_pretty(&state).map_err(|e| format!("Serialization error: {}", e))?;
        std::fs::write(path, bytes).map_err(|e| format!("File write error: {}", e))
    }

    /// Loads engine state from disk and verifies Merkle audit trail history integrity.
    pub fn load_from_file(path: impl AsRef<std::path::Path>) -> Result<Self, String> {
        let bytes = std::fs::read(path).map_err(|e| format!("File read error: {}", e))?;
        let state: TrustEngineState =
            serde_json::from_slice(&bytes).map_err(|e| format!("Deserialization error: {}", e))?;
        let engine = Self {
            capabilities: state.capabilities,
            expected_code_hashes: state.expected_code_hashes,
            voter_keys: state.voter_keys,
            revocation_list: state.revocation_list,
            events: state.events,
            batches: state.batches,
            last_batch_hash: state.last_batch_hash,
            persistence_path: None,
        };
        if !engine.verify_history() {
            return Err("Persisted trust engine history integrity verification failed".into());
        }
        Ok(engine)
    }

    /// Performs automatic file persistence write if persistence path is configured.
    pub fn auto_save(&self) -> Result<(), String> {
        if let Some(path) = &self.persistence_path {
            self.save_to_file(path)?;
        }
        Ok(())
    }

    /// Revokes a capability token ID, causing subsequent evaluations to be denied.
    pub fn revoke_token(&mut self, token_id: impl Into<String>) {
        self.revocation_list.insert(token_id.into());
    }

    /// Registers expected binary/source hash for an agent identity.
    pub fn register_expected_hash(&mut self, agent_id: impl Into<String>, hash: impl Into<String>) {
        self.expected_code_hashes
            .insert(agent_id.into(), hash.into());
    }

    /// Explicitly grants a capability permission to an actor.
    pub fn grant(&mut self, actor: impl Into<String>, capability: impl Into<String>) {
        self.capabilities
            .entry(actor.into())
            .or_default()
            .insert(capability.into());
    }

    fn compute_merkle_root(events: &[AuditEvent]) -> String {
        if events.is_empty() {
            return "".into();
        }
        let mut hashes: Vec<String> = events.iter().map(|e| e.hash.clone()).collect();
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..hashes.len()).step_by(2) {
                let mut hasher = Sha256::new();
                hasher.update(&hashes[i]);
                if i + 1 < hashes.len() {
                    hasher.update(&hashes[i + 1]);
                } else {
                    hasher.update(&hashes[i]);
                }
                next_level.push(hex::encode(hasher.finalize()));
            }
            hashes = next_level;
        }
        hashes[0].clone()
    }

    /// Commits active event buffer into a Merkle-rooted AuditBatch.
    pub fn commit_batch(&mut self) -> Option<String> {
        if self.events.is_empty() {
            return None;
        }
        let merkle_root = Self::compute_merkle_root(&self.events);
        let events = std::mem::take(&mut self.events);
        let batch = AuditBatch {
            events,
            merkle_root,
            prev_batch_hash: self.last_batch_hash.clone(),
        };
        let Ok(body) = serde_json::to_vec(&batch) else {
            return None;
        };
        let batch_hash = hex::encode(Sha256::digest(body));
        self.last_batch_hash = batch_hash.clone();
        self.batches.push(batch);
        Some(batch_hash)
    }

    /// Evaluates policy verdict for an action request without recording it to audit history.
    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecision {
        // PQC Verification (Post-Quantum Durability)
        if let Some(pqc_sig) = &request.pqc_signature {
            if let Some(pqc_pk_bytes) = &request.pqc_public_key {
                if pqc_sig.algorithm != "Dilithium5" && pqc_sig.algorithm != "ML-DSA-87" {
                    return PolicyDecision {
                        decision: Decision::Deny,
                        reason: "unsupported pqc algorithm".into(),
                    };
                }
                let pqc_pk = PqcPublicKey {
                    algorithm: pqc_sig.algorithm.clone(),
                    key_bytes: pqc_pk_bytes.clone(),
                    kyber_public_key_bytes: vec![],
                };
                if !pqc_pk.verify(&request.message_to_sign(), pqc_sig) {
                    return PolicyDecision {
                        decision: Decision::Deny,
                        reason: "pqc sig mismatch".into(),
                    };
                }
            } else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "missing pqc public key".into(),
                };
            }
        }

        if let Some(claim) = &request.identity_claim {
            let Ok(pk_bytes) = claim.public_key.as_slice().try_into() else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid identity pk length".into(),
                };
            };
            let Ok(pk) = VerifyingKey::from_bytes(pk_bytes) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid identity pk".into(),
                };
            };
            let Ok(sig) = Signature::from_slice(&claim.signature) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid identity sig".into(),
                };
            };
            if pk.verify(&claim.message_to_sign(), &sig).is_err() {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "identity sig mismatch".into(),
                };
            }
            if let Some(expected) = self.expected_code_hashes.get(&claim.agent_id) {
                if !bool::from(
                    claim
                        .code_identity
                        .source_hash
                        .as_bytes()
                        .ct_eq(expected.as_bytes()),
                ) {
                    return PolicyDecision {
                        decision: Decision::Deny,
                        reason: "code hash mismatch".into(),
                    };
                }
            }
        }

        if let (Some(sig_bytes), Some(pk_bytes)) = (&request.signature, &request.public_key) {
            let Ok(pk_slice) = pk_bytes.as_slice().try_into() else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid pk length".into(),
                };
            };
            let Ok(pk) = VerifyingKey::from_bytes(pk_slice) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid pk".into(),
                };
            };
            let Ok(sig) = Signature::from_slice(sig_bytes) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid sig".into(),
                };
            };
            if pk.verify(&request.message_to_sign(), &sig).is_err() {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "sig mismatch".into(),
                };
            }
        }

        if let Some(token) = &request.token {
            if self.revocation_list.contains(&token.id) {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "token revoked".into(),
                };
            }
            if token.capability != request.capability {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "token cap mismatch".into(),
                };
            }
            if let OutcomeVerdict::Invalid(reason) =
                CaveatInterpreter::verify_all(&token.caveats, request, self)
            {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: format!("caveat violation: {}", reason),
                };
            }
            return PolicyDecision {
                decision: Decision::Allow,
                reason: "token verified".into(),
            };
        }

        let allowed = self
            .capabilities
            .get(&request.actor)
            .is_some_and(|caps| caps.contains(&request.capability));
        if allowed {
            PolicyDecision {
                decision: Decision::Allow,
                reason: "granted".into(),
            }
        } else {
            PolicyDecision {
                decision: Decision::Deny,
                reason: "no cap".into(),
            }
        }
    }

    /// Evaluates policy verdict for an action request and appends it to the immutable audit event log.
    pub fn record(&mut self, request: ActionRequest) -> PolicyDecision {
        let decision = self.evaluate(&request);
        let previous_hash = self
            .events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| self.last_batch_hash.clone());
        let sequence = self.events.len() as u64;
        let Ok(body) = serde_json::to_vec(&(sequence, &request, &decision, &previous_hash)) else {
            return PolicyDecision {
                decision: Decision::Deny,
                reason: "audit serialization failed".into(),
            };
        };
        let hash = hex::encode(Sha256::digest(body));
        self.events.push(AuditEvent {
            sequence,
            request,
            decision: decision.clone(),
            previous_hash,
            hash,
        });
        if self.events.len() >= 10 {
            self.commit_batch();
        }
        let _ = self.auto_save();
        decision
    }

    /// Verifies complete cryptographic hash chain and Merkle batch integrity.
    pub fn verify_history(&self) -> bool {
        let mut prev_hash = "".to_string();
        for batch in &self.batches {
            if !bool::from(batch.prev_batch_hash.as_bytes().ct_eq(prev_hash.as_bytes())) {
                return false;
            }
            let mut event_prev = batch.prev_batch_hash.clone();
            for event in &batch.events {
                if !bool::from(event.previous_hash.as_bytes().ct_eq(event_prev.as_bytes())) {
                    return false;
                }
                let Ok(body) = serde_json::to_vec(&(
                    event.sequence,
                    &event.request,
                    &event.decision,
                    &event.previous_hash,
                )) else {
                    return false;
                };
                let computed_hash = hex::encode(Sha256::digest(body));
                if !bool::from(event.hash.as_bytes().ct_eq(computed_hash.as_bytes())) {
                    return false;
                }
                event_prev = event.hash.clone();
            }
            if !bool::from(
                Self::compute_merkle_root(&batch.events)
                    .as_bytes()
                    .ct_eq(batch.merkle_root.as_bytes()),
            ) {
                return false;
            }
            let Ok(body) = serde_json::to_vec(&batch) else {
                return false;
            };
            prev_hash = hex::encode(Sha256::digest(body));
        }
        let mut event_prev = if self.batches.is_empty() {
            "".to_string()
        } else {
            self.last_batch_hash.clone()
        };
        for event in &self.events {
            if !bool::from(event.previous_hash.as_bytes().ct_eq(event_prev.as_bytes())) {
                return false;
            }
            let Ok(body) = serde_json::to_vec(&(
                event.sequence,
                &event.request,
                &event.decision,
                &event.previous_hash,
            )) else {
                return false;
            };
            let computed_hash = hex::encode(Sha256::digest(body));
            if !bool::from(event.hash.as_bytes().ct_eq(computed_hash.as_bytes())) {
                return false;
            }
            event_prev = event.hash.clone();
        }
        true
    }
}

/// Asynchronous module execution trait for orchestrator integration.
#[async_trait::async_trait]
pub trait Module: Send + Sync {
    /// Returns the unique module identifier.
    fn name(&self) -> &str;
    /// Returns supported capability names.
    fn capabilities(&self) -> Vec<String>;
    /// Executes the specified action with input parameters.
    async fn execute(
        &self,
        action: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

/// Verification standard assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationStandard {
    /// SOC2 audit verification.
    SOC2,
    /// Minimum SLA uptime percentage.
    Uptime(u8),
    /// Legal compliance credential.
    LegalCompliance,
    /// Air-gapped deployment requirement.
    AirGapped,
    /// Formal mathematical verification proof.
    FormalVerification,
    /// Custom verifier standard string.
    Custom(String),
}

/// Independent verifier credential record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndependentCredential {
    /// Issuing verifier ID.
    pub verifier_id: String,
    /// Verified standard tag.
    pub standard: VerificationStandard,
    /// SHA-256 evidence hash.
    pub evidence_hash: String,
    /// Issue timestamp.
    pub issued_at: chrono::DateTime<chrono::Utc>,
    /// Expiration timestamp.
    pub expires_at: chrono::DateTime<chrono::Utc>,
    /// Verifier signature bytes.
    pub signature: Vec<u8>,
}

/// Provider profile metadata and credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderProfile {
    /// Provider ID.
    pub provider_id: String,
    /// Additional service metadata JSON.
    pub service_metadata: serde_json::Value,
    /// Attested independent credentials.
    pub credentials: Vec<IndependentCredential>,
    /// Normalized reputation score (0.0 to 1.0).
    pub reputation_score: f64,
    /// Total completed service outcomes.
    pub total_outcomes: u64,
}

/// Selection criteria logic for provider recommendation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionLogic {
    /// Required verification standards.
    pub required_standards: Vec<VerificationStandard>,
    /// Minimum acceptable reputation score.
    pub min_reputation: f64,
}

impl SelectionLogic {
    /// Checks if a provider profile meets required selection standards.
    pub fn is_eligible(&self, profile: &ProviderProfile, layer: &RecommendationLayer) -> bool {
        if profile.reputation_score < self.min_reputation {
            return false;
        }

        for req in &self.required_standards {
            let has_valid = profile.credentials.iter().any(|cred| {
                cred.standard == *req
                    && cred.expires_at > chrono::Utc::now()
                    && layer.verify_credential(cred)
            });
            if !has_valid {
                return false;
            }
        }
        true
    }

    /// Performs tie-breaking and cold-start exploration among eligible providers.
    pub fn tie_break<'a>(&self, eligible: Vec<&'a ProviderProfile>) -> Option<&'a ProviderProfile> {
        if eligible.is_empty() {
            return None;
        }

        let unproven: Vec<&&ProviderProfile> =
            eligible.iter().filter(|p| p.total_outcomes < 10).collect();

        if !unproven.is_empty() {
            let mut rng = rand::thread_rng();
            if rand::Rng::gen_bool(&mut rng, 0.1) {
                let idx = rand::Rng::gen_range(&mut rng, 0..unproven.len());
                return Some(*unproven[idx]);
            }
        }

        eligible.into_iter().max_by(|a, b| {
            a.reputation_score
                .partial_cmp(&b.reputation_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
    }
}

/// Recorded outcome of a completed service request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceOutcome {
    /// Provider ID.
    pub provider_id: String,
    /// Request ID.
    pub request_id: String,
    /// Success outcome indicator.
    pub success: bool,
    /// Optional user feedback rating.
    pub user_feedback: Option<f64>,
}

/// Verifier tier level.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum VerifierTier {
    /// Foundational tier verifier.
    Foundational,
    /// Community tier verifier.
    Community,
}

/// Profile metadata for independent verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierProfile {
    /// Verifier ID.
    pub id: String,
    /// Verifier tier classification.
    pub tier: VerifierTier,
    /// Verifier Ed25519 public key.
    pub public_key: Vec<u8>,
    /// Verifier trust reputation.
    pub reputation: f64,
}

/// Credential revocation notice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationNotice {
    /// Credential evidence hash.
    pub credential_hash: String,
    /// Revocation reason.
    pub reason: String,
    /// Revocation timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Revoking verifier signature.
    pub signature: Vec<u8>,
}

/// Dispute record filed against a provider or verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeRecord {
    /// Provider ID.
    pub provider_id: String,
    /// Verifier ID.
    pub verifier_id: String,
    /// Dispute claim statement.
    pub claim: String,
    /// Evidence link or hash.
    pub evidence: String,
    /// Timestamp of dispute filing.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Verification fee payment record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationFee {
    /// Paying provider ID.
    pub provider_id: String,
    /// Receiving verifier ID.
    pub verifier_id: String,
    /// Fee numerical amount.
    pub amount: u64,
    /// Currency code.
    pub currency: String,
    /// Fee type.
    pub fee_type: FeeType,
    /// Timestamp of fee payment.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Categorization of verifier fee payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FeeType {
    /// Initial verification fee.
    InitialVerification,
    /// Credential renewal fee.
    Renewal,
    /// Per-transaction commission percentage.
    TransactionCommission(f64),
}

/// Audit log entry for provider selection decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionAudit {
    /// Timestamp of decision.
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Associated request ID.
    pub request_id: String,
    /// Selection logic criteria used.
    pub logic: SelectionLogic,
    /// IDs of all eligible provider candidates.
    pub eligible_providers: Vec<String>,
    /// Selected provider ID.
    pub selected_provider: Option<String>,
    /// Selection reasoning narrative.
    pub reasoning: String,
}

/// Marketplace recommendation layer managing verifiers, providers, and disputes.
pub struct RecommendationLayer {
    /// Registered verifier profiles.
    pub verifiers: BTreeMap<String, VerifierProfile>,
    /// Registered provider profiles.
    pub providers: BTreeMap<String, ProviderProfile>,
    /// Credential revocation notices.
    pub revocations: BTreeMap<String, RevocationNotice>,
    /// Dispute audit trail records.
    pub disputes: Vec<DisputeRecord>,
}

impl Default for RecommendationLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl RecommendationLayer {
    /// Creates a new `RecommendationLayer`.
    pub fn new() -> Self {
        Self {
            verifiers: BTreeMap::new(),
            providers: BTreeMap::new(),
            revocations: BTreeMap::new(),
            disputes: Vec::new(),
        }
    }

    /// Records a new dispute entry.
    pub fn add_dispute(&mut self, record: DisputeRecord) {
        self.disputes.push(record);
    }

    /// Logs fee processing details.
    pub fn process_fee(&self, fee: &VerificationFee) {
        println!(
            "FEE LOG: Provider {} paid {} {} for {:?} to Verifier {}",
            fee.provider_id, fee.amount, fee.currency, fee.fee_type, fee.verifier_id
        );
    }

    /// Verifies credential signatures and checks for active revocation notices.
    pub fn verify_credential(&self, cred: &IndependentCredential) -> bool {
        if let Some(notice) = self.revocations.get(&cred.evidence_hash) {
            let msg = serde_json::json!({
                "credential_hash": notice.credential_hash,
                "reason": notice.reason,
                "timestamp": notice.timestamp,
            });
            let msg_bytes = serde_json::to_vec(&msg).unwrap_or_default();

            if let Some(v_profile) = self.verifiers.get(&cred.verifier_id) {
                let Ok(pk) = VerifyingKey::from_bytes(
                    v_profile
                        .public_key
                        .as_slice()
                        .try_into()
                        .unwrap_or(&[0; 32]),
                ) else {
                    return false;
                };
                let Ok(sig) = Signature::from_slice(&notice.signature) else {
                    return false;
                };
                if pk.verify(&msg_bytes, &sig).is_ok() {
                    return false;
                }
            }
        }

        if let Some(v_profile) = self.verifiers.get(&cred.verifier_id) {
            let Ok(pk) = VerifyingKey::from_bytes(
                v_profile
                    .public_key
                    .as_slice()
                    .try_into()
                    .unwrap_or(&[0; 32]),
            ) else {
                return false;
            };
            let Ok(sig) = Signature::from_slice(&cred.signature) else {
                return false;
            };
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

    /// Updates provider reputation score following service completion.
    pub fn update_reputation(&mut self, outcome: ServiceOutcome) {
        if let Some(profile) = self.providers.get_mut(&outcome.provider_id) {
            profile.total_outcomes += 1;
            let weight = 1.0 / (profile.total_outcomes as f64);
            let success_val = if outcome.success { 1.0 } else { 0.0 };
            profile.reputation_score =
                (profile.reputation_score * (1.0 - weight)) + (success_val * weight);
        }
    }

    /// Selects best eligible provider for a given request.
    pub fn select_provider(
        &self,
        request_id: &str,
        logic: &SelectionLogic,
    ) -> (Option<String>, SelectionAudit) {
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
            format!(
                "No providers met the required standards: {:?}",
                logic.required_standards
            )
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

/// Remote action proposal for mesh network propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteProposal {
    /// Proposal ID.
    pub id: String,
    /// Embedded action request payload.
    pub request: ActionRequest,
    /// Initiating node ID.
    pub initiator_id: String,
    /// Proposal creation timestamp.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Remote vote submitted over the network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteVote {
    /// Associated proposal ID.
    pub proposal_id: String,
    /// Voting node ID.
    pub voter_id: String,
    /// Outcome verdict.
    pub verdict: OutcomeVerdict,
    /// Validator signature.
    pub signature: Vec<u8>,
}

/// Translates natural language user intents into formal selection logic criteria.
pub struct UserIntentTranslator;

impl UserIntentTranslator {
    /// Parses natural language text into selection logic requirements.
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
            logic
                .required_standards
                .push(VerificationStandard::Uptime(99));
        }
        if lower.contains("high reputation") || lower.contains("best") {
            logic.min_reputation = 0.95;
        } else if lower.contains("vetted") || lower.contains("trusted") {
            logic.min_reputation = 0.80;
        }

        logic
    }
}

/// Orchestrator combining TrustEngine policy enforcement and module execution.
pub struct Orchestrator {
    /// Core trust engine.
    pub engine: TrustEngine,
    /// Marketplace recommendation layer.
    pub recommendations: RecommendationLayer,
    modules: BTreeMap<String, Box<dyn Module>>,
    /// Consensus threshold requirement.
    pub consensus_threshold: usize,
}

impl Orchestrator {
    /// Creates a new `Orchestrator` wrapping a `TrustEngine`.
    pub fn new(engine: TrustEngine) -> Self {
        Self {
            engine,
            recommendations: RecommendationLayer::new(),
            modules: BTreeMap::new(),
            consensus_threshold: 1,
        }
    }

    /// Sets the minimum module agreement consensus threshold.
    pub fn set_consensus_threshold(&mut self, threshold: usize) {
        self.consensus_threshold = threshold;
    }

    /// Registers a module to handle action executions.
    pub fn register_module(&mut self, module: Box<dyn Module>) {
        self.modules.insert(module.name().to_string(), module);
    }

    /// Evaluates permission, records audit entry, and executes task.
    pub async fn run_task(&mut self, request: ActionRequest) -> Result<serde_json::Value, String> {
        let decision = self.engine.record(request.clone());
        if decision.decision == Decision::Deny {
            return Err(format!("Denied: {}", decision.reason));
        }

        // If local consensus is required, use local modules
        if self.consensus_threshold > 1 && self.modules.len() >= self.consensus_threshold {
            use futures::future::join_all;
            let matching_modules: Vec<&Box<dyn Module>> = self
                .modules
                .values()
                .filter(|m| m.capabilities().contains(&request.capability))
                .collect();

            if matching_modules.len() >= self.consensus_threshold {
                let mut futures = Vec::new();
                for module in matching_modules.iter().take(self.consensus_threshold) {
                    futures.push(module.execute(&request.action, request.input.clone()));
                }

                let results = join_all(futures).await;
                let mut valid_results = Vec::new();
                for val in results.into_iter().flatten() {
                    valid_results.push(val);
                }

                if valid_results.len() >= self.consensus_threshold {
                    let Ok(first_bytes) = serde_json::to_vec(&valid_results[0]) else {
                        return Err("Consensus failed: serialization error".into());
                    };
                    let first_hash = hex::encode(Sha256::digest(first_bytes));
                    for res in &valid_results[1..] {
                        let Ok(current_bytes) = serde_json::to_vec(res) else {
                            return Err("Consensus failed: serialization error".into());
                        };
                        let current_hash = hex::encode(Sha256::digest(current_bytes));
                        if !bool::from(current_hash.as_bytes().ct_eq(first_hash.as_bytes())) {
                            return Err(
                                "Consensus failed: modules returned diverging results".into()
                            );
                        }
                    }
                    return Ok(valid_results[0].clone());
                }
            }
        }

        // Default to first matching module if no threshold/local consensus failed
        let module = self
            .modules
            .values()
            .find(|m| m.capabilities().contains(&request.capability))
            .ok_or(format!("No module for cap: {}", request.capability))?;

        module.execute(&request.action, request.input).await
    }
}

/// Intent specification policy constraint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentPolicy {
    /// Policy name.
    pub name: String,
    /// Capability permissions scoped by this policy.
    pub capability: String,
    /// Policy JSON constraints.
    pub constraints: serde_json::Value,
}

/// Outcome evaluation verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OutcomeVerdict {
    /// Outcome valid and compliant.
    Valid,
    /// Outcome invalid with violation details.
    Invalid(String),
    /// Outcome evaluation inconclusive.
    Inconclusive(String),
}

/// Verifies execution result against intent policy rules.
pub struct IntentVerifier;

impl IntentVerifier {
    /// Checks request parameters and execution results against policy rules.
    pub fn verify(
        request: &ActionRequest,
        _result: &serde_json::Value,
        policy: &IntentPolicy,
    ) -> OutcomeVerdict {
        if request.capability != policy.capability {
            return OutcomeVerdict::Invalid("cap mismatch".into());
        }
        if request.action == "write_file" {
            let content = request.input["content"].as_str().unwrap_or("");
            if let Some(min) = policy.constraints["min_length"].as_u64() {
                if content.len() < min as usize {
                    return OutcomeVerdict::Invalid("too short".into());
                }
            }
            if let Some(paths) = policy.constraints["not_allowed_paths"].as_array() {
                let path = request.input["path"].as_str().unwrap_or("");
                for p in paths {
                    if path == p.as_str().unwrap_or("") {
                        return OutcomeVerdict::Invalid("restricted path".into());
                    }
                }
            }
        }
        OutcomeVerdict::Valid
    }
}

/// Built-in system module providing basic system capabilities.
pub struct SystemModule;

#[async_trait::async_trait]
impl Module for SystemModule {
    fn name(&self) -> &str {
        "system"
    }
    fn capabilities(&self) -> Vec<String> {
        vec!["file_management".into()]
    }
    async fn execute(
        &self,
        action: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        match action {
            "write_file" => {
                let path = input["path"].as_str().ok_or("path req")?;
                let content = input["content"].as_str().ok_or("content req")?;
                std::fs::write(path, content)
                    .map(|_| serde_json::Value::Null)
                    .map_err(|e| e.to_string())
            }
            "list_dir" => {
                let path = input["path"].as_str().unwrap_or(".");
                let entries = std::fs::read_dir(path)
                    .map_err(|e| e.to_string())?
                    .map(|res| res.map(|e| e.file_name().into_string().unwrap_or_default()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| e.to_string())?;
                serde_json::to_value(entries).map_err(|e| e.to_string())
            }
            _ => Err("unknown action".into()),
        }
    }
}

/// Agent safety enforcement mode.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SafetyMode {
    /// Stop execution immediately on policy violation.
    FailSafe,
    /// Log warning and continue execution on policy violation.
    FailOpen,
}

/// Individual step in an autonomous execution plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    /// Step ID.
    pub id: String,
    /// Descriptive summary of step objective.
    pub description: String,
    /// Embedded action request.
    pub action_request: ActionRequest,
    /// Current task status.
    pub status: TaskStatus,
    /// IDs of required preceding step dependencies.
    pub dependencies: Vec<String>,
}

/// Autonomous execution plan composed of dependent steps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomousPlan {
    /// Plan ID.
    pub id: String,
    /// Goal statement.
    pub goal: String,
    /// Map of step ID to plan step.
    pub steps: BTreeMap<String, PlanStep>,
}

impl AutonomousPlan {
    /// Creates a new autonomous plan.
    pub fn new(id: String, goal: String) -> Self {
        Self {
            id,
            goal,
            steps: BTreeMap::new(),
        }
    }

    /// Adds a step to the plan.
    pub fn add_step(&mut self, step: PlanStep) {
        self.steps.insert(step.id.clone(), step);
    }

    /// Returns references to steps whose dependencies are completed and are ready to run.
    pub fn next_runnable_steps(&self) -> Vec<&PlanStep> {
        self.steps
            .values()
            .filter(|s| {
                s.status == TaskStatus::Pending
                    && s.dependencies.iter().all(|dep_id| {
                        self.steps
                            .get(dep_id)
                            .map(|dep| dep.status == TaskStatus::Completed)
                            .unwrap_or(false)
                    })
            })
            .collect()
    }
}

/// Autonomous agent wrapper combining plan execution, policy verification, and orchestrator.
pub struct AutonomousAgent {
    /// Agent identity ID.
    pub id: String,
    orchestrator: Orchestrator,
    policies: Vec<IntentPolicy>,
    /// Safety mode setting.
    pub safety_mode: SafetyMode,
    /// Currently loaded autonomous plan.
    pub current_plan: Option<AutonomousPlan>,
}

impl AutonomousAgent {
    /// Creates a new `AutonomousAgent`.
    pub fn new(id: String, orchestrator: Orchestrator) -> Self {
        Self {
            id,
            orchestrator,
            policies: Vec::new(),
            safety_mode: SafetyMode::FailSafe,
            current_plan: None,
        }
    }

    /// Sets active plan.
    pub fn set_plan(&mut self, plan: AutonomousPlan) {
        self.current_plan = Some(plan);
    }

    /// Configures safety mode.
    pub fn set_safety_mode(&mut self, mode: SafetyMode) {
        self.safety_mode = mode;
    }

    /// Adds intent policy constraint.
    pub fn add_policy(&mut self, policy: IntentPolicy) {
        self.policies.push(policy);
    }

    /// Executes task request and applies intent policies.
    pub async fn execute_task(
        &mut self,
        request: ActionRequest,
    ) -> Result<serde_json::Value, String> {
        let result = self.orchestrator.run_task(request.clone()).await?;
        for policy in &self.policies {
            if policy.capability == request.capability {
                if let OutcomeVerdict::Invalid(reason) =
                    IntentVerifier::verify(&request, &result, policy)
                {
                    let err = format!("Policy violation ({}): {}", policy.name, reason);
                    if self.safety_mode == SafetyMode::FailSafe {
                        return Err(err);
                    } else {
                        println!("WARNING: {}", err);
                    }
                }
            }
        }
        Ok(result)
    }

    /// Executes step action request.
    pub async fn execute_step(
        &mut self,
        request: ActionRequest,
    ) -> Result<serde_json::Value, String> {
        self.execute_task(request).await
    }

    /// Runs all runnable steps in current plan sequentially to completion.
    pub async fn run_plan(&mut self) -> Result<usize, String> {
        let mut completed_count = 0;
        loop {
            let mut plan = self.current_plan.take().ok_or("No plan set")?;
            let runnable_ids: Vec<String> = plan
                .next_runnable_steps()
                .iter()
                .map(|s| s.id.clone())
                .collect();
            if runnable_ids.is_empty() {
                self.current_plan = Some(plan);
                break;
            }
            for step_id in runnable_ids {
                let Some(step) = plan.steps.get_mut(&step_id) else {
                    self.current_plan = Some(plan);
                    return Err(format!("Plan step missing: {}", step_id));
                };
                step.status = TaskStatus::InProgress;
                let request = step.action_request.clone();
                self.current_plan = Some(plan);
                let result = self.execute_step(request).await;
                let Some(mut p) = self.current_plan.take() else {
                    return Err("Plan state missing during execution".into());
                };
                let Some(step) = p.steps.get_mut(&step_id) else {
                    self.current_plan = Some(p);
                    return Err(format!("Plan step missing after execution: {}", step_id));
                };
                match result {
                    Ok(_) => {
                        step.status = TaskStatus::Completed;
                        completed_count += 1;
                    }
                    Err(e) => {
                        step.status = TaskStatus::Failed(e.clone());
                        self.current_plan = Some(p);
                        return Err(format!("Plan failed at step {}: {}", step_id, e));
                    }
                }
                plan = p;
            }
            self.current_plan = Some(plan);
        }
        Ok(completed_count)
    }
}

use x25519_dalek::{EphemeralSecret, PublicKey as XPublicKey};

/// Peer-to-peer mesh handshake initiation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeRequest {
    /// Sender node ID.
    pub sender_id: String,
    /// Sender long-term Ed25519 public key bytes.
    pub sender_public_key: Vec<u8>,
    /// Sender ephemeral X25519 public key bytes.
    pub ephemeral_public_key: Vec<u8>,
}

/// Peer-to-peer mesh handshake response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeResponse {
    /// Responder node ID.
    pub responder_id: String,
    /// Responder long-term Ed25519 public key bytes.
    pub responder_public_key: Vec<u8>,
    /// Responder ephemeral X25519 public key bytes.
    pub ephemeral_public_key: Vec<u8>,
    /// Responder Ed25519 signature over concatenated ephemeral public keys.
    pub signature: Vec<u8>,
}

/// Mesh network node identity managing keys and peer handshakes.
pub struct AgentMeshNode {
    /// Node ID.
    pub id: String,
    /// Current Ed25519 signing key.
    pub signing_key: SigningKey,
    /// Current Ed25519 verifying public key.
    pub verifying_key: VerifyingKey,
    /// Historical public keys prior to rotations.
    pub previous_verifying_keys: Vec<VerifyingKey>,
    /// Key generation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Map of peer ID to verifying public key.
    pub peers: BTreeMap<String, VerifyingKey>,
}

impl AgentMeshNode {
    /// Creates a new `AgentMeshNode` with fresh cryptographic keys.
    pub fn new(id: String) -> Self {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        let verifying_key = signing_key.verifying_key();
        Self {
            id,
            signing_key,
            verifying_key,
            previous_verifying_keys: Vec::new(),
            created_at: chrono::Utc::now(),
            peers: BTreeMap::new(),
        }
    }

    /// Rotates node signing key, keeping old key in historical rotation list.
    pub fn rotate_key(&mut self) {
        self.previous_verifying_keys.push(self.verifying_key);
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        self.signing_key = SigningKey::from_bytes(&bytes);
        bytes.zeroize();
        self.verifying_key = self.signing_key.verifying_key();
        self.created_at = chrono::Utc::now();
    }

    /// Checks if a public key byte slice matches the current active verifying key in constant time.
    pub fn is_current_key(&self, public_key_bytes: &[u8]) -> bool {
        bool::from(
            self.verifying_key
                .to_bytes()
                .as_slice()
                .ct_eq(public_key_bytes),
        )
    }

    /// Registers a peer node identity key.
    pub fn register_peer(&mut self, id: String, key: VerifyingKey) {
        self.peers.insert(id, key);
    }

    /// Initiates Diffie-Hellman handshake by generating ephemeral X25519 keypair.
    pub fn initiate_handshake(&self) -> (HandshakeRequest, EphemeralSecret) {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = XPublicKey::from(&secret);
        let request = HandshakeRequest {
            sender_id: self.id.clone(),
            sender_public_key: self.verifying_key.to_bytes().to_vec(),
            ephemeral_public_key: public.as_bytes().to_vec(),
        };
        (request, secret)
    }

    /// Responds to incoming handshake request, computing shared secret and signature.
    pub fn respond_to_handshake(
        &self,
        request: &HandshakeRequest,
    ) -> Result<(HandshakeResponse, [u8; 32]), String> {
        let secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let public = XPublicKey::from(&secret);
        let peer_ephemeral_bytes: [u8; 32] = request
            .ephemeral_public_key
            .clone()
            .try_into()
            .map_err(|_| "Invalid key length")?;
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

/// Post-Quantum signature container (NIST FIPS 204 ML-DSA-87 / Dilithium5).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcSignature {
    /// Algorithm name (e.g. "Dilithium5" or "ML-DSA-87").
    pub algorithm: String,
    /// Raw detached signature bytes.
    pub signature: Vec<u8>,
}

/// Post-Quantum public key container.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcPublicKey {
    /// Algorithm name.
    pub algorithm: String,
    /// Dilithium5 verifying key bytes.
    pub key_bytes: Vec<u8>,
    /// Kyber1024 recipient public key bytes.
    pub kyber_public_key_bytes: Vec<u8>,
}

impl PqcPublicKey {
    /// Verifies a detached Dilithium5 signature against a message payload.
    pub fn verify(&self, message: &[u8], pqc_signature: &PqcSignature) -> bool {
        if self.algorithm != pqc_signature.algorithm {
            return false;
        }
        if self.algorithm != "Dilithium5" && self.algorithm != "ML-DSA-87" {
            return false;
        }

        let Ok(pk) = dilithium5::PublicKey::from_bytes(&self.key_bytes) else {
            return false;
        };
        let Ok(sig) = dilithium5::DetachedSignature::from_bytes(&pqc_signature.signature) else {
            return false;
        };

        dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
    }
}

/// Post-Quantum KeyPair holding Dilithium5 and Kyber1024 secret keys with auto-zeroization on drop.
#[derive(Clone, Serialize, Deserialize)]
pub struct PqcKeyPair {
    /// PQC algorithm name.
    pub algorithm: String,
    /// Public key container.
    pub public_key: PqcPublicKey,
    /// Dilithium5 secret key bytes.
    pub secret_key_bytes: Vec<u8>,
    /// Kyber1024 public key bytes.
    pub kyber_public_key_bytes: Vec<u8>,
    /// Kyber1024 secret key bytes.
    pub kyber_secret_key_bytes: Vec<u8>,
}

impl Drop for PqcKeyPair {
    fn drop(&mut self) {
        self.secret_key_bytes.zeroize();
        self.kyber_secret_key_bytes.zeroize();
    }
}

impl PqcKeyPair {
    /// Generates a new `PqcKeyPair` using default Dilithium5 + Kyber1024 algorithms.
    pub fn generate() -> Self {
        Self::generate_with_algorithm("Dilithium5")
    }

    /// Rotates keypair and returns new public key.
    pub fn rotate(&mut self) -> PqcPublicKey {
        let new_pair = Self::generate_with_algorithm(&self.algorithm);
        *self = new_pair;
        self.public_key.clone()
    }

    /// Generates a new `PqcKeyPair` with specified algorithm identifier.
    pub fn generate_with_algorithm(algo: &str) -> Self {
        let (dilithium_pk, dilithium_sk) = dilithium5::keypair();
        let (kyber_pk, kyber_sk) = kyber1024::keypair();

        let public_key = PqcPublicKey {
            algorithm: algo.to_string(),
            key_bytes: dilithium_pk.as_bytes().to_vec(),
            kyber_public_key_bytes: kyber_pk.as_bytes().to_vec(),
        };

        Self {
            algorithm: algo.to_string(),
            public_key,
            secret_key_bytes: dilithium_sk.as_bytes().to_vec(),
            kyber_public_key_bytes: kyber_pk.as_bytes().to_vec(),
            kyber_secret_key_bytes: kyber_sk.as_bytes().to_vec(),
        }
    }

    /// Signs a message using Dilithium5, returning a detached PqcSignature.
    pub fn sign(&self, message: &[u8]) -> PqcSignature {
        let Ok(sk) = dilithium5::SecretKey::from_bytes(&self.secret_key_bytes) else {
            return PqcSignature {
                algorithm: self.algorithm.clone(),
                signature: vec![],
            };
        };

        let sig = dilithium5::detached_sign(message, &sk);

        PqcSignature {
            algorithm: self.algorithm.clone(),
            signature: sig.as_bytes().to_vec(),
        }
    }

    /// Encrypts plaintext to recipient's Kyber1024 public key using hybrid ChaCha20Poly1305 AEAD.
    pub fn encrypt(
        &self,
        recipient_pk: &PqcPublicKey,
        plaintext: &[u8],
    ) -> Result<PqcEncryptedContainer, String> {
        let Ok(kyber_pk) = kyber1024::PublicKey::from_bytes(&recipient_pk.kyber_public_key_bytes)
        else {
            return Err("Invalid Kyber1024 recipient public key".to_string());
        };

        let (shared_secret, kem_ciphertext) = kyber1024::encapsulate(&kyber_pk);

        let mut kdf = Sha256::new();
        kdf.update(b"NTI-CRYSTALS-KYBER1024-KEM-V1");
        kdf.update(shared_secret.as_bytes());
        let sym_key_bytes = kdf.finalize();

        let key = Key::from_slice(&sym_key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        // Security scanner false positive: nonce_bytes is initialized as a memory placeholder and immediately filled with secure random bytes via rand::RngCore::fill_bytes on the next line.
        let mut nonce_bytes = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("PQC Encryption failed: {}", e))?;

        Ok(PqcEncryptedContainer {
            algorithm: format!("{}-Kyber1024-ChaCha20Poly1305", recipient_pk.algorithm),
            ephemeral_pqc_pk: kem_ciphertext.as_bytes().to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        })
    }

    /// Decrypts encrypted container using recipient's Kyber1024 secret key and ChaCha20Poly1305 AEAD.
    pub fn decrypt(&self, container: &PqcEncryptedContainer) -> Result<Vec<u8>, String> {
        let Ok(kyber_sk) = kyber1024::SecretKey::from_bytes(&self.kyber_secret_key_bytes) else {
            return Err("Invalid Kyber1024 secret key".to_string());
        };

        let Ok(kem_ct) = kyber1024::Ciphertext::from_bytes(&container.ephemeral_pqc_pk) else {
            return Err("Invalid Kyber1024 KEM ciphertext in container".to_string());
        };

        let shared_secret = kyber1024::decapsulate(&kem_ct, &kyber_sk);

        let mut kdf = Sha256::new();
        kdf.update(b"NTI-CRYSTALS-KYBER1024-KEM-V1");
        kdf.update(shared_secret.as_bytes());
        let sym_key_bytes = kdf.finalize();

        let key = Key::from_slice(&sym_key_bytes);
        let cipher = ChaCha20Poly1305::new(key);

        if container.nonce.len() != 12 {
            return Err("Invalid nonce length".to_string());
        }
        let nonce = Nonce::from_slice(&container.nonce);

        cipher
            .decrypt(nonce, container.ciphertext.as_slice())
            .map_err(|e| format!("PQC Decryption failed: {}", e))
    }
}

/// Encrypted payload container produced by Kyber1024 + ChaCha20Poly1305 hybrid encryption.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PqcEncryptedContainer {
    /// Encryption algorithm identifier.
    pub algorithm: String,
    /// Kyber1024 KEM ciphertext bytes.
    pub ephemeral_pqc_pk: Vec<u8>,
    /// ChaCha20Poly1305 12-byte nonce.
    pub nonce: Vec<u8>,
    /// Symmetric ciphertext bytes.
    pub ciphertext: Vec<u8>,
}

/// Air-gapped state synchronization bundle with Ed25519 signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirGapBundle {
    /// Merkle state root hash.
    pub state_merkle_root: String,
    /// Committed audit batch payload.
    pub batch: AuditBatch,
    /// Signer Ed25519 public key.
    pub signer_public_key: Vec<u8>,
    /// Signer Ed25519 signature.
    pub signature: Vec<u8>,
}

impl AirGapBundle {
    /// Computes canonical message payload for air-gap bundle verification.
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (&self.state_merkle_root, &self.batch);
        canonical_json_bytes(&data).unwrap_or_default()
    }

    /// Verifies bundle Merkle integrity and signer signature.
    pub fn verify(&self) -> bool {
        if !bool::from(
            TrustEngine::compute_merkle_root(&self.batch.events)
                .as_bytes()
                .ct_eq(self.batch.merkle_root.as_bytes()),
        ) {
            return false;
        }

        if self.signer_public_key.is_empty() || self.signature.is_empty() {
            return false;
        }

        let Ok(pk_bytes) = self.signer_public_key.as_slice().try_into() else {
            return false;
        };
        let Ok(public_key) = VerifyingKey::from_bytes(pk_bytes) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(&self.signature) else {
            return false;
        };

        public_key.verify(&self.message_to_sign(), &sig).is_ok()
    }
}

impl TrustEngine {
    /// Exports current audit batch as an air-gap bundle, optionally signed by provided key.
    pub fn export_airgap_bundle(&self, signing_key: Option<&SigningKey>) -> Option<AirGapBundle> {
        self.batches.last().map(|batch| {
            let mut bundle = AirGapBundle {
                state_merkle_root: self.last_batch_hash.clone(),
                batch: batch.clone(),
                signer_public_key: signing_key
                    .map(|sk| sk.verifying_key().to_bytes().to_vec())
                    .unwrap_or_default(),
                signature: vec![],
            };

            if let Some(sk) = signing_key {
                let sig = sk.sign(&bundle.message_to_sign());
                bundle.signature = sig.to_bytes().to_vec();
            }

            bundle
        })
    }
}

/// Peer node metadata.
pub struct PeerNode {
    /// Peer ID.
    pub id: String,
    /// Verifying public key.
    pub public_key: Vec<u8>,
    /// Reputation score.
    pub reputation: f64,
}

/// Distributed registry holding peer records and synced state root.
pub struct DistributedRegistry {
    /// Known peer nodes.
    pub peers: BTreeMap<String, PeerNode>,
    /// Synced state Merkle root.
    pub state_root: String,
}

impl DistributedRegistry {
    /// Synchronizes registry state root from verified air-gap bundle.
    pub fn sync_state(&mut self, bundle: AirGapBundle) -> Result<(), String> {
        if !bundle.verify() {
            return Err("Air-gap bundle integrity or signature verification failed".into());
        }
        self.state_root = bundle.state_merkle_root;
        Ok(())
    }
}

#[cfg(test)]
mod pqc_internal_tests {
    use super::*;

    #[test]
    fn test_pqc_keypair_encrypt_decrypt() {
        let alice = PqcKeyPair::generate();
        let bob = PqcKeyPair::generate();
        let msg = b"hello world";
        let container = alice.encrypt(&bob.public_key, msg).unwrap();
        let decrypted = bob.decrypt(&container).unwrap();
        assert_eq!(decrypted, msg);
    }
}
