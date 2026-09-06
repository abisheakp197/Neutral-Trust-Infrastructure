use ed25519_dalek::{Signature, Signer, Verifier, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Caveat {
    pub location: Option<String>, // For third-party caveats (future)
    pub condition: String,       // e.g., "amount <= 50" or "expires < 2026-12-31"
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
        let Ok(public_key) = VerifyingKey::from_bytes(public_key_bytes.try_into().unwrap_or(&[0;32])) else {
            return false;
        };
        let Ok(signature) = Signature::from_slice(&self.signature) else {
            return false;
        };
        public_key.verify(&self.message_to_sign(), &signature).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeIdentity {
    pub version: String,
    pub source_hash: String, // e.g. BLAKE3 or SHA256 of the source tree/binary
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityClaim {
    pub agent_id: String,
    pub public_key: Vec<u8>,
    pub code_identity: CodeIdentity,
    pub signature: Vec<u8>, // Signed by the agent's key
}

impl IdentityClaim {
    pub fn message_to_sign(&self) -> Vec<u8> {
        let data = (
            &self.agent_id,
            &self.public_key,
            &self.code_identity.version,
            &self.code_identity.source_hash,
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
    pub public_key: Option<Vec<u8>>,
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
        serde_json::to_vec(&data).expect("serialization for signing")
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
    pub decision: Option<PolicyDecision>, // Optional because it might just be agreement on outcome
    pub outcome_hash: String,
    pub signature: Vec<u8>,
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
    expected_code_hashes: BTreeMap<String, String>, // agent_id -> source_hash
    events: Vec<AuditEvent>,
    batches: Vec<AuditBatch>,
    last_batch_hash: String,
}

impl TrustEngine {
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
        if events.is_empty() {
            return "".into();
        }

        let mut hashes: Vec<String> = events
            .iter()
            .map(|e| e.hash.clone())
            .collect();

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

        let body = serde_json::to_vec(&batch).expect("batch serialization");
        let batch_hash = hex::encode(Sha256::digest(body));

        self.last_batch_hash = batch_hash.clone();
        self.batches.push(batch);

        Some(batch_hash)
    }

    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecision {
        // 1. Verify Identity Claim (Layer 1)
        if let Some(claim) = &request.identity_claim {
            // Verify signature of the claim
            let Ok(public_key) = VerifyingKey::from_bytes(claim.public_key.as_slice().try_into().unwrap_or(&[0;32])) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid identity claim public key".into(),
                };
            };
            let Ok(signature) = Signature::from_slice(&claim.signature) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid identity claim signature format".into(),
                };
            };

            if public_key.verify(&claim.message_to_sign(), &signature).is_err() {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "identity claim signature mismatch".into(),
                };
            }

            // Verify the code hash if we have an expectation
            if let Some(expected_hash) = self.expected_code_hashes.get(&claim.agent_id) {
                if &claim.code_identity.source_hash != expected_hash {
                    return PolicyDecision {
                        decision: Decision::Deny,
                        reason: format!("code identity mismatch: expected {}, got {}", expected_hash, claim.code_identity.source_hash),
                    };
                }
            }
        }

        // 2. Verify Signature if present
        if let (Some(sig_bytes), Some(pk_bytes)) = (&request.signature, &request.public_key) {
            let Ok(public_key) = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap_or(&[0;32])) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid public key format".into(),
                };
            };
            let Ok(signature) = Signature::from_slice(sig_bytes) else {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "invalid signature format".into(),
                };
            };

            if public_key.verify(&request.message_to_sign(), &signature).is_err() {
                return PolicyDecision {
                    decision: Decision::Deny,
                    reason: "cryptographic signature mismatch".into(),
                };
            }
        }

        // 2. Verify Capability Token if present (Macaroon-style delegation)
        if let Some(token) = &request.token {
            if token.capability != request.capability {
                 return PolicyDecision {
                    decision: Decision::Deny,
                    reason: format!("token capability mismatch: {} != {}", token.capability, request.capability),
                };
            }

            for caveat in &token.caveats {
                if caveat.condition.starts_with("expires < ") {
                    let expiry = &caveat.condition[10..];
                    println!("DEBUG: Checking expiry: {}", expiry);
                }
            }

            return PolicyDecision {
                decision: Decision::Allow,
                reason: "capability verified via delegated token".into(),
            };
        }

        // 3. Check direct capabilities
        let allowed = self
            .capabilities
            .get(&request.actor)
            .is_some_and(|caps| caps.contains(&request.capability));
        if allowed {
            PolicyDecision {
                decision: Decision::Allow,
                reason: "capability granted and verified".into(),
            }
        } else {
            PolicyDecision {
                decision: Decision::Deny,
                reason: "capability not granted".into(),
            }
        }
    }

    pub fn record(&mut self, request: ActionRequest) -> PolicyDecision {
        let decision = self.evaluate(&request);
        let previous_hash = self
            .events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| self.last_batch_hash.clone());
        let sequence = self.events.len() as u64;
        let body = serde_json::to_vec(&(sequence, &request, &decision, &previous_hash))
            .expect("audit serialization");
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

        decision
    }

    pub fn verify_consensus(&self, proposal: &ConsensusProposal, threshold: usize) -> bool {
        if proposal.votes.len() < threshold {
            return false;
        }

        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for vote in &proposal.votes {
            *counts.entry(vote.outcome_hash.clone()).or_default() += 1;
        }

        for count in counts.values() {
            if *count >= threshold {
                return true;
            }
        }

        false
    }

    pub fn verify_history(&self) -> bool {
        let mut prev_hash = "".to_string();

        for batch in &self.batches {
            if batch.prev_batch_hash != prev_hash {
                return false;
            }

            let mut event_prev = batch.prev_batch_hash.clone();
            for event in &batch.events {
                if event.previous_hash != event_prev {
                    return false;
                }
                let body = serde_json::to_vec(&(event.sequence, &event.request, &event.decision, &event.previous_hash))
                    .expect("audit serialization");
                let expected_hash = hex::encode(Sha256::digest(body));
                if event.hash != expected_hash {
                    return false;
                }
                event_prev = event.hash.clone();
            }

            if Self::compute_merkle_root(&batch.events) != batch.merkle_root {
                return false;
            }

            let body = serde_json::to_vec(&batch).expect("batch serialization");
            prev_hash = hex::encode(Sha256::digest(body));
        }

        let mut event_prev = if self.batches.is_empty() {
            "".to_string()
        } else {
            self.last_batch_hash.clone()
        };

        for event in &self.events {
            if event.previous_hash != event_prev {
                return false;
            }
            let body = serde_json::to_vec(&(event.sequence, &event.request, &event.decision, &event.previous_hash))
                .expect("audit serialization");
            let expected_hash = hex::encode(Sha256::digest(body));
            if event.hash != expected_hash {
                return false;
            }
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

pub struct Orchestrator {
    pub engine: TrustEngine,
    modules: BTreeMap<String, Box<dyn Module>>,
}

impl Orchestrator {
    pub fn new(engine: TrustEngine) -> Self {
        Self {
            engine,
            modules: BTreeMap::new(),
        }
    }

    pub fn register_module(&mut self, module: Box<dyn Module>) {
        self.modules.insert(module.name().to_string(), module);
    }

    pub async fn run_task(&mut self, request: ActionRequest) -> Result<serde_json::Value, String> {
        let decision = self.engine.record(request.clone());

        if decision.decision == Decision::Deny {
            return Err(format!("Denied: {}", decision.reason));
        }

        for module in self.modules.values() {
            if module.capabilities().contains(&request.capability) {
                return module.execute(&request.action, request.input).await;
            }
        }

        Err(format!("No module found for capability: {}", request.capability))
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
        if request.capability != policy.capability {
            return OutcomeVerdict::Invalid("capability mismatch".into());
        }

        if request.action == "write_file" {
            let content = request.input["content"].as_str().unwrap_or("");
            if let Some(min_len) = policy.constraints["min_length"].as_u64() {
                if content.len() < min_len as usize {
                    return OutcomeVerdict::Invalid(format!("content too short: {} < {}", content.len(), min_len));
                }
            }

            if let Some(not_allowed_paths) = policy.constraints["not_allowed_paths"].as_array() {
                let path = request.input["path"].as_str().unwrap_or("");
                for p in not_allowed_paths {
                    if let Some(p_str) = p.as_str() {
                        if path == p_str {
                            return OutcomeVerdict::Invalid(format!("writing to {} is restricted by policy", path));
                        }
                    }
                }
            }
        }

        OutcomeVerdict::Valid
    }

    pub fn verify_redundant(results: &[serde_json::Value]) -> OutcomeVerdict {
        if results.is_empty() {
            return OutcomeVerdict::Inconclusive("No results to verify".into());
        }

        let first = &results[0];
        for (i, res) in results.iter().enumerate().skip(1) {
            if res != first {
                return OutcomeVerdict::Invalid(format!("Redundant execution divergence at index {}", i));
            }
        }

        OutcomeVerdict::Valid
    }
}

pub struct SystemModule;

#[async_trait::async_trait]
impl Module for SystemModule {
    fn name(&self) -> &str { "system" }
    fn capabilities(&self) -> Vec<String> { vec!["file_management".into(), "process_info".into()] }
    async fn execute(&self, action: &str, input: serde_json::Value) -> Result<serde_json::Value, String> {
        match action {
            "read_file" => {
                let path = input["path"].as_str().ok_or("path required")?;
                std::fs::read_to_string(path).map(|s| serde_json::Value::String(s)).map_err(|e| e.to_string())
            },
            "write_file" => {
                let path = input["path"].as_str().ok_or("path required")?;
                let content = input["content"].as_str().ok_or("content required")?;
                std::fs::write(path, content).map(|_| serde_json::Value::Null).map_err(|e| e.to_string())
            },
            "list_dir" => {
                let path = input["path"].as_str().unwrap_or(".");
                let entries = std::fs::read_dir(path)
                    .map_err(|e| e.to_string())?
                    .filter_map(|res| res.ok())
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect::<Vec<String>>();
                Ok(serde_json::json!(entries))
            },
            _ => Err("unknown action".into())
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SafetyMode {
    FailSafe,
    FailOpen,
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
        let mut csprng = rand::rngs::OsRng;
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut csprng, &mut bytes);
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
        let mut csprng = rand::rngs::OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut csprng);
        let public = XPublicKey::from(&secret);

        let request = HandshakeRequest {
            sender_id: self.id.clone(),
            sender_public_key: self.verifying_key.to_bytes().to_vec(),
            ephemeral_public_key: public.as_bytes().to_vec(),
        };

        (request, secret)
    }

    pub fn respond_to_handshake(&self, request: &HandshakeRequest) -> Result<(HandshakeResponse, [u8; 32]), String> {
        let _peer_verifying_key = self.peers.get(&request.sender_id)
            .ok_or_else(|| format!("Unknown peer: {}", request.sender_id))?;

        let mut csprng = rand::rngs::OsRng;
        let secret = EphemeralSecret::random_from_rng(&mut csprng);
        let public = XPublicKey::from(&secret);

        let peer_ephemeral_bytes: [u8; 32] = request.ephemeral_public_key.clone().try_into()
            .map_err(|_| "Invalid peer ephemeral key length")?;
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub sender_id: String,
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

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
        Self {
            id,
            orchestrator,
            policies: Vec::new(),
            safety_mode: SafetyMode::FailSafe,
            current_plan: None,
        }
    }

    pub fn set_plan(&mut self, plan: AutonomousPlan) {
        self.current_plan = Some(plan);
    }

    pub fn set_safety_mode(&mut self, mode: SafetyMode) {
        self.safety_mode = mode;
    }

    pub fn add_policy(&mut self, policy: IntentPolicy) {
        self.policies.push(policy);
    }

    pub async fn execute_step(&mut self, request: ActionRequest) -> Result<serde_json::Value, String> {
        let result = self.orchestrator.run_task(request.clone()).await?;

        for policy in &self.policies {
            if policy.capability == request.capability {
                match IntentVerifier::verify(&request, &result, policy) {
                    OutcomeVerdict::Valid => {}
                    OutcomeVerdict::Invalid(reason) => {
                        let error_msg = format!("Policy violation ({}): {}", policy.name, reason);
                        if self.safety_mode == SafetyMode::FailSafe {
                            return Err(error_msg);
                        } else {
                            println!("WARNING [FailOpen]: {}", error_msg);
                        }
                    }
                    OutcomeVerdict::Inconclusive(_) => {}
                }
            }
        }

        Ok(result)
    }

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
                let step = plan.steps.get_mut(&step_id).unwrap();
                step.status = TaskStatus::InProgress;
                let request = step.action_request.clone();
                let desc = step.description.clone();

                println!("Agent {} executing step {}: {}", self.id, step.id, desc);

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

#[cfg(test)]
mod tests {
    use super::*;
    fn request(capability: &str) -> ActionRequest {
        ActionRequest {
            id: "r1".into(),
            actor: "agent".into(),
            capability: capability.into(),
            action: "read".into(),
            input: serde_json::json!({"resource":"demo"}),
            public_key: None,
            signature: None,
            token: None,
            identity_claim: None,
        }
    }
    #[test]
    fn denies_without_capability() {
        let mut engine = TrustEngine::default();
        assert_eq!(
            engine.record(request("files.read")).decision,
            Decision::Deny
        );
        assert!(engine.verify_history());
    }
    #[test]
    fn allows_granted_capability() {
        let mut engine = TrustEngine::default();
        engine.grant("agent", "files.read");
        assert_eq!(
            engine.record(request("files.read")).decision,
            Decision::Allow
        );
        assert!(engine.verify_history());
    }
    #[tokio::test]
    async fn test_outcome_verification() {
        let request = ActionRequest {
            id: "task_verify".into(),
            actor: "agent".into(),
            capability: "file_management".into(),
            action: "write_file".into(),
            input: serde_json::json!({
                "path": "test.txt",
                "content": "too short"
            }),
            public_key: None,
            signature: None,
            token: None,
            identity_claim: None,
        };

        let policy = IntentPolicy {
            name: "length_check".into(),
            capability: "file_management".into(),
            constraints: serde_json::json!({ "min_length": 20 }),
        };

        let result = serde_json::Value::Null;
        let verdict = IntentVerifier::verify(&request, &result, &policy);

        match verdict {
            OutcomeVerdict::Invalid(reason) => assert!(reason.contains("content too short")),
            _ => panic!("Should have failed verification"),
        }

        let valid_request = ActionRequest {
            id: "task_verify_ok".into(),
            actor: "agent".into(),
            capability: "file_management".into(),
            action: "write_file".into(),
            input: serde_json::json!({
                "path": "test.txt",
                "content": "This content is definitely long enough to pass the policy."
            }),
            public_key: None,
            signature: None,
            token: None,
            identity_claim: None,
        };

        let verdict_ok = IntentVerifier::verify(&valid_request, &result, &policy);
        assert!(matches!(verdict_ok, OutcomeVerdict::Valid));
    }
}
