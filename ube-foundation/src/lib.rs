use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActionRequest {
    pub id: String,
    pub actor: String,
    pub capability: String,
    pub action: String,
    pub input: serde_json::Value,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyDecision {
    pub decision: Decision,
    pub reason: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub request: ActionRequest,
    pub decision: PolicyDecision,
    pub previous_hash: String,
    pub hash: String,
}
#[derive(Debug, Default)]
pub struct TrustEngine {
    capabilities: BTreeMap<String, BTreeSet<String>>,
    events: Vec<AuditEvent>,
}
impl TrustEngine {
    pub fn grant(&mut self, actor: impl Into<String>, capability: impl Into<String>) {
        self.capabilities
            .entry(actor.into())
            .or_default()
            .insert(capability.into());
    }
    pub fn evaluate(&self, request: &ActionRequest) -> PolicyDecision {
        let allowed = self
            .capabilities
            .get(&request.actor)
            .is_some_and(|caps| caps.contains(&request.capability));
        if allowed {
            PolicyDecision {
                decision: Decision::Allow,
                reason: "capability granted".into(),
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
            .unwrap_or_default();
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
        decision
    }
    pub fn events(&self) -> &[AuditEvent] {
        &self.events
    }
    pub fn verify_chain(&self) -> bool {
        self.events.iter().enumerate().all(|(i, e)| {
            e.sequence == i as u64
                && (i == 0 || e.previous_hash == self.events[i - 1].hash)
                && hex::encode(Sha256::digest(
                    serde_json::to_vec(&(e.sequence, &e.request, &e.decision, &e.previous_hash))
                        .expect("audit serialization"),
                )) == e.hash
        })
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
        }
    }
    #[test]
    fn denies_without_capability() {
        let mut engine = TrustEngine::default();
        assert_eq!(
            engine.record(request("files.read")).decision,
            Decision::Deny
        );
        assert!(engine.verify_chain());
    }
    #[test]
    fn allows_granted_capability() {
        let mut engine = TrustEngine::default();
        engine.grant("agent", "files.read");
        assert_eq!(
            engine.record(request("files.read")).decision,
            Decision::Allow
        );
        assert!(engine.verify_chain());
    }
    #[test]
    fn detects_tampering() {
        let mut engine = TrustEngine::default();
        engine.grant("agent", "files.read");
        engine.record(request("files.read"));
        engine.events[0].request.action = "write".into();
        assert!(!engine.verify_chain());
    }
}
