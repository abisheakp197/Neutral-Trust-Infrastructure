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
}

pub struct IntentVerifier;

impl IntentVerifier {
    pub fn verify(request: &ActionRequest, result: &serde_json::Value, policy: &IntentPolicy) -> OutcomeVerdict {
        if request.capability != policy.capability {
            return OutcomeVerdict::Invalid("capability mismatch".into());
        }

        // Example constraint check: write_file content length or specific keywords
        if request.action == "write_file" {
            let content = request.input["content"].as_str().unwrap_or("");
            if let Some(min_len) = policy.constraints["min_length"].as_u64() {
                if content.len() < min_len as usize {
                    return OutcomeVerdict::Invalid(format!("content too short: {} < {}", content.len(), min_len));
                }
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
            _ => Err("unknown action".into())
        }
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
        };

        let verdict_ok = IntentVerifier::verify(&valid_request, &result, &policy);
        assert!(matches!(verdict_ok, OutcomeVerdict::Valid));
    }
}
