use ed25519_dalek::{Signer, SigningKey};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use ube_foundation::*;

fn token() -> CapabilityToken {
    let issuer = SigningKey::from_bytes(&[42; 32]);
    let mut token = CapabilityToken {
        id: "signed-fixture".into(),
        root_actor: "issuer".into(),
        capability: "transfer".into(),
        caveats: vec![],
        signature: vec![],
    };
    token.signature = issuer.sign(&token.message_to_sign()).to_bytes().to_vec();
    token
}
fn engine() -> TrustEngine {
    let mut engine = TrustEngine::new();
    let issuer = SigningKey::from_bytes(&[42; 32]);
    engine
        .register_issuer_key("issuer", issuer.verifying_key().to_bytes().to_vec())
        .unwrap();
    engine.grant("issuer", "transfer");
    engine
}
fn request(token: Option<CapabilityToken>) -> ActionRequest {
    ActionRequest {
        id: "patch-control".into(),
        actor: "recipient".into(),
        capability: "transfer".into(),
        action: "transfer".into(),
        input: serde_json::json!({"amount": 1}),
        signature: None,
        public_key: None,
        pqc_signature: None,
        pqc_public_key: None,
        identity_claim: None,
        token,
    }
}
#[test]
fn trusted_signed_token_is_accepted_but_tampering_is_denied() {
    let engine = engine();
    assert_eq!(
        engine.evaluate(&request(Some(token()))).decision,
        Decision::Allow
    );
    for field in ["id", "issuer", "capability", "caveats", "signature"] {
        let mut modified = token();
        match field {
            "id" => modified.id.push('x'),
            "issuer" => modified.root_actor.push('x'),
            "capability" => modified.capability.push('x'),
            "caveats" => modified.caveats.push(Caveat {
                location: None,
                condition: CaveatType::Expires("2099-01-01T00:00:00Z".into()),
            }),
            _ => modified.signature.clear(),
        }
        assert_eq!(
            engine.evaluate(&request(Some(modified))).decision,
            Decision::Deny,
            "{field}"
        );
    }
}
#[test]
fn issuer_key_and_scope_must_both_be_trusted_locally() {
    let mut configured = engine();
    let outsider = SigningKey::from_bytes(&[7; 32]);
    let mut forged = token();
    forged.signature = outsider.sign(&forged.message_to_sign()).to_bytes().to_vec();
    let mut forged_request = request(Some(forged));
    forged_request.public_key = Some(outsider.verifying_key().to_bytes().to_vec());
    forged_request.signature = Some(
        outsider
            .sign(&forged_request.message_to_sign())
            .to_bytes()
            .to_vec(),
    );
    assert_eq!(
        configured.evaluate(&forged_request).decision,
        Decision::Deny
    );
    configured.capabilities.clear();
    assert_eq!(
        configured.evaluate(&request(Some(token()))).decision,
        Decision::Deny
    );
    configured.grant("issuer", "transfer");
    configured.issuer_keys.clear();
    assert_eq!(
        configured.evaluate(&request(Some(token()))).decision,
        Decision::Deny
    );
    assert!(configured.register_issuer_key("bad", vec![0; 31]).is_err());
    assert!(configured.register_issuer_key("weak", vec![0; 32]).is_err());
}
#[test]
fn issuer_trust_survives_persistence_and_legacy_state_defaults_to_no_issuers() {
    let path = std::env::temp_dir().join(format!("nti-issuer-{}.json", rand::random::<u64>()));
    engine().save_to_file(&path).unwrap();
    let loaded = TrustEngine::load_from_file(&path).unwrap();
    assert_eq!(
        loaded.evaluate(&request(Some(token()))).decision,
        Decision::Allow
    );
    let mut legacy = serde_json::to_value(loaded.export_state()).unwrap();
    legacy.as_object_mut().unwrap().remove("issuer_keys");
    std::fs::write(&path, serde_json::to_vec(&legacy).unwrap()).unwrap();
    let loaded = TrustEngine::load_from_file(&path).unwrap();
    std::fs::remove_file(path).unwrap();
    assert_eq!(
        loaded.evaluate(&request(Some(token()))).decision,
        Decision::Deny
    );
}
struct TestModule {
    name: &'static str,
    capability: &'static str,
    calls: Arc<AtomicUsize>,
    outcome: Result<serde_json::Value, String>,
}
#[async_trait::async_trait]
impl Module for TestModule {
    fn name(&self) -> &str {
        self.name
    }
    fn capabilities(&self) -> Vec<String> {
        vec![self.capability.into()]
    }
    async fn execute(&self, _: &str, _: serde_json::Value) -> Result<serde_json::Value, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.outcome.clone()
    }
}
#[tokio::test]
async fn quorum_counts_eligible_modules_before_dispatch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let mut o = Orchestrator::new(engine());
    o.engine.grant("recipient", "transfer");
    o.set_consensus_threshold(2);
    for (name, cap) in [("a", "transfer"), ("b", "unrelated")] {
        o.register_module(Box::new(TestModule {
            name,
            capability: cap,
            calls: calls.clone(),
            outcome: Ok(serde_json::json!(1)),
        }));
    }
    assert!(o.run_task(request(None)).await.is_err());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn quorum_success_errors_and_disagreement_never_fall_back() {
    for (second, expected_success) in [
        (Ok(serde_json::json!(1)), true),
        (Err("fixture failure".into()), false),
        (Ok(serde_json::json!(2)), false),
    ] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut o = Orchestrator::new(engine());
        o.engine.grant("recipient", "transfer");
        o.set_consensus_threshold(2);
        for (name, outcome) in [("a", Ok(serde_json::json!(1))), ("b", second)] {
            o.register_module(Box::new(TestModule {
                name,
                capability: "transfer",
                calls: calls.clone(),
                outcome,
            }));
        }
        assert_eq!(o.run_task(request(None)).await.is_ok(), expected_success);
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "no fallback or duplicate dispatch"
        );
    }
}
