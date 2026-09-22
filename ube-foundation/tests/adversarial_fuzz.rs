use ube_foundation::*;
use serde_json::json;

#[test]
fn test_adversarial_malformed_pqc_signatures() {
    let engine = TrustEngine::default();

    // Test Case 1: Wrong Algorithm Name (Fuzzing the algorithm string)
    let req_wrong_algo = ActionRequest {
        id: "adv-1".into(),
        actor: "attacker".into(),
        capability: "admin".into(),
        action: "delete".into(),
        input: json!({}),
        signature: None,
        pqc_signature: Some(PqcSignature {
            algorithm: "NotARealAlgo".into(),
            signature: vec![0u8; 64],
        }),
        public_key: None,
        pqc_public_key: Some(vec![1u8; 32]),
        token: None,
        identity_claim: None,
    };

    // Should be Denied due to unsupported algorithm
    assert_eq!(engine.evaluate(&req_wrong_algo).decision, Decision::Deny);
}

#[test]
fn test_adversarial_empty_identities() {
    let engine = TrustEngine::default();

    // Test Case 2: Action request with no credentials at all
    let req_empty = ActionRequest {
        id: "adv-2".into(),
        actor: "ghost".into(),
        capability: "restricted".into(),
        action: "read".into(),
        input: json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    // Should Deny because no permission is granted and no identity/token is present
    assert_eq!(engine.evaluate(&req_empty).decision, Decision::Deny);
}

#[test]
fn test_adversarial_merkle_tampering() {
    use ed25519_dalek::SigningKey;
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);

    let mut engine = TrustEngine::default();
    let req = ActionRequest {
        id: "req-1".into(),
        actor: "actor-1".into(),
        capability: "cap-1".into(),
        action: "act-1".into(),
        input: json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };
    engine.grant("actor-1", "cap-1");
    engine.record(req);
    engine.commit_batch();

    let valid_bundle = engine.export_airgap_bundle(Some(&signing_key)).unwrap();

    let mut registry = DistributedRegistry {
        peers: std::collections::BTreeMap::new(),
        state_root: "initial".into(),
    };

    // Valid signed bundle should sync successfully
    assert!(registry.sync_state(valid_bundle.clone()).is_ok());

    // Tampered Merkle Root in AirGap bundle should fail
    let mut tampered_bundle = valid_bundle.clone();
    tampered_bundle.state_merkle_root = "fake_root".into();
    assert!(registry.sync_state(tampered_bundle).is_err());

    // Unsigned bundle (stripped signature) should fail
    let mut unsigned_bundle = valid_bundle.clone();
    unsigned_bundle.signature = vec![];
    assert!(registry.sync_state(unsigned_bundle).is_err());
}

#[test]
fn test_adversarial_identity_spoofing() {
    let engine = TrustEngine::default();

    // Create a request claiming a version it doesn't have
    let req_spoof = ActionRequest {
        id: "adv-3".into(),
        actor: "malicious_agent".into(),
        capability: "system".into(),
        action: "upgrade".into(),
        input: json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: Some(IdentityClaim {
            agent_id: "malicious_agent".into(),
            code_identity: CodeIdentity {
                version: "999.9.9".into(),
                source_hash: "fake-hash".into(),
            },
            provider: "malicious-host".into(),
            claim_type: "version_spoof".into(),
            value: "untrusted".into(),
            proof: vec![],
            public_key: vec![],
            signature: vec![],
        }),
    };

    // Should deny because there's no policy allowing "999.9.9" for "system" capability
    assert_eq!(engine.evaluate(&req_spoof).decision, Decision::Deny);
}
