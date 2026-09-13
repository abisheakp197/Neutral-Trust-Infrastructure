use ube_foundation::*;
use serde_json::json;

#[test]
fn test_adversarial_malformed_pqc_signatures() {
    let mut engine = TrustEngine::default();

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
    let mut engine = TrustEngine::default();

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
    let mut engine = TrustEngine::default();
    let mut registry = DistributedRegistry {
        peers: std::collections::BTreeMap::new(),
        state_root: "initial".into(),
    };

    // Test Case 3: Tampered Merkle Root in AirGap bundle
    let tampered_bundle = AirGapBundle {
        state_merkle_root: "fake_root".into(),
        batch: AuditBatch {
            events: vec![],
            merkle_root: "real_root".into(),
            prev_batch_hash: "none".into(),
        },
        signature: vec![],
    };

    let result = registry.sync_state(tampered_bundle);
    assert!(result.is_err(), "Sync should fail when state_merkle_root does not match batch.merkle_root");
}

#[test]
fn test_adversarial_identity_spoofing() {
    let mut engine = TrustEngine::default();

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
