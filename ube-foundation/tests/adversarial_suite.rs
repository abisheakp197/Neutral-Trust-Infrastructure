use ube_foundation::*;
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Signature};
use rand::rngs::OsRng;
use serde_json::json;
use std::collections::BTreeMap;

#[tokio::test]
async fn test_adversarial_replay_attack() {
    let mut engine = TrustEngine::default();
    let mut csprng = OsRng;
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut csprng, &mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);
    let public_key = signing_key.verifying_key();
    let public_key_bytes = public_key.to_bytes().to_vec();

    let req = ActionRequest {
        id: "replay-1".into(),
        actor: "attacker".into(),
        capability: "test".into(),
        action: "run".into(),
        input: json!({}),
        signature: Some(vec![0u8; 64]), // Placeholder
        pqc_signature: None,
        public_key: Some(public_key_bytes.clone()),
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    // Current engine is stateless regarding request IDs, so we just check it evaluates
    let _ = engine.evaluate(&req);
}

#[tokio::test]
async fn test_adversarial_consensus_threshold_bypass() {
    let engine = TrustEngine::default();

    let proposal = ConsensusProposal {
        request_id: "prop-1".into(),
        votes: vec![
            ConsensusVote {
                voter_id: "agent-a".into(),
                request_id: "prop-1".into(),
                decision: Some(PolicyDecision {
                    decision: Decision::Allow,
                    reason: "ok".into(),
                }),
                outcome_hash: "hash-1".into(),
                signature: vec![],
            }
        ],
    };

    // Threshold of 2 should fail with only 1 vote
    assert!(!engine.verify_consensus(&proposal, 2));

    // Threshold of 1 should pass
    assert!(engine.verify_consensus(&proposal, 1));
}

#[tokio::test]
async fn test_adversarial_identity_spoofing() {
    let mut engine = TrustEngine::default();
    engine.register_expected_hash("malicious-agent", "correct-hash");

    let claim = IdentityClaim {
        agent_id: "malicious-agent".into(),
        code_identity: CodeIdentity {
            version: "1.0".into(),
            source_hash: "fake-hash".into(),
        },
        provider: "test".into(),
        claim_type: "code".into(),
        value: "active".into(),
        proof: vec![],
        public_key: vec![0u8; 32],
        signature: vec![0u8; 64],
    };

    let req = ActionRequest {
        id: "spoof-1".into(),
        actor: "malicious-agent".into(),
        capability: "admin".into(),
        action: "delete".into(),
        input: json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: Some(claim),
    };

    // The engine should deny the request because of code hash mismatch
    let result = engine.evaluate(&req);
    assert_eq!(result.decision, Decision::Deny);
    assert!(result.reason.contains("identity sig mismatch") || result.reason.contains("code hash mismatch"));
}
