use ube_foundation::*;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use serde_json::json;

#[tokio::test]
async fn test_adversarial_replay_attack() {
    let engine = TrustEngine::default();
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
        signature: Some(vec![0u8; 64]), // Invalid signature
        pqc_signature: None,
        public_key: Some(public_key_bytes.clone()),
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    let decision = engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Deny);
}

#[tokio::test]
async fn test_pqc_signature_and_encryption_flow() {
    let keypair_alice = PqcKeyPair::generate();
    let keypair_bob = PqcKeyPair::generate();

    // 1. PQC Signature test
    let message = b"Critical Post-Quantum Command";
    let sig = keypair_alice.sign(message);
    assert!(keypair_alice.public_key.verify(message, &sig));

    // Tampering test
    let tampered_msg = b"Tampered Command";
    assert!(!keypair_alice.public_key.verify(tampered_msg, &sig));

    // 2. PQC Encryption/Decryption test
    let plaintext = b"Top secret post-quantum payload";
    let encrypted = keypair_alice.encrypt(&keypair_bob.public_key, plaintext).unwrap();
    let decrypted = keypair_bob.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[tokio::test]
async fn test_consensus_vote_signature_rejection() {
    let mut engine = TrustEngine::default();
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key = signing_key.verifying_key();

    engine.register_voter_key("voter-1", verifying_key.to_bytes().to_vec());

    let vote = ConsensusVote {
        voter_id: "voter-1".into(),
        request_id: "req-1".into(),
        decision: Some(PolicyDecision {
            decision: Decision::Allow,
            reason: "ok".into(),
        }),
        outcome_hash: "hash-1".into(),
        signature: vec![1u8; 64], // Invalid signature
    };

    let proposal = ConsensusProposal {
        request_id: "req-1".into(),
        votes: vec![vote],
    };

    // Should fail signature verification and thus threshold check
    assert!(!engine.verify_consensus(&proposal, 1));
}

#[tokio::test]
async fn test_adversarial_consensus_threshold_bypass() {
    let mut engine = TrustEngine::default();
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);
    let verifying_key = signing_key.verifying_key();

    engine.register_voter_key("agent-a", verifying_key.to_bytes().to_vec());

    let mut vote = ConsensusVote {
        voter_id: "agent-a".into(),
        request_id: "prop-1".into(),
        decision: Some(PolicyDecision {
            decision: Decision::Allow,
            reason: "ok".into(),
        }),
        outcome_hash: "hash-1".into(),
        signature: vec![],
    };
    vote.signature = signing_key.sign(&vote.message_to_sign()).to_bytes().to_vec();

    let proposal = ConsensusProposal {
        request_id: "prop-1".into(),
        votes: vec![vote],
    };

    // Threshold of 2 should fail with only 1 valid vote
    assert!(!engine.verify_consensus(&proposal, 2));

    // Threshold of 1 should pass
    assert!(engine.verify_consensus(&proposal, 1));

    // Unregistered voter with empty signature should fail even at threshold 1
    let unauth_proposal = ConsensusProposal {
        request_id: "prop-1".into(),
        votes: vec![
            ConsensusVote {
                voter_id: "unregistered-attacker".into(),
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
    assert!(!engine.verify_consensus(&unauth_proposal, 1));
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
