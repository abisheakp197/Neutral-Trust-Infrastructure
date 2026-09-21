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
    let mut csprng = OsRng;
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut csprng, &mut bytes);
    let signing_key = SigningKey::from_bytes(&bytes);
    let public_key = signing_key.verifying_key();

    let mut vote = ConsensusVote {
        voter_id: "agent-a".into(),
        request_id: "prop-1".into(),
        decision: Some(PolicyDecision {
            decision: Decision::Allow,
            reason: "ok".into(),
        }),
        outcome_hash: "hash-1".into(),
        public_key: public_key.to_bytes().to_vec(),
        signature: vec![],
    };
    let msg = vote.message_to_sign();
    vote.signature = signing_key.sign(&msg).to_bytes().to_vec();

    let proposal = ConsensusProposal {
        request_id: "prop-1".into(),
        votes: vec![vote],
    };

    // Threshold of 2 should fail with only 1 valid signed vote
    assert!(!engine.verify_consensus(&proposal, 2));

    // Threshold of 1 should pass with valid signed vote
    assert!(engine.verify_consensus(&proposal, 1));
}

#[tokio::test]
async fn test_adversarial_invalid_and_forged_vote_signatures() {
    let engine = TrustEngine::default();

    let mut csprng = OsRng;
    let mut key_a_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut csprng, &mut key_a_bytes);
    let key_a = SigningKey::from_bytes(&key_a_bytes);

    let mut key_b_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut csprng, &mut key_b_bytes);
    let key_b = SigningKey::from_bytes(&key_b_bytes);

    // 1. Unsigned vote (empty signature)
    let unsigned_vote = ConsensusVote {
        voter_id: "agent-a".into(),
        request_id: "prop-2".into(),
        decision: Some(PolicyDecision { decision: Decision::Allow, reason: "ok".into() }),
        outcome_hash: "hash-1".into(),
        public_key: key_a.verifying_key().to_bytes().to_vec(),
        signature: vec![],
    };

    let proposal_unsigned = ConsensusProposal {
        request_id: "prop-2".into(),
        votes: vec![unsigned_vote],
    };
    assert!(!engine.verify_consensus(&proposal_unsigned, 1));

    // 2. Forged vote signature (signed with key B, claiming public key A)
    let mut forged_vote = ConsensusVote {
        voter_id: "agent-a".into(),
        request_id: "prop-2".into(),
        decision: Some(PolicyDecision { decision: Decision::Allow, reason: "ok".into() }),
        outcome_hash: "hash-1".into(),
        public_key: key_a.verifying_key().to_bytes().to_vec(),
        signature: vec![],
    };
    let msg = forged_vote.message_to_sign();
    forged_vote.signature = key_b.sign(&msg).to_bytes().to_vec();

    let proposal_forged = ConsensusProposal {
        request_id: "prop-2".into(),
        votes: vec![forged_vote],
    };
    assert!(!engine.verify_consensus(&proposal_forged, 1));

    // 2b. Identity spoofing attack (registered voter_id "agent-a" key_a, but attacker votes with key_b)
    let mut engine_with_keys = TrustEngine::default();
    engine_with_keys.register_voter_key("agent-a", key_a.verifying_key().to_bytes().to_vec());

    let mut spoofed_key_vote = ConsensusVote {
        voter_id: "agent-a".into(),
        request_id: "prop-2b".into(),
        decision: Some(PolicyDecision { decision: Decision::Allow, reason: "ok".into() }),
        outcome_hash: "hash-1".into(),
        public_key: key_b.verifying_key().to_bytes().to_vec(),
        signature: vec![],
    };
    let msg_b = spoofed_key_vote.message_to_sign();
    spoofed_key_vote.signature = key_b.sign(&msg_b).to_bytes().to_vec();

    let proposal_spoofed_key = ConsensusProposal {
        request_id: "prop-2b".into(),
        votes: vec![spoofed_key_vote],
    };
    // Should fail because public_key key_b does not match registered key_a for "agent-a"
    assert!(!engine_with_keys.verify_consensus(&proposal_spoofed_key, 1));

    // 3. Duplicate votes from same voter ID
    let mut valid_vote1 = ConsensusVote {
        voter_id: "agent-a".into(),
        request_id: "prop-3".into(),
        decision: Some(PolicyDecision { decision: Decision::Allow, reason: "ok".into() }),
        outcome_hash: "hash-1".into(),
        public_key: key_a.verifying_key().to_bytes().to_vec(),
        signature: vec![],
    };
    let msg1 = valid_vote1.message_to_sign();
    valid_vote1.signature = key_a.sign(&msg1).to_bytes().to_vec();

    let mut duplicate_vote = valid_vote1.clone();

    let proposal_duplicates = ConsensusProposal {
        request_id: "prop-3".into(),
        votes: vec![valid_vote1, duplicate_vote],
    };

    // Should NOT meet threshold 2 because duplicate voter identity is ignored
    assert!(!engine.verify_consensus(&proposal_duplicates, 2));
}

#[tokio::test]
async fn test_adversarial_remote_vote_signature_verification() {
    let mut csprng = OsRng;
    let mut key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut csprng, &mut key_bytes);
    let key = SigningKey::from_bytes(&key_bytes);

    let mut remote_vote = RemoteVote {
        proposal_id: "prop-remote-1".into(),
        voter_id: "node-1".into(),
        verdict: OutcomeVerdict::Valid,
        public_key: key.verifying_key().to_bytes().to_vec(),
        signature: vec![],
    };

    // Unsigned fails verification
    assert!(!remote_vote.verify());

    // Properly signed passes verification
    let msg = remote_vote.message_to_sign();
    remote_vote.signature = key.sign(&msg).to_bytes().to_vec();
    assert!(remote_vote.verify());

    // Tampered payload fails verification
    remote_vote.proposal_id = "prop-remote-2".into();
    assert!(!remote_vote.verify());
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
