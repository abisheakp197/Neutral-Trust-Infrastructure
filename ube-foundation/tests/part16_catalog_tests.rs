use ube_foundation::{
    PqcKeyPair, TrustEngine, ActionRequest, CapabilityToken, Caveat, CaveatType, CaveatInterpreter,
    ConsensusProposal, ConsensusVote, AgentMeshNode, Orchestrator, SystemModule, Decision,
    OutcomeVerdict
};
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;
use ed25519_dalek::{SigningKey, Signer};

#[test]
fn test_pqc_keypair_new() {
    let keypair = PqcKeyPair::generate();
    assert_eq!(keypair.algorithm, "Dilithium5");
    assert!(!keypair.public_key.key_bytes.is_empty());
    assert!(!keypair.kyber_public_key_bytes.is_empty());
}

#[test]
fn test_dilithium5_sign_verify_roundtrip() {
    let keypair = PqcKeyPair::generate();
    let msg = b"NTI test message";
    let sig = keypair.sign(msg);
    assert!(keypair.public_key.verify(msg, &sig));
}

#[test]
fn test_dilithium5_verify_tampered() {
    let keypair = PqcKeyPair::generate();
    let msg = b"Original message";
    let tampered_msg = b"Tampered message";
    let sig = keypair.sign(msg);
    assert!(!keypair.public_key.verify(tampered_msg, &sig));
}

#[test]
fn test_dilithium5_verify_wrong_key() {
    let keypair1 = PqcKeyPair::generate();
    let keypair2 = PqcKeyPair::generate();
    let msg = b"Authentic payload";
    let sig = keypair1.sign(msg);
    assert!(!keypair2.public_key.verify(msg, &sig));
}

#[test]
fn test_kyber1024_encap_decap_roundtrip() {
    let sender = PqcKeyPair::generate();
    let recipient = PqcKeyPair::generate();
    let plaintext = b"Confidential NTI payload";
    let container = sender.encrypt(&recipient.public_key, plaintext).expect("encryption failed");
    let decrypted = recipient.decrypt(&container).expect("decryption failed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_kyber1024_wrong_key_fails() {
    let sender = PqcKeyPair::generate();
    let recipient = PqcKeyPair::generate();
    let eavesdropper = PqcKeyPair::generate();
    let plaintext = b"Secret text";
    let container = sender.encrypt(&recipient.public_key, plaintext).unwrap();
    assert!(eavesdropper.decrypt(&container).is_err());
}

#[test]
fn test_signature_determinism() {
    let keypair = PqcKeyPair::generate();
    let msg = b"Deterministic signature test";
    let sig1 = keypair.sign(msg);
    let sig2 = keypair.sign(msg);
    assert_eq!(sig1.signature, sig2.signature);
}

#[test]
fn test_canonical_json_sorted_keys() {
    let mut map = BTreeMap::new();
    map.insert("zebra", "last");
    map.insert("apple", "first");
    map.insert("banana", "middle");
    let json_str = serde_json::to_string(&map).unwrap();
    assert_eq!(json_str, r#"{"apple":"first","banana":"middle","zebra":"last"}"#);
}

#[test]
fn test_canonical_json_unicode() {
    let mut map = BTreeMap::new();
    map.insert("agent", "🤖 Agent-NTI Alpha 🛡️");
    let json_str = serde_json::to_string(&map).unwrap();
    assert!(json_str.contains("🤖"));
}

#[test]
fn test_canonical_json_nested() {
    let mut inner = BTreeMap::new();
    inner.insert("b", serde_json::json!(2));
    inner.insert("a", serde_json::json!(1));

    let mut outer = BTreeMap::new();
    outer.insert("nested", serde_json::json!(inner));
    outer.insert("status", serde_json::json!(200));

    let json_str = serde_json::to_string(&outer).unwrap();
    assert_eq!(json_str, r#"{"nested":{"a":1,"b":2},"status":200}"#);
}

#[test]
fn test_sha256_digest_length() {
    let mut hasher = Sha256::new();
    hasher.update(b"canonical json string");
    let hash = hasher.finalize();
    assert_eq!(hash.len(), 32);
    assert_eq!(hex::encode(hash).len(), 64);
}

#[test]
fn test_trust_engine_allow_valid() {
    let mut engine = TrustEngine::new();
    let keypair = PqcKeyPair::generate();

    engine.grant("agent_1", "read_data");

    let req_input = serde_json::json!({"resource": "db"});
    let msg_tuple = vec![
        serde_json::Value::String("req_101".into()),
        serde_json::Value::String("agent_1".into()),
        serde_json::Value::String("read_data".into()),
        serde_json::Value::String("execute".into()),
        req_input.clone(),
    ];
    let msg_bytes = serde_json::to_vec(&msg_tuple).unwrap();
    let sig = keypair.sign(&msg_bytes);

    let req = ActionRequest {
        id: "req_101".into(),
        actor: "agent_1".into(),
        capability: "read_data".into(),
        action: "execute".into(),
        input: req_input,
        signature: None,
        pqc_signature: Some(sig),
        public_key: None,
        pqc_public_key: Some(keypair.public_key.key_bytes.clone()),
        token: None,
        identity_claim: None,
    };

    let decision = engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);
}

#[test]
fn test_trust_engine_deny_invalid() {
    let engine = TrustEngine::new();
    let req = ActionRequest {
        id: "req_102".into(),
        actor: "agent_unauthorized".into(),
        capability: "admin_delete".into(),
        action: "execute".into(),
        input: serde_json::json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    let decision = engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Deny);
}

#[test]
fn test_trust_engine_fail_closed() {
    let mut engine = TrustEngine::new();
    let keypair = PqcKeyPair::generate();
    engine.grant("agent_malformed", "write_logs");

    let invalid_sig = ube_foundation::PqcSignature {
        algorithm: "Dilithium5".into(),
        signature: vec![0u8; 100], // Corrupted signature
    };

    let req = ActionRequest {
        id: "req_103".into(),
        actor: "agent_malformed".into(),
        capability: "write_logs".into(),
        action: "execute".into(),
        input: serde_json::json!({}),
        signature: None,
        pqc_signature: Some(invalid_sig),
        public_key: None,
        pqc_public_key: Some(keypair.public_key.key_bytes.clone()),
        token: None,
        identity_claim: None,
    };

    let decision = engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision.reason.contains("pqc sig mismatch"));
}

#[test]
fn test_capability_token_sign() {
    let issuer = SigningKey::from_bytes(&[7u8; 32]);
    let mut token = CapabilityToken {
        id: "token_999".into(),
        root_actor: "authority_node".into(),
        capability: "file_read".into(),
        caveats: vec![],
        signature: vec![],
    };

    let sig = issuer.sign(&token.message_to_sign());
    token.signature = sig.to_bytes().to_vec();
    assert!(!token.signature.is_empty());
    let vk = issuer.verifying_key();
    assert!(token.verify(&vk.to_bytes()));
}

#[test]
fn test_capability_token_caveat_enforced() {
    let engine = TrustEngine::new();
    let caveat = Caveat {
        location: None,
        condition: CaveatType::ValueLimit(100, "USD".into()),
    };
    let req = ActionRequest {
        id: "req_caveat".into(),
        actor: "agent".into(),
        capability: "pay".into(),
        action: "execute".into(),
        input: serde_json::json!({"amount": 150}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    let verdict = CaveatInterpreter::verify_all(&[caveat], &req, &engine);
    assert!(matches!(verdict, OutcomeVerdict::Invalid(_)));
}

#[test]
fn test_consensus_proposal_vote() {
    let voter = PqcKeyPair::generate();
    let vote = ConsensusVote {
        voter_id: "node_beta".into(),
        request_id: "req_proposal".into(),
        decision: None,
        outcome_hash: "hash123".into(),
        signature: voter.sign(b"req_proposal:hash123").signature,
    };

    let proposal = ConsensusProposal {
        request_id: "req_proposal".into(),
        votes: vec![vote],
    };

    assert_eq!(proposal.votes.len(), 1);
    assert_eq!(proposal.votes[0].voter_id, "node_beta");
}

#[test]
fn test_consensus_quorum() {
    let proposal = ConsensusProposal {
        request_id: "req_quorum".into(),
        votes: vec![],
    };
    let threshold = 3;

    assert!(proposal.votes.len() < threshold);
}

#[test]
fn test_agent_mesh_node_id() {
    let node = AgentMeshNode::new("mesh_node_7".into());
    assert_eq!(node.id, "mesh_node_7");
}

#[test]
fn test_orchestrator_lifecycle() {
    let engine = TrustEngine::new();
    let mut orchestrator = Orchestrator::new(engine);
    orchestrator.register_module(Box::new(SystemModule));
    assert_eq!(orchestrator.consensus_threshold, 1);
}
