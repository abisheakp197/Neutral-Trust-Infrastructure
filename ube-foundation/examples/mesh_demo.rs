use ube_foundation::{
    AgentMeshNode, ConsensusProposal, ConsensusVote, Decision, PolicyDecision, TrustEngine,
};

fn main() {
    println!("--- Layer 6: Multi-Agent Mesh & BFT Consensus Demo ---");

    // 1. Setup Mesh Nodes
    let mut node_a = AgentMeshNode::new("agent-a".into());
    let mut node_b = AgentMeshNode::new("agent-b".into());
    let node_c = AgentMeshNode::new("agent-c".into());

    // Register peers so they can verify each other
    node_a.register_peer("agent-b".into(), node_b.verifying_key);
    node_b.register_peer("agent-a".into(), node_a.verifying_key);

    // 2. Demonstrate Secure Handshake (X25519 + Ed25519)
    println!("\n[1] Initiating Secure Handshake between Agent A and Agent B...");
    let (req, secret_a) = node_a.initiate_handshake();
    let (resp, shared_b) = node_b.respond_to_handshake(&req).unwrap();

    // Agent A completes the handshake
    let peer_ephemeral_bytes: [u8; 32] = resp.ephemeral_public_key.clone().try_into().unwrap();
    let shared_a = secret_a.diffie_hellman(&x25519_dalek::PublicKey::from(peer_ephemeral_bytes));

    println!("Handshake Complete!");
    println!("Shared Secret (A side): {}", hex::encode(shared_a.as_bytes()));
    println!("Shared Secret (B side): {}", hex::encode(shared_b));
    assert_eq!(shared_a.as_bytes(), &shared_b);

    // 3. Demonstrate BFT Consensus
    println!("\n[2] Simulating BFT Consensus (Majority Voting)...");
    let trust = TrustEngine::default();
    let request_id = "task-123".to_string();
    let outcome_hash = "hash-of-successful-result".to_string();

    let decision_ok = PolicyDecision {
        decision: Decision::Allow,
        reason: "Valid outcome".into(),
    };

    // Simulate 3 agents voting
    let votes = vec![
        ConsensusVote {
            voter_id: "agent-a".into(),
            request_id: request_id.clone(),
            decision: Some(decision_ok.clone()),
            outcome_hash: outcome_hash.clone(),
            signature: vec![], // Placeholder
        },
        ConsensusVote {
            voter_id: "agent-b".into(),
            request_id: request_id.clone(),
            decision: Some(decision_ok.clone()),
            outcome_hash: outcome_hash.clone(),
            signature: vec![],
        },
        ConsensusVote {
            voter_id: "agent-c".into(),
            request_id: request_id.clone(),
            decision: None,
            outcome_hash: "corrupt-hash".into(),
            signature: vec![],
        },
    ];

    let proposal = ConsensusProposal {
        request_id: request_id.clone(),
        votes,
    };

    // Threshold = 2 (Majority of 3)
    let threshold = 2;
    let verified = trust.verify_consensus(&proposal, threshold);

    println!("Consensus Result (Threshold {}/3): {}", threshold, if verified { "PASS (Majority Reached)" } else { "FAIL" });
    assert!(verified);

    println!("\n--- Multi-Agent Mesh Demo Complete ---");
}
