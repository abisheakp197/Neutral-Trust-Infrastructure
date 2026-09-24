use ube_foundation::*;
use ed25519_dalek::{SigningKey, Signer};
use rand::{RngCore, SeedableRng};
use rand::rngs::StdRng;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::thread;

/// 1. High-Throughput Concurrent Multi-Threaded Stress Test
#[test]
fn test_concurrent_multi_threaded_stress_load() {
    let engine = Arc::new(Mutex::new(TrustEngine::new()));

    // Seed capabilities across 100 actors
    {
        let mut guard = engine.lock().unwrap();
        for i in 0..100 {
            guard.grant(format!("actor_{}", i), "execute_trade");
        }
    }

    let mut handles = vec![];

    // Spawn 10 concurrent threads processing 200 requests each (2,000 requests total)
    for t_idx in 0..10 {
        let engine_clone = Arc::clone(&engine);
        let handle = thread::spawn(move || {
            for req_idx in 0..200 {
                let actor_id = format!("actor_{}", (t_idx * 20 + req_idx) % 100);
                let req = ActionRequest {
                    id: format!("stress_req_{}_{}", t_idx, req_idx),
                    actor: actor_id,
                    capability: "execute_trade".into(),
                    action: "trade".into(),
                    input: json!({"amount": req_idx}),
                    signature: None,
                    pqc_signature: None,
                    public_key: None,
                    pqc_public_key: None,
                    token: None,
                    identity_claim: None,
                };

                let mut guard = engine_clone.lock().unwrap();
                let decision = guard.record(req);
                assert_eq!(decision.decision, Decision::Allow);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let guard = engine.lock().unwrap();
    assert_eq!(guard.events.len() + guard.batches.len() * 10, 2000);
    assert!(guard.verify_history());
}

/// 2. Deep Adversarial Fuzzing on PQC Dilithium5 & Kyber1024
#[test]
fn test_pqc_adversarial_bit_flip_fuzzing() {
    let mut rng = StdRng::seed_from_u64(0xDEADBEEF);
    let alice = PqcKeyPair::generate();
    let bob = PqcKeyPair::generate();

    let msg = b"CRITICAL FINANCIAL INSTRUCTION: TRANSFER $5,000,000";
    let valid_sig = alice.sign(msg);

    // Verify valid signature passes
    assert!(alice.public_key.verify(msg, &valid_sig));

    // Fuzzing 100 corrupted signatures with single/multi bit-flips
    for i in 0..100 {
        let mut corrupted_sig_bytes = valid_sig.signature.clone();
        let flip_idx = (rng.next_u32() as usize) % corrupted_sig_bytes.len();
        corrupted_sig_bytes[flip_idx] ^= (rng.next_u32() % 255 + 1) as u8;

        let corrupted_sig = PqcSignature {
            algorithm: valid_sig.algorithm.clone(),
            signature: corrupted_sig_bytes,
        };

        // Corrupted signature must NEVER pass verification
        assert!(
            !alice.public_key.verify(msg, &corrupted_sig),
            "Fuzz iteration {} failed: Corrupted Dilithium5 signature passed verification!",
            i
        );
    }

    // Fuzzing Kyber1024 Decryption with corrupted ciphertext
    let plaintext = b"Unencrypted Sensitive Data Payload";
    let valid_container = alice.encrypt(&bob.public_key, plaintext).unwrap();

    for i in 0..50 {
        let mut corrupted_container = valid_container.clone();
        let flip_idx = (rng.next_u32() as usize) % corrupted_container.ciphertext.len();
        corrupted_container.ciphertext[flip_idx] ^= (rng.next_u32() % 255 + 1) as u8;

        // Decryption of corrupted ciphertext must return Err or produce mismatched plaintext
        let res = bob.decrypt(&corrupted_container);
        if let Ok(decrypted_bytes) = res {
            assert_ne!(
                decrypted_bytes, plaintext,
                "Fuzz iteration {} failed: Corrupted Kyber ciphertext decrypted to original plaintext!",
                i
            );
        }
    }
}

/// 3. Byzantine BFT Consensus Attack Scenarios
#[test]
fn test_byzantine_sybil_and_divergent_hash_attacks() {
    let mut engine = TrustEngine::new();
    let mut rng = StdRng::seed_from_u64(0xCAFEBABE);

    let mut voter_keys = vec![];

    // Register 5 legitimate voters
    for i in 0..5 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let voter_id = format!("voter_{}", i);
        engine.register_voter_key(&voter_id, signing_key.verifying_key().to_bytes().to_vec());
        voter_keys.push((voter_id, signing_key));
    }

    // Scenario A: Attackers try Sybil attack with 10 unregistered voters
    let mut votes = vec![];
    for i in 0..10 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        let sybil_key = SigningKey::from_bytes(&bytes);

        let mut vote = ConsensusVote {
            voter_id: format!("sybil_voter_{}", i),
            request_id: "req_prop_1".into(),
            decision: Some(PolicyDecision {
                decision: Decision::Allow,
                reason: "Sybil vote".into(),
            }),
            outcome_hash: "hash_malicious".into(),
            signature: vec![],
        };
        vote.signature = sybil_key.sign(&vote.message_to_sign()).to_bytes().to_vec();
        votes.push(vote);
    }

    let sybil_proposal = ConsensusProposal {
        request_id: "req_prop_1".into(),
        votes,
    };

    // Unregistered sybil votes must fail threshold checks
    assert!(!engine.verify_consensus(&sybil_proposal, 3));

    // Scenario B: Legitimate voters produce split outcome hashes (2 agree, 2 disagree)
    let mut split_votes = vec![];
    for (idx, (voter_id, signing_key)) in voter_keys.iter().take(4).enumerate() {
        let outcome_hash = if idx < 2 { "outcome_A" } else { "outcome_B" };
        let mut vote = ConsensusVote {
            voter_id: voter_id.clone(),
            request_id: "req_prop_2".into(),
            decision: Some(PolicyDecision {
                decision: Decision::Allow,
                reason: "Legitimate vote".into(),
            }),
            outcome_hash: outcome_hash.into(),
            signature: vec![],
        };
        vote.signature = signing_key.sign(&vote.message_to_sign()).to_bytes().to_vec();
        split_votes.push(vote);
    }

    let split_proposal = ConsensusProposal {
        request_id: "req_prop_2".into(),
        votes: split_votes,
    };

    // Require threshold of 3; split votes (max 2 per hash) must fail
    assert!(!engine.verify_consensus(&split_proposal, 3));
}

/// 4. Persisted State Corruption & Recovery Rejection Test
#[test]
fn test_persisted_state_tampering_detection() {
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join(format!("tamper_test_{}.json", rand::random::<u64>()));

    let mut engine = TrustEngine::new().with_persistence(&file_path);
    engine.grant("alice", "admin");

    for i in 0..15 {
        let req = ActionRequest {
            id: format!("req_{}", i),
            actor: "alice".into(),
            capability: "admin".into(),
            action: "write".into(),
            input: json!({"val": i}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
        };
        engine.record(req);
    }

    // Confirm state file saved and valid
    assert!(file_path.exists());
    let recovered = TrustEngine::load_from_file(&file_path);
    assert!(recovered.is_ok());

    // Tamper with state file on disk (corrupt an audit log hash)
    let raw_bytes = std::fs::read(&file_path).unwrap();
    let mut raw_str = String::from_utf8(raw_bytes).unwrap();
    raw_str = raw_str.replace("req_0", "req_tampered_0");
    std::fs::write(&file_path, raw_str).unwrap();

    // Loading tampered state MUST fail integrity verification
    let corrupted_recovery = TrustEngine::load_from_file(&file_path);
    assert!(
        corrupted_recovery.is_err(),
        "State loading succeeded despite tampered audit log sequence!"
    );

    let _ = std::fs::remove_file(file_path);
}
