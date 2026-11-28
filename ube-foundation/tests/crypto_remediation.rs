//! Regression tests for the crypto remediation in 0.1.9.
//!
//! Three defects are covered, each with a positive control so a passing test
//! cannot be explained by the engine denying everything:
//!
//! 1. PQC key binding  - a valid ML-DSA-87 signature must only authorize the
//!    actor whose key is pinned; a self-signed request must be denied.
//! 2. RFC 6962 Merkle  - the audit root promotes odd nodes instead of
//!    duplicating them, and inclusion proofs fold to the batch root.
//! 3. Policy timing    - token expiry is evaluated against an explicit `now`,
//!    and a caveat that cannot be evaluated fails closed.

use chrono::{Duration, Utc};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use ube_foundation::merkle::{self, MerkleSiblingPosition};
use ube_foundation::*;

const ACTOR: &str = "did:webvh:QmTestActor:agents.example.com";
const CAPABILITY: &str = "shell.execute";

fn signed_pqc_request(
    actor: &str,
    presented_key: Vec<u8>,
    signature: PqcSignature,
) -> ActionRequest {
    ActionRequest {
        id: "req-pqc-binding".into(),
        actor: actor.into(),
        capability: CAPABILITY.into(),
        action: "bash".into(),
        input: json!({"command": "ls -la"}),
        signature: None,
        pqc_signature: Some(signature),
        public_key: None,
        pqc_public_key: Some(presented_key),
        token: None,
        identity_claim: None,
        workload_measurement_hash: None,
    }
}

// -- 1. PQC key binding ---------------------------------------------------

#[test]
fn pqc_signature_from_pinned_key_is_allowed() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    engine
        .register_pqc_identity_key(ACTOR, key_pair.public_key.key_bytes.clone(), None)
        .unwrap();

    let mut request = signed_pqc_request(
        ACTOR,
        key_pair.public_key.key_bytes.clone(),
        PqcSignature {
            algorithm: "ML-DSA-87".into(),
            signature: vec![],
        },
    );
    request.pqc_signature = Some(key_pair.sign(&request.message_to_sign()));

    assert_eq!(engine.evaluate(&request).decision, Decision::Allow);
}

#[test]
fn self_signed_request_without_pinned_key_is_denied() {
    // The pre-remediation engine allowed this: any caller could present its own
    // key and a matching signature, and "the signature verifies" was mistaken
    // for "the actor is authorized".
    let attacker = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);

    let mut request = signed_pqc_request(
        ACTOR,
        attacker.public_key.key_bytes.clone(),
        PqcSignature {
            algorithm: "ML-DSA-87".into(),
            signature: vec![],
        },
    );
    request.pqc_signature = Some(attacker.sign(&request.message_to_sign()));

    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason, "no pqc identity key bound to actor");
}

#[test]
fn valid_signature_from_a_different_key_is_denied() {
    // A well-formed signature over the exact message, but made by a key that is
    // not the one pinned for the actor. Signature validity alone must not pass.
    let pinned = PqcKeyPair::generate();
    let impostor = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    engine
        .register_pqc_identity_key(ACTOR, pinned.public_key.key_bytes.clone(), None)
        .unwrap();

    let mut request = signed_pqc_request(
        ACTOR,
        impostor.public_key.key_bytes.clone(),
        PqcSignature {
            algorithm: "ML-DSA-87".into(),
            signature: vec![],
        },
    );
    request.pqc_signature = Some(impostor.sign(&request.message_to_sign()));

    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(decision.reason, "pqc key not bound to actor");
}

#[test]
fn tampered_payload_with_pinned_key_is_denied() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    engine
        .register_pqc_identity_key(ACTOR, key_pair.public_key.key_bytes.clone(), None)
        .unwrap();

    let mut request = signed_pqc_request(
        ACTOR,
        key_pair.public_key.key_bytes.clone(),
        PqcSignature {
            algorithm: "ML-DSA-87".into(),
            signature: vec![],
        },
    );
    request.pqc_signature = Some(key_pair.sign(&request.message_to_sign()));
    request.input = json!({"command": "rm -rf /"});

    assert_eq!(engine.evaluate(&request).decision, Decision::Deny);
}

#[test]
fn bare_public_key_without_signature_is_denied() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    engine
        .register_pqc_identity_key(ACTOR, key_pair.public_key.key_bytes.clone(), None)
        .unwrap();

    let request = ActionRequest {
        id: "req-no-sig".into(),
        actor: ACTOR.into(),
        capability: CAPABILITY.into(),
        action: "bash".into(),
        input: json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: Some(key_pair.public_key.key_bytes.clone()),
        token: None,
        identity_claim: None,
        workload_measurement_hash: None,
    };

    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert_eq!(
        decision.reason,
        "pqc public key presented without signature"
    );
}

#[test]
fn malformed_identity_key_is_rejected_at_registration() {
    let mut engine = TrustEngine::new();
    assert!(engine
        .register_pqc_identity_key(ACTOR, vec![0u8; 8], None)
        .is_err());
    assert!(engine.pqc_identity_keys.is_empty());
}

#[test]
fn identity_key_survives_state_round_trip() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    engine
        .register_pqc_identity_key(ACTOR, key_pair.public_key.key_bytes.clone(), None)
        .unwrap();

    let dir = std::env::temp_dir().join(format!("nti-pqc-{}", std::process::id()));
    let path = dir.join("state.json");
    std::fs::create_dir_all(&dir).unwrap();
    engine.save_to_file(&path).unwrap();
    let restored = TrustEngine::load_from_file(&path).unwrap();

    assert_eq!(
        restored.pqc_identity_keys.get(ACTOR),
        Some(&key_pair.public_key.key_bytes)
    );

    let mut request = signed_pqc_request(
        ACTOR,
        key_pair.public_key.key_bytes.clone(),
        PqcSignature {
            algorithm: "ML-DSA-87".into(),
            signature: vec![],
        },
    );
    request.pqc_signature = Some(key_pair.sign(&request.message_to_sign()));
    assert_eq!(restored.evaluate(&request).decision, Decision::Allow);

    std::fs::remove_dir_all(&dir).ok();
}

// -- 2. RFC 6962 Merkle ---------------------------------------------------

fn digest_of(label: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(label.as_bytes()))
}

#[test]
fn audit_root_promotes_odd_nodes_instead_of_duplicating() {
    let three = [digest_of("a"), digest_of("b"), digest_of("c")];
    let mut four = three.to_vec();
    four.push(digest_of("c"));

    assert_ne!(
        merkle::merkle_root(&three),
        merkle::merkle_root(&four),
        "a 3-leaf tree must not collide with a 4-leaf tree whose last leaf repeats"
    );
}

#[test]
fn audit_root_uses_the_documented_domain_prefix() {
    // Leaf hash is SHA-256("nti-s5-leaf-v1:" || digest), per the conformance
    // spec, so the Rust root matches the witness generator.
    use sha2::{Digest, Sha256};
    let leaf = digest_of("only-leaf");
    let mut hasher = Sha256::new();
    hasher.update(b"nti-s5-leaf-v1:");
    hasher.update(hex::decode(&leaf).unwrap());
    let expected = hex::encode(hasher.finalize());

    assert_eq!(merkle::merkle_root(&[leaf]), Some(expected));
}

#[test]
fn committed_batch_exposes_a_verifiable_inclusion_proof() {
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    for index in 0..5 {
        engine.record(ActionRequest {
            id: format!("req-{index}"),
            actor: ACTOR.into(),
            capability: CAPABILITY.into(),
            action: "bash".into(),
            input: json!({"command": format!("echo {index}")}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
            workload_measurement_hash: None,
        });
    }
    engine.commit_batch().expect("batch committed");
    assert_eq!(engine.batches.len(), 1);

    let batch = &engine.batches[0];
    assert_eq!(batch.events.len(), 5);

    // The batch root is the RFC 6962 root over the event hashes; last_batch_hash
    // is the digest of the whole serialized batch, which binds that root too.
    let event_hashes: Vec<String> = batch.events.iter().map(|e| e.hash.clone()).collect();
    assert_eq!(
        batch.merkle_root,
        merkle::merkle_root(&event_hashes).unwrap()
    );
    assert_ne!(engine.last_batch_hash, batch.merkle_root);

    for event in &batch.events {
        let (root, proof) = engine
            .audit_inclusion_proof(0, event.sequence)
            .expect("proof for every committed event");
        assert_eq!(root, batch.merkle_root);
        assert!(merkle::verify_inclusion(&event.hash, &proof, &root));
    }

    assert!(!merkle::verify_inclusion(
        &digest_of("not-in-the-batch"),
        &engine.audit_inclusion_proof(0, 0).unwrap().1,
        &batch.merkle_root
    ));

    assert!(engine.audit_inclusion_proof(0, 99).is_none());
    assert!(engine.audit_inclusion_proof(9, 0).is_none());
}

#[test]
fn promotion_step_in_a_proof_cannot_be_forged() {
    let leaves = [digest_of("a"), digest_of("b"), digest_of("c")];
    let root = merkle::merkle_root(&leaves).unwrap();
    let proof = merkle::inclusion_proof(&leaves, 2).unwrap();
    assert!(proof
        .iter()
        .any(|s| s.position == MerkleSiblingPosition::Promoted));

    let mut forged = proof.clone();
    forged[0].sha256 = digest_of("attacker");
    assert!(!merkle::verify_inclusion(&leaves[2], &forged, &root));
}

#[test]
fn tampered_audit_batch_fails_history_verification() {
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    for index in 0..3 {
        engine.record(ActionRequest {
            id: format!("req-{index}"),
            actor: ACTOR.into(),
            capability: CAPABILITY.into(),
            action: "bash".into(),
            input: json!({"command": "ls"}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
            workload_measurement_hash: None,
        });
    }
    engine.commit_batch();
    assert!(engine.verify_history());

    // Flip a recorded verdict; the recomputed event hash no longer matches.
    engine.batches[0].events[1].decision = PolicyDecision {
        decision: Decision::Deny,
        reason: "rewritten after the fact".into(),
    };
    assert!(
        !engine.verify_history(),
        "a mutated decision must break the root"
    );
}

// -- 3. Policy timing -----------------------------------------------------

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn token_request(token: CapabilityToken) -> ActionRequest {
    ActionRequest {
        id: "req-timing".into(),
        actor: "recipient".into(),
        capability: "transfer".into(),
        action: "transfer".into(),
        input: json!({"amount": 10}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: Some(token),
        identity_claim: None,
        workload_measurement_hash: None,
    }
}

fn signed_token(caveats: Vec<Caveat>) -> CapabilityToken {
    let key = issuer();
    let mut token = CapabilityToken {
        id: "token-timing".into(),
        root_actor: "issuer".into(),
        capability: "transfer".into(),
        caveats,
        signature: vec![],
    };
    token.signature = key.sign(&token.message_to_sign()).to_bytes().to_vec();
    token
}

fn engine_with_issuer() -> TrustEngine {
    let mut engine = TrustEngine::new();
    engine
        .register_issuer_key("issuer", issuer().verifying_key().to_bytes().to_vec())
        .unwrap();
    engine.grant("issuer", "transfer");
    engine
}

#[test]
fn expiry_is_evaluated_against_the_supplied_time() {
    let engine = engine_with_issuer();
    let expiry = Utc::now() + Duration::hours(1);
    let token = signed_token(vec![Caveat {
        location: None,
        condition: CaveatType::Expires(expiry.to_rfc3339()),
    }]);
    let request = token_request(token);

    assert_eq!(
        engine
            .evaluate_at(&request, expiry - Duration::minutes(1))
            .decision,
        Decision::Allow
    );
    assert_eq!(
        engine
            .evaluate_at(&request, expiry + Duration::minutes(1))
            .decision,
        Decision::Deny
    );
}

#[test]
fn unevaluable_caveats_fail_closed() {
    let engine = engine_with_issuer();

    // Missing `amount` must not be read as 0 and allowed.
    let token = signed_token(vec![Caveat {
        location: None,
        condition: CaveatType::ValueLimit(100, "USD".into()),
    }]);
    let mut request = token_request(token);
    request.input = json!({"note": "no amount here"});
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision.reason.contains("requires a non-negative integer"));

    // Wrongly-typed `amount` must not be coerced.
    let token = signed_token(vec![Caveat {
        location: None,
        condition: CaveatType::ValueLimit(100, "USD".into()),
    }]);
    let mut request = token_request(token);
    request.input = json!({"amount": "10"});
    assert_eq!(engine.evaluate(&request).decision, Decision::Deny);

    // Missing `path` must not be treated as an empty string that starts with "".
    let token = signed_token(vec![Caveat {
        location: None,
        condition: CaveatType::PathRestricted("/srv/".into()),
    }]);
    let mut request = token_request(token);
    request.input = json!({"amount": 10});
    assert_eq!(engine.evaluate(&request).decision, Decision::Deny);
}

#[test]
fn valid_caveats_still_pass() {
    // Positive control: fail-closed must not mean always-deny.
    let engine = engine_with_issuer();
    let token = signed_token(vec![
        Caveat {
            location: None,
            condition: CaveatType::ValueLimit(100, "USD".into()),
        },
        Caveat {
            location: None,
            condition: CaveatType::PathRestricted("/srv/".into()),
        },
        Caveat {
            location: None,
            condition: CaveatType::Expires((Utc::now() + Duration::days(1)).to_rfc3339()),
        },
    ]);
    let mut request = token_request(token);
    request.input = json!({"amount": 10, "path": "/srv/data.csv"});

    assert_eq!(engine.evaluate(&request).decision, Decision::Allow);
}

#[test]
fn execution_limit_without_a_token_fails_closed() {
    let engine = engine_with_issuer();
    let request = ActionRequest {
        id: "req-no-token".into(),
        actor: "recipient".into(),
        capability: "transfer".into(),
        action: "transfer".into(),
        input: json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
        workload_measurement_hash: None,
    };
    let caveat = Caveat {
        location: None,
        condition: CaveatType::MaxExecutions(3),
    };

    assert!(matches!(
        CaveatInterpreter::verify_all(&[caveat], &request, &engine),
        OutcomeVerdict::Invalid(_)
    ));
}

// -- 4. Risk caveat (ingress risk score, e.g. CanaryGuard) -----------------
//
// The threshold is an upper bound on the caller-supplied risk score. Every
// case has a positive control below, so a passing suite cannot be explained
// by an engine that denies everything.

fn risk_token(threshold: f32) -> CapabilityToken {
    signed_token(vec![Caveat {
        location: None,
        condition: CaveatType::RiskBelow(threshold),
    }])
}

#[test]
fn risk_below_allows_a_score_under_the_threshold() {
    let engine = engine_with_issuer();
    let mut request = token_request(risk_token(0.65));
    request.input = json!({"risk_score": 0.12});
    assert_eq!(engine.evaluate(&request).decision, Decision::Allow);
}

#[test]
fn risk_below_denies_at_the_threshold() {
    // The contract is "at or above", so equality must deny, not allow.
    let engine = engine_with_issuer();
    let mut request = token_request(risk_token(0.65));
    request.input = json!({"risk_score": 0.65});
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision.reason.contains("at or above"), "{}", decision.reason);
}

#[test]
fn risk_below_denies_above_the_threshold() {
    let engine = engine_with_issuer();
    let mut request = token_request(risk_token(0.65));
    request.input = json!({"risk_score": 0.91});
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision.reason.contains("at or above"), "{}", decision.reason);
}

#[test]
fn risk_caveat_fails_closed_without_a_score() {
    // A missing score must not be read as zero, which would always pass.
    let engine = engine_with_issuer();
    let mut request = token_request(risk_token(0.65));
    request.input = json!({"note": "no score here"});
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision.reason.contains("numeric 'risk_score'"), "{}", decision.reason);
}

#[test]
fn risk_caveat_fails_closed_on_a_non_numeric_score() {
    // A string must not be coerced into a number.
    let engine = engine_with_issuer();
    let mut request = token_request(risk_token(0.65));
    request.input = json!({"risk_score": "0.1"});
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(decision.reason.contains("numeric 'risk_score'"), "{}", decision.reason);
}

#[test]
fn risk_caveat_fails_closed_on_a_non_finite_threshold() {
    // NaN cannot arrive over JSON, so this is defence in depth for in-process
    // callers: `score >= NaN` is false, which would otherwise allow.
    let engine = engine_with_issuer();
    let mut request = token_request(risk_token(0.65));
    request.input = json!({"risk_score": 0.0});
    let verdict = CaveatInterpreter::verify_all_at(
        &[Caveat {
            location: None,
            condition: CaveatType::RiskBelow(f32::NAN),
        }],
        &request,
        &engine,
        Utc::now(),
    );
    match verdict {
        OutcomeVerdict::Invalid(reason) => assert!(reason.contains("finite"), "{}", reason),
        other => panic!("expected Invalid for a non-finite threshold, got {:?}", other),
    }
}

#[test]
fn risk_caveat_uses_the_externally_tagged_wire_format() {
    // Integrators hand-write this in token JSON, so pin the shape.
    let encoded = serde_json::to_string(&CaveatType::RiskBelow(0.65)).unwrap();
    assert_eq!(encoded, r#"{"RiskBelow":0.65}"#);
    let decoded: CaveatType = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, CaveatType::RiskBelow(0.65));
}
