//! Regression tests for workload-bound identity.
//!
//! The defect these cover: binding an identity to a key proves *who* is calling
//! but not *what* is calling. An attacker who steals the private key and a
//! capability token could replay both from any host and be authorized.
//!
//! A first attempt at this (0.2.0) compared the expected measurement against
//! `ActionRequest::workload_measurement_hash`. That field travels with the
//! request and is signed by whoever holds the key, so a thief could set it to the
//! expected digest and sign the result. `stolen_key_cannot_self_report_measurement`
//! is the test that fails against that design: it performs the attack rather than
//! asserting a proxy for it. The measurement is now supplied by the enforcement
//! point from the actual runtime, and the request field is only checked for
//! transit consistency.
//!
//! Each denial case has a positive control, so a passing suite cannot be
//! explained by the engine denying everything.

use serde_json::json;
use ube_foundation::*;

const ACTOR: &str = "did:webvh:QmWorkloadActor:agents.example.com";
const CAPABILITY: &str = "shell.execute";
const HEX_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const HEX_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn oci(hex: &str) -> String {
    format!("sha256:{hex}")
}

/// Engine with `actor` registered, optionally bound to a workload measurement.
fn bound_engine(key_pair: &PqcKeyPair, measurement: Option<String>) -> TrustEngine {
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    engine
        .register_pqc_identity_key(ACTOR, key_pair.public_key.key_bytes.clone(), measurement)
        .expect("registration");
    engine
}

/// A fully valid, correctly signed request, optionally carrying a measurement.
fn signed_request(key_pair: &PqcKeyPair, measurement: Option<String>) -> ActionRequest {
    let mut request = ActionRequest {
        id: "req-workload".into(),
        actor: ACTOR.into(),
        capability: CAPABILITY.into(),
        action: "bash".into(),
        input: json!({"command": "ls -la"}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: Some(key_pair.public_key.key_bytes.clone()),
        token: None,
        identity_claim: None,
        workload_measurement_hash: measurement,
    };
    request.pqc_signature = Some(key_pair.sign(&request.message_to_sign()));
    request
}

#[test]
fn attested_matching_measurement_is_allowed() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate_with_measurement(
        &signed_request(&key_pair, Some(oci(HEX_A))),
        Some(&oci(HEX_A)),
        chrono::Utc::now(),
    );
    assert_eq!(decision.decision, Decision::Allow, "{}", decision.reason);
}

#[test]
fn stolen_key_cannot_self_report_measurement() {
    // The attack: the key is stolen, the host is not the pinned workload, and the
    // attacker declares the expected digest in the request they sign.
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let forged = signed_request(&key_pair, Some(oci(HEX_A)));
    assert!(
        forged.pqc_signature.is_some(),
        "the forged request must carry a valid signature, or this proves nothing"
    );

    let decision = engine.evaluate_with_measurement(&forged, None, chrono::Utc::now());
    assert_eq!(
        decision.decision,
        Decision::Deny,
        "a self-declared measurement must never satisfy the binding"
    );

    // Same request, but the enforcement point observed a different workload.
    let decision = engine.evaluate_with_measurement(&forged, Some(&oci(HEX_B)), chrono::Utc::now());
    assert_eq!(
        decision.decision,
        Decision::Deny,
        "observed workload must override what the request claims"
    );
}

#[test]
fn replay_from_unmeasured_host_is_denied() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    // A verbatim capture of a legitimate request is still not authorized from a
    // host the enforcement point did not measure as the pinned workload.
    let captured = signed_request(&key_pair, Some(oci(HEX_A)));
    let decision = engine.evaluate(&captured);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("not observed"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn observed_mismatch_is_denied() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate_with_measurement(
        &signed_request(&key_pair, None),
        Some(&oci(HEX_B)),
        chrono::Utc::now(),
    );
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("does not match"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn declared_measurement_contradicting_observation_is_denied() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    // Observation is correct, but the request claims something else: the request
    // was altered in transit, so it is rejected rather than quietly accepted.
    let decision = engine.evaluate_with_measurement(
        &signed_request(&key_pair, Some(oci(HEX_B))),
        Some(&oci(HEX_A)),
        chrono::Utc::now(),
    );
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("does not match observed"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn malformed_observed_measurement_is_denied() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate_with_measurement(
        &signed_request(&key_pair, None),
        Some("not-a-digest"),
        chrono::Utc::now(),
    );
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("malformed"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn unregistered_measurement_keeps_key_only_authorization() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, None);

    let decision = engine.evaluate(&signed_request(&key_pair, None));
    assert_eq!(decision.decision, Decision::Allow, "{}", decision.reason);
}

#[test]
fn oci_prefixed_and_bare_hex_compare_equal() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate_with_measurement(
        &signed_request(&key_pair, Some(HEX_A.into())),
        Some(HEX_A),
        chrono::Utc::now(),
    );
    assert_eq!(decision.decision, Decision::Allow, "{}", decision.reason);
}

#[test]
fn registration_rejects_malformed_measurement() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    let err = engine
        .register_pqc_identity_key(
            ACTOR,
            key_pair.public_key.key_bytes.clone(),
            Some("nope".into()),
        )
        .expect_err("malformed measurement must be rejected at registration");
    assert!(err.contains("SHA-256"), "unexpected error: {err}");
}

#[test]
fn workload_binding_applies_without_a_pqc_signature() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let request = ActionRequest {
        id: "req-unsigned".into(),
        actor: ACTOR.into(),
        capability: CAPABILITY.into(),
        action: "bash".into(),
        input: json!({}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
        workload_measurement_hash: Some(oci(HEX_A)),
    };
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("not observed"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn workload_measurement_is_normalized_in_persisted_state() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = bound_engine(&key_pair, Some(oci(HEX_A)));
    engine
        .register_workload_measurement(ACTOR, oci(&HEX_B.to_uppercase()))
        .expect("re-registration");

    let state = engine.export_state();
    assert_eq!(
        state.workload_measurements.get(ACTOR).map(String::as_str),
        Some(HEX_B),
        "persisted state must hold bare lowercase hex regardless of input form"
    );
}

#[test]
fn workload_binding_survives_save_and_reload() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let dir = std::env::temp_dir().join(format!("nti-workload-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("state.json");
    engine.save_to_file(&path).expect("save");

    let reloaded = TrustEngine::load_from_file(&path).expect("reload");
    std::fs::remove_dir_all(&dir).ok();

    let allowed = reloaded.evaluate_with_measurement(
        &signed_request(&key_pair, None),
        Some(&oci(HEX_A)),
        chrono::Utc::now(),
    );
    assert_eq!(allowed.decision, Decision::Allow, "{}", allowed.reason);

    let denied = reloaded.evaluate_with_measurement(
        &signed_request(&key_pair, None),
        Some(&oci(HEX_B)),
        chrono::Utc::now(),
    );
    assert_eq!(denied.decision, Decision::Deny);
}

#[test]
fn record_with_measurement_audits_the_observation() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let allowed =
        engine.record_with_measurement(signed_request(&key_pair, None), Some(&oci(HEX_A)));
    assert_eq!(allowed.decision, Decision::Allow, "{}", allowed.reason);

    let denied = engine.record(signed_request(&key_pair, None));
    assert_eq!(
        denied.decision,
        Decision::Deny,
        "record() observes nothing, so a bound actor must not be authorized"
    );
    assert!(engine.verify_history());
}
