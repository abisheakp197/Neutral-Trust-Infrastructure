//! Regression tests for workload-bound identity (0.2.0).
//!
//! The defect these cover: binding an identity to a key proves *who* is calling
//! but not *what* is calling. An attacker who steals the private key and a
//! capability token could replay both from any host and be authorized. Binding
//! the identity to a workload measurement restores the missing half of the
//! binding.
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
fn matching_workload_measurement_is_allowed() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate(&signed_request(&key_pair, Some(oci(HEX_A))));
    assert_eq!(
        decision.decision,
        Decision::Allow,
        "positive control failed: {}",
        decision.reason
    );
}

#[test]
fn mismatched_workload_measurement_is_denied() {
    // The attacker holds the stolen key and can produce a perfectly valid
    // signature. Only the workload measurement distinguishes them.
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate(&signed_request(&key_pair, Some(oci(HEX_B))));
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("workload measurement does not match"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn missing_workload_measurement_is_denied_when_registered() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate(&signed_request(&key_pair, None));
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("workload measurement required"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn unregistered_measurement_keeps_key_only_authorization() {
    // Backwards compatibility with 0.1.x: an actor with no measurement
    // registered is authorized on key possession, as before.
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, None);

    let decision = engine.evaluate(&signed_request(&key_pair, None));
    assert_eq!(decision.decision, Decision::Allow, "{}", decision.reason);
}

#[test]
fn oci_prefixed_and_bare_hex_compare_equal() {
    // A registry reports `sha256:<hex>`; a workload may report the bare digest.
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate(&signed_request(&key_pair, Some(HEX_A.into())));
    assert_eq!(decision.decision, Decision::Allow, "{}", decision.reason);
}

#[test]
fn malformed_presented_measurement_is_denied() {
    let key_pair = PqcKeyPair::generate();
    let engine = bound_engine(&key_pair, Some(oci(HEX_A)));

    let decision = engine.evaluate(&signed_request(&key_pair, Some("not-a-digest".into())));
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("malformed workload measurement"),
        "unexpected reason: {}",
        decision.reason
    );
}

#[test]
fn registration_rejects_malformed_measurement() {
    let key_pair = PqcKeyPair::generate();
    let mut engine = TrustEngine::new();
    let err = engine
        .register_pqc_identity_key(
            ACTOR,
            key_pair.public_key.key_bytes.clone(),
            Some("sha256:deadbeef".into()),
        )
        .expect_err("short digest must be rejected at registration");
    assert!(err.contains("SHA-256"), "unexpected error: {err}");
}

#[test]
fn workload_binding_applies_without_a_pqc_signature() {
    // The check must not be reachable only through the PQC path. A request with
    // no signature at all from a workload-bound actor must still be denied for
    // the missing measurement rather than falling through to another branch.
    let mut engine = TrustEngine::new();
    engine.grant(ACTOR, CAPABILITY);
    engine
        .register_workload_measurement(ACTOR, oci(HEX_A))
        .expect("registration");

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
        workload_measurement_hash: None,
    };
    let decision = engine.evaluate(&request);
    assert_eq!(decision.decision, Decision::Deny);
    assert!(
        decision.reason.contains("workload measurement"),
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

    let allowed = reloaded.evaluate(&signed_request(&key_pair, Some(oci(HEX_A))));
    assert_eq!(allowed.decision, Decision::Allow, "{}", allowed.reason);

    let denied = reloaded.evaluate(&signed_request(&key_pair, Some(oci(HEX_B))));
    assert_eq!(denied.decision, Decision::Deny);
}
