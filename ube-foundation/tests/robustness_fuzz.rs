use ube_foundation::*;
use serde_json::Value;

#[test]
fn test_capability_token_garbage_verification() {
    let dummy_key = [0u8; 32];
    
    // Test with empty signature
    let token = CapabilityToken {
        id: "test".to_string(),
        root_actor: "actor".to_string(),
        capability: "cap".to_string(),
        caveats: vec![],
        signature: vec![],
    };
    assert!(!token.verify(&dummy_key));

    // Test with malformed signature length
    let token = CapabilityToken {
        id: "test".to_string(),
        root_actor: "actor".to_string(),
        capability: "cap".to_string(),
        caveats: vec![],
        signature: vec![1, 2, 3],
    };
    assert!(!token.verify(&dummy_key));
}

#[test]
fn test_action_request_garbage_parsing() {
    let garbage = b"{\"id\": \"test\", \"actor\": \"{{{\", \"input\": null}";
    let _ = serde_json::from_slice::<ActionRequest>(garbage);
}

#[test]
fn test_caveat_interpreter_edge_cases() {
    let engine = TrustEngine::new();
    let request = ActionRequest {
        id: "test".to_string(),
        actor: "test".to_string(),
        capability: "test".to_string(),
        action: "test".to_string(),
        input: Value::Null,
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    // Test with invalid timestamp
    let caveat = Caveat {
        location: None,
        condition: CaveatType::Expires("not-a-date".to_string()),
    };
    let _ = CaveatInterpreter::verify_all(&[caveat], &request, &engine);
    
    // Test with empty string
    let caveat = Caveat {
        location: None,
        condition: CaveatType::Expires("".to_string()),
    };
    let _ = CaveatInterpreter::verify_all(&[caveat], &request, &engine);

    // Test with real timestamp format
    let caveat = Caveat {
        location: None,
        condition: CaveatType::Expires("2026-09-11T12:00:00Z".to_string()),
    };
    let _ = CaveatInterpreter::verify_all(&[caveat], &request, &engine);
}
