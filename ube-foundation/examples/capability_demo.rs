use ube_foundation::{
    ActionRequest, AutonomousAgent, CapabilityToken, Caveat, Orchestrator, TrustEngine,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;

#[tokio::main]
async fn main() -> Result<(), String> {
    // 1. Setup Trust Engine and Actors
    let mut trust = TrustEngine::default();

    // Create cryptographic keys for the "User" (Root Actor)
    let user_signing_key = SigningKey::from_bytes(&[0u8; 32]); // In real app, use OsRng
    let user_public_key = user_signing_key.verifying_key();
    let _user_pub_bytes = user_public_key.to_bytes().to_vec();

    // The user has the original "file_management" capability
    trust.grant("user-alice", "file_management");

    // 2. Setup Orchestrator and Agent
    let mut orchestrator = Orchestrator::new(trust);
    orchestrator.register_module(Box::new(ube_foundation::SystemModule));

    // The agent doesn't have direct permission to manage files!
    let mut agent = AutonomousAgent::new("agent-bob".into(), orchestrator);

    println!("--- Step 1: Unauthorized Action (Direct) ---");
    let req1 = ActionRequest {
        id: "req-1".into(),
        actor: "agent-bob".into(),
        capability: "file_management".into(),
        action: "list_dir".into(),
        input: serde_json::json!({ "path": "." }),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    let res1 = agent.execute_step(req1).await;
    match res1 {
        Ok(_) => println!("Error: Should have failed!"),
        Err(e) => println!("Caught expected error (Unauthorized): {}", e),
    }

    println!("\n--- Step 2: Delegating Authority via Capability Token ---");
    // User Alice creates a token for Agent Bob
    let mut token = CapabilityToken {
        id: "token-123".into(),
        root_actor: "user-alice".into(),
        capability: "file_management".into(),
        caveats: vec![
            Caveat {
                location: None,
                condition: ube_foundation::CaveatType::Expires("2026-12-31".into()),
            }
        ],
        signature: Vec::new(),
    };

    // Alice signs the token
    let token_sig = user_signing_key.sign(&token.message_to_sign());
    token.signature = token_sig.to_vec();

    println!("Token created and signed by user-alice for file_management.");

    println!("\n--- Step 3: Authorized Action (Via Token) ---");
    let req2 = ActionRequest {
        id: "req-2".into(),
        actor: "agent-bob".into(),
        capability: "file_management".into(),
        action: "list_dir".into(),
        input: serde_json::json!({ "path": "." }),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: Some(token),
        identity_claim: None,
    };

    let res2 = agent.execute_step(req2).await?;
    println!("Result (Authorized via token): {}", res2);

    Ok(())
}
