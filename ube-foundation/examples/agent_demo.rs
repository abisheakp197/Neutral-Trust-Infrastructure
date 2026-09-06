use ube_foundation::{
    ActionRequest, AutonomousAgent, IntentPolicy, Orchestrator, SafetyMode, TrustEngine,
};

#[tokio::main]
async fn main() -> Result<(), String> {
    // 1. Setup Trust Engine and Orchestrator
    let mut trust = TrustEngine::default();
    trust.grant("agent-1", "file_management");

    let mut orchestrator = Orchestrator::new(trust);
    orchestrator.register_module(Box::new(ube_foundation::SystemModule));

    // 2. Setup Agent
    let mut agent = AutonomousAgent::new("agent-1".into(), orchestrator);

    // 3. Add a policy: prevent writing to "secret.txt"
    agent.add_policy(IntentPolicy {
        name: "no-secret-writes".into(),
        capability: "file_management".into(),
        constraints: serde_json::json!({
            "not_allowed_paths": ["secret.txt"]
        }),
    });

    println!("--- Step 1: Valid Action (List Directory) ---");
    let req1 = ActionRequest {
        id: "req-1".into(),
        actor: "agent-1".into(),
        capability: "file_management".into(),
        action: "list_dir".into(),
        input: serde_json::json!({ "path": "." }),
        public_key: None,
        signature: None,
        token: None,
        identity_claim: None,
    };

    let res1 = agent.execute_step(req1).await?;
    println!("Result (files): {}", res1);

    println!("\n--- Step 2: Policy Violation (Fail-Safe) ---");
    let req2 = ActionRequest {
        id: "req-2".into(),
        actor: "agent-1".into(),
        capability: "file_management".into(),
        action: "write_file".into(),
        input: serde_json::json!({
            "path": "secret.txt",
            "content": "stolen data"
        }),
        public_key: None,
        signature: None,
        token: None,
        identity_claim: None,
    };

    let res2 = agent.execute_step(req2).await;
    match res2 {
        Ok(_) => println!("Error: Should have failed!"),
        Err(e) => println!("Caught expected violation: {}", e),
    }

    println!("\n--- Step 3: Policy Violation (Fail-Open) ---");
    agent.set_safety_mode(SafetyMode::FailOpen);
    let req3 = ActionRequest {
        id: "req-3".into(),
        actor: "agent-1".into(),
        capability: "file_management".into(),
        action: "write_file".into(),
        input: serde_json::json!({
            "path": "secret.txt",
            "content": "stolen data (logged)"
        }),
        public_key: None,
        signature: None,
        token: None,
        identity_claim: None,
    };

    let res3 = agent.execute_step(req3).await?;
    println!("Result (FailOpen): {:?}", res3);

    // Clean up
    let _ = std::fs::remove_file("secret.txt");

    Ok(())
}
