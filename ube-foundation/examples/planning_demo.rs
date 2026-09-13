use ube_foundation::{
    ActionRequest, AutonomousAgent, AutonomousPlan, IntentPolicy, Orchestrator, PlanStep,
    SafetyMode, SystemModule, TrustEngine, TaskStatus,
};

#[tokio::main]
async fn main() -> Result<(), String> {
    // 1. Setup Trust Engine and Orchestrator
    let mut trust = TrustEngine::default();
    trust.grant("sovereign-agent", "file_management");

    let mut orchestrator = Orchestrator::new(trust);
    orchestrator.register_module(Box::new(SystemModule));

    // 2. Setup Agent
    let mut agent = AutonomousAgent::new("sovereign-agent".into(), orchestrator);

    // 3. Define a Multi-Step Plan
    let mut plan = AutonomousPlan::new("init-project".into(), "Initialize workspace".into());

    plan.add_step(PlanStep {
        id: "step-1".into(),
        description: "Scan current directory".into(),
        action_request: ActionRequest {
            id: "req-1".into(),
            actor: "sovereign-agent".into(),
            capability: "file_management".into(),
            action: "list_dir".into(),
            input: serde_json::json!({ "path": "." }),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
        },
        status: TaskStatus::Pending,
        dependencies: vec![],
    });

    plan.add_step(PlanStep {
        id: "step-2".into(),
        description: "Create workspace marker".into(),
        action_request: ActionRequest {
            id: "req-2".into(),
            actor: "sovereign-agent".into(),
            capability: "file_management".into(),
            action: "write_file".into(),
            input: serde_json::json!({
                "path": "UBE_WORKSPACE.md",
                "content": "# UBE Workspace\nInitialized by Autonomous Agent."
            }),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
        },
        status: TaskStatus::Pending,
        dependencies: vec!["step-1".into()],
    });

    agent.set_plan(plan);

    println!("--- Running Autonomous Plan ---");
    let completed = agent.run_plan().await?;
    println!("Plan finished. Steps completed: {}", completed);

    // 4. Demonstrate Policy Interruption in Plan
    println!("\n--- Running Plan with Policy Violation ---");
    agent.add_policy(IntentPolicy {
        name: "restrict-docs".into(),
        capability: "file_management".into(),
        constraints: serde_json::json!({
            "not_allowed_paths": ["RESTRICTED.md"]
        }),
    });

    let mut failing_plan = AutonomousPlan::new("fail-project".into(), "Attempt restricted write".into());
    failing_plan.add_step(PlanStep {
        id: "fail-step".into(),
        description: "Write to restricted file".into(),
        action_request: ActionRequest {
            id: "req-fail".into(),
            actor: "sovereign-agent".into(),
            capability: "file_management".into(),
            action: "write_file".into(),
            input: serde_json::json!({
                "path": "RESTRICTED.md",
                "content": "Sensitive data"
            }),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
        },
        status: TaskStatus::Pending,
        dependencies: vec![],
    });

    agent.set_plan(failing_plan);
    let res = agent.run_plan().await;
    match res {
        Ok(_) => println!("Error: Plan should have been blocked by policy!"),
        Err(e) => println!("Correctly blocked: {}", e),
    }

    Ok(())
}
