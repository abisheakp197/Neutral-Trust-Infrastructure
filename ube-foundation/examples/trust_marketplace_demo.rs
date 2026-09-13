use ube_foundation::*;
use chrono::{Utc, Duration};
use std::collections::BTreeMap;
use ed25519_dalek::{SigningKey, Signer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("--- UBE Trust Marketplace Demo ---");

    // 1. Setup Verifier (Independent Third Party)
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    let verifier_signing_key = SigningKey::from_bytes(&bytes);
    let verifier_pub_key = verifier_signing_key.verifying_key();
    let verifier_id = "independent-auditor-inc";

    // 2. Setup UBE Recommendation Layer
    let mut rec_layer = RecommendationLayer::new();
    rec_layer.verifiers.insert(verifier_id.to_string(), VerifierProfile {
        id: verifier_id.to_string(),
        tier: VerifierTier::Foundational,
        public_key: verifier_pub_key.to_bytes().to_vec(),
        reputation: 1.0,
    });

    // 3. Create a Provider (CloudService-X)
    let provider_id = "cloud-service-x";

    // Create a SOC2 Credential
    let soc2_evidence = "SOC2-REPORT-2026-HASH-12345";
    let mut cred = IndependentCredential {
        verifier_id: verifier_id.to_string(),
        standard: VerificationStandard::SOC2,
        evidence_hash: soc2_evidence.to_string(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::days(365),
        signature: Vec::new(),
    };

    // Verifier signs the credential
    let msg = serde_json::json!({
        "verifier_id": cred.verifier_id,
        "standard": cred.standard,
        "evidence_hash": cred.evidence_hash,
        "issued_at": cred.issued_at,
        "expires_at": cred.expires_at,
    });
    let msg_bytes = serde_json::to_vec(&msg)?;
    cred.signature = verifier_signing_key.sign(&msg_bytes).to_bytes().to_vec();

    // Register Provider
    let profile = ProviderProfile {
        provider_id: provider_id.to_string(),
        service_metadata: serde_json::json!({"type": "compute", "region": "us-east-1"}),
        credentials: vec![cred],
        reputation_score: 0.95, // High starting reputation
        total_outcomes: 100,
    };
    rec_layer.providers.insert(provider_id.to_string(), profile);

    // 4. User/Agent Selection Logic (Rule-Setter)
    let user_logic = SelectionLogic {
        required_standards: vec![VerificationStandard::SOC2],
        min_reputation: 0.90,
    };

    // 5. Perform Selection (Selector)
    println!("Step 1: Agent selecting provider for task 'process-secure-data'");
    let (selected, audit) = rec_layer.select_provider("task-001", &user_logic);

    if let Some(id) = selected {
        println!("✅ Selection Successful: {}", id);
        println!("Reasoning: {}", audit.reasoning);
        println!("Audit Trail (Eligible): {:?}", audit.eligible_providers);
    }

    // 6. Reputation Compounding (Outcome Tracking)
    println!("\nStep 2: Recording outcome...");
    let outcome = ServiceOutcome {
        provider_id: provider_id.to_string(),
        request_id: "task-001".into(),
        success: true, // It worked!
        user_feedback: Some(5.0),
    };
    rec_layer.update_reputation(outcome);
    println!("Updated Reputation for {}: {:.4}", provider_id, rec_layer.providers[provider_id].reputation_score);

    // 7. Revocation Test
    println!("\nStep 3: Auditor revokes SOC2 credential (security breach detected)");
    let notice = RevocationNotice {
        credential_hash: soc2_evidence.to_string(),
        reason: "Security breach detected".into(),
        timestamp: Utc::now(),
        signature: Vec::new(),
    };
    let notice_msg = serde_json::json!({
        "credential_hash": notice.credential_hash,
        "reason": notice.reason,
        "timestamp": notice.timestamp,
    });
    let notice_bytes = serde_json::to_vec(&notice_msg)?;
    let mut notice = notice;
    notice.signature = verifier_signing_key.sign(&notice_bytes).to_bytes().to_vec();

    rec_layer.revocations.insert(soc2_evidence.to_string(), notice);

    let (selected_after, audit_after) = rec_layer.select_provider("task-002", &user_logic);
    if selected_after.is_none() {
        println!("❌ Selection Failed as expected: {}", audit_after.reasoning);
    }

    println!("\n--- Demo Complete: Trust is math, not marketing. ---");
    Ok(())
}
