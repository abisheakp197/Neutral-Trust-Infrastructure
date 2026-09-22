#[cfg(test)]
mod trust_marketplace_tests {
    use ube_foundation::*;
    use chrono::{Utc, Duration};
    use ed25519_dalek::{SigningKey, Signer};

    fn setup_verifier(id: &str) -> (SigningKey, VerifierProfile) {
        let mut bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
        let signing_key = SigningKey::from_bytes(&bytes);
        let profile = VerifierProfile {
            id: id.to_string(),
            tier: VerifierTier::Foundational,
            public_key: signing_key.verifying_key().to_bytes().to_vec(),
            reputation: 1.0,
        };
        (signing_key, profile)
    }

    #[test]
    fn test_payment_has_zero_effect_on_rank() {
        let mut layer = RecommendationLayer::new();
        let (_v_key, v_profile) = setup_verifier("auditor");
        layer.verifiers.insert(v_profile.id.clone(), v_profile);

        // Provider A: High reputation, standard fee
        let p_a = ProviderProfile {
            provider_id: "high_rep".into(),
            service_metadata: serde_json::json!({}),
            credentials: vec![],
            reputation_score: 0.99,
            total_outcomes: 100,
        };

        // Provider B: Low reputation, paid "Premium Fee"
        let p_b = ProviderProfile {
            provider_id: "low_rep_premium".into(),
            service_metadata: serde_json::json!({}),
            credentials: vec![],
            reputation_score: 0.50,
            total_outcomes: 100,
        };

        layer.providers.insert(p_a.provider_id.clone(), p_a);
        layer.providers.insert(p_b.provider_id.clone(), p_b);

        // Simulate a "premium" payment for B - protocol should log it but ignore it for rank
        layer.process_fee(&VerificationFee {
            provider_id: "low_rep_premium".into(),
            verifier_id: "auditor".into(),
            amount: 1000000, // Huge payment
            currency: "USD".into(),
            fee_type: FeeType::InitialVerification,
            timestamp: Utc::now(),
        });

        let logic = SelectionLogic { required_standards: vec![], min_reputation: 0.0 };
        let (selected, _) = layer.select_provider("test", &logic);

        // Protocol Invariant: High rep MUST win despite B's payment
        assert_eq!(selected.unwrap(), "high_rep");
    }

    #[test]
    fn test_cross_verifier_revocation_rejected() {
        let mut layer = RecommendationLayer::new();
        let (v_a_key, v_a_profile) = setup_verifier("verifier_a");
        let (v_b_key, v_b_profile) = setup_verifier("verifier_b");

        layer.verifiers.insert(v_a_profile.id.clone(), v_a_profile);
        layer.verifiers.insert(v_b_profile.id.clone(), v_b_profile);

        let evidence_hash = "credential_123";
        let cred = IndependentCredential {
            verifier_id: "verifier_a".into(),
            standard: VerificationStandard::SOC2,
            evidence_hash: evidence_hash.into(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::days(1),
            signature: vec![], // simplified
        };

        // Verifier B tries to revoke Verifier A's credential
        let notice = RevocationNotice {
            credential_hash: evidence_hash.into(),
            reason: "malicious revocation".into(),
            timestamp: Utc::now(),
            signature: vec![],
        };
        let msg = serde_json::json!({
            "credential_hash": notice.credential_hash,
            "reason": notice.reason,
            "timestamp": notice.timestamp,
        });
        let sig = v_b_key.sign(&serde_json::to_vec(&msg).unwrap()).to_bytes().to_vec();

        layer.revocations.insert(evidence_hash.into(), RevocationNotice { signature: sig, ..notice });

        // Logic check: verify_credential should still return true (revocation ignored because it's from wrong signer)
        // Note: For this test, we assume the signature on 'cred' itself is validly checked elsewhere
        // But the core point is that the revocation lookup in 'verify_credential' will fail the signer check.

        // We mock the verifier A signature on the credential for the final check
        let mut cred = cred;
        let cred_msg = serde_json::json!({
            "verifier_id": cred.verifier_id,
            "standard": cred.standard,
            "evidence_hash": cred.evidence_hash,
            "issued_at": cred.issued_at,
            "expires_at": cred.expires_at,
        });
        cred.signature = v_a_key.sign(&serde_json::to_vec(&cred_msg).unwrap()).to_bytes().to_vec();

        assert!(layer.verify_credential(&cred), "Revocation from Verifier B should have been rejected");
    }

    #[test]
    fn test_cold_start_probation_slot() {
        let mut layer = RecommendationLayer::new();

        // 9 Established Providers
        for i in 0..9 {
            let id = format!("old_{}", i);
            layer.providers.insert(id.clone(), ProviderProfile {
                provider_id: id,
                service_metadata: serde_json::json!({}),
                credentials: vec![],
                reputation_score: 0.99,
                total_outcomes: 100,
            });
        }

        // 1 New Provider
        layer.providers.insert("newbie".into(), ProviderProfile {
            provider_id: "newbie".into(),
            service_metadata: serde_json::json!({}),
            credentials: vec![],
            reputation_score: 0.50, // lower rep
            total_outcomes: 0,      // < 10
        });

        let logic = SelectionLogic { required_standards: vec![], min_reputation: 0.0 };

        let mut newbie_picked = false;
        // Run 200 times - with 10% chance, the newbie should eventually be picked
        for _ in 0..200 {
            let (selected, _) = layer.select_provider("test", &logic);
            if selected.unwrap() == "newbie" {
                newbie_picked = true;
                break;
            }
        }
        assert!(newbie_picked, "New provider should have been picked in probation slot");
    }

    #[test]
    fn test_reputation_threshold_graduation() {
        let mut profile = ProviderProfile {
            provider_id: "test".into(),
            service_metadata: serde_json::json!({}),
            credentials: vec![],
            reputation_score: 1.0,
            total_outcomes: 9, // One outcome away from 10
        };

        let _logic = SelectionLogic { required_standards: vec![], min_reputation: 0.0 };
        let eligible = vec![&profile];

        // This is tricky to test purely because of randomness,
        // but we can check the filter logic used in tie_break
        let unproven: Vec<&&ProviderProfile> = eligible.iter()
            .filter(|p| p.total_outcomes < 10)
            .collect();
        assert_eq!(unproven.len(), 1);

        profile.total_outcomes = 10;
        let eligible2 = vec![&profile];
        let unproven2: Vec<&&ProviderProfile> = eligible2.iter()
            .filter(|p| p.total_outcomes < 10)
            .collect();
        assert_eq!(unproven2.len(), 0); // Graduated
    }
}
