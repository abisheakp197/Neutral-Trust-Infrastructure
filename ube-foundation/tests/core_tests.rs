#[cfg(test)]
mod tests {
    use ube_foundation::*;
    use chrono::{Utc, Duration};

    #[tokio::test]
    async fn test_capability_token_expiry() {
        let engine = TrustEngine::default();
        let future_date = (Utc::now() + Duration::days(1)).to_rfc3339();
        let past_date = (Utc::now() - Duration::days(1)).to_rfc3339();

        let valid_token = CapabilityToken {
            id: "valid".into(),
            root_actor: "alice".into(),
            capability: "test".into(),
            caveats: vec![Caveat { location: None, condition: CaveatType::Expires(future_date) }],
            signature: vec![],
        };

        let expired_token = CapabilityToken {
            id: "expired".into(),
            root_actor: "alice".into(),
            capability: "test".into(),
            caveats: vec![Caveat { location: None, condition: CaveatType::Expires(past_date) }],
            signature: vec![],
        };

        let req_valid = ActionRequest {
            id: "1".into(),
            actor: "bob".into(),
            capability: "test".into(),
            action: "run".into(),
            input: serde_json::json!({}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: Some(valid_token),
            identity_claim: None,
        };

        let req_expired = ActionRequest {
            id: "2".into(),
            actor: "bob".into(),
            capability: "test".into(),
            action: "run".into(),
            input: serde_json::json!({}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: Some(expired_token),
            identity_claim: None,
        };

        assert_eq!(engine.evaluate(&req_valid).decision, Decision::Allow);
        assert_eq!(engine.evaluate(&req_expired).decision, Decision::Deny);
    }

    #[test]
    fn test_token_revocation() {
        let mut engine = TrustEngine::default();
        let token_id = "token-123";
        let token = CapabilityToken {
            id: token_id.into(),
            root_actor: "alice".into(),
            capability: "test".into(),
            caveats: vec![],
            signature: vec![],
        };

        let req = ActionRequest {
            id: "1".into(),
            actor: "bob".into(),
            capability: "test".into(),
            action: "run".into(),
            input: serde_json::json!({}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: Some(token),
            identity_claim: None,
        };

        assert_eq!(engine.evaluate(&req).decision, Decision::Allow);
        engine.revoke_token(token_id);
        assert_eq!(engine.evaluate(&req).decision, Decision::Deny);
    }

    #[tokio::test]
    async fn test_consensus_orchestrator() {
        let engine = TrustEngine::default();
        let mut orchestrator = Orchestrator::new(engine);
        orchestrator.set_consensus_threshold(2);

        struct TestModule(&'static str);
        #[async_trait::async_trait]
        impl Module for TestModule {
            fn name(&self) -> &str { self.0 }
            fn capabilities(&self) -> Vec<String> { vec!["compute".into()] }
            async fn execute(&self, _a: &str, _i: serde_json::Value) -> Result<serde_json::Value, String> {
                Ok(serde_json::json!({"result": 42}))
            }
        }

        orchestrator.register_module(Box::new(TestModule("m1")));
        orchestrator.register_module(Box::new(TestModule("m2")));

        let req = ActionRequest {
            id: "task-1".into(),
            actor: "admin".into(),
            capability: "compute".into(),
            action: "calc".into(),
            input: serde_json::json!({}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
        };

        orchestrator.engine.grant("admin", "compute");
        let res = orchestrator.run_task(req).await;
        assert!(res.is_ok());
        assert_eq!(res.unwrap()["result"], 42);
    }

    #[test]
    fn test_trust_engine_persistence_and_recovery() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("nti_test_state_{}.json", rand::random::<u64>()));

        let mut engine = TrustEngine::new().with_persistence(&file_path);
        engine.grant("alice", "admin_access");
        engine.revoke_token("token-revoked-99");
        engine.register_voter_key("voter-alice", vec![1, 2, 3, 4]);

        let req = ActionRequest {
            id: "persist-req-1".into(),
            actor: "alice".into(),
            capability: "admin_access".into(),
            action: "read".into(),
            input: serde_json::json!({}),
            signature: None,
            pqc_signature: None,
            public_key: None,
            pqc_public_key: None,
            token: None,
            identity_claim: None,
        };

        engine.record(req);
        assert!(file_path.exists());

        // Recover engine from file
        let recovered_engine = TrustEngine::load_from_file(&file_path).unwrap();

        assert_eq!(recovered_engine.capabilities.get("alice").unwrap().contains("admin_access"), true);
        assert!(recovered_engine.revocation_list.contains("token-revoked-99"));
        assert_eq!(recovered_engine.voter_keys.get("voter-alice").unwrap(), &vec![1, 2, 3, 4]);
        assert_eq!(recovered_engine.events.len(), 1);
        assert!(recovered_engine.verify_history());

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_key_rotation_lifecycle() {
        let mut node = AgentMeshNode::new("agent-x".into());
        let initial_pk = node.verifying_key.to_bytes().to_vec();

        assert!(node.is_current_key(&initial_pk));
        assert_eq!(node.previous_verifying_keys.len(), 0);

        // Rotate Mesh node identity key
        node.rotate_key();
        let new_pk = node.verifying_key.to_bytes().to_vec();

        assert!(!node.is_current_key(&initial_pk));
        assert!(node.is_current_key(&new_pk));
        assert_eq!(node.previous_verifying_keys.len(), 1);

        // PQC KeyPair rotation
        let mut pqc_pair = PqcKeyPair::generate();
        let old_pqc_pk = pqc_pair.public_key.clone();
        let new_pqc_pk = pqc_pair.rotate();

        assert_ne!(old_pqc_pk.key_bytes, new_pqc_pk.key_bytes);
    }
}
