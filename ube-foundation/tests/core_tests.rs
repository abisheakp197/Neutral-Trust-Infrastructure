#[cfg(test)]
mod tests {
    use super::*;
    use ube_foundation::*;
    use chrono::{Utc, Duration};

    #[tokio::test]
    async fn test_capability_token_expiry() {
        let mut engine = TrustEngine::default();
        let future_date = (Utc::now() + Duration::days(1)).to_rfc3339();
        let past_date = (Utc::now() - Duration::days(1)).to_rfc3339();

        let mut valid_token = CapabilityToken {
            id: "valid".into(),
            root_actor: "alice".into(),
            capability: "test".into(),
            caveats: vec![Caveat { location: None, condition: CaveatType::Expires(future_date) }],
            signature: vec![],
        };

        let mut expired_token = CapabilityToken {
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
        let mut engine = TrustEngine::default();
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
}
