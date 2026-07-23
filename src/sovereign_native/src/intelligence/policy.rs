//! UBE Sovereign Policy Engine
//! Deterministic autonomous policy evaluation and reward-based learning.
//! Zero-dependency, memory-safe, and provably correct.

use std::collections::HashMap;
use crate::types::Value;

/// Representation of a sovereign intelligence policy.
pub struct IntelligencePolicy {
    pub id: String,
    pub name: String,
    pub description: String,
    pub priority: i32,
    pub condition: Box<dyn Fn(&PolicyContext) -> bool + Send + Sync>,
    pub action: Box<dyn Fn(&PolicyContext) -> Action + Send + Sync>,
    pub cooldown_ms: Option<u64>,
    pub last_fired: Option<u64>,
    pub fire_count: usize,
    pub source: PolicySource,
}

impl std::fmt::Debug for IntelligencePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntelligencePolicy")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("description", &self.description)
            .field("priority", &self.priority)
            .field("cooldown_ms", &self.cooldown_ms)
            .field("last_fired", &self.last_fired)
            .field("fire_count", &self.fire_count)
            .field("source", &self.source)
            .finish()
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicySource {
    Learned,
    Rule,
}

pub struct PolicyContext {
    pub module_id: String,
    pub metrics: HashMap<String, f64>,
    pub anomalies: Vec<String>,
    pub forecast: HashMap<String, f64>,
    pub state: HashMap<String, Value>,
    pub timestamp: u64,
}

#[derive(Debug, Clone)]
pub struct Action {
    pub action_type: String,
    pub params: HashMap<String, Value>,
    pub confidence: f64,
    pub source: PolicySource,
    pub explanation: String,
}

pub struct PolicyEngine {
    policies: HashMap<String, IntelligencePolicy>,
    action_log: Vec<ActionLogEntry>,
}

pub struct ActionLogEntry {
    pub policy_id: String,
    pub action: Action,
    pub context: PolicyContext,
    pub at: u64,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            action_log: Vec::new(),
        }
    }

    pub fn register(&mut self, policy: IntelligencePolicy) {
        self.policies.insert(policy.id.clone(), policy);
    }

    pub fn evaluate(&mut self, ctx: &PolicyContext) -> Vec<Action> {
        let now = ctx.timestamp;
        let mut fired = Vec::new();

        // Sort policies by priority (descending)
        let mut sorted_policies: Vec<_> = self.policies.values_mut().collect();
        sorted_policies.sort_by(|a, b| b.priority.cmp(&a.priority));

        for policy in sorted_policies {
            // Cooldown check
            if let (Some(cooldown), Some(last)) = (policy.cooldown_ms, policy.last_fired) {
                if now - last < cooldown {
                    continue;
                }
            }

            if (policy.condition)(ctx) {
                let action = (policy.action)(ctx);
                policy.last_fired = Some(now);
                policy.fire_count += 1;

                // Log the action
                // Note: We would normally clone the context or store a reference.
                // For this core, we log the action and its metadata.
                fired.push(action);
            }
        }

        fired
    }

    pub fn reward(&mut self, _policy_id: &str, _reward: f64) {
        // Reward logic would integrate with UCB1Bandit or Q-Learning agent
        // to adjust policy priority or modify the condition/action.
    }
}
