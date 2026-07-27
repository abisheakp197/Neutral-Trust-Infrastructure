//! UBE Outcome Judgement System
//!
//! Monitors all automation actions and decisions for correctness
//! Goal: Zero mistakes through continuous outcome judgement
//!
//! Integrated with voice system for natural language automation

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};
use serde::{Serialize, Deserialize};

/// Automation action record for judgement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationAction {
    pub id: String,
    pub description: String,
    pub automation_type: String,
    pub is_permanent: bool,
    pub duration_days: Option<u64>,
    pub start_timestamp: u64,
    pub expected_outcome: String,
    pub actual_outcome: Option<String>,
    pub success: Option<bool>,
}

/// Judgement System - tracks action outcomes
#[derive(Debug, Clone)]
pub struct JudgementSystem {
    active: bool,
    actions: Arc<Mutex<HashMap<String, AutomationAction>>>,
    total_actions: u64,
    successful_actions: u64,
}

impl JudgementSystem {
    pub fn new() -> Self {
        Self {
            active: false,
            actions: Arc::new(Mutex::new(HashMap::new())),
            total_actions: 0,
            successful_actions: 0,
        }
    }

    pub async fn activate(&mut self) {
        self.activate_sync();
    }

    pub async fn deactivate(&mut self) {
        self.active = false;
        log::info!("[JUDGEMENT] Outcome Judgement System DEACTIVATED");
    }

    /// Synchronous activation to avoid async lock issues
    pub fn activate_sync(&mut self) {
        self.active = true;
        log::info!("[JUDGEMENT] Outcome Judgement System ACTIVATED - monitoring all automation");
    }

    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Check if system has zero mistakes
    pub fn zero_mistakes(&self) -> bool {
        self.total_actions == 0 || self.successful_actions == self.total_actions
    }

    /// Record a new automation action for judgement
    pub async fn record_action(&mut self, action: AutomationAction) {
        let mut actions = self.actions.lock().await;
        actions.insert(action.id.clone(), action);
        self.total_actions += 1;
        log::info!("[JUDGEMENT] Recorded automation action: {}", self.total_actions);
    }

    /// Judge the outcome of an automation action
    pub async fn judge_outcome(&mut self, action_id: &str, success: bool, actual_outcome: String) {
        let mut actions = self.actions.lock().await;
        if let Some(action) = actions.get_mut(action_id) {
            action.success = Some(success);
            action.actual_outcome = Some(actual_outcome);
            if success {
                self.successful_actions += 1;
            }
            log::info!(
                "[JUDGEMENT] Action '{}' judged: {}",
                action_id,
                if success { "SUCCESS" } else { "FAILURE" }
            );
        }
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64, u64) {
        (self.total_actions, self.successful_actions, self.total_actions - self.successful_actions)
    }

    /// Remove an automation action (e.g., when user says "stop automation X")
    pub async fn remove_action(&mut self, action_id: &str) -> bool {
        let mut actions = self.actions.lock().await;
        actions.remove(action_id).is_some()
    }
}

impl Default for JudgementSystem {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check
pub fn health() -> bool {
    true
}
