//! UBE Omniscience Observer
//!
//! WATCHES ALL user activity and identifies repetitive patterns
//! NO manual setup - fully automatic
//!
//! Architecture:
//! 1. Observer - watches all system events
//! 2. PatternDetector - finds repetitions
//! 3. LawCreator - generates automation laws
//! 4. AutoExecutor - enforces and automates

use std::collections::{HashMap, VecDeque, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::{Arc, Mutex, RwLock};
use serde::{Serialize, Deserialize};

/// Event observed by Omniscience
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniEvent {
    pub event_id: String,
    pub user_id: String,
    pub action: String,
    pub target: String,
    pub timestamp: u64,
    pub duration: u64,
    pub success: bool,
    pub context: HashMap<String, String>,
}

/// Detected pattern in user behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmniPattern {
    pub pattern_id: String,
    pub user_id: String,
    pub pattern_type: String,
    pub action_pattern: String,
    pub frequency: usize,
    pub first_seen: u64,
    pub last_seen: u64,
    pub average_duration: u64,
    pub confidence: f64,
}

/// Universal Law generated from patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniversalLaw {
    pub law_id: String,
    pub pattern_id: String,
    pub user_id: String,
    pub trigger: String,
    pub action: String,
    pub conditions: Vec<LawCondition>,
    pub enforcement: LawEnforcement,
    pub created_at: u64,
}

/// Law condition (WHEN this is true)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LawCondition {
    pub field: String,
    pub operator: String, // =, !=, >, <, contains, starts_with, ends_with
    pub value: String,
}

/// Law enforcement method
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LawEnforcement {
    pub mode: EnforcementMode,
    pub priority: u8,
    pub retry: u8,
    pub timeout: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnforcementMode {
    Allow,
    Block,
    Notify,
    AutoExecute,
    RequireApproval,
}

/// The Omniscience Observer - watches ALL activity
#[derive(Debug)]
pub struct OmniscienceObserver {
    pub events: Arc<RwLock<VecDeque<OmniEvent>>>,
    pub patterns: Arc<RwLock<HashMap<String, OmniPattern>>>,
    pub laws: Arc<RwLock<HashMap<String, UniversalLaw>>>,
    pub user_laws: Arc<RwLock<HashMap<String, Vec<String>>>>, // user_id -> law_ids
    pub max_events: usize,
    pub pattern_threshold: usize,
}

impl OmniscienceObserver {
    pub fn new() -> Self {
        Self {
            events: Arc::new(RwLock::new(VecDeque::new())),
            patterns: Arc::new(RwLock::new(HashMap::new())),
            laws: Arc::new(RwLock::new(HashMap::new())),
            user_laws: Arc::new(RwLock::new(HashMap::new())),
            max_events: 10000,
            pattern_threshold: 3, // Minimum repetitions to detect pattern
        }
    }

    /// Record an event (called by UBE hooks)
    pub fn observe(&self, event: OmniEvent) {
        // Store event
        {
            let mut events = self.events.write().unwrap();
            events.push_back(event.clone());
            if events.len() > self.max_events {
                events.pop_front();
            }
        }

        // Detect patterns from this event
        self.detect_patterns(&event);

        // Generate laws from patterns
        self.generate_laws(&event);
    }

    /// Detect repetitive patterns
    fn detect_patterns(&self, event: &OmniEvent) {
        let mut patterns = self.patterns.write().unwrap();

        // Key for pattern: user + action + target
        let pattern_key = format!("{}:{}:{}", event.user_id, event.action, event.target);

        // Find or create pattern
        if let Some(pattern) = patterns.get_mut(&pattern_key) {
            pattern.frequency += 1;
            pattern.last_seen = event.timestamp;
            // Update average duration
            pattern.average_duration =
                (pattern.average_duration * (pattern.frequency - 1) as u64 + event.duration)
                / pattern.frequency as u64;

            // Increase confidence
            pattern.confidence = (pattern.frequency as f64 / (pattern.frequency as f64 + 1.0)) * 1.0;
        } else {
            // New pattern
            let new_pattern = OmniPattern {
                pattern_id: format!("pattern_{}", event.timestamp),
                user_id: event.user_id.clone(),
                pattern_type: "repetitive_action".to_string(),
                action_pattern: format!("{}:{}", event.action, event.target),
                frequency: 1,
                first_seen: event.timestamp,
                last_seen: event.timestamp,
                average_duration: event.duration,
                confidence: 0.3, // Initial confidence
            };
            patterns.insert(pattern_key, new_pattern);
        }
    }

    /// Generate laws from detected patterns
    fn generate_laws(&self, event: &OmniEvent) {
        let patterns = self.patterns.read().unwrap();
        let mut laws = self.laws.write().unwrap();
        let mut user_laws = self.user_laws.write().unwrap();

        // Check all patterns for this user
        for (pattern_key, pattern) in patterns.iter() {
            if pattern.user_id != event.user_id {
                continue;
            }

            // Only generate law if pattern is confident enough
            if pattern.confidence >= 0.8 && pattern.frequency >= self.pattern_threshold {
                let law_id = format!("law_{}_{}", pattern.user_id, pattern.pattern_id);

                // Check if law already exists
                if laws.get(&law_id).is_none() {
                    // Create universal law
                    let law = UniversalLaw {
                        law_id: law_id.clone(),
                        pattern_id: pattern.pattern_id.clone(),
                        user_id: pattern.user_id.clone(),
                        trigger: pattern.action_pattern.clone(),
                        action: "auto_execute".to_string(),
                        conditions: vec![
                            LawCondition {
                                field: "action".to_string(),
                                operator: "starts_with".to_string(),
                                value: pattern.action_pattern.split(':').next().unwrap().to_string(),
                            }
                        ],
                        enforcement: LawEnforcement {
                            mode: EnforcementMode::AutoExecute,
                            priority: 5,
                            retry: 3,
                            timeout: 5000,
                        },
                        created_at: event.timestamp,
                    };

                    laws.insert(law_id.clone(), law);

                    // Add to user's laws
                    user_laws.entry(pattern.user_id.clone())
                        .or_default()
                        .push(law_id);
                }
            }
        }
    }

    /// Check if an action should be automated
    pub fn check_automation(&self, user_id: &str, action: &str, target: &str) -> Option<UniversalLaw> {
        let laws = self.laws.read().unwrap();
        let user_laws = self.user_laws.read().unwrap();

        if let Some(law_ids) = user_laws.get(user_id) {
            for law_id in law_ids {
                if let Some(law) = laws.get(law_id) {
                    // Check if action matches trigger pattern
                    if action.starts_with(&law.trigger.split(':').next().unwrap_or_default()) {
                        // Check conditions
                        let mut matches = true;
                        for condition in &law.conditions {
                            let actual = match condition.field.as_str() {
                                "action" => action.to_string(),
                                "target" => target.to_string(),
                                _ => "".to_string(),
                            };

                            if !Self::check_condition(&actual, &condition.operator, &condition.value) {
                                matches = false;
                                break;
                            }
                        }

                        if matches {
                            return Some(law.clone());
                        }
                    }
                }
            }
        }
        None
    }

    fn check_condition(actual: &str, op: &str, expected: &str) -> bool {
        match op {
            "==" => actual == expected,
            "!=" => actual != expected,
            ">" => actual > expected,
            "<" => actual < expected,
            "contains" => actual.contains(expected),
            "starts_with" => actual.starts_with(expected),
            "ends_with" => actual.ends_with(expected),
            _ => false,
        }
    }

    /// Get all laws for a user
    pub fn get_user_laws(&self, user_id: &str) -> Vec<UniversalLaw> {
        let laws = self.laws.read().unwrap();
        let user_laws = self.user_laws.read().unwrap();

        user_laws.get(user_id)
            .map(|law_ids| {
                law_ids.iter()
                    .filter_map(|id| laws.get(id).cloned())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all patterns for a user
    pub fn get_user_patterns(&self, user_id: &str) -> Vec<OmniPattern> {
        let patterns = self.patterns.read().unwrap();
        patterns.values()
            .filter(|p| p.user_id == user_id)
            .cloned()
            .collect()
    }

    /// Get statistics for a user
    pub fn get_stats(&self, user_id: &str) -> OmniStats {
        let patterns = self.patterns.read().unwrap();
        let laws = self.laws.read().unwrap();

        let user_patterns: Vec<_> = patterns.values()
            .filter(|p| p.user_id == user_id)
            .collect();

        let user_laws: Vec<_> = laws.values()
            .filter(|l| l.user_id == user_id)
            .collect();

        OmniStats {
            total_events: self.events.read().unwrap().len(),
            total_patterns: user_patterns.len(),
            total_laws: user_laws.len(),
            automation_rate: if user_patterns.is_empty() { 0.0 } else {
                user_laws.len() as f64 / user_patterns.len() as f64
            },
        }
    }
}

/// Omniscience statistics
#[derive(Debug, Clone)]
pub struct OmniStats {
    pub total_events: usize,
    pub total_patterns: usize,
    pub total_laws: usize,
    pub automation_rate: f64,
}

impl Default for OmniscienceObserver {
    fn default() -> Self {
        Self::new()
    }
}

// Global Omniscience Observer instance
lazy_static::lazy_static! {
    pub static ref OMNI_OBSERVER: Arc<OmniscienceObserver> = Arc::new(OmniscienceObserver::new());
}

// Convenience functions for hooking into UBE
pub fn observe_event(user_id: String, action: String, target: String, duration: u64, success: bool) {
    let context = HashMap::new();
    let event = OmniEvent {
        event_id: format!("evt_{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()),
        user_id,
        action,
        target,
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        duration,
        success,
        context,
    };
    OMNI_OBSERVER.observe(event);
}

pub fn check_automation(user_id: &str, action: &str, target: &str) -> Option<UniversalLaw> {
    OMNI_OBSERVER.check_automation(user_id, action, target)
}
