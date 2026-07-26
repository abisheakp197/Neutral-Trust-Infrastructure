//! UBE Sovereign Learning Engine
//! Deterministic reinforcement learning for autonomous optimization.
//! Implements UCB1 Multi-Armed Bandit and Tabular Q-Learning.

use std::collections::HashMap;

/// Multi-Armed Bandit for configuration auto-tuning using UCB1 algorithm.
#[derive(Debug, Clone)]
pub struct UCB1Bandit {
    arms: HashMap<String, BanditArm>,
    total_pulls: usize,
}

#[derive(Debug, Clone)]
pub struct BanditArm {
    pub id: String,
    pub config: HashMap<String, String>, // Simplified config as String map
    pub pulls: usize,
    pub total_reward: f64,
    pub mean_reward: f64,
}

impl UCB1Bandit {
    pub fn new() -> Self {
        Self {
            arms: HashMap::new(),
            total_pulls: 0,
        }
    }

    pub fn add_arm(&mut self, id: String, config: HashMap<String, String>) {
        self.arms.insert(id.clone(), BanditArm {
            id,
            config,
            pulls: 0,
            total_reward: 0.0,
            mean_reward: 0.0,
        });
    }

    /// Select the best arm using Upper Confidence Bound (UCB1).
    pub fn select(&self) -> Option<String> {
        if self.arms.is_empty() { return None; }

        // 1. Explore unexplored arms first
        for (id, arm) in &self.arms {
            if arm.pulls == 0 { return Some(id.clone()); }
        }

        // 2. Select arm with highest UCB1 score
        let mut best_arm = None;
        let mut best_score = f64::NEG_INFINITY;

        let ln_n = (self.total_pulls as f64).ln();

        for (id, arm) in &self.arms {
            let exploration = (2.0 * ln_n / arm.pulls as f64).sqrt();
            let score = arm.mean_reward + exploration;
            if score > best_score {
                best_score = score;
                best_arm = Some(id.clone());
            }
        }

        best_arm
    }

    pub fn update(&mut self, arm_id: &str, reward: f64) {
        if let Some(arm) = self.arms.get_mut(arm_id) {
            arm.pulls += 1;
            arm.total_reward += reward;
            arm.mean_reward = arm.total_reward / arm.pulls as f64;
            self.total_pulls += 1;
        }
    }

    pub fn best_arm(&self) -> Option<String> {
        self.arms.values()
            .max_by(|a, b| a.mean_reward.partial_cmp(&b.mean_reward).unwrap())
            .map(|arm| arm.id.clone())
    }
}

/// Tabular Q-Learning Agent for adaptive routing and scheduling.
#[derive(Debug, Clone)]
pub struct QLearningAgent {
    q_table: HashMap<String, HashMap<String, f64>>,
    actions: Vec<String>,
    epsilon: f64,
    epsilon_decay: f64,
    min_epsilon: f64,
    alpha: f64,
    gamma: f64,
    steps: usize,
}

impl QLearningAgent {
    pub fn new(actions: Vec<String>, alpha: f64, gamma: f64, epsilon: f64) -> Self {
        Self {
            q_table: HashMap::new(),
            actions,
            epsilon,
            epsilon_decay: 0.995,
            min_epsilon: 0.01,
            alpha,
            gamma,
            steps: 0,
        }
    }

    fn state_key(state: &HashMap<String, f64>) -> String {
        let mut sorted_entries: Vec<_> = state.iter().collect();
        sorted_entries.sort_by(|a, b| a.0.cmp(b.0));
        format!("{:?}", sorted_entries)
    }

    pub fn act(&mut self, state: &HashMap<String, f64>) -> String {
        let sk = Self::state_key(state);

        // Epsilon-greedy exploration
        if rand_f64() < self.epsilon {
            return self.actions[deterministic_rand(self.actions.len()) % self.actions.len()].clone();
        }

        // Exploitation: find max Q value
        let q_vals = self.q_table.get(&sk);
        if let Some(vals) = q_vals {
            let best_action = self.actions.iter()
                .max_by(|a, b| {
                    let q_a = vals.get(*a).unwrap_or(&0.0);
                    let q_b = vals.get(*b).unwrap_or(&0.0);
                    q_a.partial_cmp(q_b).unwrap()
                })
                .unwrap();
            return best_action.clone();
        }

        self.actions[0].clone()
    }

    pub fn learn(&mut self, state: &HashMap<String, f64>, action: &str, reward: f64, next_state: &HashMap<String, f64>) {
        let sk = Self::state_key(state);
        let nsk = Self::state_key(next_state);

        // Max Q for next state
        let max_next_q = self.q_table.get(&nsk)
            .map(|vals| self.actions.iter().map(|a| vals.get(a).unwrap_or(&0.0)).fold(f64::NEG_INFINITY, |acc, &x| acc.max(x)))
            .unwrap_or(0.0);

        let current_q = *self.q_table.get(&sk)
            .and_then(|vals| vals.get(action))
            .unwrap_or(&0.0);

        // Q-Learning update rule: Q(s,a) = Q(s,a) + alpha * (reward + gamma * maxQ(s',a') - Q(s,a))
        let new_q = current_q + self.alpha * (reward + self.gamma * max_next_q - current_q);

        self.q_table.entry(sk).or_default().insert(action.to_string(), new_q);

        self.epsilon = (self.epsilon * self.epsilon_decay).max(self.min_epsilon);
        self.steps += 1;
    }
}

// Helper functions for deterministic pseudo-randomness in 'no_std'
fn rand_f64() -> f64 {
    // Simplified deterministic rand for core conversion
    (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() % 1000) as f64 / 1000.0
}

fn deterministic_rand(limit: usize) -> usize {
    (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as usize) % limit
}

// ============================================================
// Per-User Adaptive Learning System
// ============================================================

use crate::identity::ResponsibilityLevel;

/// Per-user reinforcement learning agent
#[derive(Debug, Clone)]
pub struct UserQLearningAgent {
    /// Q-table: user_id -> state -> action -> value
    pub user_q_tables: HashMap<String, HashMap<String, HashMap<String, f64>>>,
    /// Actions available for each user
    pub user_actions: HashMap<String, Vec<String>>,
    /// Learning parameters per user
    pub learning_params: HashMap<String, LearningParams>,
}

/// Learning parameters for a user
#[derive(Debug, Clone)]
pub struct LearningParams {
    pub alpha: f64,      // Learning rate
    pub gamma: f64,      // Discount factor
    pub epsilon: f64,    // Exploration rate
    pub epsilon_decay: f64,
    pub min_epsilon: f64,
}

impl Default for LearningParams {
    fn default() -> Self {
        Self {
            alpha: 0.1,
            gamma: 0.9,
            epsilon: 0.5,
            epsilon_decay: 0.995,
            min_epsilon: 0.01,
        }
    }
}

impl UserQLearningAgent {
    pub fn new() -> Self {
        Self {
            user_q_tables: HashMap::new(),
            user_actions: HashMap::new(),
            learning_params: HashMap::new(),
        }
    }

    /// Initialize learning for a new user
    pub fn init_user(&mut self, user_id: String, actions: Vec<String>) {
        self.user_q_tables.insert(user_id.clone(), HashMap::new());
        self.user_actions.insert(user_id.clone(), actions);
        self.learning_params.insert(user_id, LearningParams::default());
    }

    /// Get the best action for a user given their state
    pub fn act(&mut self, user_id: &str, state: &HashMap<String, f64>) -> Option<String> {
        let actions = self.user_actions.get(user_id)?;
        let sk = Self::state_key(state);
        let params = self.learning_params.get_mut(user_id)?;

        // Epsilon-greedy exploration
        if rand_f64() < params.epsilon {
            return Some(actions[deterministic_rand(actions.len())].clone());
        }

        // Exploitation: find max Q value
        if let Some(q_vals) = self.user_q_tables.get(user_id).and_then(|t| t.get(&sk)) {
            let best_action = actions.iter()
                .max_by(|a, b| {
                    let q_a = q_vals.get(*a).unwrap_or(&0.0);
                    let q_b = q_vals.get(*b).unwrap_or(&0.0);
                    q_a.partial_cmp(q_b).unwrap()
                })
                .cloned();
            return best_action;
        }

        // Fallback: random action
        Some(actions[0].clone())
    }

    /// Update learning for a user
    pub fn learn(&mut self, user_id: &str, state: &HashMap<String, f64>,
                 action: &str, reward: f64, next_state: &HashMap<String, f64>) {
        let sk = Self::state_key(state);
        let nsk = Self::state_key(next_state);
        let params = self.learning_params.get(user_id).expect("User not initialized");

        // Get Q-table for this user
        let q_table = self.user_q_tables.get_mut(user_id)
            .expect("User not initialized");

        // Max Q for next state
        let max_next_q = q_table.get(&nsk)
            .map(|vals| {
                let actions = self.user_actions.get(user_id).unwrap();
                actions.iter()
                    .map(|a| vals.get(a).unwrap_or(&0.0))
                    .fold(f64::NEG_INFINITY, |acc, &x| acc.max(x))
            })
            .unwrap_or(0.0);

        // Current Q
        let current_q = q_table.get(&sk)
            .and_then(|vals| vals.get(action))
            .unwrap_or(&0.0);

        // Q-Learning update: Q(s,a) = Q(s,a) + alpha * (reward + gamma * maxQ(s',a') - Q(s,a))
        let new_q = current_q + params.alpha * (reward + params.gamma * max_next_q - current_q);

        q_table.entry(sk).or_default().insert(action.to_string(), new_q);

        // Decay epsilon
        let mut params_mut = self.learning_params.get_mut(user_id).unwrap();
        params_mut.epsilon = (params_mut.epsilon * params_mut.epsilon_decay).max(params_mut.min_epsilon);
    }

    /// Adapt learning parameters based on user's responsibility level
    pub fn adapt_to_responsibility(&mut self, user_id: &str, level: ResponsibilityLevel) {
        if let Some(params) = self.learning_params.get_mut(user_id) {
            // Higher responsibility = more conservative learning
            match level {
                ResponsibilityLevel::Personal => {
                    params.alpha = 0.2;   // Fast learning
                    params.epsilon = 0.4; // More exploration
                }
                ResponsibilityLevel::Professional => {
                    params.alpha = 0.15;
                    params.epsilon = 0.3;
                }
                ResponsibilityLevel::Financial => {
                    params.alpha = 0.1;   // Conservative learning
                    params.epsilon = 0.2; // Less exploration
                }
                ResponsibilityLevel::Government => {
                    params.alpha = 0.05;
                    params.epsilon = 0.1;
                }
                ResponsibilityLevel::Military => {
                    params.alpha = 0.01;  // Very conservative
                    params.epsilon = 0.05; // Minimal exploration
                }
            }
        }
    }

    fn state_key(state: &HashMap<String, f64>) -> String {
        let mut sorted_entries: Vec<_> = state.iter().collect();
        sorted_entries.sort_by(|a, b| a.0.cmp(b.0));
        format!("{:?}", sorted_entries)
    }
}

// ============================================================
// Per-User Bandit Learning for Automation Tuning
// ============================================================

/// Per-user Multi-Armed Bandit for finding optimal automation settings
#[derive(Debug, Clone)]
pub struct UserAutomationBandit {
    /// Bandits per user: user_id -> UserBandit
    pub user_bandits: HashMap<String, UserBandit>,
}

/// Bandit for a single user's automation tuning
#[derive(Debug, Clone)]
pub struct UserBandit {
    pub arms: HashMap<String, BanditArm>,
    pub total_pulls: usize,
    pub user_id: String,
}

impl UserAutomationBandit {
    pub fn new() -> Self {
        Self {
            user_bandits: HashMap::new(),
        }
    }

    /// Initialize bandit for a user with action-based arms (fully automatic)
    pub fn init_user(&mut self, user_id: String, actions: Vec<String>) {
        let mut arms = HashMap::new();
        for action in actions {
            arms.insert(action.clone(), BanditArm {
                id: action,
                config: HashMap::new(),
                pulls: 0,
                total_reward: 0.0,
                mean_reward: 0.0,
            });
        }
        self.user_bandits.insert(user_id.clone(), UserBandit {
            arms,
            total_pulls: 0,
            user_id,
        });
    }

    /// Select best action for user (fully automatic - no profiles)
    pub fn select_action(&self, user_id: &str) -> Option<String> {
        let bandit = self.user_bandits.get(user_id)?;

        // Find arm with best UCB1 score
        if bandit.arms.is_empty() { return None; }

        // Check for unexplored arms
        for (id, arm) in &bandit.arms {
            if arm.pulls == 0 {
                return Some(id.clone());
            }
        }

        let mut best_arm: Option<String> = None;
        let mut best_score = f64::NEG_INFINITY;
        let ln_n = (bandit.total_pulls as f64).ln();

        for (id, arm) in &bandit.arms {
            let exploration = (2.0 * ln_n / arm.pulls as f64).sqrt();
            let score = arm.mean_reward + exploration;
            if score > best_score {
                best_score = score;
                best_arm = Some(id.clone());
            }
        }

        best_arm
    }

    /// Update bandit with user feedback on action
    pub fn update(&mut self, user_id: &str, action: &str, reward: f64) {
        if let Some(bandit) = self.user_bandits.get_mut(user_id) {
            if let Some(arm) = bandit.arms.get_mut(action) {
                arm.pulls += 1;
                arm.total_reward += reward;
                arm.mean_reward = arm.total_reward / arm.pulls as f64;
                bandit.total_pulls += 1;
            }
        }
    }
}
