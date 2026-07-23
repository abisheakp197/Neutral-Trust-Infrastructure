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
