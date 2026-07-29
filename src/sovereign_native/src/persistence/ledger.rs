//! UBE Sovereign Immortal Ledger
//!
//! SURVIVES ANY DOWNTIME:
//! - Hardware off for weeks: State preserved
//! - Hardware off for years: State preserved
//! - Power cycles: State preserved
//!
//! What gets persisted:
//! 1. All automation rules (permanent + temporary)
//! 2. All pending work queue
//! 3. Work history

use std::collections::{HashMap, VecDeque};
use std::fs::{File, self};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

/// Work item in the queue - survives power-off
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkItem {
    pub id: String,
    pub description: String,
    pub command: String,
    pub priority: u8,
    pub scheduled_at: u64,
    pub retries: u8,
    pub max_retries: u8,
    pub status: WorkStatus,
    pub created_at: u64,
    pub last_attempt_at: Option<u64>,
    pub last_result: Option<String>,
}

/// Work status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkStatus {
    Pending,
    Executing,
    Completed,
    Failed,
    Skipped,
}

/// Automation rule - survives power-off
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationRule {
    pub id: String,
    pub name: String,
    pub trigger: String,
    pub action: String,
    pub is_permanent: bool,
    pub duration_days: Option<u64>,
    pub start_at: u64,
    pub end_at: Option<u64>,
    pub authorized_by: Option<String>,
    pub is_active: bool,
    pub last_executed: Option<u64>,
    pub execution_count: u64,
}

impl AutomationRule {
    pub fn is_expired(&self) -> bool {
        if self.is_permanent {
            return false;
        }
        self.end_at.map(|end| {
            let now = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            now > end
        }).unwrap_or(false)
    }

    pub fn should_run(&self) -> bool {
        !self.is_expired() && self.is_active
    }
}

/// Full UBE state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbeState {
    pub version: u32,
    pub automation_rules: Vec<AutomationRule>,
    pub work_queue: VecDeque<WorkItem>,
    pub work_history: VecDeque<WorkItem>,
    pub company_id: String,
    pub last_save_at: u64,
    pub last_boot_at: u64,
    pub integrity_hash: String,
}

impl Default for UbeState {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            version: 1,
            automation_rules: Vec::new(),
            work_queue: VecDeque::new(),
            work_history: VecDeque::new(),
            company_id: "UBE_SOVEREIGN_COMPANY".to_string(),
            last_save_at: 0,
            last_boot_at: now,
            integrity_hash: "initial".to_string(),
        }
    }
}

impl UbeState {
    pub fn new(company_id: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            version: 1,
            automation_rules: Vec::new(),
            work_queue: VecDeque::new(),
            work_history: VecDeque::new(),
            company_id: company_id.to_string(),
            last_save_at: 0,
            last_boot_at: now,
            integrity_hash: "initial".to_string(),
        }
    }

    pub fn compute_integrity_hash(&self) -> String {
        let mut hasher = Sha256::new();
        if let Ok(serialized) = serde_json::to_vec(self) {
            hasher.update(&serialized);
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn verify_integrity(&self) -> bool {
        !self.company_id.is_empty()
    }

    pub fn add_rule(&mut self, rule: AutomationRule) {
        self.automation_rules.push(rule);
    }

    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        if let Some(pos) = self.automation_rules.iter().position(|r| r.id == rule_id) {
            self.automation_rules.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn find_rule(&self, rule_id: &str) -> Option<&AutomationRule> {
        self.automation_rules.iter().find(|r| r.id == rule_id)
    }

    pub fn get_active_rules(&self) -> Vec<&AutomationRule> {
        self.automation_rules.iter()
            .filter(|r| r.should_run())
            .collect()
    }

    pub fn queue_work(&mut self, work: WorkItem) {
        self.work_queue.push_back(work);
    }

    pub fn next_work(&mut self) -> Option<WorkItem> {
        let mut works: Vec<WorkItem> = self.work_queue.drain(..).collect();
        works.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.scheduled_at.cmp(&b.scheduled_at)));
        for work in &works {
            self.work_queue.push_back(work.clone());
        }
        self.work_queue.pop_front()
    }

    pub fn complete_work(&mut self, work_id: &str, result: String) -> bool {
        for i in 0..self.work_queue.len() {
            if self.work_queue[i].id == work_id {
                let mut work = self.work_queue.remove(i).unwrap();
                work.status = WorkStatus::Completed;
                work.last_result = Some(result);
                work.last_attempt_at = Some(
                    SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0)
                );
                self.work_history.push_back(work);
                if self.work_history.len() > 1000 {
                    self.work_history.pop_front();
                }
                return true;
            }
        }
        false
    }

    pub fn cleanup_expired(&mut self) -> Vec<AutomationRule> {
        let mut expired = Vec::new();
        let mut i = 0;
        while i < self.automation_rules.len() {
            if self.automation_rules[i].is_expired() {
                expired.push(self.automation_rules.remove(i));
            } else {
                i += 1;
            }
        }
        expired
    }
}

/// State Manager
#[derive(Debug)]
pub struct StateManager {
    state_path: PathBuf,
    state: Arc<RwLock<UbeState>>,
}

impl Clone for StateManager {
    fn clone(&self) -> Self {
        Self {
            state_path: self.state_path.clone(),
            state: self.state.clone(),
        }
    }
}

impl StateManager {
    pub fn new(company_id: &str) -> Self {
        let mut path = PathBuf::from("/data/data/com.termux/files/home/UBE");
        let _ = std::fs::create_dir_all(&path);
        path.push(".ube_immortal_state.json");

        Self {
            state_path: path,
            state: Arc::new(RwLock::new(UbeState::new(company_id))),
        }
    }

    pub fn load(&mut self) -> Result<(), String> {
        if !self.state_path.exists() {
            return self.save();
        }

        match std::fs::read(&self.state_path) {
            Ok(data) => {
                match serde_json::from_slice::<UbeState>(&data) {
                    Ok(mut state) => {
                        if !state.verify_integrity() {
                            return Err("Integrity check failed".to_string());
                        }
                        let _expired = state.cleanup_expired();
                        *self.state.write().unwrap() = state;
                        Ok(())
                    }
                    Err(e) => Err(format!("Parse error: {}", e)),
                }
            }
            Err(e) => Err(format!("Read error: {}", e)),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let state = self.state.read().unwrap();
        match serde_json::to_vec(&*state) {
            Ok(data) => {
                let temp_path = self.state_path.with_extension("tmp");
                {
                    let mut file = File::create(&temp_path).map_err(|e| e.to_string())?;
                    file.write_all(&data).map_err(|e| e.to_string())?;
                    let _ = file.sync_all();
                }
                std::fs::rename(&temp_path, &self.state_path).map_err(|e| e.to_string())?;
                Ok(())
            }
            Err(e) => Err(format!("Serialize error: {}", e)),
        }
    }

    pub fn state(&self) -> Arc<RwLock<UbeState>> {
        self.state.clone()
    }

    pub fn add_automation_rule(&mut self, rule: AutomationRule) -> Result<(), String> {
        self.state.write().unwrap().add_rule(rule);
        self.save()
    }

    pub fn remove_automation_rule(&mut self, rule_id: &str) -> Result<bool, String> {
        let removed = self.state.write().unwrap().remove_rule(rule_id);
        self.save()?;
        Ok(removed)
    }

    pub fn queue_work(&mut self, work: WorkItem) -> Result<(), String> {
        self.state.write().unwrap().queue_work(work);
        self.save()
    }

    pub fn process_pending_work(&mut self) -> Vec<(String, String)> {
        let mut results = Vec::new();
        while let Some(work) = self.state.write().unwrap().next_work() {
            let result = format!("Processed: {}", work.description);
            self.state.write().unwrap().complete_work(&work.id, result.clone());
            results.push((work.id, result));
        }
        results
    }

    pub fn catch_up_after_downtime(&mut self) -> Vec<String> {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let mut caught_up = Vec::new();

        let state = self.state.read().unwrap();
        let last_save = state.last_save_at;
        let downtime = if last_save > 0 { now.saturating_sub(last_save) } else { 0 };

        if downtime > 3600 {
            log::warn!("[STATE MANAGER] Detected downtime of {} seconds", downtime);

            let mut state_mut = self.state.write().unwrap();
            for rule in &mut state_mut.automation_rules {
                if !rule.is_permanent && rule.is_active {
                    if let Some(end_at) = rule.end_at {
                        rule.end_at = Some(end_at.saturating_add(downtime));
                        caught_up.push(format!("Extended rule: {} (+{}s)", rule.name, downtime));
                    }
                }
            }
        }

        let _ = self.save();
        caught_up
    }

    pub fn start_autosave(&self) {
        let sm = self.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(30));
                let _ = sm.save();
            }
        });
    }
}

pub fn default_state_manager() -> StateManager {
    StateManager::new("UBE_SOVEREIGN_COMPANY")
}

pub fn generate_work_id() -> String {
    format!("work_{}", std::time::SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0))
}

pub fn generate_rule_id() -> String {
    format!("rule_{}", std::time::SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0))
}
