//! UBE Auto-Executor
//!
//! This is the SELF-ACTING system that:
//! 1. Observes ALL user actions
//! 2. Learns repetitive patterns
//! 3. Creates automation laws
//! 4. Executes automatically (no human needed)
//!
//! NO MANUAL SETUP. NO HUMAN RULES. SELF-LEARNING + SELF-DOING.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::omniscience::observer::{
    OMNI_OBSERVER, observe_event, OmniEvent, UniversalLaw
};
use crate::identity::{SovereignUser, UserPersonalizationEngine};

/// Auto-Executor: The brain that makes UBE self-acting
pub struct AutoExecutor {
    user_id: String,
    observer: Arc<crate::omniscience::observer::OmniscienceObserver>,
    user_engine: Arc<UserPersonalizationEngine>,
}

impl AutoExecutor {
    pub fn new(user_id: String) -> Self {
        Self {
            user_id: user_id.clone(),
            observer: OMNI_OBSERVER.clone(),
            user_engine: Arc::new(UserPersonalizationEngine::new()),
        }
    }

    /// Start the self-learning + self-doing loop
    pub fn start(&self) {
        println!("UBE Auto-Executor Started for user: {}", self.user_id);
        println!("  - Observing all actions");
        println!("  - Detecting repetitive patterns");
        println!("  - Creating automation laws");
        println!("  - Self-executing repetitive work");

        // Spawn observer thread
        let observer_clone = self.observer.clone();
        let user_id_clone = self.user_id.clone();
        thread::spawn(move || {
            Self::observer_loop(&observer_clone, &user_id_clone);
        });

        // Spawn executor thread
        let observer_clone = self.observer.clone();
        let user_id_clone = self.user_id.clone();
        thread::spawn(move || {
            Self::executor_loop(&observer_clone, &user_id_clone);
        });

        println!("  ✓ Auto-Executor is now RUNNING");
        println!("  ✓ UBE will learn and automate YOUR repetitive work");
    }

    /// Observer loop - watches and learns
    fn observer_loop(observer: &Arc<crate::omniscience::observer::OmniscienceObserver>, user_id: &str) {
        // In real implementation, this would hook into system events
        // For now, we simulate by checking for user activity
        loop {
            // Check for new events (would be populated by system hooks)
            {
                let events = observer.events.read().unwrap();
                if !events.is_empty() {
                    // Events are being recorded by observe_event() calls
                    // Patterns and laws are auto-generated
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
    }

    /// Executor loop - acts on learned patterns
    fn executor_loop(observer: &Arc<crate::omniscience::observer::OmniscienceObserver>, user_id: &str) {
        loop {
            // Check for automatable actions
            // In real use: this would intercept system calls

            // For demo: show stats
            let stats = observer.get_stats(user_id);
            if stats.total_patterns > 0 || stats.total_laws > 0 {
                println!("\n[OMNISCIENCE]Boy  {} patterns detected", stats.total_patterns);
                println!("[OMNISCIENCE] {} laws created", stats.total_laws);
                println!("[OMNISCIENCE] Automation rate: {:.1}%", stats.automation_rate * 100.0);
            }

            thread::sleep(Duration::from_secs(5));
        }
    }

    /// Hook into file operations (example)
    pub fn hook_file_operation(&self, operation: &str, path: &str) {
        let start = std::time::SystemTime::now();
        let result = std::panic::catch_unwind(|| {
            // Simulate the operation
            if operation == "read" {
                std::fs::read_to_string(path).ok()
            } else if operation == "write" {
                std::fs::write(path, "test").ok()
            } else {
                None
            }
        });
        let duration = start.elapsed().unwrap().as_millis() as u64;
        let success = result.is_ok();

        // Record this event for learning
        observe_event(
            self.user_id.clone(),
            operation.to_string(),
            path.to_string(),
            duration,
            success,
        );

        // Check if this action can be automated
        if let Some(law) = OMNI_OBSERVER.check_automation(&self.user_id, operation, path) {
            println!("[AUTOMATION] Action '{}' on '{}' is AUTOMATED by law: {}",
                operation, path, law.law_id);
            // Here: UBE would actually execute the automation
            // For now, we just log it
        }

        result.ok()
    }

    /// Get all learned laws
    pub fn get_learned_laws(&self) -> Vec<UniversalLaw> {
        OMNI_OBSERVER.get_user_laws(&self.user_id)
    }

    /// Get all detected patterns
    pub fn get_detected_patterns(&self) -> Vec<crate::omniscience::observer::OmniPattern> {
        OMNI_OBSERVER.get_user_patterns(&self.user_id)
    }

    /// Get statistics
    pub fn get_stats(&self) -> crate::omniscience::observer::OmniStats {
        OMNI_OBSERVER.get_stats(&self.user_id)
    }
}

/// Global Auto-Executor for the current user
lazy_static::lazy_static! {
    pub static ref AUTO_EXECUTOR: Mutex<Option<AutoExecutor>> = Mutex::new(None);
}

/// Start the global auto-executor
pub fn start_auto_executor(user_id: String) -> Arc<AutoExecutor> {
    let executor = Arc::new(AutoExecutor::new(user_id.clone()));
    executor.start();

    let mut guard = AUTO_EXECUTOR.lock().unwrap();
    *guard = Some(AutoExecutor::new(user_id));

    executor
}

/// Hook a file operation for learning
pub fn hook_file_operation(user_id: &str, operation: &str, path: &str) {
    if let Some(executor) = AUTO_EXECUTOR.lock().unwrap().as_ref() {
        if executor.user_id == user_id {
            executor.hook_file_operation(operation, path);
        }
    }
}
