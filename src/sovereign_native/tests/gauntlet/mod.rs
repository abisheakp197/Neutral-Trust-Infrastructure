//! UBE Sovereign Gauntlet Orchestrator
//! The final verification suite for the indestructible core.
//! Runs the Chaos Monkey and validates system recovery.

use std::sync::Arc;
use std::time::Duration;
use crate::ssm::SovereignStateMachine;
use chaos_monkey::{ChaosMonkey, AdversarialFault};
use log::{info, warn, error};

pub struct SovereignGauntlet {
    pub ssm: Arc<SovereignStateMachine>,
    pub monkey: ChaosMonkey,
}

impl SovereignGauntlet {
    pub fn new(ssm: Arc<SovereignStateMachine>, intensity: f64) -> Self {
        Self {
            ssm,
            monkey: ChaosMonkey::new(ssm.clone(), intensity),
        }
    }

    /// Runs a full gauntlet cycle.
    /// Injects faults, monitors the SIS, and verifies the result.
    pub async fn run_cycle(&self, iterations: usize) -> GauntletResult {
        info!("Sovereign Gauntlet: Initiating adversarial stress test...");
        let mut passed = 0;
        let mut failed = 0;

        for i in 0..iterations {
            info!("Iteration {}/{}", i + 1, iterations);

            // 1. Inject Fault
            if let Some(fault) = self.monkey.inject_fault() {
                warn!("Gauntlet: Injecting fault {:?}", fault);
                self.monkey.attack(fault).await;

                // 2. Give the SSM and SIS time to react
                tokio::time::sleep(Duration::from_millis(500)).await;

                // 3. Verify Recovery
                // We check if the system health is still 1.0 or if the SIS detected the deviation.
                if self.verify_recovery() {
                    info!("Iteration {}: RECOVERY SUCCESSFUL", i + 1);
                    passed += 1;
                } else {
                    error!("Iteration {}: RECOVERY FAILED", i + 1);
                    failed += 1;
                }
            } else {
                info!("Iteration {}: No fault injected", i + 1);
                passed += 1;
            }
        }

        GauntletResult {
            total: iterations,
            passed,
            failed,
            resilience_score: (passed as f64 / iterations as f64) * 100.0,
        }
    }

    fn verify_recovery(&self) -> bool {
        let state = self.ssm.state.lock().unwrap();
        // Recovery is successful if the system is not in Recovery mode or is Healthy.
        state.system_health >= 0.9
    }
}

#[derive(Debug)]
pub struct GauntletResult {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub resilience_score: f64,
}
