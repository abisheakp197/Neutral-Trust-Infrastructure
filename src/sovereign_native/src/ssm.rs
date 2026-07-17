//! UBE Sovereign State Machine (SSM)
//! The central heartbeat of the Sovereign OS.
//! Implements the Sovereign Trinity: Agent (Decision) -> Proxy (Orchestration) -> Tool (Execution).

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::types::Value;
use crate::intelligence::core::IntelligenceHub;
use crate::automation::{AutomationEngine, AutomationRequest, AutomationStatus};
use crate::connector::ConnectorRegistry;
use crate::gateway::SovereignGateway;

/// Represents a high-level Sovereign Mandate.
/// A mandate is a standing order that the SSM must maintain or achieve.
#[derive(Debug, Clone)]
pub struct SovereignMandate {
    pub id: String,
    pub name: String,
    pub priority: i32,
    pub trigger_condition: Box<dyn Fn(&IntelligenceHub) -> bool + Send + Sync>,
    pub action_request: AutomationRequest,
    pub is_active: bool,
}

/// The state of the Sovereign OS.
#[derive(Debug, Clone)]
pub struct SovereignState {
    pub current_tick: u64,
    pub active_mandates: Vec<String>,
    pub system_health: f64,
    pub operational_mode: OperationalMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationalMode {
    Stealth,
    Active,
    Recovery,
    AirGap,
}

/// The Sovereign State Machine (SSM).
/// The "Brain" that eliminates the attention tax by autonomously actioning mandates.
pub struct SovereignStateMachine {
    pub state: Arc<Mutex<SovereignState>>,
    pub mandates: Arc<Mutex<HashMap<String, SovereignMandate>>>,
    pub queue: Arc<Mutex<VecDeque<String>>>,

    // The Trinity Layers
    pub intelligence: Arc<Mutex<IntelligenceHub>>,
    pub automation: Arc<AutomationEngine>,
    pub connectors: Arc<Mutex<ConnectorRegistry>>,
    // Gateway integration for external connectivity
    pub gateway: Option<Arc<SovereignGateway>>,
}

impl SovereignStateMachine {
    pub fn new(tenant_id: &str) -> Self {
        Self {
            state: Arc::new(Mutex::new(SovereignState {
                current_tick: 0,
                active_mandates: Vec::new(),
                system_health: 1.0,
                operational_mode: OperationalMode::Active,
            })),
            mandates: Arc::new(Mutex::new(HashMap::new())),
            queue: Arc::new(Mutex::new(VecDeque::new())),
            intelligence: Arc::new(Mutex::new(IntelligenceHub::new())),
            automation: Arc::new(AutomationEngine::new(tenant_id)),
            connectors: Arc::new(Mutex::new(ConnectorRegistry::new())),
            gateway: None,
        }
    }

    /// Create SSM with Gateway integration
    pub fn with_gateway(mut self, gateway: Arc<SovereignGateway>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Registers a new sovereign mandate into the system.
    pub fn register_mandate(&self, mandate: SovereignMandate) {
        let mut mandates = self.mandates.lock().unwrap();
        mandates.insert(mandate.id.clone(), mandate);
    }

    /// The main autonomous loop (The Heartbeat).
    /// Evaluates intelligence, checks mandates, and action-sequences tasks.
    pub async fn tick(&self) {
        let mut state = self.state.lock().unwrap();
        state.current_tick += 1;

        let intelligence = self.intelligence.lock().unwrap();
        let mandates = self.mandates.lock().unwrap();

        // 1. Evaluation Phase: Which mandates are triggered by the current environment?
        for (id, mandate) in mandates.iter() {
            if mandate.is_active && (mandate.trigger_condition)(&intelligence) {
                let mut queue = self.queue.lock().unwrap();
                if !queue.contains(id) {
                    queue.push_back(id.clone());
                }
            }
        }
        drop(mandates);
        drop(intelligence);
        drop(state);

        // 2. Execution Phase: Action the highest priority mandate in the queue.
        self.process_queue().await;
    }

    async fn process_queue(&self) {
        let mandate_id = {
            let mut queue = self.queue.lock().unwrap();
            queue.pop_front()
        };

        if let Some(id) = mandate_id {
            let mandate = {
                let mandates = self.mandates.lock().unwrap();
                mandates.get(&id).cloned()
            };

            if let Some(m) = mandate {
                // EXECUTION: Trigger the Automation Engine to perform the action.
                // This is where "Actioning" happens without a user request.
                let result = self.automation.execute(m.action_request);

                // Log result to the Sovereign Ledger (if implemented)
                // and update IntelligenceHub based on success/failure.
                println!("Sovereign Action completed: {} -> {:?}", m.name, result.status);
            }
        }
    }
}
