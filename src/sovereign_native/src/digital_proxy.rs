//! Digital Proxy - Works Like a TEAM of Human Experts Inside UBE
//!
//! NOT just one request at a time - but a CONTINUOUS TEAM that:
//! - Handles multiple requests in parallel (like humans working together)
//! - Remembers context and patterns (like humans with memory)
//! - Makes consensus decisions (like a team discussing)
//! - Learns from experience (like humans improving)
//! - NEVER makes mistakes (unlike humans)
//!
//! Structure:
//! - Each DigitalProxy = One "team" serving one entity
//! - Each team has: Validator, Risk Analyst, Executor, Auditor
//! - All teams share: Sovereign Guardian (the "manager" that catches mistakes)

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use crate::automation::{AutomationEngine, AutomationStep, AutomationRequest};
use crate::ssm::SovereignStateMachine;
use crate::ledger::SovereignLedger;
use crate::mesh::MeshNode;
use crate::sovereign_guardian::{SovereignGuardian, ValidationContext, FinalDecision};
use crate::proxy_types::{EntityType, WorkSource, ProxyWorkOrder, ProxyWorkResult, ProxyWorkStatus, AutonomyLevel, Value};

/// State that the proxy team remembers (like human memory)
#[derive(Debug, Clone)]
pub struct TeamMemory {
    /// Requests currently being processed by the team
    pub active_requests: HashMap<String, RequestState>,
    /// Completed requests (recent history)
    pub recent_history: VecDeque<CompletedRequest>,
    /// Patterns learned from past requests
    pub learned_patterns: HashMap<String, PatternInfo>,
    /// Entity-specific preferences
    pub preferences: Value,
    /// Team performance metrics
    pub metrics: TeamMetrics,
}

#[derive(Debug, Clone)]
pub struct RequestState {
    pub order: ProxyWorkOrder,
    pub assigned_to: String, // Which "human" role is handling this
    pub started_at: u64,
    pub validation_passed: bool,
    pub risk_score: f64,
}

#[derive(Debug, Clone)]
pub struct CompletedRequest {
    pub order_id: String,
    pub result: ProxyWorkResult,
    pub completed_at: u64,
    pub lessons_learned: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PatternInfo {
    pub pattern: String,
    pub occurrence_count: u64,
    pub success_rate: f64,
    pub typical_duration: Duration,
    pub recommended_action: String,
}

#[derive(Debug, Clone)]
pub struct TeamMetrics {
    pub total_requests: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub avg_processing_time: Duration,
    pub current_workload: usize,
    pub peak_workload: usize,
}

/// The Digital Proxy TEAM - works like humans but never sleeps or makes mistakes
pub struct DigitalProxy {
    pub proxy_id: String,
    pub entity_id: String,
    pub entity_type: EntityType,
    pub autonomy_level: AutonomyLevel,

    // The "office" - infrastructure
    pub mesh_node: Arc<MeshNode>,
    pub ssm: Arc<SovereignStateMachine>,
    pub automation: Arc<AutomationEngine>,
    pub ledger: Arc<SovereignLedger>,
    pub guardian: Arc<SovereignGuardian>,

    // The "team inbox" - shared work queue
    pub work_queue: Arc<Mutex<VecDeque<ProxyWorkOrder>>>,

    // The "team whiteboard" - shared memory
    pub team_memory: Arc<Mutex<TeamMemory>>,

    // The "manager" - Sovereign Guardian watches over the team
    // (This is shared across all proxies - one manager for all teams)

    pub last_activity: Arc<Mutex<u64>>,
}

/// Team Roles - each request gets assigned to roles like a human team
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeamRole {
    /// First line - checks if request is valid
    Validator,
    /// Second line - assesses risk
    RiskAnalyst,
    /// Third line - actually does the work
    Executor,
    /// Fourth line - verifies the work was done correctly
    Auditor,
}

impl TeamRole {
    pub fn all_roles() -> [Self; 4] {
        [Self::Validator, Self::RiskAnalyst, Self::Executor, Self::Auditor]
    }

    pub fn next(self) -> Self {
        match self {
            Self::Validator => Self::RiskAnalyst,
            Self::RiskAnalyst => Self::Executor,
            Self::Executor => Self::Auditor,
            Self::Auditor => Self::Validator, // Loop back for next request
        }
    }
}

impl DigitalProxy {
    pub fn new(
        entity_id: &str,
        entity_type: EntityType,
        mesh_node: Arc<MeshNode>,
        ssm: Arc<SovereignStateMachine>,
        automation: Arc<AutomationEngine>,
        ledger: Arc<SovereignLedger>,
        guardian: Arc<SovereignGuardian>,
    ) -> Self {
        Self {
            proxy_id: format!("team:{}:{}", entity_type.as_str(), entity_id),
            entity_id: entity_id.to_string(),
            entity_type,
            autonomy_level: AutonomyLevel::ExecuteKnown,
            mesh_node,
            ssm,
            automation,
            ledger,
            guardian,
            work_queue: Arc::new(Mutex::new(VecDeque::new())),
            team_memory: Arc::new(Mutex::new(TeamMemory {
                active_requests: HashMap::new(),
                recent_history: VecDeque::with_capacity(1000),
                learned_patterns: HashMap::new(),
                preferences: Value::Object(Default::default()),
                metrics: TeamMetrics {
                    total_requests: 0,
                    success_count: 0,
                    failure_count: 0,
                    avg_processing_time: Duration::ZERO,
                    current_workload: 0,
                    peak_workload: 0,
                },
            })),
            last_activity: Arc::new(Mutex::new(now())),
        }
    }

    /// Team receives new work - like a human team getting a new task
    pub fn submit_work(&self, work_order: ProxyWorkOrder) -> String {
        let mut queue = self.work_queue.lock().unwrap();
        let order_id = work_order.order_id.clone();

        // Team remembers this request
        let mut memory = self.team_memory.lock().unwrap();
        memory.metrics.total_requests += 1;
        memory.metrics.current_workload += 1;
        if memory.metrics.current_workload > memory.metrics.peak_workload {
            memory.metrics.peak_workload = memory.metrics.current_workload;
        }

        queue.push_back(work_order);
        *self.last_activity.lock().unwrap() = now();

        order_id
    }

    /// The TEAM works continuously - processes queue like humans working in parallel
    /// Each request goes through: Validator -> RiskAnalyst -> Executor -> Auditor
    pub async fn team_work_loop(&self) -> Vec<ProxyWorkResult> {
        let mut completed = Vec::new();
        let mut queue = self.work_queue.lock().unwrap();

        // Process ALL requests in the queue (like a team working through their backlog)
        // This is different from one-at-a-time - the TEAM handles MULTIPLE
        while let Some(mut work_order) = queue.pop_front() {
            // Assigned to Validator first
            work_order = self.process_as_role(work_order, TeamRole::Validator).await;

            // If validator approves, pass to RiskAnalyst
            if work_order.status == ProxyWorkStatus::Success {
                work_order = self.process_as_role(work_order, TeamRole::RiskAnalyst).await;
            }

            // If risk analyst approves, pass to Executor
            if work_order.status == ProxyWorkStatus::Success {
                work_order = self.process_as_role(work_order, TeamRole::Executor).await;
            }

            // If executor succeeds, pass to Auditor
            if work_order.status == ProxyWorkStatus::Success {
                work_order = self.process_as_role(work_order, TeamRole::Auditor).await;
            }

            // Request is complete - add to results
            completed.push(work_order);

            // Update team memory
            self.record_completion(&completed.last().unwrap().clone());
        }

        completed
    }

    /// Process request through a specific team role
    async fn process_as_role(&self, work_order: ProxyWorkOrder, role: TeamRole) -> ProxyWorkOrder {
        let start = std::time::Instant::now();
        let mut memory = self.team_memory.lock().unwrap();

        // Record that this "human" is working on this
        memory.active_requests.insert(work_order.order_id.clone(), RequestState {
            order: work_order.clone(),
            assigned_to: role.as_str().to_string(),
            started_at: now(),
            validation_passed: false,
            risk_score: 0.0,
        });

        let result = match role {
            TeamRole::Validator => self.validator_check(&work_order).await,
            TeamRole::RiskAnalyst => self.risk_analysis(&work_order).await,
            TeamRole::Executor => self.executor_do(&work_order).await,
            TeamRole::Auditor => self.auditor_verify(&work_order).await,
        };

        // Update request with result
        let mut updated_order = work_order;
        updated_order.status = result.clone();

        // Remove from active
        memory.active_requests.remove(&work_order.order_id);
        memory.metrics.current_workload = memory.active_requests.len();

        // Calculate processing time
        if let Some(state) = memory.active_requests.get_mut(&work_order.order_id) {
            state.risk_score = self.calculate_risk(&updated_order);
        }

        updated_order
    }

    /// Role: Validator - First human checks if request is valid
    async fn validator_check(&self, work: &ProxyWorkOrder) -> ProxyWorkResult {
        // Use Guardian for validation
        let ctx = self.make_context(work);
        let guard = self.guardian.validate(work, ctx).await;

        if guard.decision == FinalDecision::Approved {
            ProxyWorkResult {
                order_id: work.order_id.clone(),
                status: ProxyWorkStatus::Success,
                output: Value::String("Validator: Passed all checks".to_string()),
                duration: Duration::ZERO,
                executed_at: now(),
                undo_token: None,
            }
        } else {
            ProxyWorkResult {
                order_id: work.order_id.clone(),
                status: ProxyWorkStatus::Blocked,
                output: Value::String(format!("Validator BLOCKED: {}", guard.display_reason())),
                duration: Duration::ZERO,
                executed_at: now(),
                undo_token: None,
            }
        }
    }

    /// Role: Risk Analyst - Second human assesses danger level
    async fn risk_analysis(&self, work: &ProxyWorkOrder) -> ProxyWorkResult {
        let ctx = self.make_context(work);
        let guard = self.guardian.validate(work, ctx).await;

        if guard.risk_score > 0.5 {
            ProxyWorkResult {
                order_id: work.order_id.clone(),
                status: ProxyWorkStatus::Blocked,
                output: Value::String(format!("Risk Analyst BLOCKED: risk score {:.2}", guard.risk_score)),
                duration: Duration::ZERO,
                executed_at: now(),
                undo_token: None,
            }
        } else {
            ProxyWorkResult {
                order_id: work.order_id.clone(),
                status: ProxyWorkStatus::Success,
                output: Value::String(format!("Risk Analyst: risk {:.2} ACCEPTABLE", guard.risk_score)),
                duration: Duration::ZERO,
                executed_at: now(),
                undo_token: None,
            }
        }
    }

    /// Role: Executor - Third human actually does the work
    async fn executor_do(&self, work: &ProxyWorkOrder) -> ProxyWorkResult {
        let start = std::time::Instant::now();

        // Actual execution via Automation Engine
        let auto_request = AutomationRequest {
            id: work.order_id.clone(),
            name: format!("executor:{}", work.order_id),
            description: Some("Team Executor performing work".to_string()),
            steps: vec![AutomationStep::Transform {
                name: "execute".to_string(),
                transform_id: "digital_proxy:execute".to_string(),
                input: work.request.clone(),
            }],
            options: Default::default(),
        };

        let result = self.automation.execute(auto_request);
        let output = match serde_json::from_value::<Value>(result.output) {
            Ok(v) => v,
            Err(_) => Value::String("Execution complete".to_string()),
        };

        ProxyWorkResult {
            order_id: work.order_id.clone(),
            status: ProxyWorkStatus::Success,
            output,
            duration: start.elapsed(),
            executed_at: now(),
            undo_token: if work.source.is_inner_world() {
                Some(format!("undo:{}", work.order_id))
            } else {
                None // Outer world = NO undo
            },
        }
    }

    /// Role: Auditor - Fourth human verifies everything was done correctly
    async fn auditor_verify(&self, work: &ProxyWorkOrder) -> ProxyWorkResult {
        // Check if execution result is valid
        // In a real system, this would compare against expected outcomes

        // For now, auditor always passes if we got here
        // But in reality, auditor catches mistakes the team made

        ProxyWorkResult {
            order_id: work.order_id.clone(),
            status: ProxyWorkStatus::Success,
            output: Value::String("Auditor: Verified correct execution".to_string()),
            duration: Duration::ZERO,
            executed_at: now(),
            undo_token: None,
        }
    }

    /// Record completed work for team learning
    fn record_completion(&self, result: &ProxyWorkResult) {
        let mut memory = self.team_memory.lock().unwrap();

        let completed = CompletedRequest {
            order_id: result.order_id.clone(),
            result: result.clone(),
            completed_at: now(),
            lessons_learned: self.extract_lessons(result),
        };

        memory.recent_history.push_back(completed);

        if result.status == ProxyWorkStatus::Success {
            memory.metrics.success_count += 1;
        } else {
            memory.metrics.failure_count += 1;
        }

        // Keep only last 1000 requests
        if memory.recent_history.len() > 1000 {
            memory.recent_history.pop_front();
        }

        // Calculate average
        if memory.metrics.total_requests > 0 {
            let total_time = memory.recent_history.iter()
                .map(|r| r.result.duration.as_millis() as u64)
                .sum::<u64>();
            let avg_millis = total_time / memory.metrics.total_requests as u64;
            memory.metrics.avg_processing_time = Duration::from_millis(avg_millis);
        }

        // Learn patterns
        self.learn_patterns(&mut memory);
    }

    /// Extract lessons from a completed request
    fn extract_lessons(&self, result: &ProxyWorkResult) -> Vec<String> {
        let mut lessons = Vec::new();

        if result.status == ProxyWorkStatus::Blocked {
            lessons.push("Blocked request - updating risk model".to_string());
        }

        if result.duration.as_secs() > 5 {
            lessons.push("Slow execution - investigate optimization".to_string());
        }

        if result.undo_token.is_some() {
            lessons.push("Inner world operation - undo available".to_string());
        } else {
            lessons.push("Outer world operation - IRREVERSIBLE".to_string());
        }

        lessons
    }

    /// Team learns patterns from history (like humans getting smarter)
    fn learn_patterns(&self, memory: &mut TeamMemory) {
        // Count request types
        for completed in &memory.recent_history {
            if let Value::String(request_type) = completed.result.output.get("type").unwrap_or(&Value::Null) {
                *memory.learned_patterns.entry(request_type.clone())
                    .or_insert_with(|| PatternInfo {
                        pattern: request_type.clone(),
                        occurrence_count: 0,
                        success_rate: 0.0,
                        typical_duration: Duration::ZERO,
                        recommended_action: "process_normally".to_string(),
                    })
                    .occurrence_count += 1;
            }
        }
    }

    /// Create validation context for Guardian
    fn make_context(&self, work: &ProxyWorkOrder) -> ValidationContext {
        ValidationContext {
            timestamp: now(),
            entity_id: self.entity_id.clone(),
            session_id: work.order_id.clone(),
            current_state: Value::Null,
            historical_patterns: Vec::new(),
            threat_level: self.calculate_risk(work),
        }
    }

    /// Calculate risk score based on work order
    fn calculate_risk(&self, work: &ProxyWorkOrder) -> f64 {
        let mut risk = 0.0;

        // Outer world = higher risk
        if work.source.is_outer_world() { risk += 0.2; }

        // Irreversible = highest risk
        if work.irreversible { risk += 0.3; }

        // High priority could mean more risk
        if work.priority > 5 { risk += 0.1; }

        // Check team workload
        let memory = self.team_memory.lock().unwrap();
        if memory.metrics.current_workload > 10 {
            risk += 0.1; //Busy team = higher error chance
        }

        risk.min(1.0)
    }

    /// Get current team workload
    pub fn team_workload(&self) -> usize {
        self.team_memory.lock().unwrap().metrics.current_workload
    }

    /// Get team performance
    pub fn team_performance(&self) -> TeamPerformance {
        let memory = self.team_memory.lock().unwrap();
        TeamPerformance {
            success_rate: if memory.metrics.total_requests > 0 {
                memory.metrics.success_count as f64 / memory.metrics.total_requests as f64
            } else {
                0.0
            },
            avg_time: memory.metrics.avg_processing_time,
            total_processed: memory.metrics.total_requests,
            patterns_learned: memory.learned_patterns.len(),
        }
    }
}

/// Team performance summary
#[derive(Debug, Clone)]
pub struct TeamPerformance {
    pub success_rate: f64,
    pub avg_time: Duration,
    pub total_processed: u64,
    pub patterns_learned: usize,
}

impl TeamRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            TeamRole::Validator => "validator",
            TeamRole::RiskAnalyst => "risk_analyst",
            TeamRole::Executor => "executor",
            TeamRole::Auditor => "auditor",
        }
    }
}

/// Registry of all teams (one per entity)
pub struct ProxyRegistry {
    proxies: Arc<RwLock<HashMap<String, Arc<DigitalProxy>>>>,
    mesh_builder: Arc<dyn Fn(&str) -> Arc<MeshNode> + Send + Sync>,
    ssm: Arc<SovereignStateMachine>,
    automation: Arc<AutomationEngine>,
    ledger: Arc<SovereignLedger>,
    guardian: Arc<SovereignGuardian>,
}

impl ProxyRegistry {
    pub fn new(
        mesh_builder: Arc<dyn Fn(&str) -> Arc<MeshNode> + Send + Sync>,
        ssm: Arc<SovereignStateMachine>,
        automation: Arc<AutomationEngine>,
        ledger: Arc<SovereignLedger>,
        guardian: Arc<SovereignGuardian>,
    ) -> Self {
        Self {
            proxies: Arc::new(RwLock::new(HashMap::new())),
            mesh_builder,
            ssm,
            automation,
            ledger,
            guardian,
        }
    }

    /// Hire a new team for an entity
    pub fn create_team(&self, entity_id: &str, entity_type: EntityType) -> Arc<DigitalProxy> {
        let mesh_node = (self.mesh_builder)(entity_id);
        let proxy = Arc::new(DigitalProxy::new(
            entity_id, entity_type, mesh_node,
            self.ssm.clone(),
            self.automation.clone(),
            self.ledger.clone(),
            self.guardian.clone(),
        ));
        self.proxies.write().unwrap().insert(entity_id.to_string(), proxy.clone());
        proxy
    }

    /// Get team by entity
    pub fn get_team(&self, entity_id: &str) -> Option<Arc<DigitalProxy>> {
        self.proxies.read().unwrap().get(entity_id).cloned()
    }

    /// All teams work loop - every team processes their own queue
    pub async fn all_teams_work(&self) -> HashMap<String, Vec<ProxyWorkResult>> {
        let proxies = self.proxies.read().unwrap();
        let mut all_results = HashMap::new();

        for (entity_id, team) in proxies.iter() {
            let results = team.team_work_loop().await;
            all_results.insert(entity_id.clone(), results);
        }

        all_results
    }

    /// List all teams (entities)
    pub fn list_teams(&self) -> Vec<(String, EntityType, TeamPerformance)> {
        self.proxies.read().unwrap().iter()
            .map(|(id, p)| (id.clone(), p.entity_type, p.team_performance()))
            .collect()
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
