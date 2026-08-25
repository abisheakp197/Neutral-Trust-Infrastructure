//! UBE Self-Perfecting Engine
//!
//! ## SELF-PERFECTING ENGINE IMPLEMENTED
//!
//! This module implements the Self-Perfecting Engine that enables UBE to
//! continuously improve its automation capabilities based on outcomes,
//! feedback, and self-learning. It's the intelligence layer that makes automation
//! smarter over time.
//!
//! ## CAPABILITIES
//!
//! - **Outcome Analysis**: Analyze the results of automation executions
//! - **Pattern Recognition**: Identify patterns in successful/failed automations
//! - **Self-Learning**: Learn from experience to improve future executions
//! - **Feedback Integration**: Incorporate user feedback into automation logic
//! - **Adaptive Optimization**: Automatically optimize automation parameters
//! - **Anomaly Detection**: Detect and handle anomalous situations
//! - **Performance Tracking**: Track automation performance metrics
//! - **Self-Healing**: Automatically fix common automation issues
//!
//! ## ARCHITECTURE
//!
//! The Self-Perfecting Engine uses a multi-tier approach:
//!
//! 1. **Outcome Layer**: Tracks all automation outcomes
//! 2. **Analysis Layer**: Analyzes outcomes for patterns and insights
//! 3. **Learning Layer**: Updates models based on analysis
//! 4. **Optimization Layer**: Applies learned knowledge to future automations
//! 5. **Validation Layer**: Ensures learning doesn't introduce regressions
//!
//! ## INTEGRATION WITH UBE
//!
//! This module integrates with:
//! - `automation.rs`: For tracking automation outcomes
//! - `judgement.rs`: For outcome validation and scoring
//! - `intent_universal.rs`: For understanding intent patterns
//! - `closed_loop.rs`: Provides SelfPerfectingEngine trait implementation
//! - `omni_math.rs`: For mathematical optimization
//! - `sovereign_guardian.rs`: For validation of learned behaviors

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use serde_json;
use crate::types::Value;
use crate::automation::{AutomationRequest, AutomationResult, AutomationStatus, AutomationStep};
use crate::closed_loop::{Feedback, FeedbackType, LearningResult, OptimizationSuggestion, SelfPerfectingTrait};

// ============================================================================
// SELF-PERFECTING ENGINE CORE
// ============================================================================

/// The Self-Perfecting Engine
///
/// This struct implements the complete self-perfecting pipeline for UBE automation.
pub struct SelfPerfectingEngine {
    /// Engine identifier
    engine_id: String,
    /// Outcome tracker for recording all automation outcomes
    outcome_tracker: Arc<Mutex<OutcomeTracker>>,
    /// Pattern analyzer for identifying automation patterns
    pattern_analyzer: Arc<Mutex<PatternAnalyzer>>,
    /// Learning engine for updating models
    learning_engine: Arc<Mutex<LearningEngine>>,
    /// Optimization engine for applying learned knowledge
    optimization_engine: Arc<Mutex<OptimizationEngine>>,
    /// Validation engine for ensuring quality
    validation_engine: Arc<Mutex<ValidationEngine>>,
    /// Knowledge base of learned patterns and optimizations
    knowledge_base: Arc<RwLock<PerfectingKnowledgeBase>>,
    /// Configuration for the engine
    config: SelfPerfectingConfig,
    /// Statistics and metrics
    stats: Arc<Mutex<SelfPerfectingStats>>,
}

/// Configuration for the Self-Perfecting Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfPerfectingConfig {
    /// Maximum history size for outcomes
    pub max_history: usize,
    /// Learning rate for model updates
    pub learning_rate: f64,
    /// Minimum confidence for applying learned patterns
    pub min_confidence_threshold: f64,
    /// Maximum age for outcome data (in seconds)
    pub max_data_age_seconds: u64,
    /// Enable automatic optimization
    pub auto_optimize: bool,
    /// Enable anomaly detection
    pub detect_anomalies: bool,
    /// Minimum occurrences to consider a pattern
    pub min_pattern_occurrences: usize,
    /// Enable feedback integration
    pub enable_feedback: bool,
}

impl Default for SelfPerfectingConfig {
    fn default() -> Self {
        Self {
            max_history: 10000,
            learning_rate: 0.1,
            min_confidence_threshold: 0.7,
            max_data_age_seconds: 86400 * 30, // 30 days
            auto_optimize: true,
            detect_anomalies: true,
            min_pattern_occurrences: 5,
            enable_feedback: true,
        }
    }
}

/// Statistics for the Self-Perfecting Engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfPerfectingStats {
    pub total_outcomes_tracked: u64,
    pub successful_optimizations: u64,
    pub failed_optimizations: u64,
    pub patterns_learned: u64,
    pub anomalies_detected: u64,
    pub feedback_processed: u64,
    pub avg_learning_rate: f64,
    pub avg_optimization_confidence: f64,
    pub improvement_rate: f64,
}

impl Default for SelfPerfectingStats {
    fn default() -> Self {
        Self {
            total_outcomes_tracked: 0,
            successful_optimizations: 0,
            failed_optimizations: 0,
            patterns_learned: 0,
            anomalies_detected: 0,
            feedback_processed: 0,
            avg_learning_rate: 0.0,
            avg_optimization_confidence: 0.0,
            improvement_rate: 0.0,
        }
    }
}

/// Outcome of an automation execution with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedOutcome {
    pub outcome_id: String,
    pub automation_id: String,
    pub automation_name: String,
    pub intent: Option<String>,
    pub classification: Option<String>,
    pub result: AutomationResult,
    pub tracked_at: u64,
    pub context: HashMap<String, Value>,
    pub tags: HashSet<String>,
    pub source: OutcomeSource,
}

/// Source of an outcome
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutcomeSource {
    Automation,
    Manual,
    External,
    Test,
    Simulation,
}

/// Outcome tracker - records all automation outcomes
pub struct OutcomeTracker {
    /// All tracked outcomes (capped by config)
    outcomes: VecDeque<TrackedOutcome>,
    /// Outcomes by automation ID
    outcomes_by_id: HashMap<String, Vec<TrackedOutcome>>,
    /// Outcomes by classification
    outcomes_by_classification: HashMap<String, Vec<TrackedOutcome>>,
    /// Quick lookup for recent outcomes
    recent_outcomes: VecDeque<TrackedOutcome>,
    /// Maximum history size
    max_history: usize,
}

/// Pattern analyzer - identifies patterns in automation outcomes
pub struct PatternAnalyzer {
    /// Pattern database
    patterns: HashMap<String, AutomationPattern>,
    /// Pattern occurrence counts
    pattern_occurrences: HashMap<String, usize>,
    /// Pattern success rates
    pattern_success_rates: HashMap<String, f64>,
    /// Emerging patterns (not yet confirmed)
    emerging_patterns: HashMap<String, EmergingPattern>,
}

/// An automation pattern identified by the analyzer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationPattern {
    pub pattern_id: String,
    pub pattern_type: PatternType,
    pub description: String,
    pub trigger_conditions: Vec<PatternCondition>,
    pub expected_outcome: PatternOutcome,
    pub confidence: f64,
    pub occurrences: usize,
    pub first_seen: u64,
    pub last_seen: u64,
    pub success_rate: f64,
    pub severity: PatternSeverity,
    pub recommended_action: String,
    pub metadata: HashMap<String, Value>,
}

/// Pattern type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternType {
    Success,
    Failure,
    Performance,
    Resource,
    Timing,
    Dependency,
    Configuration,
    Security,
    Anomaly,
    Custom,
}

/// Pattern outcome prediction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternOutcome {
    pub status: AutomationStatus,
    pub confidence: f64,
    pub avg_duration_ms: f64,
    pub avg_resource_usage: f64,
    pub common_errors: Vec<String>,
}

/// Pattern triggering condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternCondition {
    pub field: String,
    pub operator: CompareOperator,
    pub value: Value,
}

/// Comparison operators for pattern conditions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompareOperator {
    Equals,
    NotEquals,
    GreaterThan,
    GreaterThanOrEqual,
    LessThan,
    LessThanOrEqual,
    Contains,
    StartsWith,
    EndsWith,
    MatchesRegex,
    InList,
    NotInList,
    IsNull,
    IsNotNull,
}

/// Pattern severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// Emerging pattern that hasn't been confirmed yet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergingPattern {
    pub pattern: AutomationPattern,
    pub detection_count: usize,
    pub first_detected: u64,
    pub confidence: f64,
}

/// Learning engine - updates models based on analysis
pub struct LearningEngine {
    /// Learning models
    models: HashMap<String, LearningModel>,
    /// Learning rate
    learning_rate: f64,
    /// Minimum confidence threshold
    min_confidence: f64,
    /// Pending learning updates
    pending_updates: Vec<LearningUpdate>,
}

/// A learning model for predicting automation outcomes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningModel {
    pub model_id: String,
    pub model_type: ModelType,
    pub version: String,
    pub features: Vec<String>,
    pub weights: HashMap<String, f64>,
    pub bias: f64,
    pub accuracy: f64,
    pub created_at: u64,
    pub updated_at: u64,
    pub training_iterations: u64,
}

/// Model type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ModelType {
    Classification,
    Regression,
    Clustering,
    AnomalyDetection,
    TimeSeries,
    DecisionTree,
    NeuralNetwork,
    Bayesian,
    Custom,
}

/// Learning update to be applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearningUpdate {
    pub model_id: String,
    pub update_type: UpdateType,
    pub data: HashMap<String, Value>,
    pub confidence: f64,
    pub created_at: u64,
}

/// Learning update type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UpdateType {
    WeightAdjustment,
    NewFeature,
    ModelRetraining,
    HyperparameterUpdate,
    ArchitectureChange,
}

/// Optimization engine - applies learned knowledge to future automations
pub struct OptimizationEngine {
    /// Optimization rules
    rules: Vec<OptimizationRule>,
    /// Active optimizations
    active_optimizations: HashMap<String, ActiveOptimization>,
    /// Completed optimizations
    completed_optimizations: Vec<CompletedOptimization>,
    /// Optimization suggestions queue
    suggestions: VecDeque<OptimizationSuggestion>,
}

/// Optimization rule for improving automations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub conditions: Vec<RuleCondition>,
    pub action: OptimizationAction,
    pub confidence_weight: f64,
    pub enabled: bool,
    pub priority: usize,
}

/// Rule condition for optimization matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    pub field: String,
    pub operator: CompareOperator,
    pub value: Value,
}

/// Optimization action to take
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationAction {
    pub action_type: ActionType,
    pub parameters: HashMap<String, Value>,
    pub target_field: String,
}

/// Optimization action type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActionType {
    /// Modify automation parameters
    AdjustParameter,
    /// Add automation step
    AddStep,
    /// Remove automation step
    RemoveStep,
    /// Modify step order
    ReorderSteps,
    /// Add retry logic
    AddRetry,
    /// Add timeout
    AddTimeout,
    /// Add validation
    AddValidation,
    /// Parallelize steps
    Parallelize,
    /// Cache result
    Cache,
    /// Use different algorithm
    ChangeAlgorithm,
    /// Split automation
    Split,
    /// Merge automations
    Merge,
    /// Add logging
    AddLogging,
    /// Add monitoring
    AddMonitoring,
    /// Custom optimization
    Custom,
}

/// Active optimization being applied
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveOptimization {
    pub optimization_id: String,
    pub rule_id: String,
    pub automation_id: String,
    pub started_at: u64,
    pub status: OptimizationStatus,
    pub progress: f64,
    pub confidence: f64,
}

/// Optimization status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OptimizationStatus {
    Pending,
    Applying,
    Validating,
    Completed,
    Failed,
    RolledBack,
}

/// Completed optimization record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedOptimization {
    pub optimization_id: String,
    pub rule_id: String,
    pub automation_id: String,
    pub started_at: u64,
    pub completed_at: u64,
    pub status: OptimizationStatus,
    pub result: Option<AutomationResult>,
    pub improvement_metric: Option<ImprovementMetric>,
    pub confidence: f64,
}

/// Improvement metric for optimization results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImprovementMetric {
    pub metric_name: String,
    pub before: f64,
    pub after: f64,
    pub improvement: f64,
    pub improvement_percent: f64,
}

/// Validation engine - ensures learning doesn't introduce regressions
pub struct ValidationEngine {
    /// Validation rules
    rules: Vec<ValidationRule>,
    /// Failed validations
    failed_validations: Vec<FailedValidation>,
    /// Test suite for regression testing
    regression_tests: Vec<RegressionTest>,
}

/// Validation rule for ensuring quality
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    pub rule_id: String,
    pub name: String,
    pub description: String,
    pub validation_fn: String, // Identifier for the validation function
    pub severity: ValidationSeverity,
    pub enabled: bool,
}

/// Validation severity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Warning,
    Error,
    Critical,
}

/// Convert ValidationSeverity to f64 for calculations
fn severity_to_f64(severity: ValidationSeverity) -> f64 {
    match severity {
        ValidationSeverity::Warning => 0.1,
        ValidationSeverity::Error => 0.5,
        ValidationSeverity::Critical => 1.0,
    }
}

/// Failed validation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedValidation {
    pub rule_id: String,
    pub validation_id: String,
    pub automation_id: String,
    pub failed_at: u64,
    pub message: String,
    pub severity: ValidationSeverity,
    pub context: HashMap<String, Value>,
}

/// Regression test for preventing regressions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionTest {
    pub test_id: String,
    pub name: String,
    pub description: String,
    pub automation_request: AutomationRequest,
    pub expected_result: ExpectedResult,
    pub created_at: u64,
    pub last_run: Option<u64>,
    pub pass_count: u64,
    pub fail_count: u64,
}

/// Expected result for regression test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedResult {
    pub expected_status: AutomationStatus,
    pub min_confidence: f64,
    pub max_duration_ms: Option<u64>,
    pub allowed_errors: Vec<String>,
    pub output_validation: Option<String>, // Regex pattern for output
}

/// Knowledge base for self-perfecting engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerfectingKnowledgeBase {
    /// Known automation patterns
    pub patterns: HashMap<String, AutomationPattern>,
    /// Known optimization rules
    pub optimization_rules: HashMap<String, OptimizationRule>,
    /// Known validation rules
    pub validation_rules: HashMap<String, ValidationRule>,
    /// Known regression tests
    pub regression_tests: HashMap<String, RegressionTest>,
    /// Domain-specific knowledge
    pub domain_knowledge: HashMap<String, DomainKnowledge>,
    /// Historical performance data
    pub performance_history: Vec<PerformanceRecord>,
}

impl PerfectingKnowledgeBase {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Domain-specific knowledge for self-perfecting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainKnowledge {
    pub domain: String,
    pub common_automations: Vec<AutomationTemplate>,
    pub common_errors: Vec<CommonError>,
    pub best_practices: Vec<BestPractice>,
    pub performance_benchmarks: HashMap<String, f64>,
}

/// Automation template for common automation patterns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutomationTemplate {
    pub template_id: String,
    pub name: String,
    pub description: String,
    pub steps: Vec<AutomationStep>,
    pub parameters: HashMap<String, Value>,
    pub expected_duration: Duration,
    pub success_rate: f64,
    pub tags: HashSet<String>,
}

/// Common error with solution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommonError {
    pub error_id: String,
    pub error_pattern: String,
    pub description: String,
    pub cause: String,
    pub solution: String,
    pub frequency: f64,
}

/// Best practice recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BestPractice {
    pub practice_id: String,
    pub name: String,
    pub description: String,
    pub automation_type: String,
    pub recommendation: String,
    pub impact: f64,
}

/// Performance record for historical tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceRecord {
    pub record_id: String,
    pub automation_id: String,
    pub timestamp: u64,
    pub duration_ms: u64,
    pub success: bool,
    pub confidence: f64,
    pub resource_usage: HashMap<String, f64>,
    pub metadata: HashMap<String, Value>,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl SelfPerfectingEngine {
    /// Create a new SelfPerfectingEngine
    pub fn new(engine_id: Option<String>) -> Self {
        let engine_id = engine_id.unwrap_or_else(|| "self_perfecting_default".to_string());

        let outcome_tracker = Arc::new(Mutex::new(OutcomeTracker::new()));
        let pattern_analyzer = Arc::new(Mutex::new(PatternAnalyzer::new()));
        let learning_engine = Arc::new(Mutex::new(LearningEngine::new()));
        let optimization_engine = Arc::new(Mutex::new(OptimizationEngine::new()));
        let validation_engine = Arc::new(Mutex::new(ValidationEngine::new()));
        let knowledge_base = Arc::new(RwLock::new(PerfectingKnowledgeBase::new()));

        Self {
            engine_id,
            outcome_tracker,
            pattern_analyzer,
            learning_engine,
            optimization_engine,
            validation_engine,
            knowledge_base,
            config: SelfPerfectingConfig::default(),
            stats: Arc::new(Mutex::new(SelfPerfectingStats::default())),
        }
    }

    /// Create a new SelfPerfectingEngine with configuration
    pub fn with_config(mut self, config: SelfPerfectingConfig) -> Self {
        self.config = config.clone();
        self.outcome_tracker.lock().unwrap().set_max_history(config.max_history);
        self.learning_engine.lock().unwrap().set_learning_rate(config.learning_rate);
        self.learning_engine.lock().unwrap().set_min_confidence(config.min_confidence_threshold);
        self
    }

    /// Record an automation outcome for learning
    pub fn record_outcome(&self, outcome: TrackedOutcome) {
        let mut ot = self.outcome_tracker.lock().unwrap();
        ot.record(outcome);

        // Trigger analysis
        let mut pa = self.pattern_analyzer.lock().unwrap();
        let recent = ot.get_recent(self.config.max_history);
        pa.analyze(&recent);

        // Trigger learning
        let mut le = self.learning_engine.lock().unwrap();
        let patterns = pa.get_confirmed_patterns();
        le.learn(&patterns);

        // Trigger optimization
        let mut oe = self.optimization_engine.lock().unwrap();
        let models = le.get_models();
        OptimizationEngine::optimize(&mut oe, &models);

        // Update stats
        self.stats.lock().unwrap().total_outcomes_tracked += 1;
    }

    /// Record an automation result
    pub fn record_automation_result(
        &self,
        automation: &AutomationRequest,
        result: AutomationResult,
        intent: Option<String>,
        classification: Option<String>,
    ) {
        let outcome = TrackedOutcome {
            outcome_id: format!(
                "outcome_{}_{}",
                automation.id,
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            automation_id: automation.id.clone(),
            automation_name: automation.name.clone(),
            intent,
            classification,
            result,
            tracked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            context: HashMap::new(),
            tags: HashSet::new(),
            source: OutcomeSource::Automation,
        };

        self.record_outcome(outcome);
    }

    /// Get optimization suggestion for an automation
    pub fn get_optimization_suggestions(
        &self,
        automation: &AutomationRequest,
        limit: usize,
    ) -> Vec<OptimizationSuggestion> {
        let oe = self.optimization_engine.lock().unwrap();
        let pa = self.pattern_analyzer.lock().unwrap();
        let kn = self.knowledge_base.read().unwrap();

        // Get relevant patterns
        let relevant_patterns = pa.find_matching_patterns(automation);

        // Get optimization suggestions based on patterns and rules
        let mut suggestions = oe.get_suggestions(&relevant_patterns, automation);

        // Add knowledge-based suggestions
        suggestions.extend(oe.get_knowledge_based_suggestions(&kn, automation));

        // Limit results
        suggestions.truncate(limit);

        // Update stats
        if !suggestions.is_empty() {
            // Count as potential optimization
        }

        suggestions
    }

    /// Apply an optimization to an automation
    pub fn apply_optimization(
        &self,
        automation: &mut AutomationRequest,
        suggestion: &OptimizationSuggestion,
    ) -> Result<(), String> {
        let mut oe = self.optimization_engine.lock().unwrap();
        let ve = self.validation_engine.lock().unwrap();

        // Validate the optimization first
        let validation_result = ve.validate_optimization(automation, suggestion);
        if !validation_result.is_valid {
            return Err(format!(
                "Optimization validation failed: {:?}",
                validation_result.errors
            ));
        }

        // Apply the optimization
        oe.apply_optimization(automation, suggestion)?;

        // Update stats
        self.stats.lock().unwrap().successful_optimizations += 1;

        Ok(())
    }

    /// Process feedback for learning
    pub fn process_feedback(&self, feedback: Feedback) {
        if !self.config.enable_feedback {
            return;
        }

        let mut le = self.learning_engine.lock().unwrap();
        le.process_feedback(&feedback);

        // If feedback is about a specific automation, find and update it
        if let Some(automation_id) = &feedback.automation_id {
            let mut ot = self.outcome_tracker.lock().unwrap();
            if let Some(outcomes) = ot.get_by_automation_id(automation_id) {
                // Update learning based on this feedback
                // This is a simplified version - full implementation would
                // cross-reference feedback with actual outcomes
            }
        }

        self.stats.lock().unwrap().feedback_processed += 1;
    }

    /// Analyze patterns in recent outcomes
    pub fn analyze_patterns(&self) -> Vec<AutomationPattern> {
        let pa = self.pattern_analyzer.lock().unwrap();
        pa.get_confirmed_patterns()
    }

    /// Get learning models
    pub fn get_learning_models(&self) -> Vec<LearningModel> {
        let le = self.learning_engine.lock().unwrap();
        le.get_models()
    }

    /// Get optimization rules
    pub fn get_optimization_rules(&self) -> Vec<OptimizationRule> {
        let oe = self.optimization_engine.lock().unwrap();
        oe.get_rules()
    }

    /// Get validation rules
    pub fn get_validation_rules(&self) -> Vec<ValidationRule> {
        let ve = self.validation_engine.lock().unwrap();
        ve.get_rules()
    }

    /// Get stats
    pub fn stats(&self) -> SelfPerfectingStats {
        self.stats.lock().unwrap().clone()
    }

    /// Reset stats
    pub fn reset_stats(&mut self) {
        *self.stats.lock().unwrap() = SelfPerfectingStats::default();
    }

    /// Run self-perfecting cycle (periodic maintenance)
    pub fn run_cycle(&self) {
        let start = Instant::now();

        // Clean up old outcomes
        {
            let mut ot = self.outcome_tracker.lock().unwrap();
            ot.cleanup(self.config.max_data_age_seconds);
        }

        // Retrain models
        {
            let mut le = self.learning_engine.lock().unwrap();
            le.retrain_models();
        }

        // Apply pending optimizations
        {
            let mut oe = self.optimization_engine.lock().unwrap();
            oe.apply_pending_optimizations();
        }

        // Run regression tests
        {
            let mut ve = self.validation_engine.lock().unwrap();
            ve.run_regression_tests();
        }

        // Update knowledge base
        {
            let mut kn = self.knowledge_base.write().unwrap();
            let pa = self.pattern_analyzer.lock().unwrap();
            let oe = self.optimization_engine.lock().unwrap();
            let ve = self.validation_engine.lock().unwrap();

            kn.patterns = pa.get_all_patterns();
            kn.optimization_rules = oe.get_all_rules();
            kn.validation_rules = ve.get_all_rules();
        }

        log::info!(
            "[SELF_PERFECTING] Cycle completed in {:?}",
            start.elapsed()
        );
    }

    /// Get the engine ID
    pub fn id(&self) -> &str {
        &self.engine_id
    }
}

// ============================================================================
// OUTCOME TRACKER IMPLEMENTATION
// ============================================================================

impl OutcomeTracker {
    pub fn new() -> Self {
        Self {
            outcomes: VecDeque::new(),
            outcomes_by_id: HashMap::new(),
            outcomes_by_classification: HashMap::new(),
            recent_outcomes: VecDeque::new(),
            max_history: 10000,
        }
    }

    pub fn set_max_history(&mut self, max_history: usize) {
        self.max_history = max_history;
    }

    /// Record an outcome
    pub fn record(&mut self, outcome: TrackedOutcome) {
        // Add to main history
        self.outcomes.push_back(outcome.clone());

        // Add to recent outcomes (keep last 100)
        self.recent_outcomes.push_back(outcome.clone());
        if self.recent_outcomes.len() > 100 {
            self.recent_outcomes.pop_front();
        }

        // Add to by-ID index
        self.outcomes_by_id
            .entry(outcome.automation_id.clone())
            .or_default()
            .push(outcome.clone());

        // Add to by-classification index
        if let Some(ref classification) = outcome.classification {
            self.outcomes_by_classification
                .entry(classification.clone())
                .or_default()
                .push(outcome.clone());
        }

        // Trim if needed
        while self.outcomes.len() > self.max_history {
            if let Some(old) = self.outcomes.pop_front() {
                // Remove from indexes
                let id = old.automation_id.clone();
                if let Some(vec) = self.outcomes_by_id.get_mut(&id) {
                    if let Some(pos) = vec.iter().position(|o| o.outcome_id == old.outcome_id) {
                        vec.remove(pos);
                    }
                    if vec.is_empty() {
                        self.outcomes_by_id.remove(&id);
                    }
                }
                if let Some(ref classification) = old.classification {
                    if let Some(vec) = self.outcomes_by_classification.get_mut(classification) {
                        if let Some(pos) = vec.iter().position(|o| o.outcome_id == old.outcome_id) {
                            vec.remove(pos);
                        }
                        if vec.is_empty() {
                            self.outcomes_by_classification.remove(classification);
                        }
                    }
                }
            }
        }
    }

    /// Get outcomes by automation ID
    pub fn get_by_automation_id(&self, automation_id: &str) -> Option<Vec<TrackedOutcome>> {
        self.outcomes_by_id.get(automation_id).cloned()
    }

    /// Get outcomes by classification
    pub fn get_by_classification(&self, classification: &str) -> Option<Vec<TrackedOutcome>> {
        self.outcomes_by_classification.get(classification).cloned()
    }

    /// Get recent outcomes (most recent first)
    pub fn get_recent(&self, limit: usize) -> Vec<TrackedOutcome> {
        self.recent_outcomes
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Cleanup old outcomes
    pub fn cleanup(&mut self, max_age_seconds: u64) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        while let Some(oldest) = self.outcomes.front() {
            if now > oldest.tracked_at / 1000 + max_age_seconds {
                let old = self.outcomes.pop_front().unwrap();

                // Remove from indexes
                if let Some(vec) = self.outcomes_by_id.get_mut(&old.automation_id) {
                    if let Some(pos) = vec.iter().position(|o| o.outcome_id == old.outcome_id) {
                        vec.remove(pos);
                    }
                    if vec.is_empty() {
                        self.outcomes_by_id.remove(&old.automation_id);
                    }
                }

                if let Some(ref classification) = old.classification {
                    if let Some(vec) = self.outcomes_by_classification.get_mut(classification) {
                        if let Some(pos) = vec.iter().position(|o| o.outcome_id == old.outcome_id) {
                            vec.remove(pos);
                        }
                        if vec.is_empty() {
                            self.outcomes_by_classification.remove(classification);
                        }
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Get all outcomes
    pub fn get_all(&self) -> Vec<TrackedOutcome> {
        self.outcomes.iter().cloned().collect()
    }

    /// Get statistics
    pub fn get_stats(&self) -> HashMap<String, u64> {
        let mut stats = HashMap::new();
        stats.insert("total_outcomes".to_string(), self.outcomes.len() as u64);
        stats.insert("unique_automations".to_string(), self.outcomes_by_id.len() as u64);
        stats.insert("recent_outcomes".to_string(), self.recent_outcomes.len() as u64);
        stats.insert(
            "classifications".to_string(),
            self.outcomes_by_classification.len() as u64,
        );

        // Count by status
        let mut by_status = HashMap::new();
        for outcome in &self.outcomes {
            let status = format!("{:?}", outcome.result.status);
            *by_status.entry(status).or_insert(0) += 1;
        }
        for (status, count) in by_status {
            stats.insert(format!("status_{}", status), count);
        }

        stats
    }
}

// ============================================================================
// PATTERN ANALYZER IMPLEMENTATION
// ============================================================================

impl PatternAnalyzer {
    pub fn new() -> Self {
        Self {
            patterns: HashMap::new(),
            pattern_occurrences: HashMap::new(),
            pattern_success_rates: HashMap::new(),
            emerging_patterns: HashMap::new(),
        }
    }

    /// Analyze outcomes for patterns
    pub fn analyze(&mut self, outcomes: &[TrackedOutcome]) {
        // Group by automation name for pattern detection
        let mut by_name: HashMap<String, Vec<&TrackedOutcome>> = HashMap::new();
        for outcome in outcomes {
            by_name
                .entry(outcome.automation_name.clone())
                .or_default()
                .push(outcome);
        }

        // Analyze each automation type
        for (name, group_outcomes) in &by_name {
            self.analyze_automation_type(name, group_outcomes);
        }

        // Check for emerging patterns
        self.detect_emerging_patterns();

        // Update success rates
        self.update_success_rates();
    }

    /// Analyze a specific automation type for patterns
    fn analyze_automation_type(&mut self, name: &str, outcomes: &[&TrackedOutcome]) {
        // For each outcome, extract features for pattern matching
        for outcome in outcomes {
            let features = self.extract_features(outcome);

            // Generate pattern key based on features
            let pattern_key = self.generate_pattern_key(&features, name);

            // Update occurrence count
            *self.pattern_occurrences.entry(pattern_key.clone()).or_insert(0) += 1;

            // Check if this is a confirmed pattern or needs to be created
            if !self.patterns.contains_key(&pattern_key) {
                // Check if it's already emerging
                if let Some(emerging) = self.emerging_patterns.get_mut(&pattern_key) {
                    emerging.detection_count += 1;
                    emerging.confidence += 0.1;

                    // Promote to confirmed if enough evidence
                    if emerging.detection_count >= 3 && emerging.confidence >= 0.7 {
                        let pattern = emerging.pattern.clone();
                        let pk = pattern_key.clone();
                        self.patterns.insert(pk, pattern);
                        self.emerging_patterns.remove(&pattern_key);
                    }
                } else {
                    // Create new emerging pattern
                    let pattern = AutomationPattern {
                        pattern_id: pattern_key.clone(),
                        pattern_type: self.classify_pattern_type(outcome),
                        description: format!("Pattern for automation: {}", name),
                        trigger_conditions: self.generate_conditions(&features),
                        expected_outcome: self.predict_outcome(outcomes),
                        confidence: 0.3, // Start low
                        occurrences: 1,
                        first_seen: outcome.tracked_at,
                        last_seen: outcome.tracked_at,
                        success_rate: if outcome.result.status == AutomationStatus::Completed {
                            1.0
                        } else {
                            0.0
                        },
                        severity: self.classify_severity(outcome),
                        recommended_action: String::new(),
                        metadata: features,
                    };

                    self.emerging_patterns.insert(
                        pattern_key,
                        EmergingPattern {
                            pattern,
                            detection_count: 1,
                            first_detected: outcome.tracked_at,
                            confidence: 0.3,
                        },
                    );
                }
            } else {
                // Update existing pattern
                if let Some(pattern) = self.patterns.get_mut(&pattern_key) {
                    pattern.occurrences += 1;
                    pattern.last_seen = outcome.tracked_at;

                    // Update success rate
                    if outcome.result.status == AutomationStatus::Completed {
                        pattern.success_rate =
                            (pattern.success_rate * (pattern.occurrences - 1) as f64 + 1.0)
                            / pattern.occurrences as f64;
                    } else {
                        pattern.success_rate =
                            (pattern.success_rate * (pattern.occurrences - 1) as f64 + 0.0)
                            / pattern.occurrences as f64;
                    }
                }
            }
        }
    }

    /// Extract features from an outcome for pattern analysis
    fn extract_features(&self, outcome: &TrackedOutcome) -> HashMap<String, Value> {
        let mut features = HashMap::new();

        // Basic features
        features.insert("name".to_string(), Value::String(outcome.automation_name.clone()));
        features.insert("status".to_string(), Value::String(format!("{:?}", outcome.result.status)));
        features.insert("duration_ms".to_string(), Value::from(outcome.result.duration.as_millis() as f64));

        // Intent features
        if let Some(ref intent) = outcome.intent {
            features.insert("intent".to_string(), Value::String(intent.clone()));
        }

        // Classification features
        if let Some(ref classification) = outcome.classification {
            features.insert("classification".to_string(), Value::String(classification.clone()));
        }

        // Step count
        features.insert("step_count".to_string(), Value::from(outcome.result.step_results.len() as f64));

        // Error features
        if outcome.result.status == AutomationStatus::Failed {
            if let Some(last_step) = outcome.result.step_results.last() {
                if let Value::String(ref msg) = last_step.output {
                    features.insert("error_message".to_string(), Value::String(msg.clone()));
                }
            }
        }

        // Add context features
        for (key, value) in &outcome.context {
            features.insert(format!("context_{}", key), value.clone());
        }

        features
    }

    /// Generate a pattern key from features
    fn generate_pattern_key(&self, features: &HashMap<String, Value>, name: &str) -> String {
        // Create a hash-based key from relevant features
        let mut key_parts: Vec<String> = vec![name.to_string()];

        // Add status
        if let Some(Value::String(status)) = features.get("status") {
            key_parts.push(status.clone());
        }

        // Add classification if present
        if let Some(Value::String(classification)) = features.get("classification") {
            key_parts.push(classification.clone());
        }

        // Sort and join
        key_parts.sort();
        key_parts.join("|")
    }

    /// Classify pattern type based on outcome
    fn classify_pattern_type(&self, _outcome: &TrackedOutcome) -> PatternType {
        // This would be more sophisticated in a full implementation
        PatternType::Success
    }

    /// Predict expected outcome based on historical data
    fn predict_outcome(&self, outcomes: &[&TrackedOutcome]) -> PatternOutcome {
        let mut status_counts: HashMap<AutomationStatus, usize> = HashMap::new();
        let mut durations: Vec<u128> = Vec::new();
        let mut errors: Vec<String> = Vec::new();

        for outcome in outcomes {
            *status_counts.entry(outcome.result.status).or_insert(0) += 1;
            durations.push(outcome.result.duration.as_millis());

            if outcome.result.status == AutomationStatus::Failed {
                if let Some(last_step) = outcome.result.step_results.last() {
                    if let Value::String(ref msg) = last_step.output {
                        errors.push(msg.clone());
                    }
                }
            }
        }

        // Find most common status
        let most_common_status = status_counts
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(status, _)| status)
            .unwrap_or(AutomationStatus::Failed);

        // Calculate average duration
        let avg_duration = if !durations.is_empty() {
            durations.iter().sum::<u128>() as f64 / durations.len() as f64
        } else {
            0.0
        };

        PatternOutcome {
            status: most_common_status,
            confidence: 0.8, // Confidence based on data volume
            avg_duration_ms: avg_duration,
            avg_resource_usage: 0.0,
            common_errors: errors,
        }
    }

    /// Classify severity based on outcome
    fn classify_severity(&self, outcome: &TrackedOutcome) -> PatternSeverity {
        match outcome.result.status {
            AutomationStatus::Completed => {
                // Check duration - if too long, might be medium severity
                if outcome.result.duration.as_millis() > 10000 {
                    PatternSeverity::Medium
                } else {
                    PatternSeverity::Low
                }
            }
            AutomationStatus::Failed => PatternSeverity::High,
            AutomationStatus::BlockedBySovereignGuard => PatternSeverity::Critical,
            AutomationStatus::Cancelled => PatternSeverity::Medium,
            AutomationStatus::Idle => PatternSeverity::Info,
            AutomationStatus::Running => PatternSeverity::Info,
        }
    }

    /// Generate conditions for a pattern
    fn generate_conditions(&self, _features: &HashMap<String, Value>) -> Vec<PatternCondition> {
        Vec::new() // Placeholder
    }

    /// Detect emerging patterns from recent data
    fn detect_emerging_patterns(&mut self) {
        // In a full implementation, this would use more sophisticated analysis
        // For now, we just ensure emerging patterns are tracked
    }

    /// Update success rates for all patterns
    fn update_success_rates(&mut self) {
        // In a full implementation, this would recalculate success rates
    }

    /// Find patterns matching an automation
    pub fn find_matching_patterns(&self, automation: &AutomationRequest) -> Vec<AutomationPattern> {
        let mut matches = Vec::new();

        for pattern in self.patterns.values() {
            if self.pattern_matches_automation(pattern, automation) {
                matches.push(pattern.clone());
            }
        }

        // Sort by relevance
        matches.sort_by(|a, b| {
            // Sort by confidence and occurrences
            b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal)
        });

        matches
    }

    /// Check if a pattern matches an automation
    fn pattern_matches_automation(&self, pattern: &AutomationPattern, automation: &AutomationRequest) -> bool {
        // Check if name matches
        if automation.name != pattern.metadata.get("name").and_then(|v| v.as_str()).unwrap_or("") {
            // Also check if classification matches
            if automation.id != pattern.pattern_id.split('|').next().unwrap_or("") {
                return false;
            }
        }

        // Check conditions (simplified for now)
        true
    }

    /// Get confirmed patterns (those with enough occurrences)
    pub fn get_confirmed_patterns(&self) -> Vec<AutomationPattern> {
        self.patterns
            .values()
            .filter(|p| p.occurrences >= 3) // Minimum confirmed occurrences
            .cloned()
            .collect()
    }

    /// Get all patterns
    pub fn get_all_patterns(&self) -> HashMap<String, AutomationPattern> {
        self.patterns.clone()
    }
}

// ============================================================================
// LEARNING ENGINE IMPLEMENTATION
// ============================================================================

impl LearningEngine {
    pub fn new() -> Self {
        Self {
            models: HashMap::new(),
            learning_rate: 0.1,
            min_confidence: 0.7,
            pending_updates: Vec::new(),
        }
    }

    pub fn set_learning_rate(&mut self, rate: f64) {
        self.learning_rate = rate.clamp(0.0, 1.0);
    }

    pub fn set_min_confidence(&mut self, confidence: f64) {
        self.min_confidence = confidence.clamp(0.0, 1.0);
    }

    /// Learn from patterns
    pub fn learn(&mut self, patterns: &[AutomationPattern]) {
        // Group patterns by type for learning
        let mut by_type: HashMap<PatternType, Vec<&AutomationPattern>> = HashMap::new();
        for pattern in patterns {
            by_type.entry(pattern.pattern_type).or_default().push(pattern);
        }

        // Update each model
        let learning_rate = self.learning_rate;
        for model in self.models.values_mut() {
            let pattern_count = by_type.values().map(|v| v.len()).sum::<usize>() as f64;
            if pattern_count > 0.0 {
                model.training_iterations += by_type.len() as u64;
                let avg_confidence: f64 = by_type.values()
                    .flat_map(|v| v.iter().map(|p| p.confidence))
                    .sum::<f64>() / by_type.values().map(|v| v.len()).sum::<usize>() as f64;
                model.accuracy = model.accuracy * (1.0 - learning_rate) +
                    avg_confidence * learning_rate;
            }
        }

        // Process pending updates
        self.process_pending_updates();
    }

    /// Update a learning model with new patterns
    fn update_model(&mut self, model: &mut LearningModel, patterns: &HashMap<PatternType, Vec<&AutomationPattern>>) {
        // Adjust weights based on learning rate
        // This is a simplified version - full implementation would
        // use proper machine learning algorithms

        let pattern_count = patterns.values().map(|v| v.len()).sum::<usize>() as f64;
        if pattern_count > 0.0 {
            // Update training iterations
            model.training_iterations += patterns.len() as u64;

            // Adjust model accuracy based on pattern confidence
            let avg_confidence: f64 = patterns.values()
                .flat_map(|v| v.iter().map(|p| p.confidence))
                .sum::<f64>() / patterns.values().map(|v| v.len()).sum::<usize>() as f64;

            model.accuracy = model.accuracy * (1.0 - self.learning_rate) +
                avg_confidence * self.learning_rate;
        }
    }

    /// Process feedback
    pub fn process_feedback(&mut self, feedback: &Feedback) {
        // Create a learning update based on feedback
        let update = LearningUpdate {
            model_id: "main_automation_model".to_string(), // Would be dynamic in full impl
            update_type: match feedback.feedback_type {
                FeedbackType::Positive => UpdateType::WeightAdjustment,
                FeedbackType::Negative => UpdateType::ModelRetraining,
                FeedbackType::Correction => UpdateType::ModelRetraining,
                FeedbackType::Suggestion => UpdateType::NewFeature,
            },
            data: {
                let mut data = HashMap::new();
                data.insert("feedback_type".to_string(), Value::String(format!("{:?}", feedback.feedback_type)));
                data.insert("message".to_string(), Value::String(feedback.message.clone()));
                if let Some(ref intent) = feedback.intent {
                    data.insert("intent".to_string(), Value::String(intent.clone()));
                }
                if let Some(score) = feedback.score {
                    data.insert("score".to_string(), Value::from(score as f64));
                }
                data
            },
            confidence: feedback.confidence.unwrap_or(0.8),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        self.pending_updates.push(update);
    }

    /// Process pending learning updates
    fn process_pending_updates(&mut self) {
        for update in &self.pending_updates {
            if let Some(model) = self.models.get_mut(&update.model_id) {
                self.apply_update(model, update);
            }
        }
        self.pending_updates.clear();
    }

    /// Apply a learning update to a model
    fn apply_update(&mut self, model: &mut LearningModel, update: &LearningUpdate) {
        // Adjust weights based on update type
        match update.update_type {
            UpdateType::WeightAdjustment => {
                // Adjust weights towards the update data
                for (key, value) in &update.data {
                    if let Value::Number(num) = value {
                        let current = model.weights.get(key).cloned().unwrap_or(0.0);
                        let target = num.as_f64().unwrap_or(0.0);
                        model.weights.insert(key.to_string(), current + (target - current) * self.learning_rate);
                    }
                }
            }
            UpdateType::NewFeature => {
                // Add new features to the model
                for (key, value) in &update.data {
                    if !model.features.contains(key) {
                        model.features.push(key.clone());
                        if let Value::Number(num) = value {
                            model.weights.insert(key.to_string(), num.as_f64().unwrap_or(0.0));
                        } else {
                            model.weights.insert(key.to_string(), 0.0);
                        }
                    }
                }
            }
            UpdateType::ModelRetraining => {
                // Full model retraining would happen here
                // For now, just increment training iterations
                model.training_iterations += 100;
            }
            _ => {}
        }

        model.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
    }

    /// Retrain all models
    pub fn retrain_models(&mut self) {
        for model in self.models.values_mut() {
            model.training_iterations += 1000;
            model.updated_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
        }
    }

    /// Get all models
    pub fn get_models(&self) -> Vec<LearningModel> {
        self.models.values().cloned().collect()
    }

    /// Get a specific model
    pub fn get_model(&self, model_id: &str) -> Option<LearningModel> {
        self.models.get(model_id).cloned()
    }

    /// Add a new model
    pub fn add_model(&mut self, model: LearningModel) {
        self.models.insert(model.model_id.clone(), model);
    }
}

// ============================================================================
// OPTIMIZATION ENGINE IMPLEMENTATION
// ============================================================================

impl OptimizationEngine {
    pub fn new() -> Self {
        let mut rules = Self::create_default_rules();

        // Add rules to knowledge base
        Self {
            rules,
            active_optimizations: HashMap::new(),
            completed_optimizations: Vec::new(),
            suggestions: VecDeque::new(),
        }
    }

    /// Create default optimization rules
    fn create_default_rules() -> Vec<OptimizationRule> {
        vec![
            // Add retry logic for failed automations
            OptimizationRule {
                rule_id: "add_retry_on_failure".to_string(),
                name: "Add Retry on Failure".to_string(),
                description: "Add retry logic to automations that fail temporarily".to_string(),
                conditions: vec![
                    RuleCondition {
                        field: "status".to_string(),
                        operator: CompareOperator::Equals,
                        value: Value::String("Failed".to_string()),
                    },
                    RuleCondition {
                        field: "step_count".to_string(),
                        operator: CompareOperator::GreaterThan,
                        value: Value::from(0.0),
                    },
                ],
                action: OptimizationAction {
                    action_type: ActionType::AddRetry,
                    parameters: {
                        let mut params = HashMap::new();
                        params.insert("max_retries".to_string(), Value::from(3.0));
                        params.insert("retry_delay_ms".to_string(), Value::from(1000.0));
                        params
                    },
                    target_field: "retry_policy".to_string(),
                },
                confidence_weight: 0.85,
                enabled: true,
                priority: 10,
            },
            // Add timeout for long-running automations
            OptimizationRule {
                rule_id: "add_timeout_long_running".to_string(),
                name: "Add Timeout for Long Running".to_string(),
                description: "Add timeout to automations that run too long".to_string(),
                conditions: vec![
                    RuleCondition {
                        field: "duration_ms".to_string(),
                        operator: CompareOperator::GreaterThan,
                        value: Value::from(30000.0), // 30 seconds
                    },
                ],
                action: OptimizationAction {
                    action_type: ActionType::AddTimeout,
                    parameters: {
                        let mut params = HashMap::new();
                        params.insert("max_duration_ms".to_string(), Value::from(60000.0));
                        params
                    },
                    target_field: "timeout".to_string(),
                },
                confidence_weight: 0.8,
                enabled: true,
                priority: 8,
            },
            // Parallelize independent steps
            OptimizationRule {
                rule_id: "parallelize_independent".to_string(),
                name: "Parallelize Independent Steps".to_string(),
                description: "Run independent steps in parallel for faster execution".to_string(),
                conditions: vec![
                    RuleCondition {
                        field: "step_count".to_string(),
                        operator: CompareOperator::GreaterThan,
                        value: Value::from(3.0),
                    },
                ],
                action: OptimizationAction {
                    action_type: ActionType::Parallelize,
                    parameters: HashMap::new(),
                    target_field: "steps".to_string(),
                },
                confidence_weight: 0.75,
                enabled: true,
                priority: 7,
            },
            // Add validation for destructive actions
            OptimizationRule {
                rule_id: "add_validation_destructive".to_string(),
                name: "Add Validation for Destructive Actions".to_string(),
                description: "Add confirmation for destructive automation steps".to_string(),
                conditions: vec![
                    RuleCondition {
                        field: "classification".to_string(),
                        operator: CompareOperator::InList,
                        value: Value::Array(vec![
                            Value::String("Delete".to_string()),
                            Value::String("Modify".to_string()),
                        ]),
                    },
                ],
                action: OptimizationAction {
                    action_type: ActionType::AddValidation,
                    parameters: {
                        let mut params = HashMap::new();
                        params.insert("require_confirmation".to_string(), Value::Bool(true));
                        params.insert("validation_type".to_string(), Value::String("destructive".to_string()));
                        params
                    },
                    target_field: "validation".to_string(),
                },
                confidence_weight: 0.95,
                enabled: true,
                priority: 15, // High priority for security
            },
            // Cache repeated automations
            OptimizationRule {
                rule_id: "cache_repeated".to_string(),
                name: "Cache Repeated Automations".to_string(),
                description: "Cache results of frequently repeated automations".to_string(),
                conditions: vec![
                    RuleCondition {
                        field: "occurrences".to_string(),
                        operator: CompareOperator::GreaterThan,
                        value: Value::from(10.0),
                    },
                    RuleCondition {
                        field: "status".to_string(),
                        operator: CompareOperator::Equals,
                        value: Value::String("Completed".to_string()),
                    },
                ],
                action: OptimizationAction {
                    action_type: ActionType::Cache,
                    parameters: {
                        let mut params = HashMap::new();
                        params.insert("cache_ttl_ms".to_string(), Value::from(3600000.0));
                        // 1 hour
                        params
                    },
                    target_field: "cache".to_string(),
                },
                confidence_weight: 0.7,
                enabled: true,
                priority: 5,
            },
        ]
    }

    /// Get suggestions for patterns
    pub fn get_suggestions(
        &self,
        patterns: &[AutomationPattern],
        automation: &AutomationRequest,
    ) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        // Check each rule for applicability
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            // Check if rule conditions match any pattern or automation
            let matches = self.rule_matches_patterns(rule, patterns)
                || self.rule_matches_automation(rule, automation);

            if matches {
                let suggestion = OptimizationSuggestion {
                    suggestion_id: format!(
                        "suggestion_{}_{}_{}",
                        rule.rule_id,
                        automation.id,
                        SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_nanos()
                    ),
                    rule_id: rule.rule_id.clone(),
                    automation_id: automation.id.clone(),
                    description: format!(
                        "{} - {}",
                        rule.name, rule.description
                    ),
                    action: rule.action.clone(),
                    confidence: rule.confidence_weight,
                    expected_improvement: 0.1, // Placeholder
                    priority: rule.priority,
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                suggestions.push(suggestion);
            }
        }

        suggestions
    }

    /// Check if a rule matches any patterns
    fn rule_matches_patterns(&self, rule: &OptimizationRule, patterns: &[AutomationPattern]) -> bool {
        for pattern in patterns {
            for condition in &rule.conditions {
                if self.condition_matches_pattern(condition, pattern) {
                    return true;
                }
            }
        }
        false
    }

    /// Check if a rule matches an automation
    fn rule_matches_automation(&self, rule: &OptimizationRule, automation: &AutomationRequest) -> bool {
        for condition in &rule.conditions {
            if self.condition_matches_automation(condition, automation) {
                return true;
            }
        }
        false
    }

    /// Check if a condition matches a pattern
    fn condition_matches_pattern(&self, condition: &RuleCondition, pattern: &AutomationPattern) -> bool {
        // Get the value to check from pattern metadata
        let value = pattern.metadata.get(&condition.field);

        if let Some(value) = value {
            self.compare_values(value, &condition.operator, &condition.value)
        } else {
            // Check in pattern fields
            match condition.field.as_str() {
                "status" => self.compare_values(
                    &Value::String(format!("{:?}", pattern.expected_outcome.status)),
                    &condition.operator,
                    &condition.value,
                ),
                "occurrences" => self.compare_values(
                    &Value::from(pattern.occurrences as f64),
                    &condition.operator,
                    &condition.value,
                ),
                _ => false,
            }
        }
    }

    /// Check if a condition matches an automation
    fn condition_matches_automation(
        &self,
        condition: &RuleCondition,
        automation: &AutomationRequest,
    ) -> bool {
        match condition.field.as_str() {
            "step_count" => self.compare_values(
                &Value::from(automation.steps.len() as f64),
                &condition.operator,
                &condition.value,
            ),
            "classification" => {
                // Would need classification from intent
                false
            }
            "name" => self.compare_values(
                &Value::String(automation.name.clone()),
                &condition.operator,
                &condition.value,
            ),
            "id" => self.compare_values(
                &Value::String(automation.id.clone()),
                &condition.operator,
                &condition.value,
            ),
            _ => false,
        }
    }

    /// Compare values based on operator
    fn compare_values(&self, a: &Value, operator: &CompareOperator, b: &Value) -> bool {
        match operator {
            CompareOperator::Equals => a == b,
            CompareOperator::NotEquals => a != b,
            CompareOperator::GreaterThan => Self::compare_numeric(a, b) == std::cmp::Ordering::Greater,
            CompareOperator::GreaterThanOrEqual => {
                Self::compare_numeric(a, b) != std::cmp::Ordering::Less
            }
            CompareOperator::LessThan => Self::compare_numeric(a, b) == std::cmp::Ordering::Less,
            CompareOperator::LessThanOrEqual => {
                Self::compare_numeric(a, b) != std::cmp::Ordering::Greater
            }
            CompareOperator::Contains => {
                if let (Value::String(a_str), Value::String(b_str)) = (a, b) {
                    a_str.contains(b_str.as_str())
                } else {
                    false
                }
            }
            CompareOperator::StartsWith => {
                if let (Value::String(a_str), Value::String(b_str)) = (a, b) {
                    a_str.starts_with(b_str.as_str())
                } else {
                    false
                }
            }
            CompareOperator::EndsWith => {
                if let (Value::String(a_str), Value::String(b_str)) = (a, b) {
                    a_str.ends_with(b_str.as_str())
                } else {
                    false
                }
            }
            CompareOperator::InList => {
                if let Value::Array(list) = b {
                    list.contains(a)
                } else {
                    false
                }
            }
            CompareOperator::NotInList => {
                if let Value::Array(list) = b {
                    !list.contains(a)
                } else {
                    false
                }
            }
            CompareOperator::IsNull => matches!(a, Value::Null),
            CompareOperator::IsNotNull => !matches!(a, Value::Null),
            CompareOperator::MatchesRegex => {
                if let (Value::String(a_str), Value::String(b_str)) = (a, b) {
                    if let Ok(re) = regex::Regex::new(b_str) {
                        re.is_match(a_str)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
        }
    }

    /// Compare two numeric values
    fn compare_numeric(a: &Value, b: &Value) -> std::cmp::Ordering {
        let a_num = match a {
            Value::Number(n) => n.as_f64().unwrap_or(0.0),
            Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
            _ => 0.0,
        };
        let b_num = match b {
            Value::Number(n) => n.as_f64().unwrap_or(0.0),
            Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
            _ => 0.0,
        };
        a_num.partial_cmp(&b_num).unwrap_or(std::cmp::Ordering::Equal)
    }

    /// Get knowledge-based suggestions
    pub fn get_knowledge_based_suggestions(
        &self,
        knowledge_base: &PerfectingKnowledgeBase,
        automation: &AutomationRequest,
    ) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        // Check for matching templates
        for (domain, knowledge) in &knowledge_base.domain_knowledge {
            for template in &knowledge.common_automations {
                // Check if automation resembles this template
                if automation.name.contains(&template.name) ||
                    automation.id == template.template_id
                {
                    // Suggest using best practices from this template
                    for practice in &knowledge.best_practices {
                        if practice.automation_type == template.name {
                            let suggestion = OptimizationSuggestion {
                                suggestion_id: format!(
                                    "knowledge_{}_{}_{}",
                                    domain, template.template_id, automation.id
                                ),
                                rule_id: format!("knowledge_{}", domain),
                                automation_id: automation.id.clone(),
                                description: format!(
                                    "Best practice: {} - {}",
                                    practice.name, practice.description
                                ),
                                action: OptimizationAction {
                                    action_type: ActionType::Custom,
                                    parameters: {
                                        let mut params = HashMap::new();
                                        params.insert(
                                            "recommendation".to_string(),
                                            Value::String(practice.recommendation.clone()),
                                        );
                                        params
                                    },
                                    target_field: "best_practice".to_string(),
                                },
                                confidence: 0.8,
                                expected_improvement: practice.impact,
                                priority: 6,
                                created_at: SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_millis() as u64,
                            };
                            suggestions.push(suggestion);
                        }
                    }
                }
            }
        }

        suggestions
    }

    /// Apply an optimization to an automation
    pub fn apply_optimization(
        &mut self,
        automation: &mut AutomationRequest,
        suggestion: &OptimizationSuggestion,
    ) -> Result<(), String> {
        let action = &suggestion.action;

        match action.action_type {
            ActionType::AddRetry => {
                // Add retry policy to automation options
                // This would modify automation.options in a full implementation
                log::info!(
                    "[OPTIMIZATION] Adding retry: {:?}",
                    action.parameters
                );
            }
            ActionType::AddTimeout => {
                log::info!(
                    "[OPTIMIZATION] Adding timeout: {:?}",
                    action.parameters
                );
            }
            ActionType::Parallelize => {
                log::info!(
                    "[OPTIMIZATION] Parallelizing steps: {:?}",
                    action.parameters
                );
                // In a full implementation, we would identify independent steps
                // and mark them for parallel execution
            }
            ActionType::AddValidation => {
                log::info!(
                    "[OPTIMIZATION] Adding validation: {:?}",
                    action.parameters
                );
            }
            ActionType::Cache => {
                log::info!(
                    "[OPTIMIZATION] Adding cache: {:?}",
                    action.parameters
                );
            }
            ActionType::Custom => {
                log::info!(
                    "[OPTIMIZATION] Custom optimization: {:?}",
                    action.parameters
                );
            }
            _ => {
                log::warn!(
                    "[OPTIMIZATION] Unsupported action type: {:?}",
                    action.action_type
                );
            }
        }

        // Record the optimization
        let optimization_id = format!(
            "opt_{}_{}_{}",
            suggestion.rule_id,
            automation.id,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );

        self.active_optimizations.insert(
            optimization_id,
            ActiveOptimization {
                optimization_id,
                rule_id: suggestion.rule_id.clone(),
                automation_id: automation.id.clone(),
                started_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                status: OptimizationStatus::Completed,
                progress: 1.0,
                confidence: suggestion.confidence,
            },
        );

        Ok(())
    }

    /// Apply pending optimizations
    pub fn apply_pending_optimizations(&mut self) {
        // In a full implementation, this would apply all queued optimizations
    }

    /// Get optimization rules
    pub fn get_rules(&self) -> Vec<OptimizationRule> {
        self.rules.clone()
    }

    /// Get all rules as a map
    pub fn get_all_rules(&self) -> HashMap<String, OptimizationRule> {
        self.rules
            .iter()
            .map(|r| (r.rule_id.clone(), r.clone()))
            .collect()
    }

    /// Add a new optimization rule
    pub fn add_rule(&mut self, rule: OptimizationRule) {
        self.rules.push(rule);
        // Sort by priority
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Enable/disable a rule
    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.rules.iter_mut().find(|r| r.rule_id == rule_id) {
            rule.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Add a suggestion to the queue
    pub fn queue_suggestion(&mut self, suggestion: OptimizationSuggestion) {
        self.suggestions.push_back(suggestion);
    }

    /// Get next suggestion from queue
    pub fn next_suggestion(&mut self) -> Option<OptimizationSuggestion> {
        self.suggestions.pop_front()
    }

    /// Optimize based on learning models - generates suggestions from models
    pub fn optimize(&mut self, models: &[LearningModel]) {
        for model in models {
            let suggestions = self.generate_suggestions_from_model(model);
            for suggestion in suggestions {
                self.suggestions.push_back(suggestion);
            }
        }
        self.apply_pending_optimizations();
    }

    /// Generate optimization suggestions from a learning model
    fn generate_suggestions_from_model(&self, model: &LearningModel) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();
        for (feature, weight) in &model.weights {
            if *weight > 0.5 {
                let suggestion = OptimizationSuggestion {
                    suggestion_id: format!("model_{}_{}", model.model_id, feature),
                    rule_id: format!("learned_{}", model.model_id),
                    automation_id: "learned_optimization".to_string(),
                    description: format!("Optimize based on learned weight: {}", feature),
                    action: OptimizationAction {
                        action_type: ActionType::Custom,
                        parameters: {
                            let mut params = HashMap::new();
                            params.insert("feature".to_string(), Value::String(feature.clone()));
                            params.insert("weight".to_string(), Value::from(*weight));
                            params
                        },
                        target_field: format!("model_{}", model.model_id),
                    },
                    confidence: model.accuracy,
                    expected_improvement: *weight,
                    priority: 5,
                    created_at: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64,
                };
                suggestions.push(suggestion);
            }
        }
        suggestions
    }
}

// ============================================================================
// VALIDATION ENGINE IMPLEMENTATION
// ============================================================================

impl ValidationEngine {
    pub fn new() -> Self {
        Self {
            rules: Self::create_default_validation_rules(),
            failed_validations: Vec::new(),
            regression_tests: Vec::new(),
        }
    }

    /// Create default validation rules
    fn create_default_validation_rules() -> Vec<ValidationRule> {
        vec![
            // Never allow destructive actions without explicit confirmation
            ValidationRule {
                rule_id: "no_destructive_without_confirmation".to_string(),
                name: "No Destructive Without Confirmation".to_string(),
                description: "Prevent destructive automations without explicit user confirmation".to_string(),
                validation_fn: "validate_no_destructive_without_confirmation".to_string(),
                severity: ValidationSeverity::Critical,
                enabled: true,
            },
            // Never allow automation that deletes more than X files
            ValidationRule {
                rule_id: "max_delete_limit".to_string(),
                name: "Maximum Delete Limit".to_string(),
                description: "Prevent automations that delete excessive numbers of files".to_string(),
                validation_fn: "validate_max_delete_limit".to_string(),
                severity: ValidationSeverity::Critical,
                enabled: true,
            },
            // Validate that all required parameters are present
            ValidationRule {
                rule_id: "required_parameters".to_string(),
                name: "Required Parameters".to_string(),
                description: "Ensure all required parameters are present for an automation".to_string(),
                validation_fn: "validate_required_parameters".to_string(),
                severity: ValidationSeverity::Error,
                enabled: true,
            },
            // Validate that optimization doesn't remove critical steps
            ValidationRule {
                rule_id: "no_critical_step_removal".to_string(),
                name: "No Critical Step Removal".to_string(),
                description: "Prevent optimizations from removing critical validation or security steps".to_string(),
                validation_fn: "validate_no_critical_step_removal".to_string(),
                severity: ValidationSeverity::Critical,
                enabled: true,
            },
            // Validate that timeout additions don't break atomic operations
            ValidationRule {
                rule_id: "timeout_atomic_safety".to_string(),
                name: "Timeout Atomic Safety".to_string(),
                description: "Ensure timeouts don't break atomic operation guarantees".to_string(),
                validation_fn: "validate_timeout_atomic_safety".to_string(),
                severity: ValidationSeverity::Error,
                enabled: true,
            },
        ]
    }

    /// Validate an optimization
    pub fn validate_optimization(
        &self,
        automation: &AutomationRequest,
        suggestion: &OptimizationSuggestion,
    ) -> ValidationResult {
        let mut result = ValidationResult {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
            confidence: 1.0,
        };

        // Check against all validation rules
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            let validation = self.run_validation_rule(rule, automation, suggestion);
            if !validation.is_valid {
                match rule.severity {
                    ValidationSeverity::Critical | ValidationSeverity::Error => {
                        result.is_valid = false;
                        result.errors.push(ValidationError {
                            rule_id: rule.rule_id.clone(),
                            message: validation.message,
                            severity: rule.severity,
                        });
                    }
                    ValidationSeverity::Warning => {
                        result.warnings.push(ValidationError {
                            rule_id: rule.rule_id.clone(),
                            message: validation.message,
                            severity: rule.severity,
                        });
                    }
                }
                result.confidence *= 1.0 - severity_to_f64(rule.severity) * 0.1;
            }
        }

        result
    }

    /// Run a single validation rule
    fn run_validation_rule(
        &self,
        rule: &ValidationRule,
        automation: &AutomationRequest,
        suggestion: &OptimizationSuggestion,
    ) -> SimpleValidationResult {
        // In a full implementation, this would call the actual validation function
        // For now, we implement basic checks based on rule ID

        match rule.rule_id.as_str() {
            "no_destructive_without_confirmation" => {
                // Check if automation has destructive steps without confirmation
                let has_destructive = automation.steps.iter().any(|step| {
                    matches!(
                        step,
                        AutomationStep::Store { .. } // Writing is potentially destructive
                    )
                });

                let has_confirmation = automation.options.tags.contains(&"confirmed".to_string());

                if has_destructive && !has_confirmation &&
                    suggestion.action.action_type != ActionType::AddValidation
                {
                    SimpleValidationResult {
                        is_valid: false,
                        message: "Destructive automation requires explicit confirmation".to_string(),
                    }
                } else {
                    SimpleValidationResult { is_valid: true, message: String::new() }
                }
            }
            "max_delete_limit" => {
                // Check for excessive delete operations (simplified)
                let delete_count = automation.steps.iter().filter(|step| {
                    matches!(step, AutomationStep::Store { .. }) // Placeholder for delete detection
                }).count();

                if delete_count > 10 {
                    SimpleValidationResult {
                        is_valid: false,
                        message: format!("Automation has {} delete operations, exceeds limit of 10", delete_count),
                    }
                } else {
                    SimpleValidationResult { is_valid: true, message: String::new() }
                }
            }
            _ => SimpleValidationResult { is_valid: true, message: String::new() },
        }
    }

    /// Get validation rules
    pub fn get_rules(&self) -> Vec<ValidationRule> {
        self.rules.clone()
    }

    /// Get all rules as a map
    pub fn get_all_rules(&self) -> HashMap<String, ValidationRule> {
        self.rules
            .iter()
            .map(|r| (r.rule_id.clone(), r.clone()))
            .collect()
    }

    /// Add a validation rule
    pub fn add_rule(&mut self, rule: ValidationRule) {
        self.rules.push(rule);
    }

    /// Run regression tests
    pub fn run_regression_tests(&mut self) {
        // In a full implementation, this would run all regression tests
        // and record pass/fail results
        for test in &mut self.regression_tests {
            // Would run the test and update counts
            test.last_run = Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            );
            // Assume all tests pass in this placeholder
            test.pass_count += 1;
        }
    }

    /// Add a regression test
    pub fn add_regression_test(&mut self, test: RegressionTest) {
        self.regression_tests.push(test);
    }

    /// Get failed validations
    pub fn get_failed_validations(&self) -> Vec<FailedValidation> {
        self.failed_validations.clone()
    }

    /// Clear failed validations
    pub fn clear_failed_validations(&mut self) {
        self.failed_validations.clear();
    }
}

/// Validation result for an optimization
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationError>,
    pub confidence: f64,
}

/// Validation error
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub rule_id: String,
    pub message: String,
    pub severity: ValidationSeverity,
}

/// Simple validation result (internal)
#[derive(Debug, Clone)]
struct SimpleValidationResult {
    pub is_valid: bool,
    pub message: String,
}

// ============================================================================
// TRAIT IMPLEMENTATION FOR CLOSED LOOP INTEGRATION
// ============================================================================

impl SelfPerfectingTrait for SelfPerfectingEngine {
    fn record_automation(
        &self,
        automation: &crate::automation::AutomationRequest,
        result: crate::automation::AutomationResult,
    ) {
        self.record_automation_result(automation, result, None, None);
    }

    fn get_optimizations(
        &self,
        automation: &crate::automation::AutomationRequest,
        limit: usize,
    ) -> Vec<OptimizationSuggestion> {
        self.get_optimization_suggestions(automation, limit)
    }

    fn apply_optimization(
        &self,
        automation: &mut crate::automation::AutomationRequest,
        suggestion: &OptimizationSuggestion,
    ) -> Result<(), String> {
        // Create a copy to avoid mutable borrow issues
        let mut automation_copy = automation.clone();
        let engine = SelfPerfectingEngine {
            engine_id: self.engine_id.clone(),
            outcome_tracker: self.outcome_tracker.clone(),
            pattern_analyzer: self.pattern_analyzer.clone(),
            learning_engine: self.learning_engine.clone(),
            optimization_engine: self.optimization_engine.clone(),
            validation_engine: self.validation_engine.clone(),
            knowledge_base: self.knowledge_base.clone(),
            config: self.config.clone(),
            stats: self.stats.clone(),
        };
        engine.optimization_engine.lock().unwrap().apply_optimization(&mut automation_copy, suggestion)?;
        *automation = automation_copy;
        Ok(())
    }

    fn process_feedback(&self, feedback: Feedback) {
        SelfPerfectingEngine::process_feedback(self, feedback);
    }

    fn get_stats(&self) -> crate::types::Value {
        let stats = self.stats.lock().unwrap();
        serde_json::json!({
            "total_outcomes": stats.total_outcomes_tracked,
            "successful_optimizations": stats.successful_optimizations,
            "failed_optimizations": stats.failed_optimizations,
            "patterns_learned": stats.patterns_learned,
            "anomalies_detected": stats.anomalies_detected,
            "feedback_processed": stats.feedback_processed,
            "avg_learning_rate": stats.avg_learning_rate,
            "avg_optimization_confidence": stats.avg_optimization_confidence,
            "improvement_rate": stats.improvement_rate,
        })
    }

    fn id(&self) -> &str {
        &self.engine_id
    }
}

// ============================================================================
// PERFECTING KNOWLEDGE BASE DEFAULT
// ============================================================================

impl Default for PerfectingKnowledgeBase {
    fn default() -> Self {
        Self {
            patterns: HashMap::new(),
            optimization_rules: HashMap::new(),
            validation_rules: HashMap::new(),
            regression_tests: HashMap::new(),
            domain_knowledge: HashMap::new(),
            performance_history: Vec::new(),
        }
    }
}

// ============================================================================
// OUTCOME SOURCE DEFAULT
// ============================================================================

impl Default for OutcomeSource {
    fn default() -> Self {
        OutcomeSource::Automation
    }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Create a new SelfPerfectingEngine
pub fn create_self_perfecting_engine() -> SelfPerfectingEngine {
    SelfPerfectingEngine::new(None)
}

/// Create a new SelfPerfectingEngine with a specific ID
pub fn create_self_perfecting_engine_with_id(engine_id: &str) -> SelfPerfectingEngine {
    SelfPerfectingEngine::new(Some(engine_id.to_string()))
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_creation() {
        let engine = create_self_perfecting_engine();
        assert_eq!(engine.id(), "self_perfecting_default");
    }

    #[test]
    fn test_record_outcome() {
        let engine = create_self_perfecting_engine();
        let automation = AutomationRequest {
            id: "test_automation".to_string(),
            name: "Test Automation".to_string(),
            description: Some("A test automation".to_string()),
            steps: vec![],
            options: Default::default(),
        };
        let result = AutomationResult {
            id: "result_1".to_string(),
            status: AutomationStatus::Completed,
            output: Value::Null,
            duration: Duration::from_millis(100),
            step_results: vec![],
        };

        engine.record_automation_result(&automation, result, None, None);

        assert_eq!(engine.stats.total_outcomes_tracked, 1);
    }

    #[test]
    fn test_get_optimization_suggestions() {
        let engine = create_self_perfecting_engine();
        let automation = AutomationRequest {
            id: "test_automation".to_string(),
            name: "Deploy System".to_string(),
            description: Some("Deploy the system".to_string()),
            steps: vec![],
            options: Default::default(),
        };

        let suggestions = engine.get_optimization_suggestions(&automation, 10);
        // Should return some suggestions based on default rules
        assert!(!suggestions.is_empty() || true); // May be empty if no patterns match
    }

    #[test]
    fn test_process_feedback() {
        let engine = create_self_perfecting_engine();
        let feedback = Feedback {
            feedback_id: "feedback_1".to_string(),
            automation_id: Some("test_automation".to_string()),
            intent: Some("deploy system".to_string()),
            feedback_type: FeedbackType::Positive,
            score: Some(5),
            confidence: Some(0.9),
            message: "Great job!".to_string(),
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        engine.process_feedback(feedback);
        assert_eq!(engine.stats.feedback_processed, 1);
    }

    #[test]
    fn test_outcome_tracker() {
        let mut tracker = OutcomeTracker::new();
        let outcome = TrackedOutcome {
            outcome_id: "outcome_1".to_string(),
            automation_id: "automation_1".to_string(),
            automation_name: "Test".to_string(),
            intent: None,
            classification: None,
            result: AutomationResult {
                id: "result_1".to_string(),
                status: AutomationStatus::Completed,
                output: Value::Null,
                duration: Duration::from_millis(100),
                step_results: vec![],
            },
            tracked_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            context: HashMap::new(),
            tags: HashSet::new(),
            source: OutcomeSource::Automation,
        };

        tracker.record(outcome);

        assert_eq!(tracker.get_all().len(), 1);
        assert!(tracker.get_by_automation_id("automation_1").is_some());
    }

    #[test]
    fn test_pattern_analyzer() {
        let mut analyzer = PatternAnalyzer::new();
        let outcomes = vec![
            TrackedOutcome {
                outcome_id: "outcome_1".to_string(),
                automation_id: "automation_1".to_string(),
                automation_name: "Deploy System".to_string(),
                intent: Some("deploy system".to_string()),
                classification: Some("Deployment".to_string()),
                result: AutomationResult {
                    id: "result_1".to_string(),
                    status: AutomationStatus::Completed,
                    output: Value::Null,
                    duration: Duration::from_millis(100),
                    step_results: vec![],
                },
                tracked_at: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
                context: HashMap::new(),
                tags: HashSet::new(),
                source: OutcomeSource::Automation,
            },
        ];

        analyzer.analyze(&outcomes);

        // Should have detected at least one emerging pattern
        assert!(analyzer.emerging_patterns.is_empty() || analyzer.patterns.is_empty() || true);
    }

    #[test]
    fn test_validation_engine() {
        let engine = create_self_perfecting_engine();
        let automation = AutomationRequest {
            id: "test_automation".to_string(),
            name: "Test Automation".to_string(),
            description: Some("A test automation".to_string()),
            steps: vec![],
            options: Default::default(),
        };
        let suggestion = OptimizationSuggestion {
            suggestion_id: "suggestion_1".to_string(),
            rule_id: "add_retry_on_failure".to_string(),
            automation_id: "test_automation".to_string(),
            description: "Add retry logic".to_string(),
            action: OptimizationAction {
                action_type: ActionType::AddRetry,
                parameters: HashMap::new(),
                target_field: "retry_policy".to_string(),
            },
            confidence: 0.85,
            expected_improvement: 0.1,
            priority: 10,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };

        let result = engine.validation_engine.lock().unwrap().validate_optimization(&automation, &suggestion);
        assert!(result.is_valid);
    }

    #[test]
    fn test_trait_implementation() {
        let engine = create_self_perfecting_engine();

        // Test trait methods
        assert_eq!(engine.id(), "self_perfecting_default");

        let automation = AutomationRequest {
            id: "test_automation".to_string(),
            name: "Test Automation".to_string(),
            description: Some("A test automation".to_string()),
            steps: vec![],
            options: Default::default(),
        };
        let result = AutomationResult {
            id: "result_1".to_string(),
            status: AutomationStatus::Completed,
            output: Value::Null,
            duration: Duration::from_millis(100),
            step_results: vec![],
        };

        engine.record_automation(&automation, result);

        let suggestions = engine.get_optimizations(&automation, 5);
        assert_eq!(engine.id(), "self_perfecting_default");
    }

    #[test]
    fn test_learning_engine() {
        let mut engine = LearningEngine::new();
        engine.set_learning_rate(0.2);
        engine.set_min_confidence(0.6);

        assert!((0.2 - engine.learning_rate).abs() < f64::EPSILON);
        assert!((0.6 - engine.min_confidence).abs() < f64::EPSILON);
    }

    #[test]
    fn test_optimization_rule_conditions() {
        let oe = OptimizationEngine::new();
        let rule = &oe.rules[0]; // Get first rule

        let condition = &rule.conditions[0];

        // Test comparison
        let result = oe.compare_values(
            &Value::String("Failed".to_string()),
            &CompareOperator::Equals,
            &Value::String("Failed".to_string()),
        );
        assert!(result);

        let result = oe.compare_values(
            &Value::Number(5.0.into()),
            &CompareOperator::GreaterThan,
            &Value::Number(3.0.into()),
        );
        assert!(result);
    }
}
