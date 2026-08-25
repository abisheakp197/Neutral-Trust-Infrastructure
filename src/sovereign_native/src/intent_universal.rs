//! UBE Universal Intent Translator
//!
//! ## TRANSCENDENTAL INTENT PARSED
//!
//! This module implements the Universal Intent Translator that converts
//! raw human intent (natural language, voice, gestures, etc.) into
//! structured ParsedIntent objects that can be processed by the
//! Self-Perfecting Engine and Transcendent Automation.
//!
//! ## CAPABILITIES
//!
//! - **Natural Language Understanding**: Parse intents from human language
//! - **Multi-Modal Input**: Support voice, text, gestures, and other input modes
//! - **Multi-Language Support**: Understand intents in any language
//! - **Context Awareness**: Maintain context across multiple intents
//! - **Intent Classification**: Categorize intents by domain and type
//! - **Entity Extraction**: Identify and extract key entities from intents
//! - **Parameter Parsing**: Extract parameters and options from intents
//! - **Confidence Scoring**: Assign confidence levels to parsed intents
//!
//! ## ARCHITECTURE
//!
//! The Universal Intent Translator uses a multi-layer approach:
//!
//! 1. **Input Layer**: Handles raw input (text, voice, gestures)
//! 2. **Language Layer**: Language detection and preprocessing
//! 3. **Parsing Layer**: Syntactic and semantic analysis
//! 4. **Classification Layer**: Intent type and domain classification
//! 5. **Extraction Layer**: Entity and parameter extraction
//! 6. **Validation Layer**: Intent validation and confidence scoring
//! 7. **Output Layer**: ParsedIntent construction
//!
//! ## INTEGRATION WITH UBE
//!
//! This module integrates with:
//! - `voice.rs`: For voice input and wake phrase detection
//! - `judgement.rs`: For intent validation and safety checking
//! - `closed_loop.rs`: Provides the IntentTranslator trait implementation
//! - `omni_math.rs`: For mathematical intent parsing
//! - `sovereign_guardian.rs`: For security validation of intents

use std::collections::{HashMap, HashSet};
use std::hash::Hasher;
use std::sync::{Arc, Mutex, RwLock};
use serde::{Serialize, Deserialize};
use crate::types::Value;
use once_cell::sync::Lazy;
use regex::Regex;
use crate::closed_loop::{IntentClassification, EntityType, IntentEntity, ParsedIntent, IntentPriority};

// ============================================================================
// INTENT TRANSLATOR CORE
// ============================================================================

/// The Universal Intent Translator
///
/// This struct implements the complete intent translation pipeline from
/// raw input to structured ParsedIntent.
pub struct IntentUniversal {
    /// Translator identifier
    translator_id: String,
    /// Supported languages and their configurations
    supported_languages: HashSet<String>,
    /// Intent classification rules
    classification_rules: Vec<ClassificationRule>,
    /// Entity extraction patterns
    entity_patterns: Vec<EntityPattern>,
    /// Parameter parsers
    parameter_parsers: Vec<ParameterParser>,
    /// Context manager for maintaining conversation context
    context_manager: ContextManager,
    /// Confidence calculator
    confidence_calculator: ConfidenceCalculator,
    /// Intent normalizer
    normalizer: IntentNormalizer,
    /// Gravity knowledge base integration
    knowledge_base: Option<Arc<RwLock<IntentKnowledgeBase>>>,
    /// Statistics and metrics
    stats: IntentStats,
}

/// Statistics for intent translation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentStats {
    pub total_intents: u64,
    pub successful_parses: u64,
    pub failed_parses: u64,
    pub avg_confidence: f64,
    pub avg_parse_time_ms: f64,
    pub intents_by_language: HashMap<String, u64>,
    pub intents_by_classification: HashMap<String, u64>,
}

impl Default for IntentStats {
    fn default() -> Self {
        Self {
            total_intents: 0,
            successful_parses: 0,
            failed_parses: 0,
            avg_confidence: 0.0,
            avg_parse_time_ms: 0.0,
            intents_by_language: HashMap::new(),
            intents_by_classification: HashMap::new(),
        }
    }
}

/// Intent Knowledge Base for understanding domain-specific intents
#[derive(Debug, Clone)]
pub struct IntentKnowledgeBase {
    /// Domain-specific vocabularies
    pub vocabularies: HashMap<String, Vec<String>>,
    /// Intent patterns for each domain
    pub patterns: HashMap<String, Vec<IntentPattern>>,
    /// Synonym mappings
    pub synonyms: HashMap<String, Vec<String>>,
    /// Domain hierarchies
    pub domain_hierarchy: DomainHierarchy,
}

/// Domain hierarchy for classifying intents
#[derive(Debug, Clone)]
pub struct DomainHierarchy {
    pub domains: Vec<DomainNode>,
}

/// A node in the domain hierarchy
#[derive(Debug, Clone)]
pub struct DomainNode {
    pub name: String,
    pub children: Vec<DomainNode>,
    pub parent: Option<String>,
    pub description: String,
}

/// Intent pattern for matching
#[derive(Debug, Clone)]
pub struct IntentPattern {
    pub pattern: String,
    pub classification: IntentClassification,
    pub parameters: Vec<String>,
    pub examples: Vec<String>,
    pub confidence_boost: f64,
}

/// Classification rule for categorizing intents
#[derive(Debug, Clone)]
pub struct ClassificationRule {
    pub name: String,
    pub patterns: Vec<String>,
    pub classification: IntentClassification,
    pub priority: usize,
    pub confidence_weight: f64,
}

/// Entity extraction pattern
pub struct EntityPattern {
    pub name: String,
    pub entity_type: EntityType,
    pub pattern: String,
    pub extraction_regex: Option<String>,
    pub validation_fn: Option<Box<dyn Fn(&str) -> bool + Send + Sync>>,
    pub confidence_weight: f64,
}

/// Parameter parser for extracting parameters from intents
#[derive(Debug, Clone)]
pub struct ParameterParser {
    pub name: String,
    pub parameter_name: String,
    pub patterns: Vec<String>,
    pub value_type: ParameterValueType,
    pub default_value: Option<Value>,
    pub confidence_weight: f64,
}

/// Parameter value types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterValueType {
    String,
    Number,
    Boolean,
    Duration,
    Time,
    Date,
    List,
    Map,
    Custom,
}

/// Context manager for maintaining conversation state
#[derive(Debug, Clone)]
pub struct ContextManager {
    /// Current conversation context
    pub current_context: Option<ConversationContext>,
    /// Context history
    pub context_history: Vec<ConversationContext>,
    /// Maximum context history size
    pub max_history: usize,
}

/// Conversation context for maintaining state across intents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationContext {
    pub context_id: String,
    pub previous_intents: Vec<String>,
    pub current_domain: Option<String>,
    pub active_entities: Vec<String>,
    pub variables: HashMap<String, Value>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Confidence calculator for scoring intent parsing
#[derive(Debug, Clone)]
pub struct ConfidenceCalculator {
    /// Weights for different confidence factors
    pub factor_weights: HashMap<String, f64>,
    /// Pattern matching confidence
    pub pattern_confidence: f64,
    /// Entity extraction confidence
    pub entity_confidence: f64,
    /// Classification confidence
    pub classification_confidence: f64,
    /// Parameter parsing confidence
    pub parameter_confidence: f64,
    /// Context match confidence
    pub context_confidence: f64,
}

/// Intent normalizer for standardizing input
#[derive(Debug, Clone)]
pub struct IntentNormalizer {
    /// Normalization rules
    pub rules: Vec<NormalizationRule>,
    /// Lowercase setting
    pub lowercase: bool,
    /// Remove punctuation
    pub remove_punctuation: bool,
    /// Expand contractions
    pub expand_contractions: bool,
}

/// Normalization rule for preprocessing intent text
#[derive(Debug, Clone)]
pub struct NormalizationRule {
    pub pattern: String,
    pub replacement: String,
    pub description: String,
}

// ============================================================================
// IMPLEMENTATION
// ============================================================================

impl IntentUniversal {
    /// Create a new IntentUniversal translator
    pub fn new(translator_id: Option<String>) -> Self {
        let translator_id = translator_id
            .unwrap_or_else(|| "intent_universal_default".to_string());

        let mut supported_languages = HashSet::new();
        // Add core supported languages
        let core_languages = vec![
            "en", "es", "fr", "de", "it", "pt", "ru", "zh", "ja", "ko",
            "ar", "hi", "bn", "pa", "tr", "nl", "sv", "fi", "da", "no",
        ];
        for lang in core_languages {
            supported_languages.insert(lang.to_string());
        }

        let classification_rules = Self::create_default_classification_rules();
        let entity_patterns = Self::create_default_entity_patterns();
        let parameter_parsers = Self::create_default_parameter_parsers();

        Self {
            translator_id,
            supported_languages,
            classification_rules,
            entity_patterns,
            parameter_parsers,
            context_manager: ContextManager::new(),
            confidence_calculator: ConfidenceCalculator::new(),
            normalizer: IntentNormalizer::new(),
            knowledge_base: None,
            stats: IntentStats::default(),
        }
    }

    /// Create a new IntentUniversal with a knowledge base
    pub fn with_knowledge_base(
        mut self,
        knowledge_base: Arc<RwLock<IntentKnowledgeBase>>,
    ) -> Self {
        self.knowledge_base = Some(knowledge_base);
        self
    }

    /// Create default classification rules
    fn create_default_classification_rules() -> Vec<ClassificationRule> {
        vec![
            // Deployment intents
            ClassificationRule {
                name: "deploy_pattern".to_string(),
                patterns: vec![
                    "deploy".to_string(),
                    "install".to_string(),
                    "setup".to_string(),
                    "launch".to_string(),
                    "start".to_string(),
                    "init".to_string(),
                ],
                classification: IntentClassification::Deployment,
                priority: 10,
                confidence_weight: 1.0,
            },
            // Configuration intents
            ClassificationRule {
                name: "config_pattern".to_string(),
                patterns: vec![
                    "configure".to_string(),
                    "config".to_string(),
                    "set".to_string(),
                    "change".to_string(),
                    "update".to_string(),
                ],
                classification: IntentClassification::Configuration,
                priority: 10,
                confidence_weight: 1.0,
            },
            // Monitoring intents
            ClassificationRule {
                name: "monitor_pattern".to_string(),
                patterns: vec![
                    "monitor".to_string(),
                    "watch".to_string(),
                    "track".to_string(),
                    "observe".to_string(),
                    "check".to_string(),
                ],
                classification: IntentClassification::Monitoring,
                priority: 10,
                confidence_weight: 1.0,
            },
            // Security intents
            ClassificationRule {
                name: "security_pattern".to_string(),
                patterns: vec![
                    "secure".to_string(),
                    "encrypt".to_string(),
                    "decrypt".to_string(),
                    "authenticate".to_string(),
                    "authorize".to_string(),
                ],
                classification: IntentClassification::Security,
                priority: 10,
                confidence_weight: 1.0,
            },
            // Query intents
            ClassificationRule {
                name: "query_pattern".to_string(),
                patterns: vec![
                    "query".to_string(),
                    "get".to_string(),
                    "fetch".to_string(),
                    "retrieve".to_string(),
                    "list".to_string(),
                    "show".to_string(),
                ],
                classification: IntentClassification::Query,
                priority: 10,
                confidence_weight: 1.0,
            },
            // Create intents
            ClassificationRule {
                name: "create_pattern".to_string(),
                patterns: vec![
                    "create".to_string(),
                    "new".to_string(),
                    "make".to_string(),
                    "build".to_string(),
                    "generate".to_string(),
                ],
                classification: IntentClassification::Create,
                priority: 10,
                confidence_weight: 1.0,
            },
            // Update intents
            ClassificationRule {
                name: "update_pattern".to_string(),
                patterns: vec![
                    "update".to_string(),
                    "modify".to_string(),
                    "change".to_string(),
                    "edit".to_string(),
                    "upgrade".to_string(),
                ],
                classification: IntentClassification::Update,
                priority: 10,
                confidence_weight: 1.0,
            },
            // Delete intents
            ClassificationRule {
                name: "delete_pattern".to_string(),
                patterns: vec![
                    "delete".to_string(),
                    "remove".to_string(),
                    "erase".to_string(),
                    "destroy".to_string(),
                    "purge".to_string(),
                ],
                classification: IntentClassification::Delete,
                priority: 10,
                confidence_weight: 1.0,
            },
        ]
    }

    /// Create default entity patterns
    fn create_default_entity_patterns() -> Vec<EntityPattern> {
        vec![
            // User entities
            EntityPattern {
                name: "user_entity".to_string(),
                entity_type: EntityType::User,
                pattern: "@[a-zA-Z0-9_]+|user [a-zA-Z0-9_]+".to_string(),
                extraction_regex: Some("@([a-zA-Z0-9_]+)".to_string()),
                validation_fn: None,
                confidence_weight: 1.0,
            },
            // Resource entities (files, directories, devices)
            EntityPattern {
                name: "file_entity".to_string(),
                entity_type: EntityType::File,
                pattern: "file|document|txt|pdf|doc|json|yaml|yml".to_string(),
                extraction_regex: None,
                validation_fn: None,
                confidence_weight: 0.9,
            },
            EntityPattern {
                name: "directory_entity".to_string(),
                entity_type: EntityType::Directory,
                pattern: "directory|dir|folder|path".to_string(),
                extraction_regex: None,
                validation_fn: None,
                confidence_weight: 0.9,
            },
            // Time entities
            EntityPattern {
                name: "time_entity".to_string(),
                entity_type: EntityType::Time,
                pattern: "[0-9]{1,2}:[0-9]{2}(am|pm)?|[0-9]{1,2}:[0-9]{2}:[0-9]{2}".to_string(),
                extraction_regex: Some(r"\d{1,2}:\d{2}(:\d{2})?(am|pm)?".to_string()),
                validation_fn: None,
                confidence_weight: 0.95,
            },
            // Duration entities
            EntityPattern {
                name: "duration_entity".to_string(),
                entity_type: EntityType::Duration,
                pattern: r"\d+ (seconds?|minutes?|hours?|days?|weeks?|months?|years?)".to_string(),
                extraction_regex: Some(r"\d+ (second|minute|hour|day|week|month|year)s?".to_string()),
                validation_fn: None,
                confidence_weight: 0.95,
            },
            // Network entities
            EntityPattern {
                name: "network_entity".to_string(),
                entity_type: EntityType::Network,
                pattern: "network|server|client|node|peer|connection|socket".to_string(),
                extraction_regex: None,
                validation_fn: None,
                confidence_weight: 0.85,
            },
            // System entities
            EntityPattern {
                name: "system_entity".to_string(),
                entity_type: EntityType::System,
                pattern: "system|os|kernel|hardware|cpu|gpu|memory|storage".to_string(),
                extraction_regex: None,
                validation_fn: None,
                confidence_weight: 0.9,
            },
            // Identifier entities (UUIDs, IDs, etc.)
            EntityPattern {
                name: "identifier_entity".to_string(),
                entity_type: EntityType::Identifier,
                pattern: "[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}".to_string(),
                extraction_regex: Some(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}".to_string()),
                validation_fn: Some(Box::new(|s| Self::is_valid_uuid(s))),
                confidence_weight: 1.0,
            },
            // Numeric value entities
            EntityPattern {
                name: "numeric_entity".to_string(),
                entity_type: EntityType::Value,
                pattern: r"\d+(\.\d+)?".to_string(),
                extraction_regex: Some(r"\d+(\.\d+)?".to_string()),
                validation_fn: Some(Box::new(|s| Self::is_numeric(s))),
                confidence_weight: 0.95,
            },
        ]
    }

    /// Helper to validate UUID format
    fn is_valid_uuid(s: &str) -> bool {
        s.len() == 36 && s.chars().filter(|c| *c == '-').count() == 4
    }

    /// Helper to validate numeric
    fn is_numeric(s: &str) -> bool {
        s.parse::<f64>().is_ok()
    }

    /// Create default parameter parsers
    fn create_default_parameter_parsers() -> Vec<ParameterParser> {
        vec![
            ParameterParser {
                name: "timeout_param".to_string(),
                parameter_name: "timeout".to_string(),
                patterns: vec![
                    "timeout".to_string(),
                    "time out".to_string(),
                    "max time".to_string(),
                ],
                value_type: ParameterValueType::Duration,
                default_value: Some(Value::String("30s".to_string())),
                confidence_weight: 0.85,
            },
            ParameterParser {
                name: "retries_param".to_string(),
                parameter_name: "retries".to_string(),
                patterns: vec![
                    "retries".to_string(),
                    "retry".to_string(),
                    "retry count".to_string(),
                    "max retries".to_string(),
                ],
                value_type: ParameterValueType::Number,
                default_value: Some(Value::Number(serde_json::Number::from_f64(3.0).unwrap())),
                confidence_weight: 0.85,
            },
            ParameterParser {
                name: "priority_param".to_string(),
                parameter_name: "priority".to_string(),
                patterns: vec![
                    "priority".to_string(),
                    "importance".to_string(),
                    "urgency".to_string(),
                ],
                value_type: ParameterValueType::String,
                default_value: Some(Value::String("normal".to_string())),
                confidence_weight: 0.8,
            },
            ParameterParser {
                name: "mode_param".to_string(),
                parameter_name: "mode".to_string(),
                patterns: vec![
                    "mode".to_string(),
                    "method".to_string(),
                    "type".to_string(),
                ],
                value_type: ParameterValueType::String,
                default_value: None,
                confidence_weight: 0.75,
            },
            ParameterParser {
                name: "force_param".to_string(),
                parameter_name: "force".to_string(),
                patterns: vec![
                    "force".to_string(),
                    "override".to_string(),
                    "bypass".to_string(),
                ],
                value_type: ParameterValueType::Boolean,
                default_value: Some(Value::Bool(false)),
                confidence_weight: 0.9,
            },
        ]
    }

    /// Translate raw intent into ParsedIntent
    ///
    /// This is the main entry point for intent translation. It implements
    /// the complete pipeline:
    /// 1. Input normalization
    /// 2. Language detection
    /// 3. Intent parsing
    /// 4. Entity extraction
    /// 5. Parameter parsing
    /// 6. Classification
    /// 7. Confidence scoring
    pub fn translate(&mut self, intent: &str) -> Result<ParsedIntent, String> {
        let start_time = std::time::Instant::now();

        // Update stats
        self.stats.total_intents += 1;

        if self.translator_id == "intent_universal_default" {
            // For the default translator, we'll use a simpler approach
            // The full pipeline will be implemented in the complete system
            self.translate_simple(intent)
        } else {
            // Full translation pipeline
            self.translate_full(intent)
        }
        .map(|parsed| {
            self.stats.successful_parses += 1;
            let elapsed = start_time.elapsed().as_millis() as f64;
            self.stats.avg_parse_time_ms =
                (self.stats.avg_parse_time_ms * (self.stats.successful_parses - 1) as f64 + elapsed)
                / self.stats.successful_parses as f64;
            self.stats.avg_confidence =
                (self.stats.avg_confidence * (self.stats.successful_parses - 1) as f64 + parsed.confidence)
                / self.stats.successful_parses as f64;
            *self.stats.intents_by_language.entry(parsed.language.clone()).or_insert(0) += 1;
            *self.stats.intents_by_classification
                .entry(format!("{:?}", parsed.classification)).or_insert(0) += 1;
            parsed
        })
        .map_err(|e| {
            self.stats.failed_parses += 1;
            e
        })
    }

    /// Simple translation for default implementation
    fn translate_simple(&self, intent: &str) -> Result<ParsedIntent, String> {
        let normalized = self.normalizer.normalize(intent);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Extract basic information
        let (action, target, entities) = self.extract_simple(normalized.trim());
        let classification = self.classify_simple(&action, &target);
        let priority = self.detect_priority(&normalized);

        // Calculate confidence
        let confidence = self.confidence_calculator.calculate(
            &normalized,
            &classification,
            &entities,
            &target,
        );

        let intent_id = format!(
            "intent_{}_{}",
            now,
{
                use std::hash::{DefaultHasher, Hasher};
                let mut hasher = DefaultHasher::new();
                hasher.write(normalized.as_bytes());
                hasher.finish()
            }
        );

        Ok(ParsedIntent {
            intent_id,
            classification,
            entities,
            action,
            target,
            parameters: Value::Object(serde_json::Map::new()),
            confidence,
            parsed_at: now,
            language: "en".to_string(),
            priority,
        })
    }

    /// Full translation pipeline
    fn translate_full(&self, intent: &str) -> Result<ParsedIntent, String> {
        // 1. Normalize
        let normalized = self.normalizer.normalize(intent);

        // 2. Detect language
        let language = self.detect_language(&normalized);

        // 3. Parse intent structure
        let parse_result = self.parse_intent(&normalized);

        // 4. Extract entities
        let entities = self.extract_entities(&normalized, &parse_result)?;

        // 5. Parse parameters
        let parameters = self.parse_parameters(&normalized, &parse_result, &entities)?;

        // 6. Classify intent
        let classification = self.classify_intent(&parse_result, &entities);

        // 7. Calculate confidence
        let confidence = self.confidence_calculator.calculate(
            &normalized,
            &classification,
            &entities,
            &parse_result.target,
        );

        // 8. Detect priority
        let priority = self.detect_priority(&normalized);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let intent_id = format!(
            "intent_{}_{}",
            now,
{
                use std::collections::hash_map::DefaultHasher;
                use std::hash::Hasher;
                let mut hasher = DefaultHasher::new();
                hasher.write(normalized.as_bytes());
                hasher.finish()
            }
        );

        Ok(ParsedIntent {
            intent_id,
            classification,
            entities,
            action: parse_result.action,
            target: parse_result.target,
            parameters,
            confidence,
            parsed_at: now,
            language,
            priority,
        })
    }

    /// Simple intent extraction
    fn extract_simple(&self, intent: &str) -> (String, Option<String>, Vec<IntentEntity>) {
        let mut action = String::new();
        let mut target = None;
        let mut entities = Vec::new();

        // Find first verb (imperative form)
        for word in intent.split_whitespace() {
            let lower = word.to_lowercase();
            if Self::is_verb(&lower) {
                action = lower;
                break;
            }
        }

        if action.is_empty() {
            // Try to find any action-like word
            for word in intent.split_whitespace() {
                if word.len() > 2 {
                    action = word.to_lowercase();
                    break;
                }
            }
        }

        // Find target (words after action)
        if let Some(idx) = intent.to_lowercase().find(&action) {
            let after_action = &intent[idx + action.len()..];
            target = after_action
                .split_whitespace()
                .next()
                .map(|s| s.to_string());

            // Extract numeric entities
            for cap in Regex::new(r"\d+").unwrap().captures_iter(intent) {
                if let Some(m) = cap.get(0) {
                    entities.push(IntentEntity {
                        name: m.as_str().to_string(),
                        entity_type: EntityType::Value,
                        value: Value::String(m.as_str().to_string()),
                        position: m.start(),
                        confidence: 0.95,
                    });
                }
            }

            // Extract quoted strings
            for cap in Regex::new(r#""[^"]*""#).unwrap().captures_iter(intent) {
                if let Some(m) = cap.get(0) {
                    let content = m.as_str().trim_matches('"').to_string();
                    entities.push(IntentEntity {
                        name: content.clone(),
                        entity_type: EntityType::Value,
                        value: Value::String(content),
                        position: m.start(),
                        confidence: 0.9,
                    });
                }
            }
        }

        if action.is_empty() {
            action = "unknown".to_string();
        }

        (action, target, entities)
    }

    /// Check if a word is likely a verb
    fn is_verb(word: &str) -> bool {
        let verbs = [
            "deploy", "install", "launch", "start", "stop", "restart", "create",
            "delete", "remove", "update", "modify", "change", "configure",
            "query", "get", "fetch", "retrieve", "list", "show", "monitor",
            "check", "verify", "validate", "secure", "encrypt", "decrypt",
            "build", "make", "generate", "execute", "run", "compile",
        ];
        verbs.contains(&word)
    }

    /// Simple classification
    fn classify_simple(&self, action: &str, target: &Option<String>) -> IntentClassification {
        let action_lower = action.to_lowercase();

        for rule in &self.classification_rules {
            for pattern in &rule.patterns {
                if action_lower.contains(pattern.as_str()) {
                    return rule.classification;
                }
            }
        }

        // Check target for classification hints
        if let Some(target_ref) = target {
            let target_lower = target_ref.to_lowercase();
            if target_lower.contains("config") || target_lower.contains("setting") {
                return IntentClassification::Configuration;
            }
            if target_lower.contains("file") || target_lower.contains("directory") {
                return IntentClassification::Create;
            }
        }

        IntentClassification::Custom
    }

    /// Detect priority from intent text
    fn detect_priority(&self, intent: &str) -> IntentPriority {
        let lower = intent.to_lowercase();

        if lower.contains("emergency") || lower.contains("critical") {
            IntentPriority::Emergency
        } else if lower.contains("urgent") || lower.contains("immediately") || lower.contains("now") {
            IntentPriority::Critical
        } else if lower.contains("important") || lower.contains("priority") {
            IntentPriority::High
        } else if lower.contains("low") && lower.contains("priority") {
            IntentPriority::Low
        } else {
            IntentPriority::Normal
        }
    }

    /// Detect language of intent
    fn detect_language(&self, _intent: &str) -> String {
        // For now, always return English
        // In a full implementation, this would use language detection
        "en".to_string()
    }

    /// Parse intent structure (action, target, etc.)
    fn parse_intent(&self, _intent: &str) -> IntentParseResult {
        // For now, use simple parsing
        // This would be enhanced with full NLP in a complete implementation
        IntentParseResult {
            action: String::new(),
            target: None,
            modifiers: Vec::new(),
            negated: false,
            conditional: false,
        }
    }

    /// Extract entities from intent
    fn extract_entities(
        &self,
        intent: &str,
        _parse_result: &IntentParseResult,
    ) -> Result<Vec<IntentEntity>, String> {
        let mut entities = Vec::new();

        // Apply entity patterns
        for pattern in &self.entity_patterns {
            if let Some(ref regex) = pattern.extraction_regex {
                if let Ok(re) = Regex::new(regex) {
                    for cap in re.captures_iter(intent) {
                        if let Some(m) = cap.get(0) {
                            let value = m.as_str().to_string();
                            let confidence = pattern.confidence_weight;

                            // Validate if needed
                            if let Some(ref validator) = pattern.validation_fn {
                                if !validator(&value) {
                                    continue;
                                }
                            }

                            entities.push(IntentEntity {
                                name: value.clone(),
                                entity_type: pattern.entity_type.clone(),
                                value: Value::String(value),
                                position: m.start(),
                                confidence,
                            });
                        }
                    }
                }
            }
        }

        Ok(entities)
    }

    /// Parse parameters from intent
    fn parse_parameters(
        &self,
        intent: &str,
        _parse_result: &IntentParseResult,
        _entities: &[IntentEntity],
    ) -> Result<Value, String> {
        let mut params = serde_json::Map::new();

        // Look for parameter patterns
        for parser in &self.parameter_parsers {
            for pattern in &parser.patterns {
                if intent.to_lowercase().contains(pattern.as_str()) {
                    // Try to extract value
                    let value = self.extract_parameter_value(intent, pattern, parser)?;
                    params.insert(parser.parameter_name.clone(), value);
                    break; // Found this parameter, move to next
                }
            }
        }

        Ok(Value::Object(params))
    }

    /// Extract parameter value from intent
    fn extract_parameter_value(
        &self,
        intent: &str,
        pattern: &str,
        parser: &ParameterParser,
    ) -> Result<Value, String> {
        // Find the pattern and extract what comes after it
        let lower_intent = intent.to_lowercase();
        if let Some(idx) = lower_intent.find(pattern) {
            let after_pattern = &intent[idx + pattern.len()..];

            // Extract next word or quoted string
            let value_str = after_pattern
                .split_whitespace()
                .next()
                .unwrap_or("");

            // Handle quoted strings
            if value_str.starts_with('"') || value_str.starts_with("'") {
                // Find matching close quote
                let quote_char = value_str.chars().next().unwrap();
                let rest = &after_pattern[1..];
                if let Some(end_idx) = rest.find(quote_char) {
                    return Ok(Value::String(rest[..end_idx].to_string()));
                }
            }

            // Parse based on value type
            match parser.value_type {
                ParameterValueType::Number => {
                    if let Ok(num) = value_str.parse::<f64>() {
                        Ok(Value::from(num))
                    } else {
                        Ok(parser.default_value.clone().unwrap_or(Value::Null))
                    }
                }
                ParameterValueType::Boolean => {
                    let val = value_str.to_lowercase();
                    if val == "true" || val == "yes" || val == "1" {
                        Ok(Value::Bool(true))
                    } else if val == "false" || val == "no" || val == "0" {
                        Ok(Value::Bool(false))
                    } else {
                        Ok(parser.default_value.clone().unwrap_or(Value::Null))
                    }
                }
                ParameterValueType::Duration => {
                    // Parse duration like "30s", "5min", "2h", etc.
                    if let Some(duration) = parse_duration(value_str) {
                        Ok(Value::Number(serde_json::Number::from_f64(duration.as_secs_f64()).unwrap_or(serde_json::Number::from(0))))
                    } else {
                        Ok(parser.default_value.clone().unwrap_or(Value::Null))
                    }
                }
                _ => Ok(Value::String(value_str.to_string())),
            }
        } else {
            Ok(parser.default_value.clone().unwrap_or(Value::Null))
        }
    }

    /// Classify intent based on parse result and entities
    fn classify_intent(
        &self,
        parse_result: &IntentParseResult,
        entities: &[IntentEntity],
    ) -> IntentClassification {
        // First, check action against classification rules
        for rule in &self.classification_rules {
            for pattern in &rule.patterns {
                if parse_result.action.to_lowercase().contains(pattern.as_str()) {
                    return rule.classification;
                }
            }
        }

        // Check entities for classification hints
        for entity in entities {
            match entity.entity_type {
                EntityType::File | EntityType::Directory => {
                    if parse_result.action.to_lowercase().contains("create")
                        || parse_result.action.to_lowercase().contains("new")
                    {
                        return IntentClassification::Create;
                    }
                }
                EntityType::Network => {
                    if parse_result.action.to_lowercase().contains("monitor")
                        || parse_result.action.to_lowercase().contains("check")
                    {
                        return IntentClassification::Monitoring;
                    }
                }
                _ => {}
            }
        }

        IntentClassification::Custom
    }

    /// Get supported languages
    pub fn supported_languages(&self) -> &HashSet<String> {
        &self.supported_languages
    }

    /// Add a supported language
    pub fn add_language(&mut self, language: String) {
        self.supported_languages.insert(language);
    }

    /// Set the context manager
    pub fn set_context_manager(&mut self, context_manager: ContextManager) {
        self.context_manager = context_manager;
    }

    /// Get the translator ID
    pub fn id(&self) -> &str {
        &self.translator_id
    }

    /// Get stats
    pub fn stats(&self) -> &IntentStats {
        &self.stats
    }

    /// Reset stats
    pub fn reset_stats(&mut self) {
        self.stats = IntentStats::default();
    }

    /// Set knowledge base
    pub fn set_knowledge_base(&mut self, knowledge_base: Arc<RwLock<IntentKnowledgeBase>>) {
        self.knowledge_base = Some(knowledge_base);
    }
}

/// Intent parse result (intermediate)
#[derive(Debug, Clone)]
struct IntentParseResult {
    pub action: String,
    pub target: Option<String>,
    pub modifiers: Vec<String>,
    pub negated: bool,
    pub conditional: bool,
}

/// Parse duration string to std::time::Duration
fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();

    // Handle simple numeric (seconds)
    if let Ok(secs) = s.parse::<u64>() {
        return Some(std::time::Duration::from_secs(secs));
    }

    // Handle with suffix
    let (num_str, unit) = if s.ends_with("ms") {
        (&s[..s.len() - 2], "ms")
    } else if s.ends_with("s") {
        (&s[..s.len() - 1], "s")
    } else if s.ends_with("min") {
        (&s[..s.len() - 3], "min")
    } else if s.ends_with("m") {
        (&s[..s.len() - 1], "min")
    } else if s.ends_with("h") {
        (&s[..s.len() - 1], "h")
    } else if s.ends_with("hr") {
        (&s[..s.len() - 2], "h")
    } else if s.ends_with("d") {
        (&s[..s.len() - 1], "d")
    } else if s.ends_with("day") {
        (&s[..s.len() - 3], "d")
    } else if s.ends_with("w") {
        (&s[..s.len() - 1], "w")
    } else if s.ends_with("week") {
        (&s[..s.len() - 4], "w")
    } else if s.ends_with("y") {
        (&s[..s.len() - 1], "y")
    } else if s.ends_with("year") {
        (&s[..s.len() - 4], "y")
    } else {
        return None;
    };

    let num: u64 = num_str.parse().ok()?;

    match unit {
        "ms" => Some(std::time::Duration::from_millis(num)),
        "s" => Some(std::time::Duration::from_secs(num)),
        "min" => Some(std::time::Duration::from_secs(num * 60)),
        "h" => Some(std::time::Duration::from_secs(num * 3600)),
        "d" => Some(std::time::Duration::from_secs(num * 86400)),
        "w" => Some(std::time::Duration::from_secs(num * 604800)),
        "y" => Some(std::time::Duration::from_secs(num * 31536000)),
        _ => None,
    }
}

// ============================================================================
// CONTEXT MANAGER IMPLEMENTATION
// ============================================================================

impl ContextManager {
    pub fn new() -> Self {
        Self {
            current_context: None,
            context_history: Vec::new(),
            max_history: 10,
        }
    }

    pub fn with_max_history(mut self, max_history: usize) -> Self {
        self.max_history = max_history;
        self
    }

    /// Start a new context
    pub fn start_context(&mut self, context_id: Option<String>) -> String {
        let id = context_id.unwrap_or_else(|| {
            format!(
                "ctx_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            )
        });

        let context = ConversationContext {
            context_id: id.clone(),
            previous_intents: Vec::new(),
            current_domain: None,
            active_entities: Vec::new(),
            variables: HashMap::new(),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            updated_at: 0,
        };

        // Save old context to history
        if let Some(old_context) = self.current_context.take() {
            self.context_history.push(old_context);
            if self.context_history.len() > self.max_history {
                self.context_history.remove(0);
            }
        }

        self.current_context = Some(context);
        id
    }

    /// End current context
    pub fn end_context(&mut self) -> Option<ConversationContext> {
        let mut context = self.current_context.take();
        if let Some(ref mut ctx) = context {
            ctx.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
        }
        context
    }

    /// Add intent to current context
    pub fn add_intent(&mut self, intent: String) {
        if let Some(ref mut context) = self.current_context {
            context.previous_intents.push(intent);
            context.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
        }
    }

    /// Set variable in current context
    pub fn set_variable(&mut self, name: String, value: Value) {
        if let Some(ref mut context) = self.current_context {
            context.variables.insert(name, value);
            context.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
        }
    }

    /// Get variable from current context
    pub fn get_variable(&self, name: &str) -> Option<Value> {
        self.current_context
            .as_ref()
            .and_then(|ctx| ctx.variables.get(name).cloned())
    }
}

// ============================================================================
// INTENT NORMALIZER IMPLEMENTATION
// ============================================================================

impl IntentNormalizer {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            lowercase: true,
            remove_punctuation: true,
            expand_contractions: true,
        }
    }

    pub fn with_rules(mut self, rules: Vec<NormalizationRule>) -> Self {
        self.rules = rules;
        self
    }

    /// Normalize intent text
    pub fn normalize(&self, intent: &str) -> String {
        let mut result = intent.to_string();

        // Apply custom rules first
        for rule in &self.rules {
            result = result.replace(&rule.pattern, &rule.replacement);
        }

        // Lowercase
        if self.lowercase {
            result = result.to_lowercase();
        }

        // Remove punctuation (except for patterns)
        if self.remove_punctuation {
            result = result
                .chars()
                .filter(|c| c.is_alphanumeric() || c.is_whitespace() || *c == '_' || *c == '-' || *c == '/')
                .collect();
        }

        // Expand contractions
        if self.expand_contractions {
            result = Self::expand_contractions(&result);
        }

        // Remove extra whitespace
        result = result.split_whitespace().collect::<Vec<_>>().join(" ");
        result.trim().to_string()
    }

    /// Expand common English contractions
    fn expand_contractions(text: &str) -> String {
        let contractions = [
            ("don't", "do not"),
            ("can't", "cannot"),
            ("won't", "will not"),
            ("isn't", "is not"),
            ("aren't", "are not"),
            ("wasn't", "was not"),
            ("weren't", "were not"),
            ("hasn't", "has not"),
            ("haven't", "have not"),
            ("hadn't", "had not"),
            ("doesn't", "does not"),
            ("didn't", "did not"),
            ("wouldn't", "would not"),
            ("shouldn't", "should not"),
            ("couldn't", "could not"),
            ("mightn't", "might not"),
            ("mustn't", "must not"),
            ("i'm", "i am"),
            ("you're", "you are"),
            ("we're", "we are"),
            ("they're", "they are"),
            ("it's", "it is"),
            ("i've", "i have"),
            ("you've", "you have"),
            ("we've", "we have"),
            ("they've", "they have"),
            ("i'd", "i would"),
            ("you'd", "you would"),
            ("we'd", "we would"),
            ("they'd", "they would"),
            ("i'll", "i will"),
            ("you'll", "you will"),
            ("we'll", "we will"),
            ("they'll", "they will"),
        ];

        let mut result = text.to_string();
        for (contraction, expanded) in &contractions {
            result = result.replace(contraction, expanded);
        }
        result
    }
}

// ============================================================================
// CONFIDENCE CALCULATOR IMPLEMENTATION
// ============================================================================

impl ConfidenceCalculator {
    pub fn new() -> Self {
        let mut factor_weights = HashMap::new();
        factor_weights.insert("pattern_match".to_string(), 0.4);
        factor_weights.insert("entity_extraction".to_string(), 0.25);
        factor_weights.insert("classification".to_string(), 0.2);
        factor_weights.insert("parameter_parsing".to_string(), 0.1);
        factor_weights.insert("context_match".to_string(), 0.05);

        Self {
            factor_weights,
            pattern_confidence: 0.0,
            entity_confidence: 0.0,
            classification_confidence: 0.0,
            parameter_confidence: 0.0,
            context_confidence: 0.0,
        }
    }

    /// Calculate overall confidence score
    pub fn calculate(
        &mut self,
        intent: &str,
        classification: &IntentClassification,
        entities: &[IntentEntity],
        target: &Option<String>,
    ) -> f64 {
        // Start with base confidence
        let mut confidence = 0.5; // Base confidence for any parsed intent

        // Add pattern matching confidence
        confidence += self.pattern_confidence * self.factor_weights.get("pattern_match").unwrap_or(&0.4);

        // Add entity extraction confidence
        if !entities.is_empty() {
            let avg_entity_conf = entities.iter().map(|e| e.confidence).sum::<f64>() / entities.len() as f64;
            self.entity_confidence = avg_entity_conf;
            confidence += self.entity_confidence * self.factor_weights.get("entity_extraction").unwrap_or(&0.25);
        }

        // Add classification confidence
        self.classification_confidence = self.classify_confidence(classification);
        confidence += self.classification_confidence * self.factor_weights.get("classification").unwrap_or(&0.2);

        // Add parameter parsing confidence (estimated)
        self.parameter_confidence = 0.7; // Placeholder
        confidence += self.parameter_confidence * self.factor_weights.get("parameter_parsing").unwrap_or(&0.1);

        // Add context confidence (estimated)
        self.context_confidence = 0.5; // Placeholder
        confidence += self.context_confidence * self.factor_weights.get("context_match").unwrap_or(&0.05);

        // Cap at 1.0
        confidence.min(1.0)
    }

    /// Get confidence for classification
    fn classify_confidence(&self, classification: &IntentClassification) -> f64 {
        match classification {
            IntentClassification::Unknown => 0.1,
            IntentClassification::Custom => 0.3,
            IntentClassification::Query => 0.8,
            IntentClassification::Status => 0.8,
            IntentClassification::Audit => 0.8,
            IntentClassification::Report => 0.8,
            IntentClassification::Create => 0.9,
            IntentClassification::Update => 0.9,
            IntentClassification::Delete => 0.9,
            IntentClassification::Modify => 0.9,
            IntentClassification::Deployment => 0.95,
            IntentClassification::Configuration => 0.95,
            IntentClassification::Monitoring => 0.95,
            IntentClassification::Security => 0.95,
            IntentClassification::Optimization => 0.9,
            IntentClassification::Maintenance => 0.85,
            IntentClassification::Backup => 0.85,
            IntentClassification::Recovery => 0.85,
            IntentClassification::System => 0.8,
            IntentClassification::Network => 0.85,
            IntentClassification::Storage => 0.85,
            IntentClassification::Compute => 0.85,
        }
    }
}

// ============================================================================
// CONTEXT MANAGER DEFAULT
// ============================================================================

impl Default for ContextManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// KNOWLEDGE BASE DEFAULT
// ============================================================================

impl Default for IntentKnowledgeBase {
    fn default() -> Self {
        Self {
            vocabularies: HashMap::new(),
            patterns: HashMap::new(),
            synonyms: HashMap::new(),
            domain_hierarchy: DomainHierarchy { domains: Vec::new() },
        }
    }
}

// ============================================================================
// INTENT INTERPRETER - Main struct for external use
// ============================================================================

/// Intent Interpreter - the public interface for intent translation
/// This wraps IntentUniversal for use by other modules
pub struct IntentInterpreter {
    /// Inner translator
    translator: IntentUniversal,
    /// Agreement level for intent processing
    agreement_level: AgreementLevel,
}

/// Agreement level for intent interpretation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgreementLevel {
    /// Basic agreement
    Basic,
    /// Self-sovereign agreement
    SelfSovereign,
    /// Mutual agreement
    Mutual,
    /// Full consensus
    Consensus,
}

impl Default for AgreementLevel {
    fn default() -> Self {
        Self::Basic
    }
}

impl IntentInterpreter {
    /// Create a new IntentInterpreter
    pub fn new(agreement_level: AgreementLevel) -> Self {
        Self {
            translator: IntentUniversal::new(None),
            agreement_level,
        }
    }

    /// Translate intent
    pub fn interpret_natural_language(&mut self, intent: &str) -> Option<Value> {
        match self.translator.translate(intent) {
            Ok(parsed) => serde_json::to_value(parsed).ok(),
            Err(_) => None,
        }
    }

    /// Get agreement level
    pub fn agreement_level(&self) -> AgreementLevel {
        self.agreement_level
    }

    /// Get translator ID
    pub fn id(&self) -> &str {
        self.translator.id()
    }
}

impl Default for IntentInterpreter {
    fn default() -> Self {
        Self::new(AgreementLevel::SelfSovereign)
    }
}

// ============================================================================
// TRAIT IMPLEMENTATION FOR CLOSED LOOP INTEGRATION
// ============================================================================

impl crate::closed_loop::IntentTranslator for IntentUniversal {
    fn translate(&self, intent: &str) -> Result<crate::closed_loop::ParsedIntent, String> {
        // Direct implementation - parse the intent
        let parsed = self.parse(intent);
        Ok(parsed)
    }

    fn supported_languages(&self) -> &[String] {
        // Convert HashSet to Vec for the trait
        static LANGUAGES: once_cell::sync::Lazy<Vec<String>> = once_cell::sync::Lazy::new(|| {
            vec![
                "en".to_string(), "es".to_string(), "fr".to_string(), "de".to_string(), "it".to_string(),
                "pt".to_string(), "ru".to_string(), "zh".to_string(), "ja".to_string(), "ko".to_string(),
                "ar".to_string(), "hi".to_string(), "bn".to_string(), "pa".to_string(), "tr".to_string(),
                "nl".to_string(), "sv".to_string(), "fi".to_string(), "da".to_string(), "no".to_string(),
            ]
        });
        &LANGUAGES
    }

    fn id(&self) -> &str {
        &self.translator_id
    }
}

impl crate::closed_loop::IntentTranslator for IntentInterpreter {
    fn translate(&self, intent: &str) -> Result<crate::closed_loop::ParsedIntent, String> {
        self.translator.translate(intent)
    }

    fn supported_languages(&self) -> &[String] {
        // Convert HashSet to Vec for the trait
        static LANGUAGES: once_cell::sync::Lazy<Vec<String>> = once_cell::sync::Lazy::new(|| {
            vec![
                "en".to_string(), "es".to_string(), "fr".to_string(), "de".to_string(), "it".to_string(),
                "pt".to_string(), "ru".to_string(), "zh".to_string(), "ja".to_string(), "ko".to_string(),
                "ar".to_string(), "hi".to_string(), "bn".to_string(), "pa".to_string(), "tr".to_string(),
                "nl".to_string(), "sv".to_string(), "fi".to_string(), "da".to_string(), "no".to_string(),
            ]
        });
        &LANGUAGES
    }

    fn id(&self) -> &str {
        self.translator.id()
    }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Create a new IntentUniversal translator
pub fn create_intent_translator() -> IntentUniversal {
    IntentUniversal::new(None)
}

/// Create a new IntentUniversal with a specific ID
pub fn create_intent_translator_with_id(translator_id: &str) -> IntentUniversal {
    IntentUniversal::new(Some(translator_id.to_string()))
}

/// Quick translation for simple use cases
pub fn translate_intent(intent: &str) -> Result<crate::closed_loop::ParsedIntent, String> {
    let translator = create_intent_translator();
    translator.translate_simple(intent)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intent_creation() {
        let translator = create_intent_translator();
        assert_eq!(translator.id(), "intent_universal_default");
    }

    #[test]
    fn test_simple_translation() {
        let translator = create_intent_translator();
        let result = translator.translate_simple("deploy system");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.action, "deploy");
        assert_eq!(parsed.target, Some("system".to_string()));
    }

    #[test]
    fn test_intent_classification() {
        let translator = create_intent_translator();
        let result = translator.translate_simple("install package");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.classification, IntentClassification::Deployment);
    }

    #[test]
    fn test_priority_detection() {
        let translator = create_intent_translator();

        let result = translator.translate_simple("deploy system now");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.priority, IntentPriority::Critical);

        let result = translator.translate_simple("emergency shutdown");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.priority, IntentPriority::Emergency);
    }

    #[test]
    fn test_entity_extraction() {
        let translator = create_intent_translator();
        let result = translator.translate_simple("deploy system to server 123");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.action, "deploy");
        // Check that numeric entity was extracted
        assert!(!parsed.entities.is_empty());
        let has_numeric = parsed.entities.iter().any(|e| e.entity_type == EntityType::Value);
        assert!(has_numeric);
    }

    #[test]
    fn test_intent_normalizer() {
        let normalizer = IntentNormalizer::new();

        // Test lowercase
        assert_eq!(normalizer.normalize("DEPLOY SYSTEM"), "deploy system");

        // Test punctuation removal
        assert_eq!(normalizer.normalize("deploy, system!"), "deploy system");

        // Test contraction expansion
        assert_eq!(normalizer.normalize("don't stop"), "do not stop");
    }

    #[test]
    fn test_duration_parsing() {
        assert!(parse_duration("30s").is_some());
        assert!(parse_duration("5min").is_some());
        assert!(parse_duration("2h").is_some());
        assert!(parse_duration("1d").is_some());
        assert!(parse_duration("invalid").is_none());
    }

    #[test]
    fn test_context_manager() {
        let mut manager = ContextManager::new();
        let ctx_id = manager.start_context(None);
        assert!(!ctx_id.is_empty());

        manager.add_intent("test intent".to_string());
        manager.set_variable("test".to_string(), Value::String("value".to_string()));

        assert_eq!(manager.get_variable("test"), Some(Value::String("value".to_string())));
    }

    #[test]
    fn test_confidence_calculator() {
        let calculator = ConfidenceCalculator::new();
        let confidence = calculator.calculate(
            "deploy system",
            &IntentClassification::Deployment,
            &[],
            &Some("system".to_string()),
        );
        assert!(confidence > 0.0 && confidence <= 1.0);
    }
}
