//! UBE Sovereign Directive Language (SDL)
//! Intent-based translation of human mandates into executable sovereign pipelines.
//! Designed for absolute precision, determinism, and sovereignty.

use std::collections::HashMap;
use crate::types::Value;
use crate::automation::{AutomationRequest, AutomationStep};

/// A Sovereign Directive is a high-level intent.
/// Example: "Maintain battery between 20% and 80% and notify me if it fails."
#[derive(Debug, Clone)]
pub struct SovereignDirective {
    pub id: String,
    pub intent: String,
    pub constraints: Vec<DirectiveConstraint>,
    pub desired_state: Value,
}

#[derive(Debug, Clone)]
pub struct DirectiveConstraint {
    pub parameter: String,
    pub operator: ConstraintOperator,
    pub threshold: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConstraintOperator {
    GreaterThan,
    LessThan,
    EqualTo,
    NotEqualTo,
    Contains,
}

/// The SDL Compiler translates high-level directives into executable AutomationRequests.
pub struct SdlCompiler {
    // Mapping of high-level intents to pipeline templates.
    templates: HashMap<String, Vec<AutomationStep>>,

    // Compiler for validating repair proposals.
    compiler: Box<dyn SdlCompiler>,
}

impl SdlCompiler {
    /// Creates a new SDL compiler with validation logic.
    pub fn new() -> Self {
        let compiler = Box::new(DefaultSdlCompiler);
        let mut templates = HashMap::new();
        // Example Template: "Maintain Resource Level"
        templates.insert("maintain_resource".to_string(), vec![
            AutomationStep::Connector {
                name: "ResourceCheck".to_string(),
                connector_id: "system_metrics".to_string(),
                action: "get_level".to_string(),
                input: Value::Null,
            },
            AutomationStep::Condition {
                name: "CheckThreshold".to_string(),
                expression: "value < threshold".to_string(),
                on_true: "trigger_recharge".to_string(),
                on_false: "continue".to_string(),
            },
        ]);
        Self { templates, compiler }
    }
}

impl SdlCompiler {
    pub fn new() -> Self {
        let mut templates = HashMap::new();

        // Example Template: "Maintain Resource Level"
        templates.insert("maintain_resource".to_string(), vec![
            AutomationStep::Connector {
                name: "ResourceCheck".to_string(),
                connector_id: "system_metrics".to_string(),
                action: "get_level".to_string(),
                input: Value::Null,
            },
            AutomationStep::Condition {
                name: "CheckThreshold".to_string(),
                expression: "value < threshold".to_string(),
                on_true: "trigger_recharge".to_string(),
                on_false: "continue".to_string(),
            },
        ]);

        Self { templates }
    }

    /// Compiles a high-level directive into a deterministic AutomationRequest.
    pub fn compile(&self, directive: &SovereignDirective) -> Result<AutomationRequest, String> {
        // 1. Identify the appropriate template based on the intent.
        let steps = self.templates.get(&directive.intent)
            .ok_or_else(|| format!("No template found for intent: {}", directive.intent))?;

        // 2. Parameterize the template with the constraints.
        let mut finalized_steps = Vec::new();
        for step in steps {
            let parameterized_step = self.parameterize_step(step, &directive.constraints);
            finalized_steps.push(parameterized_step);
        }

        Ok(AutomationRequest {
            id: format!("req-{}", directive.id),
            name: format!("Compiled-{}", directive.intent),
            description: Some(directive.intent.clone()),
            steps: finalized_steps,
            options: crate::automation::AutomationOptions {
                encryption_mode: crate::automation::EncryptionMode::QuantumResistant,
                retry_policy: crate::automation::RetryPolicy {
                    max_attempts: 3,
                    delay: std::time::Duration::from_secs(5),
                },
                tags: vec!["sdl-compiled".to_string()],
            },
        })
    }

    fn parameterize_step(&self, step: &AutomationStep, constraints: &[DirectiveConstraint]) -> AutomationStep {
        match step {
            AutomationStep::Connector { name, connector_id, action, input } => {
                // Replace generic inputs with directive constraints if they match.
                let mut final_input = input.clone();
                if let Some(constraint) = constraints.iter().find(|c| c.parameter == *name) {
                    final_input = constraint.threshold.clone();
                }
                AutomationStep::Connector {
                    name: name.clone(),
                    connector_id: connector_id.clone(),
                    action: action.clone(),
                    input: final_input,
                }
            }
            _ => step.clone(),
        }
    }
}
