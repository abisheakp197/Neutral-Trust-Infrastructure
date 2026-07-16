//! UBE Sovereign Connector Engine
//! Bitcoin-grade, zero-dependency adapter system for external integration.
//! Designed for absolute sovereignty and deterministic external interaction.

use std::collections::HashMap;
use std::time::Duration;
use crate::pipeline::{Value, PipelineError};

/// Definition of a Sovereign Connector.
#[derive(Debug, Clone)]
pub struct ConnectorManifest {
    pub name: String,
    pub version: String,
    pub connector_type: ConnectorType,
    pub description: String,
    pub actions: Vec<String>,
    pub config_schema: HashMap<String, FieldDefinition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectorType {
    Http,
    Socket,
    FileSystem,
    Hardware,
    Custom,
}

#[derive(Debug, Clone)]
pub struct FieldDefinition {
    pub field_type: FieldType,
    pub required: bool,
    pub description: String,
    pub pattern: Option<String>,
    pub enum_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    String,
    Number,
    Boolean,
    Array,
    Object,
}

/// Context provided to a connector during execution.
pub struct ConnectorContext {
    pub execution_id: String,
    pub tenant_id: String,
    pub trace_id: String,
    pub config: HashMap<String, Value>,
    pub secrets: HashMap<String, String>,
}

/// The core Trait for all Sovereign Connectors.
/// Replaces the abstract ConnectorBase class.
pub trait SovereignConnector: Send + Sync {
    fn manifest(&self) -> &ConnectorManifest;

    /// Initialize the connector with a given context.
    fn on_init(&mut self, _ctx: &ConnectorContext) -> Result<(), ConnectorError> {
        Ok(())
    }

    /// Execute a specific action defined in the manifest.
    fn execute(&self, action: &str, input: Value, ctx: &ConnectorContext) -> Result<Value, ConnectorError>;

    /// Perform a health check on the connector.
    fn on_health_check(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub struct ConnectorError {
    pub connector_name: String,
    pub action: Option<String>,
    pub message: String,
}

/// Registry for managing active sovereign connectors.
pub struct ConnectorRegistry {
    connectors: HashMap<String, Box<dyn SovereignConnector>>,
}

impl ConnectorRegistry {
    pub fn new() -> Self {
        Self {
            connectors: HashMap::new(),
        }
    }

    pub fn register(&mut self, connector: Box<dyn SovereignConnector>) {
        self.connectors.insert(connector.manifest().name.clone(), connector);
    }

    pub fn get(&self, name: &str) -> Option<&dyn SovereignConnector> {
        self.connectors.get(name).map(|c| c.as_ref())
    }

    pub fn list(&self) -> Vec<&ConnectorManifest> {
        self.connectors.values().map(|c| c.manifest()).collect()
    }
}

/// Field Validator for ensuring deterministic input.
pub struct FieldValidator;

impl FieldValidator {
    pub fn validate(value: &Value, definition: &FieldDefinition) -> Result<(), String> {
        match (&value.clone(), &definition.field_type) {
            (Value::Null, _) if definition.required => return Err("Field is required".to_string()),
            (Value::String(_), FieldType::String) => Ok(()),
            (Value::Int(_), FieldType::Number) => Ok(()),
            (Value::Float(_), FieldType::Number) => Ok(()),
            (Value::Bool(_), FieldType::Boolean) => Ok(()),
            (Value::List(_), FieldType::Array) => Ok(()),
            (Value::Map(_), FieldType::Object) => Ok(()),
            (val, ty) => Err(format!("Value {:?} does not match type {:?}", val, ty)),
        }
    }
}

// ============================================================
// EXAMPLE: Sovereign HTTP Connector
// ============================================================

pub struct SovereignHttpConnector {
    manifest: ConnectorManifest,
}

impl SovereignHttpConnector {
    pub fn new() -> Self {
        let mut config_schema = HashMap::new();
        config_schema.insert("baseUrl".to_string(), FieldDefinition {
            field_type: FieldType::String,
            required: false,
            description: "Base URL for requests".to_string(),
            pattern: None,
            enum_values: None,
        });

        Self {
            manifest: ConnectorManifest {
                name: "http".to_string(),
                version: "1.0.0".to_string(),
                connector_type: ConnectorType::Http,
                description: "Sovereign HTTP adapter".to_string(),
                actions: vec!["get".to_string(), "post".to_string(), "put".to_string(), "delete".to_string()],
                config_schema,
            },
        }
    }
}

impl SovereignConnector for SovereignHttpConnector {
    fn manifest(&self) -> &ConnectorManifest {
        &self.manifest
    }

    fn execute(&self, action: &str, input: Value, _ctx: &ConnectorContext) -> Result<Value, ConnectorError> {
        // In a full implementation, this would use a no_std compatible HTTP client (like smoltcp)
        // For the core conversion, we implement the deterministic interface.

        if !self.manifest.actions.contains(&action.to_string()) {
            return Err(ConnectorError {
                connector_name: self.manifest.name.clone(),
                action: Some(action.to_string()),
                message: "Action not supported".to_string(),
            });
        }

        let response = Value::String(format!("Sovereign HTTP {} executed with input {:?}", action, input));
        Ok(response)
    }
}
