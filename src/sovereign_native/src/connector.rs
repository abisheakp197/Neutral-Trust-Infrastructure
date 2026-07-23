//! UBE Sovereign Connector Engine
//! Bitcoin-grade, zero-dependency adapter system for external integration.
//! Designed for absolute sovereignty and deterministic external interaction.

use std::collections::HashMap;
use crate::types::Value;

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
        match value {
            Value::Null if definition.required => Err("Field is required".to_string()),
            Value::String(_) if definition.field_type == FieldType::String => Ok(()),
            Value::Number(_) if definition.field_type == FieldType::Number => Ok(()),
            Value::Bool(_) if definition.field_type == FieldType::Boolean => Ok(()),
            Value::Array(_) if definition.field_type == FieldType::Array => Ok(()),
            Value::Object(_) if definition.field_type == FieldType::Object => Ok(()),
            _ => Err(format!("Value does not match type {:?}", definition.field_type)),
        }
    }
}

// ============================================================
// SOCKET CONNECTOR (from socket.rs)
// ============================================================

/// Socket error types
#[derive(Debug, Clone)]
pub enum SocketError {
    Io(String),
    Serde(String),
    FrameTooLarge(usize),
    ConnectionClosed,
}

impl std::fmt::Display for SocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SocketError::Io(e) => write!(f, "IO error: {}", e),
            SocketError::Serde(e) => write!(f, "Serialization error: {}", e),
            SocketError::FrameTooLarge(s) => write!(f, "Frame too large: {}", s),
            SocketError::ConnectionClosed => write!(f, "Connection closed by peer"),
        }
    }
}

impl std::error::Error for SocketError {}

/// A SovereignFrame consists of a 4-byte length prefix followed by the JSON payload.
pub struct SovereignFrame {
    pub payload: Vec<u8>,
}

/// Low-level socket wrapper
pub struct SovereignSocket {
    // In real implementation, this would hold TcpStream or similar
    // For now, we store the frame buffer
    buffer: Vec<u8>,
}

impl SovereignSocket {
    pub fn new() -> Self {
        Self { buffer: Vec::with_capacity(4096) }
    }

    pub fn send_frame(&mut self, data: &[u8]) -> Result<(), SocketError> {
        let len = data.len() as u32;
        let _len_bytes = len.to_be_bytes();
        // In real implementation: write to TcpStream
        Ok(())
    }

    pub fn receive_frame(&mut self) -> Result<Vec<u8>, SocketError> {
        // In real implementation: read from TcpStream
        Err(SocketError::ConnectionClosed)
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
