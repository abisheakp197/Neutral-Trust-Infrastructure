use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SdlError {
    #[error("Parsing error: {0}")]
    ParseError(String),
    #[error("Invalid directive: {0}")]
    InvalidDirective(String),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum MandateAction {
    Sense { sensor: String },
    Actuate { target: String, value: String },
    Attest { proof_id: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SovereignDirective {
    pub id: String,
    pub priority: u8,
    pub actions: Vec<MandateAction>,
}

impl SovereignDirective {
    /// A simplified parser that takes a JSON string and converts it to a directive.
    /// In the full version, this would be a custom DSL parser.
    pub fn parse(input: &str) -> Result<Self, SdlError> {
        serde_json::from_str(input).map_err(|e| SdlError::ParseError(e.to_string()))
    }
}
