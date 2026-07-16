//! UBE Sovereign Common Types
//! Deterministic value system for the Sovereign Fabric.

use std::collections::HashMap;
use serde::{Serialize, Deserialize};

/// Sovereign Metadata for data assets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetMetadata {
    pub is_immutable: bool,
    pub risk_level: f64,
    pub owner_did: String,
    pub tags: Vec<String>,
}

/// Universal Data Value for the Sovereign Fabric.
/// Replaces 'unknown' in TypeScript to ensure deterministic memory layout.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    List(Vec<Value>),
    Map(HashMap<String, Value>),
    Binary(Vec<u8>),
    SovereignAsset {
        data: Box<Value>,
        metadata: AssetMetadata,
    },
}

impl std::fmt::Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Int(i) => write!(f, "{}", i),
            Value::Float(fl) => write!(f, "{}", fl),
            Value::String(s) => write!(f, "{}", s),
            Value::List(l) => write!(f, "{:?}", l),
            Value::Map(m) => write!(f, "{:?}", m),
            Value::Binary(b) => write!(f, "bin({} bytes)", b.len()),
            Value::SovereignAsset { data, .. } => write!(f, "Asset({})", data),
        }
    }
}
