//! Shared types for Digital Proxy system

use std::time::Duration;
use serde_json::Value;

/// What kind of entity this proxy serves
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityType {
    Enterprise, Government, Financial, Cloud, IoT, Telco, Sovereign,
}

impl EntityType {
    pub fn as_str(&self) -> &'static str {
        match self {
            EntityType::Enterprise => "enterprise",
            EntityType::Government => "government",
            EntityType::Financial => "financial",
            EntityType::Cloud => "cloud",
            EntityType::IoT => "iot",
            EntityType::Telco => "telco",
            EntityType::Sovereign => "sovereign",
        }
    }
}

/// Where the work comes from
#[derive(Debug, Clone)]
pub enum WorkSource {
    InnerWorld,
    OuterWorld(EntityType),
    Scheduled,
    Mandate(String),
}

impl WorkSource {
    pub fn is_inner_world(&self) -> bool {
        matches!(self, WorkSource::InnerWorld)
    }
    pub fn is_outer_world(&self) -> bool {
        matches!(self, WorkSource::OuterWorld(_))
    }
    pub fn entity_id(&self) -> String {
        match self {
            WorkSource::InnerWorld => "inner_world".to_string(),
            WorkSource::OuterWorld(et) => format!("outer:{}", et.as_str()),
            WorkSource::Scheduled => "scheduled".to_string(),
            WorkSource::Mandate(id) => format!("mandate:{}", id),
        }
    }
}

/// A work order submitted to the proxy
#[derive(Debug, Clone)]
pub struct ProxyWorkOrder {
    pub order_id: String,
    pub source: WorkSource,
    pub request: Value,
    pub priority: i32,
    pub timeout: Option<Duration>,
    pub submitted_at: u64,
    /// Outer world operations CANNOT be undone
    pub irreversible: bool,
}

/// Result of proxy work
#[derive(Debug, Clone)]
pub struct ProxyWorkResult {
    pub order_id: String,
    pub status: ProxyWorkStatus,
    pub output: Value,
    pub duration: Duration,
    pub executed_at: u64,
    /// Only for Inner World operations
    pub undo_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyWorkStatus {
    Success, Failed, Blocked, RequiresHumanApproval,
}

/// Autonomous level of the proxy
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AutonomyLevel {
    ObserveOnly = 0, Suggest = 1, ExecuteKnown = 2, FullAutonomous = 3, SelfSovereign = 4,
}
