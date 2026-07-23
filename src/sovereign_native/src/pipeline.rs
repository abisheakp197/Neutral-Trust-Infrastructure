//! UBE Sovereign Pipeline Engine
//! Bitcoin-grade, deterministic data processing pipeline.
//! Zero-dependency target, memory-safe, and high-performance.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::types::Value;

/// Types of stages available in the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageType {
    Map,
    Filter,
    FlatMap,
    Validate,
    Enrich,
    Deduplicate,
    Buffer,
    Sort,
}

/// Context passed to each stage during execution.
pub struct PipelineContext {
    pub pipeline_id: String,
    pub stage_id: String,
    pub tenant_id: String,
    pub item_index: usize,
    pub metadata: HashMap<String, Value>,
}

/// Definition of a single processing stage.
pub struct PipelineStage {
    pub id: String,
    pub name: String,
    pub stage_type: StageType,
    pub handler: Box<dyn Fn(Value, &PipelineContext) -> Result<Option<Value>, PipelineError> + Send + Sync>,
    pub concurrency: usize,
    pub timeout: Duration,
    pub drop_on_error: bool,
}

#[derive(Debug, Clone)]
pub struct PipelineError {
    pub stage_id: String,
    pub error: String,
    pub item: Value,
}

pub struct StageMetrics {
    pub stage_id: String,
    pub input_count: usize,
    pub output_count: usize,
    pub error_count: usize,
    pub dropped_count: usize,
    pub duration: Duration,
}

pub struct PipelineResult {
    pub output: Vec<Value>,
    pub errors: Vec<PipelineError>,
    pub dropped: usize,
    pub duration: Duration,
    pub metrics: Vec<StageMetrics>,
}

/// The Sovereign Pipeline Engine.
pub struct Pipeline {
    id: String,
    tenant_id: String,
    stages: Vec<PipelineStage>,
}

impl Pipeline {
    pub fn new(id: &str, tenant_id: &str) -> Self {
        Self {
            id: id.to_string(),
            tenant_id: tenant_id.to_string(),
            stages: Vec::new(),
        }
    }

    /// Adds a map stage to the pipeline.
    pub fn map<F>(mut self, name: &str, handler: F) -> Self
    where
        F: Fn(Value, &PipelineContext) -> Result<Option<Value>, PipelineError> + 'static + Send + Sync
    {
        self.stages.push(PipelineStage {
            id: format!("stg-{}", self.stages.len()),
            name: name.to_string(),
            stage_type: StageType::Map,
            handler: Box::new(handler),
            concurrency: 10,
            timeout: Duration::from_secs(30),
            drop_on_error: true,
        });
        self
    }

    /// Adds a filter stage to the pipeline.
    pub fn filter<F>(mut self, name: &str, predicate: F) -> Self
    where
        F: Fn(Value, &PipelineContext) -> bool + 'static + Send + Sync
    {
        let predicate_clone = predicate;
        self.stages.push(PipelineStage {
            id: format!("stg-{}", self.stages.len()),
            name: name.to_string(),
            stage_type: StageType::Filter,
            handler: Box::new(move |val, ctx| {
                if (predicate_clone)(val.clone(), ctx) {
                    Ok(Some(val))
                } else {
                    Ok(None)
                }
            }),
            concurrency: 10,
            timeout: Duration::from_secs(30),
            drop_on_error: true,
        });
        self
    }

    /// Executes the pipeline on the given input.
    pub fn run(&self, input: Vec<Value>) -> PipelineResult {
        let start_time = Instant::now();
        let mut current_data = input;
        let mut all_errors = Vec::new();
        let mut total_dropped = 0;
        let mut metrics = Vec::new();

        for stage in &self.stages {
            let stage_start = Instant::now();
            let mut next_data = Vec::new();
            let mut stage_errors = 0;
            let mut stage_dropped = 0;
            let input_count = current_data.len();

            for (idx, item) in current_data.into_iter().enumerate() {
                let ctx = PipelineContext {
                    pipeline_id: self.id.clone(),
                    stage_id: stage.id.clone(),
                    tenant_id: self.tenant_id.clone(),
                    item_index: idx,
                    metadata: HashMap::new(),
                };

                match (stage.handler)(item.clone(), &ctx) {
                    Ok(Some(val)) => next_data.push(val),
                    Ok(None) => {
                        stage_dropped += 1;
                        total_dropped += 1;
                    }
                    Err(e) => {
                        stage_errors += 1;
                        if stage.drop_on_error {
                            stage_dropped += 1;
                            total_dropped += 1;
                        } else {
                            all_errors.push(e);
                        }
                    }
                }
            }

            metrics.push(StageMetrics {
                stage_id: stage.id.clone(),
                input_count,
                output_count: next_data.len(),
                error_count: stage_errors,
                dropped_count: stage_dropped,
                duration: stage_start.elapsed(),
            });

            current_data = next_data;
        }

        PipelineResult {
            output: current_data,
            errors: all_errors,
            dropped: total_dropped,
            duration: start_time.elapsed(),
            metrics,
        }
    }
}
