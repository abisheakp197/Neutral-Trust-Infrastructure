//! UBE Sovereign Semantic Memory
//! Episodic memory with cosine similarity retrieval for autonomous agents.
//! Zero-dependency, deterministic, and memory-safe.

use std::collections::VecDeque;
use crate::types::Value;

/// A single memory entry representing an event or observation.
#[derive(Debug, Clone)]
pub struct MemoryEntry {
    pub id: String,
    pub timestamp: u64,
    pub module_id: String,
    pub entry_type: String,
    pub content: Value,
    pub embedding: Vec<f64>,
    pub importance: f64,
    pub tags: Vec<String>,
}

/// Sovereign Semantic Memory Engine.
/// Stores and retrieves episodic memories based on vector similarity.
pub struct SemanticMemory {
    entries: Vec<MemoryEntry>,
    max_entries: usize,
    decay_rate: f64,
}

impl SemanticMemory {
    pub fn new(max_entries: usize, decay_rate: f64) -> Self {
        Self {
            entries: Vec::new(),
            max_entries,
            decay_rate,
        }
    }

    /// Stores a new memory entry.
    pub fn store(&mut self, mut entry: MemoryEntry) -> String {
        let id = entry.id.clone();
        self.entries.push(entry);

        if self.entries.len() > self.max_entries {
            // Evict least important memory
            self.entries.sort_by(|a, b| a.importance.partial_cmp(&b.importance).unwrap());
            self.entries.drain(0..self.max_entries / 10);
        }

        id
    }

    /// Retrieves top-K similar memories using cosine similarity.
    pub fn retrieve(&self, query_embedding: &[f64], top_k: usize, module_filter: Option<&str>) -> Vec<MemoryEntry> {
        let now = 0; // In production, use real timestamp
        let mut candidates: Vec<(f64, &MemoryEntry)> = self.entries.iter()
            .filter(|e| module_filter.map_or(true, |f| e.module_id == f))
            .map(|e| {
                // Apply temporal decay to importance
                let age = 0.0; // Simplified decay for core
                let decayed_importance = e.importance * self.decay_rate.powf(age);
                let score = self.cosine_sim(query_embedding, &e.embedding) * decayed_importance;
                (score, e)
            })
            .collect();

        candidates.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
        candidates.into_iter().take(top_k).map(|(_, e)| e.clone()).collect()
    }

    fn cosine_sim(&self, a: &[f64], b: &[f64]) -> f64 {
        if a.len() != b.len() { return 0.0; }
        let dot: f64 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
        let mag_a: f64 = a.iter().map(|x| x * x).sum::<f64>().sqrt();
        let mag_b: f64 = b.iter().map(|x| x * x).sum::<f64>().sqrt();

        if mag_a > 0.0 && mag_b > 0.0 {
            dot / (mag_a * mag_b)
        } else {
            0.0
        }
    }

    /// Deterministic embedding of structured data into a feature vector.
    pub fn embed(content: &Value) -> Vec<f64> {
        let mut vec = vec![0.0; 64];
        // Simplified deterministic embedding based on content structure
        match content {
            Value::String(s) => {
                for (i, c) in s.chars().enumerate() {
                    vec[(i % 64)] += (c as f64) / 255.0;
                }
            }
            Value::Int(i) => {
                vec[0] += (*i as f64) / 1e9;
            }
            _ => {
                vec[0] = 1.0;
            }
        }

        // Normalize vector
        let mag: f64 = vec.iter().map(|x| x * x).sum::<f64>().sqrt();
        if mag > 0.0 {
            vec.iter().map(|x| x / mag).collect()
        } else {
            vec
        }
    }

    pub fn size(&self) -> usize { self.entries.len() }
    pub fn clear(&mut self) { self.entries.clear(); }
}
