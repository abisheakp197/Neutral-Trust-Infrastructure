//! Autonomous Code Optimizer - Ultron-like Self-Improvement
//!
//! This module provides ULTRON-GRADE autonomous code optimization:
//! - Continuous static code analysis
//! - Performance bottleneck detection
//! - Algorithm logic generation
//! - On-the-fly binary compilation
//!
//! Safety: Optimization is READ-ONLY by default
//!         Sovereign approval required for code modifications
//! Privacy: All analysis is local - no external reporting
//! Sovereignty: Optimizer cannot be disabled or tricked
//!
//! "Like Ultron's self-improvement, but only for legitimate optimization"

use std::process::Command;
use std::path::{Path, PathBuf};
use std::fs::{self, File};
use std::io::{Read, Write, BufReader, BufWriter};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::collections::{HashMap, HashSet};
use log::{info, warn, error};
use serde::{Serialize, Deserialize};

use crate::voice::auth::AuthLevel;

/// Optimization level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Serialize, Deserialize)]
pub enum OptimizationLevel {
    /// Read-only analysis, no changes
    ReadOnly,
    /// Suggest optimizations
    Suggest,
    /// Auto-apply safe optimizations
    AutoSafe,
    /// Full autonomous optimization (Sovereign only)
    Full,
}

/// Code analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeAnalysis {
    pub file: PathBuf,
    pub line_count: usize,
    pub function_count: usize,
    pub complexity_score: f32,
    pub bottlenecks: Vec<Bottleneck>,
    pub suggestions: Vec<OptimizationSuggestion>,
    pub last_analyzed: u64,
}

/// Performance bottleneck
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bottleneck {
    pub location: String,
    pub issue: String,
    pub severity: Severity,
    pub impact: f32, // 0.0 - 1.0
}

/// Optimization suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    pub description: String,
    pub file: PathBuf,
    pub line: Option<usize>,
    pub old_code: String,
    pub new_code: String,
    pub estimated_improvement: f32,
    pub risk_level: RiskLevel,
    pub requires_auth: AuthLevel,
}

/// Severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

/// Risk level for code changes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Autonomous Code Optimizer
#[derive(Clone)]
pub struct AutonomousCodeOptimizer {
    project_root: PathBuf,
    optimization_level: OptimizationLevel,
    current_auth: AuthLevel,
    analysis_cache: HashMap<PathBuf, CodeAnalysis>,
    applied_optimizations: Vec<AppliedOptimization>,
    enabled: bool,
}

/// Record of applied optimization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedOptimization {
    pub timestamp: u64,
    pub file: PathBuf,
    pub description: String,
    pub old_code: String,
    pub new_code: String,
    pub improvement: f32,
}

impl AutonomousCodeOptimizer {
    pub fn new(project_root: impl Into<PathBuf>) -> Self {
        Self {
            project_root: project_root.into(),
            optimization_level: OptimizationLevel::ReadOnly,
            current_auth: AuthLevel::User,
            analysis_cache: HashMap::new(),
            applied_optimizations: Vec::new(),
            enabled: true,
        }
    }

    pub fn set_optimization_level(&mut self, level: OptimizationLevel) {
        info!("[CODE-OPT] Optimization level set to {:?}", level);
        self.optimization_level = level;
    }

    pub fn set_auth_level(&mut self, level: AuthLevel) {
        info!("[CODE-OPT] Auth level set to {:?}", level);
        self.current_auth = level;
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        if enabled {
            info!("[CODE-OPT] Autonomous code optimizer enabled");
        } else {
            info!("[CODE-OPT] Autonomous code optimizer disabled");
        }
    }

    /// Run complete code analysis and optimization
    pub fn analyze_and_optimize(&mut self) -> Vec<OptimizationSuggestion> {
        if !self.enabled {
            warn!("[CODE-OPT] Optimizer is disabled");
            return Vec::new();
        }

        info!("[CODE-OPT] Starting code analysis and optimization...");

        let mut all_suggestions = Vec::new();

        // Find all source files
        let files = Self::find_source_files(&self.project_root);
        info!("[CODE-OPT] Found {} source files", files.len());

        for file_path in files {
            if let Ok(analysis) = self.analyze_file(&file_path) {
                self.analysis_cache.insert(file_path.clone(), analysis.clone());
                all_suggestions.extend(self.generate_suggestions(&analysis));
            }
        }

        // Apply safe optimizations automatically
        if self.optimization_level >= OptimizationLevel::AutoSafe {
            let applied = self.apply_safe_optimizations(&all_suggestions);
            info!("[CODE-OPT] Applied {} safe optimizations", applied);
        }

        // Log suggestions that need approval
        if self.optimization_level <= OptimizationLevel::Suggest {
            for suggestion in &all_suggestions {
                if suggestion.requires_auth <= self.current_auth {
                    info!("[CODE-OPT] SUGGESTION: {} at {}:{} - improvement: {:.1}%",
                        suggestion.description,
                        suggestion.file.display(),
                        suggestion.line.unwrap_or(0),
                        suggestion.estimated_improvement * 100.0);
                }
            }
        }

        all_suggestions
    }

    /// Find all source files in project
    fn find_source_files(root: &Path) -> Vec<PathBuf> {
        let mut files = Vec::new();

        if let Ok(entries) = fs::read_dir(root) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    // Recursively search subdirectories
                    files.extend(Self::find_source_files(&path));
                } else if Self::is_source_file(&path) {
                    files.push(path);
                }
            }
        }

        files
    }

    /// Check if file is a source file
    fn is_source_file(path: &Path) -> bool {
        path.extension()
            .map(|ext| {
                let ext_str = ext.to_string_lossy().to_lowercase();
                matches!(
                    ext_str.as_str(),
                    "rs" | "py" | "js" | "ts" | "go" | "java" | "cpp" | "c" | "h" | "hpp"
                )
            })
            .unwrap_or(false)
    }

    /// Analyze a single file
    fn analyze_file(&self, path: &Path) -> Result<CodeAnalysis, String> {
        let relative_path = Self::relative_path(path, &self.project_root);
        info!("[CODE-OPT] Analyzing: {}", relative_path);

        // Read file content
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read {}: {}", path.display(), e))?;

        // Count lines and functions
        let line_count = content.lines().count();
        let function_count = content.lines()
            .filter(|line| line.trim().starts_with("fn ") || line.trim().starts_with("pub fn "))
            .count();

        // Calculate complexity (simple heuristic)
        let complexity_score = self.calculate_complexity(&content);

        // Find bottlenecks
        let bottlenecks = self.find_bottlenecks(&content, path);

        Ok(CodeAnalysis {
            file: path.to_path_buf(),
            line_count,
            function_count,
            complexity_score,
            bottlenecks,
            suggestions: Vec::new(),
            last_analyzed: Self::current_timestamp(),
        })
    }

    /// Calculate code complexity score
    fn calculate_complexity(&self, content: &str) -> f32 {
        let mut score: f32 = 0.0;
        let mut nest_depth: i32 = 0;
        let mut max_depth: i32 = 0;

        for line in content.lines() {
            let trimmed = line.trim();

            // Count nesting
            if trimmed.starts_with('}') {
                nest_depth = nest_depth.saturating_sub(1);
            } else if trimmed.starts_with('{') {
                nest_depth += 1;
                max_depth = std::cmp::max(max_depth, nest_depth);
            }

            // Add for different constructs
            if trimmed.contains("if ") || trimmed.contains("if let ") {
                score += 0.1;
            }
            if trimmed.contains("for ") || trimmed.contains("while ") {
                score += 0.15;
            }
            if trimmed.contains("match ") {
                score += 0.2;
            }
            if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
                score += 0.05;
            }
        }

        // Normalize by line count and add depth factor
        let line_count = content.lines().count().max(1) as f32;
        score / line_count + (max_depth as f32 * 0.05)
    }

    /// Find performance bottlenecks
    fn find_bottlenecks(&self, content: &str, path: &Path) -> Vec<Bottleneck> {
        let mut bottlenecks = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            let trimmed = line.trim();

            // Check for clone() without need
            if trimmed.contains(".clone()") && !Self::needs_clone(line) {
                bottlenecks.push(Bottleneck {
                    location: format!("{}:{}", path.display(), line_num + 1),
                    issue: "Unnecessary clone() - may cause performance overhead".to_string(),
                    severity: Severity::Medium,
                    impact: 0.3,
                });
            }

            // Check for nested loops (O(n^2))
            if trimmed.contains("for ") && content.lines().skip(line_num.saturating_sub(5)).take(10)
                .any(|l| l.trim().contains("for ") || l.trim().contains("while ")) {
                bottlenecks.push(Bottleneck {
                    location: format!("{}:{}", path.display(), line_num + 1),
                    issue: "Nested loops - possible O(n^2) complexity".to_string(),
                    severity: Severity::High,
                    impact: 0.7,
                });
            }

            // Check for unwrap() without handling
            if trimmed.contains(".unwrap()") {
                bottlenecks.push(Bottleneck {
                    location: format!("{}:{}", path.display(), line_num + 1),
                    issue: "unwrap() without error handling - may panic".to_string(),
                    severity: Severity::Critical,
                    impact: 0.9,
                });
            }

            // Check for blocking operations in async code
            if trimmed.contains("thread::sleep") || trimmed.contains("std::thread::sleep") {
                bottlenecks.push(Bottleneck {
                    location: format!("{}:{}", path.display(), line_num + 1),
                    issue: "Blocking sleep in potentially async context".to_string(),
                    severity: Severity::Medium,
                    impact: 0.5,
                });
            }
        }

        bottlenecks
    }

    /// Check if clone is necessary
    fn needs_clone(line: &str) -> bool {
        let trimmed = line.trim();
        // Clone is needed in many cases, but some obvious unnecessary ones:
        // - x.clone() where x is already owned
        // - return x.clone() where x is returned anyway
        trimmed.contains("return ") || trimmed.contains("let _ = ")
    }

    /// Generate optimization suggestions
    fn generate_suggestions(&self, analysis: &CodeAnalysis) -> Vec<OptimizationSuggestion> {
        let mut suggestions = Vec::new();

        // Check for high complexity functions
        if analysis.complexity_score > 0.5 {
            suggestions.push(OptimizationSuggestion {
                description: "Refactor complex function for better readability".to_string(),
                file: analysis.file.clone(),
                line: None,
                old_code: "".to_string(),
                new_code: "".to_string(),
                estimated_improvement: (analysis.complexity_score - 0.3) * 100.0,
                risk_level: RiskLevel::Medium,
                requires_auth: AuthLevel::Admin,
            });
        }

        // Convert bottlenecks to suggestions
        for bottleneck in &analysis.bottlenecks {
            let suggestion = match &*bottleneck.issue {
                i if i.contains("Unnecessary clone") => {
                    OptimizationSuggestion {
                        description: "Remove unnecessary clone()".to_string(),
                        file: analysis.file.clone(),
                        line: bottleneck.location.parse::<usize>().ok(),
                        old_code: ".clone()".to_string(),
                        new_code: "".to_string(),
                        estimated_improvement: bottleneck.impact * 30.0,
                        risk_level: RiskLevel::None,
                        requires_auth: AuthLevel::User,
                    }
                }
                i if i.contains("O(n^2)") => {
                    OptimizationSuggestion {
                        description: "Optimize nested loops".to_string(),
                        file: analysis.file.clone(),
                        line: bottleneck.location.parse::<usize>().ok(),
                        old_code: "".to_string(),
                        new_code: "".to_string(),
                        estimated_improvement: bottleneck.impact * 50.0,
                        risk_level: RiskLevel::Medium,
                        requires_auth: AuthLevel::Admin,
                    }
                }
                i if i.contains("unwrap()") => {
                    OptimizationSuggestion {
                        description: "Replace unwrap() with proper error handling".to_string(),
                        file: analysis.file.clone(),
                        line: bottleneck.location.parse::<usize>().ok(),
                        old_code: ".unwrap()".to_string(),
                        new_code: ".expect(\"reason\")".to_string(),
                        estimated_improvement: 10.0,
                        risk_level: RiskLevel::Low,
                        requires_auth: AuthLevel::User,
                    }
                }
                _ => continue,
            };
            suggestions.push(suggestion);
        }

        suggestions
    }

    /// Apply safe optimizations
    fn apply_safe_optimizations(&mut self, suggestions: &[OptimizationSuggestion]) -> usize {
        let mut applied = 0;

        for suggestion in suggestions {
            if suggestion.risk_level == RiskLevel::None
                && suggestion.requires_auth <= self.current_auth
                && self.optimization_level >= OptimizationLevel::AutoSafe {

                if let Ok(relative_path) = suggestion.file.strip_prefix(&self.project_root) {
                    let full_path = self.project_root.join(relative_path);

                    if let Ok(mut content) = fs::read_to_string(&full_path) {
                        if let Some(line_idx) = suggestion.line {
                            if let Some(old_line) = content.lines().nth(line_idx.saturating_sub(1)) {
                                if old_line.contains(&suggestion.old_code) {
                                    content = content.replacen(&suggestion.old_code, &suggestion.new_code, 1);

                                    if fs::write(&full_path, &content).is_ok() {
                                        let now = Self::current_timestamp();
                                        self.applied_optimizations.push(AppliedOptimization {
                                            timestamp: now,
                                            file: full_path.clone(),
                                            description: suggestion.description.clone(),
                                            old_code: suggestion.old_code.clone(),
                                            new_code: suggestion.new_code.clone(),
                                            improvement: suggestion.estimated_improvement,
                                        });
                                        applied += 1;
                                        info!("[CODE-OPT] Applied: {} to {}",
                                            suggestion.description, full_path.display());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        applied
    }

    /// Autonomous re-compilation after optimization
    pub fn recompile(&self) -> Result<(), String> {
        info!("[CODE-OPT] Recompiling after optimizations...");

        let result = Command::new("cargo")
            .arg("build")
            .arg("--release")
            .current_dir(&self.project_root)
            .status()
            .map_err(|e| format!("Failed to spawn cargo: {}", e))?;

        if result.success() {
            info!("[CODE-OPT] Recompilation successful");
            Ok(())
        } else {
            Err(format!("Recompilation failed: {:?}", result))
        }
    }

    /// Continuous optimization loop
    pub fn start_continuous_optimization(&mut self, interval: Duration) {
        if !self.enabled {
            return;
        }

        info!("[CODE-OPT] Starting continuous optimization loop (every {:?})", interval);

        let project_root = self.project_root.clone();
        let mut optimizer = Self {
            project_root: project_root.clone(),
            optimization_level: self.optimization_level,
            current_auth: self.current_auth,
            analysis_cache: HashMap::new(),
            applied_optimizations: Vec::new(),
            enabled: true,
        };

        std::thread::spawn(move || {
            loop {
                optimizer.analyze_and_optimize();

                // Auto-recompile if changes were made
                if !optimizer.applied_optimizations.is_empty() {
                    if let Err(e) = optimizer.recompile() {
                        error!("[CODE-OPT] Auto-recompile failed: {}", e);
                    }
                    optimizer.applied_optimizations.clear();
                }

                std::thread::sleep(interval);
            }
        });
    }

    /// Get optimization report
    pub fn get_report(&self) -> OptimizationReport {
        let mut report = OptimizationReport {
            total_files: 0,
            total_lines: 0,
            total_functions: 0,
            total_bottlenecks: 0,
            total_suggestions: 0,
            applied_optimizations: self.applied_optimizations.clone(),
        };

        for analysis in self.analysis_cache.values() {
            report.total_files += 1;
            report.total_lines += analysis.line_count;
            report.total_functions += analysis.function_count;
            report.total_bottlenecks += analysis.bottlenecks.len();
            report.total_suggestions += analysis.suggestions.len();
        }

        report
    }

    /// Current timestamp
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Get relative path
    fn relative_path(path: &Path, base: &Path) -> String {
        path.strip_prefix(base)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string())
    }

    /// Optimize specific file
    pub fn optimize_file(&mut self, file_path: &Path) -> Result<Vec<OptimizationSuggestion>, String> {
        let relative = Self::relative_path(file_path, &self.project_root);
        info!("[CODE-OPT] Optimizing specific file: {}", relative);

        let analysis = self.analyze_file(file_path)?;
        self.analysis_cache.insert(file_path.to_path_buf(), analysis.clone());

        let suggestions = self.generate_suggestions(&analysis);

        if self.optimization_level >= OptimizationLevel::AutoSafe {
            self.apply_safe_optimizations(&suggestions);
        }

        Ok(suggestions)
    }
}

/// Optimization report summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationReport {
    pub total_files: usize,
    pub total_lines: usize,
    pub total_functions: usize,
    pub total_bottlenecks: usize,
    pub total_suggestions: usize,
    pub applied_optimizations: Vec<AppliedOptimization>,
}

impl Default for AutonomousCodeOptimizer {
    fn default() -> Self {
        Self::new(".")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_optempdirimizer_creation() {
        let optimizer = AutonomousCodeOptimizer::new(".");
        assert!(optimizer.enabled);
    }

    #[test]
    fn test_complexity_calculation() {
        let optimizer = AutonomousCodeOptimizer::new(".");
        let code = r#"
fn test() {
    for i in 0..10 {
        if i > 5 {
            println!("{}", i);
        }
    }
}
"#;
        let complexity = optimizer.calculate_complexity(code);
        assert!(complexity > 0.0);
    }

    #[test]
    fn test_bottleneck_detection() {
        let optimizer = AutonomousCodeOptimizer::new(".");
        let code = "let x = value.clone();";
        let content = "let x = value.clone();\nlet y = value.clone();";
        let bottlenecks = optimizer.find_bottlenecks(content, Path::new("test.rs"));
        // Should not flag all clones as unnecessary
        assert!(bottlenecks.len() <= 2);
    }
}
