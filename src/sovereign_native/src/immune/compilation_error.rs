//! UBE Sovereign Immune System - Compilation Error Detection
//!
//! Layer 1-3: Static analysis and compile-time error detection
//! This module detects and fixes compilation errors WITHOUT requiring full build

#![allow(dead_code)]
use std::process::Command;
use std::path::Path;
use regex::Regex;

/// A detected compilation error with full context
#[derive(Debug, Clone)]
pub struct CompilationError {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub error_code: String,
    pub message: String,
    pub severity: ErrorSeverity,
}

/// Error severity level for prioritization
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Must fix - blocks compilation
    Fatal,
    /// Should fix - warning but compiles
    Warning,
    /// Info - style/suggestion
    Info,
}

impl CompilationError {
    pub fn new(file: &str, line: u32, column: u32, error_code: &str, message: &str) -> Self {
        let severity = if error_code.starts_with('E') {
            ErrorSeverity::Fatal
        } else if error_code.starts_with('W') {
            ErrorSeverity::Warning
        } else {
            ErrorSeverity::Info
        };

        Self {
            file: file.to_string(),
            line,
            column,
            error_code: error_code.to_string(),
            message: message.to_string(),
            severity,
        }
    }

    /// Returns true if this is a fatal error (blocks compilation)
    pub fn is_fatal(&self) -> bool {
        self.severity == ErrorSeverity::Fatal
    }
}

/// Patterns for parsing Rust compiler output
#[derive(Clone)]
pub struct CompilationErrorDetector {
    project_root: String,
    /// Matches: error[E0277]: ... --> file.rs:line:column: message
    error_pattern: Regex,
    /// Matches: warning: ... --> file.rs:line:column: message
    warning_pattern: Regex,
}

impl CompilationErrorDetector {
    /// Create a new error detector for the project
    pub fn new(project_root: &str) -> Self {
        // Pattern: error[E0277]: message --> src/file.rs:line:column: detail
        let error_pattern = Regex::new(
            r"^error\[([A-Z0-9]+)\]:\s*(.+?)\s+-->\s+([^:]+):(\d+):(\d+)"
        ).unwrap();

        let warning_pattern = Regex::new(
            r"^warning:\s*(.+?)\s+-->\s+([^:]+):(\d+):(\d+)"
        ).unwrap();

        Self {
            project_root: project_root.to_string(),
            error_pattern,
            warning_pattern,
        }
    }

    /// Run cargo check (faster than build) and capture all errors
    pub fn detect_errors(&self) -> Vec<CompilationError> {
        let output = Command::new("cargo")
            .args(&["check", "--all"])
            .current_dir(&self.project_root)
            .output()
            .expect("Failed to run cargo check");

        let stderr = String::from_utf8_lossy(&output.stderr);
        self.parse_errors(&stderr)
    }

    /// Parse compiler output and extract all errors
    pub fn parse_errors(&self, output: &str) -> Vec<CompilationError> {
        let mut errors = Vec::new();

        for line in output.lines() {
            // Try error pattern first
            if let Some(caps) = self.error_pattern.captures(line) {
                let error_code = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                let message = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
                let file = caps.get(3).map(|m| m.as_str().to_string()).unwrap_or_default();
                let line_num: u32 = caps.get(4).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0);
                let col_num: u32 = caps.get(5).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0);

                errors.push(CompilationError::new(&file, line_num, col_num, &error_code, &message));
            }
            // Try warning pattern
            else if let Some(caps) = self.warning_pattern.captures(line) {
                let message = caps.get(1).map(|m| m.as_str().to_string()).unwrap_or_default();
                let file = caps.get(2).map(|m| m.as_str().to_string()).unwrap_or_default();
                let line_num: u32 = caps.get(3).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0);
                let col_num: u32 = caps.get(4).map(|m| m.as_str().parse().unwrap_or(0)).unwrap_or(0);

                errors.push(CompilationError::new(&file, line_num, col_num, "W0001", &message));
            }
        }

        errors
    }
}

/// Fix strategies for common Rust error codes
#[derive(Clone)]
pub struct CompilationErrorFixer;

impl CompilationErrorFixer {
    /// Generate a fix suggestion for an error
    pub fn suggest_fix(&self, error: &CompilationError) -> Option<CodeFix> {
        match error.error_code.as_str() {
            // E0599: No method/variant named X
            "E0599" => self.fix_e0599(error),
            // E0308: Mismatched types
            "E0308" => self.fix_e0308(error),
            // E0277: Trait bound not satisfied
            "E0277" => self.fix_e0277(error),
            // E0061: Cannot return reference to local variable
            "E0061" => self.fix_e0061(error),
            // E0282: Type annotations needed
            "E0282" => self.fix_e0282(error),
            // E0433: Failed to resolve - missing import/use
            "E0433" => self.fix_e0433(error),
            // E0412: Type not in scope
            "E0412" => self.fix_e0412(error),
            // E0596: Cannot borrow as mutable
            "E0596" => self.fix_e0596(error),
            // E0382: Borrow of moved value
            "E0382" => self.fix_e0382(error),
            // E0271: Type mismatch in trait implementation
            "E0271" => self.fix_e0271(error),
            _ => None,
        }
    }

    fn fix_e0599(&self, error: &CompilationError) -> Option<CodeFix> {
        let message = &error.message;

        // serde_json::Value::Map -> serde_json::Value::Object
        if message.contains("Map") && message.contains("serde_json::Value") {
            Some(CodeFix::replace(
                &error.file,
                error.line,
                "Value::Map(",
                "Value::Object(",
                "serde_json::Value uses Object variant, not Map",
            ))
        }
        // serde_json::Value::List -> serde_json::Value::Array
        else if message.contains("List") && message.contains("serde_json::Value") {
            Some(CodeFix::replace(
                &error.file,
                error.line,
                "Value::List(",
                "Value::Array(",
                "serde_json::Value uses Array variant, not List",
            ))
        }
        // no method named `append` for Arc
        else if message.contains("no method named `append`") {
            Some(CodeFix::replace(
                &error.file,
                error.line,
                ".append(",
                ".push(",
                "Arc<Vec> doesn't have append, use push instead",
            ))
        }
        else {
            None
        }
    }

    fn fix_e0308(&self, error: &CompilationError) -> Option<CodeFix> {
        let message = &error.message;

        // expected `Result<_, _>`, found `Option<_>`
        if message.contains("expected `Result") && message.contains("found `Option") {
            Some(CodeFix::wrap_result(
                &error.file,
                error.line,
                "Convert Option to Result with ok_or",
            ))
        }
        // expected `&str`, found `String`
        else if message.contains("expected `&str") && message.contains("found `String") {
            Some(CodeFix::add_as_str(
                &error.file,
                error.line,
                "Add .as_str() to convert String to &str",
            ))
        }
        else {
            None
        }
    }

    fn fix_e0277(&self, error: &CompilationError) -> Option<CodeFix> {
        let message = &error.message;

        // LowerHex trait bound for [u8]
        if message.contains("LowerHex") && message.contains("[u8]") {
            Some(CodeFix::replace(
                &error.file,
                error.line,
                "format!(\"{{:x}}\", data)",
                "format!(\"{{:x?}}\", data)",
                "Use Debug formatting {:x?} for byte slices",
            ))
        }
        // Clone trait for dyn Fn
        else if message.contains("Clone") && message.contains("dyn Fn") {
            Some(CodeFix::wrap_with_arc(
                &error.file,
                error.line,
                "Wrap closure in Arc for Clone",
            ))
        }
        // Default trait for custom type
        else if message.contains("Default") {
            Some(CodeFix::derive_default(
                &error.file,
                error.line,
                "Add #[derive(Default)] to struct",
            ))
        }
        else {
            None
        }
    }

    fn fix_e0061(&self, error: &CompilationError) -> Option<CodeFix> {
        Some(CodeFix::return_owned(
            &error.file,
            error.line,
            "Return owned value instead of reference to local variable",
        ))
    }

    fn fix_e0282(&self, error: &CompilationError) -> Option<CodeFix> {
        Some(CodeFix::add_type_annotation(
            &error.file,
            error.line,
            "Add explicit type annotation",
        ))
    }

    fn fix_e0433(&self, error: &CompilationError) -> Option<CodeFix> {
        let message = &error.message;
        // Missing `use` declaration or module path
        if message.contains("use of undeclared") || message.contains("cannot find") {
            Some(CodeFix::insert(
                &error.file,
                1,
                "// use crate::path::to::Module; // Add proper use statement",
                "Add missing use declaration",
            ))
        } else {
            None
        }
    }

    fn fix_e0412(&self, error: &CompilationError) -> Option<CodeFix> {
        Some(CodeFix::insert(
            &error.file,
            1,
            "// use std::... // Add missing std import",
            "Add missing std type import",
        ))
    }

    fn fix_e0596(&self, error: &CompilationError) -> Option<CodeFix> {
        let message = &error.message;
        // Cannot borrow as mutable - need mut
        if message.contains("cannot borrow") && message.contains("as mutable") {
            Some(CodeFix::replace(
                &error.file,
                error.line,
                "&",
                "&mut ",
                "Add mut keyword for mutable borrow",
            ))
        } else {
            None
        }
    }

    fn fix_e0382(&self, error: &CompilationError) -> Option<CodeFix> {
        let message = &error.message;
        // Borrow of moved value - use clone or reference
        if message.contains("borrow of moved value") {
            Some(CodeFix::replace(
                &error.file,
                error.line,
                "let x = ",
                "let x = &",
                "Borrow instead of moving value",
            ))
        } else {
            None
        }
    }

    fn fix_e0271(&self, error: &CompilationError) -> Option<CodeFix> {
        let message = &error.message;
        // Type mismatch in trait impl - often needs explicit type or trait bound
        if message.contains("expected") && message.contains("found") {
            Some(CodeFix::insert(
                &error.file,
                error.line,
                "// #[derive(...)] or add trait bound: T: Trait",
                "Add trait bound or derive",
            ))
        } else {
            None
        }
    }
}

/// A suggested fix for a compilation error
#[derive(Debug, Clone)]
pub struct CodeFix {
    pub file: String,
    pub line: u32,
    pub fix_type: FixType,
    pub description: String,
    pub rationale: String,
}

/// Types of fixes that can be applied
#[derive(Debug, Clone)]
pub enum FixType {
    /// Replace one string with another
    Replace { old: String, new: String },
    /// Insert code at a position
    Insert { at_line: u32, code: String },
    /// Add method to impl block
    AddMethod { impl_block: String, method_code: String },
    /// Wrap expression with something (like Arc)
    Wrap { expression: String, wrapper: String },
    /// Add trait derive
    Derive { trait_name: String },
    /// Add .as_str() or similar conversion
    Convert { from: String, to: String, method: String },
    /// Wrap return value to fix lifetime
    ReturnOwned,
    /// Add type annotation
    AnnotateType { type_name: String },
}

impl CodeFix {
    pub fn replace(file: &str, line: u32, old: &str, new: &str, rationale: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            fix_type: FixType::Replace {
                old: old.to_string(),
                new: new.to_string(),
            },
            description: format!("Replace '{}' with '{}'", old, new),
            rationale: rationale.to_string(),
        }
    }

    pub fn insert(file: &str, at_line: u32, code: &str, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line: at_line,
            fix_type: FixType::Insert {
                at_line,
                code: code.to_string(),
            },
            description: description.to_string(),
            rationale: "Insert missing code".to_string(),
        }
    }

    pub fn wrap_with_arc(file: &str, line: u32, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            fix_type: FixType::Wrap {
                expression: "dyn Fn".to_string(),
                wrapper: "Arc<dyn Fn>".to_string(),
            },
            description: description.to_string(),
            rationale: "Arc provides Clone implementation for trait objects".to_string(),
        }
    }

    pub fn derive_default(file: &str, line: u32, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            fix_type: FixType::Derive {
                trait_name: "Default".to_string(),
            },
            description: description.to_string(),
            rationale: "Add Default derive for automatic default implementation".to_string(),
        }
    }

    pub fn return_owned(file: &str, line: u32, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            fix_type: FixType::ReturnOwned,
            description: description.to_string(),
            rationale: "Return owned value to avoid reference to local".to_string(),
        }
    }

    pub fn add_type_annotation(file: &str, line: u32, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            fix_type: FixType::AnnotateType {
                type_name: "_".to_string(),
            },
            description: description.to_string(),
            rationale: "Add explicit type annotation for type inference".to_string(),
        }
    }

    pub fn add_method(file: &str, impl_block: &str, method_code: &str, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line: 0,
            fix_type: FixType::AddMethod {
                impl_block: impl_block.to_string(),
                method_code: method_code.to_string(),
            },
            description: description.to_string(),
            rationale: "Add missing method implementation".to_string(),
        }
    }

    pub fn wrap_result(file: &str, line: u32, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            fix_type: FixType::Convert {
                from: "Option".to_string(),
                to: "Result".to_string(),
                method: "ok_or".to_string(),
            },
            description: description.to_string(),
            rationale: "Convert Option to Result for error handling".to_string(),
        }
    }

    pub fn add_as_str(file: &str, line: u32, description: &str) -> Self {
        Self {
            file: file.to_string(),
            line,
            fix_type: FixType::Convert {
                from: "String".to_string(),
                to: "&str".to_string(),
                method: "as_str".to_string(),
            },
            description: description.to_string(),
            rationale: "Add .as_str() to convert String to &str".to_string(),
        }
    }

    /// Apply this fix to the file
    pub fn apply(&self) -> Result<bool, std::io::Error> {
        let path = Path::new(&self.file);
        if !path.exists() {
            return Ok(false);
        }

        let content = std::fs::read_to_string(path)?;
        let fixed = match &self.fix_type {
            FixType::Replace { old, new } => content.replace(old, new),
            FixType::Insert { at_line, code } => {
                let mut lines: Vec<&str> = content.lines().collect();
                if *at_line > 0 && (at_line - 1) < lines.len() as u32 {
                    lines.insert((at_line - 1) as usize, code.as_str());
                } else {
                    lines.push(code.as_str());
                }
                lines.join("\n")
            }
            FixType::Wrap { expression, wrapper } => {
                content.replace(expression, wrapper)
            }
            FixType::Derive { trait_name } => {
                // Add derive to struct
                let derive = format!("#[derive({})]", trait_name);
                if content.contains("pub struct") && !content.contains(&derive) {
                    content.replace("pub struct", &format!("{}\n{}", derive, "pub struct"))
                } else {
                    content.clone()
                }
            }
            FixType::ReturnOwned => {
                // Replace return &local with return local.clone() or return local
                content.clone().replace("return &", "return ")
            }
            FixType::Convert { from, to: _, method } => {
                content.clone().replace(&format!(".{}", from.to_lowercase()), &format!(".{}", method))
            }
            FixType::AnnotateType { type_name: _ } => {
                // This needs more context - just return unchanged for now
                content.clone()
            }
            FixType::AddMethod { impl_block, method_code } => {
                if content.contains(impl_block) {
                    let insert_pos = content.find(impl_block).unwrap_or(0) + impl_block.len();
                    let mut new_content = content.clone();
                    new_content.insert_str(insert_pos, method_code);
                    new_content
                } else {
                    content.clone()
                }
            }
        };

        if content != fixed {
            std::fs::write(path, fixed)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_compilation_error() {
        let detector = CompilationErrorDetector::new(".");
        let output = r#"error[E0277]: `(dyn for<'a> Fn(&'a IntelligenceHub) -> bool + Send + Sync + 'static)` doesn't implement `std::fmt::Debug` --> src/main.rs:102:9"#;

        let errors = detector.parse_errors(output);
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].error_code, "E0277");
        assert_eq!(errors[0].file, "src/main.rs");
        assert_eq!(errors[0].line, 102);
        assert_eq!(errors[0].column, 9);
    }

    #[test]
    fn test_suggest_fix_e0599_value_map() {
        let fixer = CompilationErrorFixer;
        let error = CompilationError::new(
            "src/test.rs",
            42,
            5,
            "E0599",
            "no variant named `Map` found for enum `serde_json::Value`",
        );

        let fix = fixer.suggest_fix(&error);
        assert!(fix.is_some());
        assert!(fix.unwrap().description.contains("Object"));
    }
}
