//! UBE Immune System - Compact Edition
//! Core self-healing protection that NEVER fails

pub mod compilation_error;
pub mod runtime_guard;
pub mod guards;

use guards::*;

/// Main Immune System
#[derive(Clone)]
pub struct ImmuneSystem {
    pub error_detector: compilation_error::CompilationErrorDetector,
    pub error_fixer: compilation_error::CompilationErrorFixer,
    pub panic_guard: runtime_guard::PanicGuard,
    pub result_guard: runtime_guard::ResultGuard,
    pub null_guard: NullGuard,
    pub bounds_guard: BoundsGuard,
    pub math_guard: MathGuard,
    pub io_guard: IoGuard,
    pub parse_guard: ParseGuard,
}

impl ImmuneSystem {
    pub fn new(root: &str) -> Self {
        Self {
            error_detector: compilation_error::CompilationErrorDetector::new(root),
            error_fixer: compilation_error::CompilationErrorFixer,
            panic_guard: runtime_guard::PanicGuard,
            result_guard: runtime_guard::ResultGuard,
            null_guard: NullGuard,
            bounds_guard: BoundsGuard,
            math_guard: MathGuard,
            io_guard: IoGuard,
            parse_guard: ParseGuard,
        }
    }

    /// Protect code from panics
    pub fn protect<F, R>(&self, f: F) -> Result<R, runtime_guard::RuntimeError>
    where
        F: FnOnce() -> R + std::panic::UnwindSafe,
        R: Send + 'static,
    {
        runtime_guard::PanicGuard::guard(f)
    }

    /// Detect compilation errors
    pub fn detect_errors(&self) -> Vec<compilation_error::CompilationError> {
        self.error_detector.detect_errors()
    }

    /// Fix compilation errors
    pub fn fix_errors(&self, errors: &[compilation_error::CompilationError]) -> Vec<compilation_error::CodeFix> {
        errors.iter()
            .filter_map(|e| self.error_fixer.suggest_fix(e))
            .collect()
    }
}
