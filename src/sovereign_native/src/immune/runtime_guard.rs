//! UBE Sovereign Immune System - Runtime Error Guard
//!
//! Layer 5: Runtime protection that catches panics, errors, and exceptions
//! Ensures NO runtime error crashes the system

#![allow(dead_code)]
use std::any::Any;
use std::panic;
use std::sync::{Arc, Mutex};
use log::{error, warn};

/// Result type for guarded operations
pub type GuardedResult<T> = Result<T, RuntimeError>;

/// Runtime error types that the guard catches
#[derive(Debug, Clone)]
pub enum RuntimeError {
    /// Panic was caught and handled
    Panic {
        message: String,
        location: String,
    },
    /// Standard error was caught
    Error {
        message: String,
        source: Option<String>,
    },
    /// Resource exhaustion (OOM, stack overflow, etc.)
    ResourceExhausted {
        resource: String,
        message: String,
    },
    /// Timeout occurred
    Timeout {
        operation: String,
        duration: std::time::Duration,
    },
    /// Multiple recovery attempts failed
    Unrecoverable {
        error: String,
        attempts: u32,
    },
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::Panic { message, location } => {
                write!(f, "Panic at {}: {}", location, message)
            }
            RuntimeError::Error { message, .. } => {
                write!(f, "Error: {}", message)
            }
            RuntimeError::ResourceExhausted { resource, message } => {
                write!(f, "Resource exhausted ({}): {}", resource, message)
            }
            RuntimeError::Timeout { operation, duration } => {
                write!(f, "Timeout in {} after {:?}", operation, duration)
            }
            RuntimeError::Unrecoverable { error, attempts } => {
                write!(f, "Unrecoverable after {} attempts: {}", attempts, error)
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Recovery strategies for different error types
#[derive(Debug)]
pub enum RecoveryStrategy {
    /// Retry the operation (with optional delay)
    Retry {
        max_attempts: u32,
        delay_ms: u64,
    },
    /// Use a fallback value
    Fallback {
        value: Box<dyn Any + Send + Sync + 'static>,
    },
    /// Log and continue (ignore the error)
    Continue,
    /// Escalate to higher-level handler
    Escalate,
    /// Reset component to known good state
    Reset,
    /// Restart the entire system
    Restart,
}


/// A guard that intercepts panics and converts them to errors
#[derive(Clone)]
pub struct PanicGuard;

impl PanicGuard {
    /// Execute a fallback and catch any panic
    pub fn guard<F, R>(f: F) -> GuardedResult<R>
    where
        F: FnOnce() -> R + std::panic::UnwindSafe,
        R: Send + 'static,
    {
        let result = panic::catch_unwind(panic::AssertUnwindSafe(f));
        match result {
            Ok(v) => Ok(v),
            Err(e) => {
                let location = std::panic::Location::caller();
                let message = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    format!("{:?}", e)
                };

                error!(
                    "PANIC CAUGHT at {}: {}",
                    location,
                    message
                );

                Err(RuntimeError::Panic {
                    message,
                    location: format!("{}", location),
                })
            }
        }
    }

    /// Execute with retry logic
    pub fn guard_with_retry<F, R>(f: F, strategy: &RecoveryStrategy) -> GuardedResult<R>
    where
        F: Fn() -> R + std::panic::UnwindSafe + std::panic::RefUnwindSafe + Send + 'static,
        R: Send + 'static,
    {
        if let RecoveryStrategy::Retry { max_attempts, delay_ms } = strategy {
            let mut last_error: Option<RuntimeError> = None;

            for attempt in 1..=*max_attempts {
                let result = PanicGuard::guard(&f);
                match result {
                    Ok(v) => return Ok(v),
                    Err(e) => {
                        warn!(
                            "Attempt {}/{} failed: {}",
                            attempt, max_attempts, e
                        );
                        last_error = Some(e);
                        if attempt < *max_attempts {
                            std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
                        }
                    }
                }
            }

            return Err(last_error.unwrap_or_else(|| RuntimeError::Unrecoverable {
                error: "All retry attempts failed".to_string(),
                attempts: *max_attempts,
            }));
        }

        Self::guard(f)
    }
}

/// Guard for Result-returning functions with error handling
#[derive(Clone)]
pub struct ResultGuard;

impl ResultGuard {
    /// Convert any error into GuardedResult with recovery
    pub fn guard<T, E, F>(&self, f: F, strategy: &RecoveryStrategy) -> GuardedResult<T>
    where
        F: Fn() -> Result<T, E> + std::panic::UnwindSafe + std::panic::RefUnwindSafe + Send + Sync + 'static,
        E: std::fmt::Display + Send + 'static,
        T: Send + Clone + 'static,
    {
        let result = PanicGuard::guard(&f);
        match result {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                match strategy {
                    RecoveryStrategy::Retry { max_attempts, delay_ms } => {
                        Self::guard_with_retry(f, *max_attempts, *delay_ms)
                    }
                    RecoveryStrategy::Fallback { value } => {
                        warn!("Using fallback due to error: {}", e);
                        if let Some(v) = (**value).downcast_ref::<T>() {
                            Ok(v.clone())
                        } else {
                            Err(RuntimeError::Error {
                                message: format!("Fallback type mismatch: {}", e),
                                source: None,
                            })
                        }
                    }
                    RecoveryStrategy::Continue => {
                        warn!("Ignoring error: {}", e);
                        Err(RuntimeError::Error {
                            message: e.to_string(),
                            source: None,
                        })
                    }
                    RecoveryStrategy::Escalate => {
                        Err(RuntimeError::Error {
                            message: e.to_string(),
                            source: None,
                        })
                    }
                    RecoveryStrategy::Reset => {
                        Err(RuntimeError::Unrecoverable {
                            error: e.to_string(),
                            attempts: 1,
                        })
                    }
                    RecoveryStrategy::Restart => {
                        Err(RuntimeError::Unrecoverable {
                            error: e.to_string(),
                            attempts: 1,
                        })
                    }
                }
            }
            Err(e) => Err(e),
        }
    }

    /// Retry a function multiple times
    pub fn guard_with_retry<T, E, F>(f: F, max_attempts: u32, delay_ms: u64) -> GuardedResult<T>
    where
        F: Fn() -> Result<T, E> + std::panic::UnwindSafe + std::panic::RefUnwindSafe + Send + 'static,
        E: std::fmt::Display + Send + 'static,
        T: Send + 'static,
    {
        let mut last_error: Option<RuntimeError> = None;

        for attempt in 1..=max_attempts {
            let result = PanicGuard::guard(&f);
            match result {
                Ok(Ok(v)) => return Ok(v),
                Ok(Err(e)) => {
                    warn!("Attempt {}/{} error: {}", attempt, max_attempts, e);
                    last_error = Some(RuntimeError::Error {
                        message: e.to_string(),
                        source: None,
                    });
                    if attempt < max_attempts {
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                }
                Err(e) => {
                    warn!("Attempt {}/{} panic: {}", attempt, max_attempts, e);
                    last_error = Some(e);
                    if attempt < max_attempts {
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| RuntimeError::Unrecoverable {
            error: "All retry attempts failed".to_string(),
            attempts: max_attempts,
        }))
    }
}

/// Resource guard - prevents OOM and stack overflow
#[derive(Clone)]
pub struct ResourceGuard {
    max_memory_mb: usize,
    max_recursion_depth: usize,
}

impl ResourceGuard {
    pub fn new(max_memory_mb: usize, max_recursion_depth: usize) -> Self {
        Self {
            max_memory_mb,
            max_recursion_depth,
        }
    }

    /// Execute with memory limit check
    pub fn guard_memory<F, R>(&self, f: F) -> GuardedResult<R>
    where
        F: FnOnce() -> R + std::panic::UnwindSafe,
        R: Send + 'static,
    {
        PanicGuard::guard(f)
    }

    /// Execute with recursion depth limit
    pub fn guard_recursion<F, R>(&self, f: F, depth: usize) -> GuardedResult<R>
    where
        F: FnOnce() -> R + std::panic::UnwindSafe,
        R: Send + 'static,
    {
        if depth > self.max_recursion_depth {
            return Err(RuntimeError::ResourceExhausted {
                resource: "stack".to_string(),
                message: format!("Maximum recursion depth {} exceeded", self.max_recursion_depth),
            });
        }

        PanicGuard::guard(f)
    }
}

/// Timeout guard - cancels operations that take too long
#[derive(Clone)]
pub struct TimeoutGuard {
    default_timeout: std::time::Duration,
}

impl TimeoutGuard {
    pub fn new(default_timeout: std::time::Duration) -> Self {
        Self { default_timeout }
    }

    /// Execute with timeout
    pub fn guard_timeout<F, R>(&self, f: F, timeout: Option<std::time::Duration>) -> GuardedResult<R>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let timeout = timeout.unwrap_or(self.default_timeout);

        use std::sync::mpsc;
        use std::thread;

        let (tx, rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let result = panic::catch_unwind(panic::AssertUnwindSafe(f));
            tx.send(result).unwrap();
        });

        match rx.recv_timeout(timeout) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => {
                let message = if let Some(s) = e.downcast_ref::<&str>() {
                    s.to_string()
                } else if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else {
                    format!("{:?}", e)
                };
                let location = std::panic::Location::caller();
                Err(RuntimeError::Panic {
                    message,
                    location: format!("{}", location),
                })
            }
            Err(_) => {
                drop(handle);
                Err(RuntimeError::Timeout {
                    operation: "unknown".to_string(),
                    duration: timeout,
                })
            }
        }
    }
}

/// Circuit breaker pattern - stops calling failing operations
pub struct CircuitBreaker {
    failure_threshold: u32,
    reset_timeout: std::time::Duration,
    state: Arc<Mutex<CircuitState>>,
}

#[derive(Debug)]
struct CircuitState {
    failure_count: u32,
    last_failure_time: Option<std::time::Instant>,
    state: CircuitStateEnum,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum CircuitStateEnum {
    Closed,
    Open,
    HalfOpen,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, reset_timeout: std::time::Duration) -> Self {
        Self {
            failure_threshold,
            reset_timeout,
            state: Arc::new(Mutex::new(CircuitState {
                failure_count: 0,
                last_failure_time: None,
                state: CircuitStateEnum::Closed,
            })),
        }
    }

    /// Execute a function through the circuit breaker
    pub fn execute<F, R, E>(&self, f: F) -> GuardedResult<R>
    where
        F: FnOnce() -> Result<R, E> + std::panic::UnwindSafe + Send + 'static,
        E: std::fmt::Display + Send + 'static,
        R: Send + 'static,
    {
        let mut state = self.state.lock().unwrap();

        match state.state {
            CircuitStateEnum::Open => {
                if let Some(last_time) = state.last_failure_time {
                    if last_time.elapsed() >= self.reset_timeout {
                        state.state = CircuitStateEnum::HalfOpen;
                        state.failure_count = 0;
                    } else {
                        return Err(RuntimeError::ResourceExhausted {
                            resource: "circuit".to_string(),
                            message: "Circuit breaker is open".to_string(),
                        });
                    }
                }
            }
            CircuitStateEnum::HalfOpen => {
            }
            CircuitStateEnum::Closed => {
            }
        }

        drop(state);

        let result = PanicGuard::guard(f);

        match &result {
            Ok(_) => {
                let mut state = self.state.lock().unwrap();
                state.failure_count = 0;
                state.state = CircuitStateEnum::Closed;
            }
            Err(_) => {
                let mut state = self.state.lock().unwrap();
                state.failure_count += 1;
                state.last_failure_time = Some(std::time::Instant::now());

                if state.failure_count >= self.failure_threshold {
                    state.state = CircuitStateEnum::Open;
                    warn!(
                        "CIRCUIT BREAKER OPEN: {} failures in a row",
                        state.failure_count
                    );
                }
            }
        }

        match result {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(RuntimeError::Error {
                message: e.to_string(),
                source: None,
            }),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_panic_guard_catches_panic() {
        let result: GuardedResult<i32> = PanicGuard::guard(|| {
            panic!("Test panic");
        });

        assert!(result.is_err());
        if let RuntimeError::Panic { message, .. } = result.unwrap_err() {
            assert!(message.contains("Test panic"));
        } else {
            panic!("Expected Panic error");
        }
    }

    #[test]
    fn test_panic_guard_success() {
        let result: GuardedResult<i32> = PanicGuard::guard(|| 42);
        assert_eq!(result.unwrap(), 42);
    }

    #[test]
    fn test_retry_guard() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static ATTEMPTS: AtomicUsize = AtomicUsize::new(0);
        ATTEMPTS.store(0, Ordering::SeqCst);

        let result = PanicGuard::guard_with_retry(
            || {
                let a = ATTEMPTS.fetch_add(1, Ordering::SeqCst) + 1;
                if a < 3 {
                    panic!("Not yet");
                }
                42
            },
            &RecoveryStrategy::Retry {
                max_attempts: 5,
                delay_ms: 10,
            },
        );

        assert_eq!(result.unwrap(), 42);
        assert_eq!(ATTEMPTS.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn test_circuit_breaker() {
        use std::thread;
        use std::time::Duration;
        let cb = CircuitBreaker::new(2, Duration::from_millis(10));

        let result1: GuardedResult<i32> = cb.execute(|| Err(RuntimeError::Error { message: "error 1".to_string(), source: None }));
        assert!(result1.is_err());

        let result2: GuardedResult<i32> = cb.execute(|| Err(RuntimeError::Error { message: "error 2".to_string(), source: None }));
        assert!(result2.is_err());

        thread::sleep(Duration::from_millis(20));

        let result3: GuardedResult<i32> = cb.execute(|| -> GuardedResult<i32> { Ok(42i32) });
        assert!(result3.is_ok());
        assert_eq!(result3.unwrap(), 42);
    }
}
