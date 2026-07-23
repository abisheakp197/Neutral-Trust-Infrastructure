//! UBE Immune System - Guards
use crate::immune::runtime_guard::RuntimeError;
pub type GuardedResult<T> = Result<T, RuntimeError>;

/// Prevents null/None dereferences
#[derive(Clone, Copy, Debug, Default)]
pub struct NullGuard;

impl NullGuard {
    pub fn check<T>(&self, value: Option<T>) -> GuardedResult<T> {
        value.ok_or(RuntimeError::Error {
            message: "Null value dereferenced".to_string(),
            source: None,
        })
    }

    pub fn check_ref<'a, T>(&self, value: &'a Option<T>) -> GuardedResult<&'a T> {
        value.as_ref().ok_or(RuntimeError::Error {
            message: "Null reference dereferenced".to_string(),
            source: None,
        })
    }
}

/// Prevents index out of bounds
#[derive(Clone, Copy, Debug, Default)]
pub struct BoundsGuard;

impl BoundsGuard {
    pub fn check<'a, T>(&self, index: usize, slice: &'a [T]) -> GuardedResult<&'a T> {
        slice.get(index).ok_or(RuntimeError::Error {
            message: format!("Index {} out of bounds for slice of length {}", index, slice.len()),
            source: None,
        })
    }

    pub fn check_usize(&self, index: usize, len: usize) -> GuardedResult<usize> {
        if index < len {
            Ok(index)
        } else {
            Err(RuntimeError::Error {
                message: format!("Index {} out of bounds for length {}", index, len),
                source: None,
            })
        }
    }
}

/// Prevents math errors
#[derive(Clone, Copy, Debug, Default)]
pub struct MathGuard;

impl MathGuard {
    pub fn check_add<T: std::ops::Add<Output = T> + Copy>(&self, a: T, b: T) -> GuardedResult<T> {
        Ok(a + b)
    }

    pub fn check_div(&self, numerator: i64, denominator: i64) -> GuardedResult<i64> {
        if denominator == 0 {
            Err(RuntimeError::Error {
                message: "Division by zero".to_string(),
                source: None,
            })
        } else {
            Ok(numerator / denominator)
        }
    }

    pub fn check_div_f64(&self, numerator: f64, denominator: f64) -> GuardedResult<f64> {
        if denominator == 0.0 {
            Err(RuntimeError::Error {
                message: "Division by zero".to_string(),
                source: None,
            })
        } else {
            Ok(numerator / denominator)
        }
    }
}

/// Prevents I/O errors
#[derive(Clone, Copy, Debug, Default)]
pub struct IoGuard;

impl IoGuard {
    pub fn check_read<T, F>(&self, f: F) -> GuardedResult<T>
    where
        F: FnOnce() -> std::io::Result<T>,
    {
        f().map_err(|e| RuntimeError::Error {
            message: format!("I/O error: {}", e),
            source: None,
        })
    }

    pub fn check_write<T, F>(&self, f: F) -> GuardedResult<T>
    where
        F: FnOnce() -> std::io::Result<T>,
    {
        f().map_err(|e| RuntimeError::Error {
            message: format!("I/O write error: {}", e),
            source: None,
        })
    }
}

/// Prevents network errors
#[derive(Clone, Debug, Default)]
pub struct NetworkGuard;

impl NetworkGuard {
    pub fn check_connection<F, T>(&self, f: F) -> GuardedResult<T>
    where
        F: FnOnce() -> Result<T, std::io::Error>,
    {
        f().map_err(|e| RuntimeError::Error {
            message: format!("Network error: {}", e),
            source: None,
        })
    }
}

/// Prevents parsing errors
#[derive(Clone, Copy, Debug, Default)]
pub struct ParseGuard;

impl ParseGuard {
    pub fn check_json<T: for<'de> serde::Deserialize<'de>>(&self, json: &str) -> GuardedResult<T> {
        serde_json::from_str(json).map_err(|e| RuntimeError::Error {
            message: format!("JSON parse error: {}", e),
            source: None,
        })
    }

    pub fn check_parse<T: std::str::FromStr>(&self, s: &str) -> GuardedResult<T> {
        s.parse().map_err(|_| RuntimeError::Error {
            message: format!("Parse error for type {}", std::any::type_name::<T>()),
            source: None,
        })
    }
}

/// Prevents type errors
#[derive(Clone, Copy, Debug, Default)]
pub struct TypeGuard;

impl TypeGuard {
    pub fn check_downcast<'a, T: 'static, U: 'static>(&self, value: &'a U) -> GuardedResult<&'a T> {
        match (value as &dyn std::any::Any).downcast_ref::<T>() {
            Some(t) => Ok(t),
            None => Err(RuntimeError::Error {
                message: format!("Type mismatch: expected {}, got {}",
                    std::any::type_name::<T>(),
                    std::any::type_name::<U>()),
                source: None,
            }),
        }
    }
}

/// Prevents conversion errors
#[derive(Clone, Copy, Debug, Default)]
pub struct ConversionGuard;

impl ConversionGuard {
    pub fn check_from<T, U>(&self, value: U) -> GuardedResult<T>
    where
        T: std::convert::From<U>,
    {
        Ok(T::from(value))
    }

    pub fn check_try_from<T, U>(&self, value: U) -> GuardedResult<T>
    where
        T: std::convert::TryFrom<U>,
    {
        T::try_from(value).map_err(|_| RuntimeError::Error {
            message: "Conversion failed".to_string(),
            source: None,
        })
    }
}
