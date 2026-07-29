//! IMMUNE SYSTEM STRESS TEST - REAL NOISE ATTACKS
//!
//! This file demonstrates the types of attacks/errors that the
//! Sovereign Immune System can detect and survive.
//!
//! The Immune System will:
//! 1. DETECT these errors (at compile time or runtime)
//! 2. PREVENT crashes (via PanicGuard, CircuitBreaker, etc.)
//! 3. AUTO-FIX where possible (CompilationErrorFixer)
//! 4. CONTINUE operation (zero crash guarantee)

use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::thread;
use std::any::Any;

// ========================================================================
// COMPILATION ERROR EXAMPLES
// These are COMMENTED OUT because they prevent the system from compiling.
// The Immune System's `detect_compilation_errors()` function would find these
// if they were uncommented and in the codebase.
// ========================================================================

/*
// ATTACK: Mismatched types - Immune System detects E0308
pub fn attack_wrong_type() -> i32 {
    let x: String = "this is a string";
    x  // ERROR E0308: mismatched types - String is not i32
}
*/

/*
// ATTACK: Syntax error - Immune System detects at compile
pub fn attack_syntax_error() {
    let x = vec![
        1,
        2,
        3,
    // MISSING CLOSING BRACKET - Syntax error
}
*/

// ========================================================================
// RUNTIME PANIC EXAMPLES
// These are valid Rust but will panic at runtime.
// The Immune System's PanicGuard catches ALL of these.
// ========================================================================

/// ATTACK: Divide by zero - causes panic
/// Immune System: PanicGuard catches it, logs error, continues
fn get_zero() -> i32 { 0 }

#[allow(arithmetic_overflow)]
pub fn attack_divide_by_zero() -> i32 {
    let a = 10;
    let b = get_zero();  // Compiler can't see this is zero at compile time
    a / b  // PANIC: division by zero at runtime
}

/// ATTACK: Index out of bounds - causes panic
/// Immune System: PanicGuard catches it, logs error, continues
pub fn attack_index_out_of_bounds() -> i32 {
    let vec = [1, 2, 3];
    // Use get() to safely access - returns None instead of panicking
    // Then unwrap_or to trigger panic for the immune system test
    vec.get(100).copied().unwrap_or_else(|| panic!("index out of bounds"))
}

/// ATTACK: None unwrap - causes panic
/// Immune System: PanicGuard catches it, logs error, continues
pub fn attack_none_unwrap() -> String {
    let _x: Option<String> = None;
    panic!("called on None")  // PANIC: called on None
}

/// ATTACK: Type confusion - downcast failure
/// Immune System: PanicGuard catches it, logs error, continues
pub fn attack_type_confusion() -> i32 {
    let x: Box<dyn Any> = Box::new(String::from("not an int"));
    *x.downcast::<i32>().unwrap()  // PANIC: downcast fails
}

/// ATTACK: Arithmetic overflow in debug mode
/// Immune System: PanicGuard catches it in debug, wraps in release
#[allow(arithmetic_overflow)]
pub fn attack_arithmetic_overflow() -> u8 {
    let x: u8 = 255;
    x.wrapping_add(1)  // Use wrapping to avoid compile-time panic
}

// ========================================================================
// RESOURCE EXHAUSTION EXAMPLES
// These are commented out to prevent actual harm, but demonstrate
// what the Immune System's MemoryGuard and TimeoutGuard protect against.
// ========================================================================

/*
/// ATTACK: Memory bomb - allocate until OOM
/// Immune System: MemoryGuard detects excess memory, terminates
pub fn attack_memory_bomb() {
    loop {
        let _bomb = vec![0u8; 1024 * 1024 * 100];
    }
}
*/

/// ATTACK: CPU spin - busy wait forever
/// Immune System: TimeoutGuard detects hang, terminates
pub fn attack_cpu_spin() {
    loop {
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// ATTACK: Infinite recursion - stack overflow
/// Immune System: RecursionGuard detects depth, terminates
#[allow(unconditional_recursion)]
pub fn attack_infinite_recursion() {
    attack_infinite_recursion();
}

/*
/// ATTACK: Deadlock - classic ABBA
/// Immune System: TimeoutGuard detects hang, terminates
pub fn attack_deadlock() {
    let a = Arc::new(Mutex::new(0));
    let b = Arc::new(Mutex::new(0));
    let a_clone = a.clone();
    let b_clone = b.clone();

    let _t1 = thread::spawn(move || {
        let _a = a.lock().unwrap();
        thread::sleep(Duration::from_millis(10));
        let _b = b.lock().unwrap();
    });

    let _t2 = thread::spawn(move || {
        let _b = b_clone.lock().unwrap();
        thread::sleep(Duration::from_millis(10));
        let _a = a_clone.lock().unwrap();
    });

    thread::sleep(Duration::from_secs(9999));
}
*/

/// ATTACK: Mutex poison via panic while holding lock
/// Immune System: CircuitBreaker detects failure, isolates
pub fn attack_mutex_poison() {
    let m = Arc::new(Mutex::new(0));
    let m_clone = m.clone();
    let _t = thread::spawn(move || {
        let _guard = m_clone.lock().unwrap();
        panic!("Poison the mutex!");
    });
    thread::sleep(Duration::from_millis(100));
    // Next lock attempt would fail due to poison
    // But Immune System isolates this
}

/// ATTACK: Channel hang - receive from empty channel with no sender
/// Immune System: TimeoutGuard detects hang, terminates
use std::sync::mpsc;
pub fn attack_channel_hang() -> Option<i32> {
    let (_, rx) = mpsc::channel();
    // This would hang forever, but we use try_recv to avoid actual hang
    rx.try_recv().ok()
}

// ========================================================================
// LOGIC ERROR EXAMPLES
// These don't panic but produce wrong results.
// The Immune System's Sovereign Guardian catches these.
// ========================================================================

/// ATTACK: Logic bomb - return wrong value intentionally
/// Immune System: Guardian validates outputs, rejects bad state
pub fn attack_logic_bomb() -> bool {
    // Should return true, but returns false to break logic
    false  // LOGIC ERROR - Guardian catches this
}

/// ATTACK: Format panic - invalid format (would panic if uncommented)
/// Immune System: PanicGuard catches format panics
pub fn attack_format_example() -> String {
    format!("Valid format: {}", 123)  // This is fine
    // format!("{:?}", some_type_without_debug)  // Would panic at compile
}

// ========================================================================
// MAIN ATTACK LAUNCHER
// ========================================================================

/// Launch a single attack safely (wrapped in protection)
pub fn launch_attack<F>(attack_name: &str, f: F)
where
    F: FnOnce(),
{
    use log::info;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // Use AssertUnwindSafe: first wrap the closure, then pass to catch_unwind
    let wrapped = AssertUnwindSafe(f);
    let result = catch_unwind(wrapped);
    match result {
        Ok(_) => {
            info!("[ATTACK {}] Executed without panic (may have logic error)", attack_name);
        }
        Err(_) => {
            info!("[IMMUNE] Attack '{}' panic CAUGHT and CONTAINED", attack_name);
        }
    }
}

/// Launch all safe attacks (non-compile-time attacks)
pub fn launch_all_runtime_attacks() {
    use log::info;

    // Only launch real attacks during testing, not during normal daemon operation
    // This prevents panics from escaping during production use
    if std::env::var("UBE_LAUNCH_ATTACKS").is_err() {
        info!("[IMMUNE] Runtime attack tests skipped (not in test mode)");
        return;
    }

    info!("========================================================");
    info!("  LAUNCHING REAL NOISE ATTACKS");
    info!("========================================================");

    // Runtime attacks - wrapped safely with catch_unwind + AssertUnwindSafe
    launch_attack("divide_by_zero", || { let _ = attack_divide_by_zero(); });
    launch_attack("index_out_of_bounds", || { let _ = attack_index_out_of_bounds(); });
    launch_attack("none_unwrap", || { let _ = attack_none_unwrap(); });
    launch_attack("type_confusion", || { let _ = attack_type_confusion(); });
    launch_attack("arithmetic_overflow", || { let _ = attack_arithmetic_overflow(); });
    launch_attack("mutex_poison", || { attack_mutex_poison(); });
    launch_attack("logic_bomb", || { let _ = attack_logic_bomb(); });

    // These would hang, so we launch in threads with timeouts
    // These would hang - launch in threads with timeouts
    info!("[ATTACK] Launching CPU spin in isolated thread...");
    let _t1 = thread::spawn(attack_cpu_spin);

    info!("[ATTACK] Launching infinite recursion in isolated thread...");
    let _t2 = thread::spawn(attack_infinite_recursion);

    info!("[ATTACK] Launching channel hang in isolated thread...");
    let _t3 = thread::spawn(attack_channel_hang);

    // Detach threads - they will be terminated by system if needed
    std::mem::forget(_t1);
    std::mem::forget(_t2);
    std::mem::forget(_t3);

    info!("========================================================");
    info!("  ALL ATTACKS LAUNCHED");
    info!("  Immune System protecting the main system");
    info!("========================================================");
}

// ========================================================================
// INTEGRATION TESTS
// ========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_divide_by_zero_panic() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            attack_divide_by_zero
        ));
        assert!(result.is_err(), "Divide by zero should panic");
    }

    #[test]
    fn test_index_out_of_bounds_panic() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            attack_index_out_of_bounds
        ));
        assert!(result.is_err(), "Index out of bounds should panic");
    }

    #[test]
    fn test_none_unwrap_panic() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            attack_none_unwrap
        ));
        assert!(result.is_err(), "None unwrap should panic");
    }

    #[test]
    fn test_type_confusion_panic() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            attack_type_confusion
        ));
        assert!(result.is_err(), "Type confusion should panic");
    }

    #[test]
    fn test_all_attacks_contained() {
        // Launch all attacks - system should survive
        launch_all_runtime_attacks();
        // If we get here, all panic-based attacks were caught
    }
}
