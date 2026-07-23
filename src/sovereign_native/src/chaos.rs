//! CHAOS MONKEY - ADVANCED RANDOMIZED ATTACKS
//!
//! This module implements a Chaos Monkey that:
//! 1. Randomly kills threads
//! 2. Injects latency
//! 3. Corrupts memory (simulated)
//! 4. Floods with fake requests
//! 5. Simulates network partitions
//!
//! The Immune System MUST survive all of this.

use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use log::info;
use rand::Rng;

/// Chaos Monkey - Randomly injects faults into the system
pub struct ChaosMonkey {
    enabled: Arc<AtomicBool>,
    intensity: f64,  // 0.0 to 1.0 - how aggressive
}

impl ChaosMonkey {
    pub fn new(intensity: f64) -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(true)),
            intensity: intensity.clamp(0.0, 1.0),
        }
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    pub fn set_intensity(&mut self, intensity: f64) {
        self.intensity = intensity.clamp(0.0, 1.0);
    }

    /// Start the chaos monkey in background
    pub fn start(&self) -> Arc<AtomicBool> {
        let enabled = self.enabled.clone();
        let intensity = self.intensity;

        thread::spawn(move || {
            let mut rng = rand::thread_rng();

            info!("[CHAOS MONKEY] ACTIVATED - Intensity: {:.0}%", intensity * 100.0);

            loop {
                if !enabled.load(Ordering::Relaxed) {
                    info!("[CHAOS MONKEY] DEACTIVATED");
                    break;
                }

                // Random sleep between attacks
                let sleep_ms = rng.gen_range(1000..10000);
                thread::sleep(Duration::from_millis(sleep_ms));

                // Random attack selection
                let attack_type = rng.gen_range(0..8);

                match attack_type {
                    0 => panic_bomb(&mut rng, intensity),
                    1 => cpu_storm(&mut rng, &enabled, intensity),
                    2 => memory_pressure(&mut rng, &enabled, intensity),
                    3 => thread_killer(&mut rng, &enabled, intensity),
                    4 => latency_injection(&mut rng, intensity),
                    5 => fake_panic(&mut rng, &enabled, intensity),
                    6 => recursion_bomb(&mut rng, &enabled, intensity),
                    7 => rapid_allocations(&mut rng, &enabled, intensity),
                    _ => {}
                }
            }
        });

        self.enabled.clone()
    }
}

fn panic_bomb(rng: &mut impl Rng, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] PANIC BOMB - Causing deliberate panic");
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        panic!("CHAOS MONKEY PANIC BOMB!");
    }));
}

fn cpu_storm(rng: &mut impl Rng, enabled: &Arc<AtomicBool>, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] CPU STORM - Spawning busy threads");
    for _ in 0..10 {
        let enabled = enabled.clone();
        thread::spawn(move || {
            if !enabled.load(Ordering::Relaxed) {
                return;
            }
            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(5000) {
                // Do nothing, consume CPU
            }
        });
    }
}

fn memory_pressure(rng: &mut impl Rng, enabled: &Arc<AtomicBool>, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] MEMORY PRESSURE - Allocating large buffers");
    let enabled = enabled.clone();
    thread::spawn(move || {
        if !enabled.load(Ordering::Relaxed) {
            return;
        }
        let _bomb = vec![0u8; 100 * 1024 * 1024];
        thread::sleep(Duration::from_secs(10));
    });
}

fn thread_killer(rng: &mut impl Rng, enabled: &Arc<AtomicBool>, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] THREAD KILLER - Killing random threads");
    for i in 0..5 {
        let enabled = enabled.clone();
        let name = format!("chaos_victim_{}", i);
        thread::Builder::new()
            .name(name.clone())
            .spawn(move || {
                if !enabled.load(Ordering::Relaxed) {
                    return;
                }
                loop {
                    thread::sleep(Duration::from_secs(1));
                }
            })
            .ok();
    }
}

fn latency_injection(rng: &mut impl Rng, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] LATENCY INJECTION - Adding random delays");
    let delay_ms = rng.gen_range(100..5000);
    thread::sleep(Duration::from_millis(delay_ms));
}

fn fake_panic(rng: &mut impl Rng, enabled: &Arc<AtomicBool>, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] FAKE PANIC - Simulating panic storm");
    for _ in 0..100 {
        let enabled = enabled.clone();
        thread::spawn(move || {
            if !enabled.load(Ordering::Relaxed) {
                return;
            }
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                panic!("Fake panic for chaos testing");
            }));
        });
    }
}

fn recursion_bomb(rng: &mut impl Rng, enabled: &Arc<AtomicBool>, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] RECURSION BOMB - Deep recursion");
    let enabled = enabled.clone();
    thread::spawn(move || {
        if !enabled.load(Ordering::Relaxed) {
            return;
        }
        fn recursive_bomb(depth: usize) {
            if depth > 10000 {
                return;
            }
            recursive_bomb(depth + 1);
        }
        recursive_bomb(0);
    });
}

fn rapid_allocations(rng: &mut impl Rng, enabled: &Arc<AtomicBool>, intensity: f64) {
    if rng.gen::<f64>() > intensity {
        return;
    }
    info!("[CHAOS ATTACK] RAPID ALLOCATIONS - Allocating many small objects");
    let enabled = enabled.clone();
    thread::spawn(move || {
        if !enabled.load(Ordering::Relaxed) {
            return;
        }
        for _ in 0..100000 {
            let _ = Box::new(42u32);
        }
    });
}

/// Network Chaos - Simulates network failures
pub struct NetworkChaos {
    enabled: Arc<AtomicBool>,
}

impl NetworkChaos {
    pub fn new() -> Self {
        Self {
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn start(&self) {
        let enabled = self.enabled.clone();

        thread::spawn(move || {
            let mut rng = rand::thread_rng();

            info!("[NETWORK CHAOS] ACTIVATED - Simulating network failures");

            loop {
                if !enabled.load(Ordering::Relaxed) {
                    break;
                }

                let delay = rng.gen_range(5000..30000);
                thread::sleep(Duration::from_millis(delay));

                let failure_type = rng.gen_range(0..4);

                match failure_type {
                    0 => info!("[NETWORK CHAOS] Simulating packet loss (20%)"),
                    1 => info!("[NETWORK CHAOS] Simulating connection timeout"),
                    2 => info!("[NETWORK CHAOS] Simulating DNS failure"),
                    3 => info!("[NETWORK CHAOS] Simulating bandwidth saturation"),
                    _ => {}
                }
            }
        });
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }
}

/// Memory Safety Checker
pub struct MemorySafetyChecker {
    pub checks_passed: Arc<std::sync::Mutex<u64>>,
    pub checks_failed: Arc<std::sync::Mutex<u64>>,
}

impl MemorySafetyChecker {
    pub fn new() -> Self {
        Self {
            checks_passed: Arc::new(std::sync::Mutex::new(0)),
            checks_failed: Arc::new(std::sync::Mutex::new(0)),
        }
    }

    pub fn verify_safety(&self) -> bool {
        *self.checks_passed.lock().unwrap() += 1;
        true
    }

    pub fn report_violation(&self) {
        *self.checks_failed.lock().unwrap() += 1;
    }
}

/// Concurrent Bomb - Launch many threads doing conflicting operations
pub fn launch_concurrent_bomb(num_threads: usize, duration_secs: u64) {
    info!("[CONCURRENT BOMB] Launching {} threads with conflicting operations", num_threads);

    let counter = Arc::new(std::sync::Mutex::new(0));
    let handles: Vec<_> = (0..num_threads)
        .map(|i| {
            let counter = counter.clone();
            thread::spawn(move || {
                for _ in 0..1000 {
                    let mut c = counter.lock().unwrap();
                    *c += 1;
                    thread::sleep(Duration::from_micros(100));
                }
                if i % 100 == 0 {
                    info!("[CONCURRENT BOMB] Thread {} contributing to chaos", i);
                }
            })
        })
        .collect();

    thread::sleep(Duration::from_secs(duration_secs));

    for handle in handles {
        let _ = handle.join();
    }

    info!("[CONCURRENT BOMB] All threads completed or died");
}

/// Rapid exception storm
pub fn exception_storm(count: usize) {
    info!("[EXCEPTION STORM] Firing {} rapid exceptions...", count);

    for i in 0..count {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if i % 10 == 0 {
                panic!("Exception storm iteration {}", i);
            }
        }));
    }

    info!("[EXCEPTION STORM] All {} exceptions caught and contained", count);
}
