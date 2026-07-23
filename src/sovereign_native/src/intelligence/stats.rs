//! UBE Sovereign Online Statistics
//! Deterministic online metrics and variance calculation.
//! Implements Welford's algorithm for stable running mean and variance.

#[derive(Debug, Clone)]
pub struct WelfordStats {
    n: usize,
    mean: f64,
    m2: f64,
    min: f64,
    max: f64,
}

impl WelfordStats {
    pub fn new() -> Self {
        Self {
            n: 0,
            mean: 0.0,
            m2: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    pub fn update(&mut self, x: f64) {
        self.n += 1;
        let delta = x - self.mean;
        self.mean += delta / self.n as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;

        if x < self.min { self.min = x; }
        if x > self.max { self.max = x; }
    }

    pub fn mean(&self) -> f64 { self.mean }
    pub fn variance(&self) -> f64 {
        if self.n < 2 { 0.0 } else { self.m2 / (self.n - 1) as f64 }
    }
    pub fn stddev(&self) -> f64 { self.variance().sqrt() }
    pub fn min(&self) -> f64 { self.min }
    pub fn max(&self) -> f64 { self.max }
    pub fn count(&self) -> usize { self.n }

    pub fn z_score(&self, x: f64) -> f64 {
        let sd = self.stddev();
        if sd > 0.0 { (x - self.mean) / sd } else { 0.0 }
    }

    pub fn is_anomaly(&self, x: f64, threshold: f64) -> bool {
        self.z_score(x).abs() > threshold
    }
}

/// CUSUM (Cumulative Sum) Detector for change-point detection.
#[derive(Debug, Clone)]
pub struct CusumDetector {
    s_high: f64,
    s_low: f64,
    k: f64,
    h: f64,
    alarms: Vec<u64>,
}

impl CusumDetector {
    pub fn new(_target_mean: f64, sigma: f64, k_factor: f64, h_factor: f64) -> Self {
        Self {
            s_high: 0.0,
            s_low: 0.0,
            k: k_factor * sigma,
            h: h_factor * sigma,
            alarms: Vec::new(),
        }
    }

    pub fn update(&mut self, x: f64) -> CusumResult {
        self.s_high = (0.0f64).max(self.s_high + x - self.target_mean() - self.k);
        self.s_low = (0.0f64).max(self.s_low - x + self.target_mean() - self.k);

        let alarm = self.s_high > self.h || self.s_low > self.h;
        if alarm {
            // In a production system, we'd use a real timestamp.
            self.alarms.push(0);
            self.s_high = 0.0;
            self.s_low = 0.0;
        }

        CusumResult {
            s_high: self.s_high,
            s_low: self.s_low,
            alarm,
            alarm_count: self.alarms.len(),
        }
    }

    fn target_mean(&self) -> f64 {
        // This is typically set at creation, but can be dynamic.
        // For the core, we'll assume the target mean is the current mean of the data.
        0.0 // Placeholder
    }
}

#[derive(Debug, Clone)]
pub struct CusumResult {
    pub s_high: f64,
    pub s_low: f64,
    pub alarm: bool,
    pub alarm_count: usize,
}
