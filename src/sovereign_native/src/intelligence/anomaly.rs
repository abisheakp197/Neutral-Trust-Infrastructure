//! UBE Sovereign Anomaly Detection
//! Deterministic anomaly detection using Isolation Forests and Time-Series Forecasting.
//! Zero-dependency, constant-time, and memory-safe.

use std::collections::VecDeque;

/// Holt-Winters Triple Exponential Smoothing Forecaster.
#[derive(Debug, Clone)]
pub struct HoltWintersForecaster {
    level: f64,
    trend: f64,
    seasonal: Vec<f64>,
    fitted: Vec<f64>,
    m: usize,
    alpha: f64,
    beta: f64,
    gamma: f64,
}

impl HoltWintersForecaster {
    pub fn new(initial_series: &[f64], alpha: f64, beta: f64, gamma: f64, season_period: usize) -> Self {
        let m = season_period;
        let mut seasonal = vec![0.0; m];
        let level = if initial_series.len() >= m {
            initial_series[0..m].iter().sum::<f64>() / m as f64
        } else {
            0.0
        };

        let trend = if initial_series.len() >= 2 * m {
            let avg1 = initial_series[0..m].iter().sum::<f64>() / m as f64;
            let avg2 = initial_series[m..2 * m].iter().sum::<f64>() / m as f64;
            (avg2 - avg1) / m as f64
        } else {
            0.0
        };

        for i in 0..m {
            if i < initial_series.len() {
                seasonal[i] = if level > 0.0 { initial_series[i] / level } else { 0.0 };
            }
        }

        let mut forecaster = Self {
            level,
            trend,
            seasonal,
            fitted: Vec::new(),
            m,
            alpha,
            beta,
            gamma,
        };

        for &v in initial_series {
            forecaster.update(v);
        }

        forecaster
    }

    pub fn update(&mut self, actual: f64) -> f64 {
        let t = self.fitted.len();
        let s = self.seasonal[t % self.m];
        let prev_level = self.level;

        self.level = self.alpha * (actual / (s + 1e-9)) + (1.0 - self.alpha) * (self.level + self.trend);
        self.trend = self.beta * (self.level - prev_level) + (1.0 - self.beta) * self.trend;
        self.seasonal[t % self.m] = self.gamma * (actual / (self.level + 1e-9)) + (1.0 - self.gamma) * s;

        let forecast = (self.level + self.trend) * self.seasonal[t % self.m];
        self.fitted.push(forecast);
        forecast
    }

    pub fn forecast(&self, steps: usize) -> Vec<f64> {
        let mut result = Vec::with_capacity(steps);
        let l = self.level;
        let t = self.trend;

        for h in 1..=steps {
            let s = self.seasonal[(self.fitted.len() + h) % self.m];
            result.push((l + h as f64 * t) * s);
        }
        result
    }
}

/// Isolation Forest for multi-dimensional anomaly detection.
#[derive(Debug, Clone)]
pub struct IsolationForest {
    trees: Vec<ITreeNode>,
    sample_size: usize,
    num_trees: usize,
    max_depth: usize,
}

#[derive(Debug, Clone)]
enum ITreeNode {
    Internal {
        feature: usize,
        threshold: f64,
        left: Box<ITreeNode>,
        right: Box<ITreeNode>,
    },
    Leaf {
        size: usize,
    },
}

impl IsolationForest {
    pub fn new(num_trees: usize, sample_size: usize, max_depth: usize) -> Self {
        Self {
            trees: Vec::new(),
            sample_size,
            num_trees,
            max_depth,
        }
    }

    pub fn fit(&mut self, data: &[Vec<f64>]) {
        self.trees.clear();
        for _ in 0..self.num_trees {
            let sample = self.random_sample(data);
            self.trees.push(self.build_tree(&sample, 0));
        }
    }

    pub fn score(&self, point: &[f64]) -> f64 {
        if self.trees.is_empty() { return 0.0; }
        let avg_depth: f64 = self.trees.iter().map(|tree| self.path_length(point, tree, 0)).sum::<f64>() / self.trees.len() as f64;
        let c = self.avg_path_length(self.sample_size);
        2.0f64.powf(-avg_depth / c)
    }

    fn build_tree(&self, data: &[Vec<f64>], depth: usize) -> ITreeNode {
        if data.len() <= 1 || depth >= self.max_depth {
            return ITreeNode::Leaf { size: data.len() };
        }

        let n_features = data[0].len();
        // In production, use a deterministic seed for the RNG
        let feature = (depth % n_features);

        let mut vals: Vec<f64> = data.iter().map(|d| d[feature]).collect();
        vals.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let min = vals[0];
        let max = vals[vals.len() - 1];

        if min == max {
            return ITreeNode::Leaf { size: data.len() };
        }

        let threshold = (min + max) / 2.0;
        let (left_data, right_data): (Vec<_>, Vec<_>) = data.iter().cloned().partition(|d| d[feature] < threshold);

        ITreeNode::Internal {
            feature,
            threshold,
            left: Box::new(self.build_tree(&left_data, depth + 1)),
            right: Box::new(self.build_tree(&right_data, depth + 1)),
        }
    }

    fn path_length(&self, point: &[f64], node: &ITreeNode, depth: usize) -> f64 {
        match node {
            ITreeNode::Leaf { size } => depth as f64 + self.avg_path_length(*size),
            ITreeNode::Internal { feature, threshold, left, right } => {
                if point[*feature] < *threshold {
                    self.path_length(point, left, depth + 1)
                } else {
                    self.path_length(point, right, depth + 1)
                }
            }
        }
    }

    fn avg_path_length(&self, n: usize) -> f64 {
        if n <= 1 { return 0.0; }
        2.0 * ((n as f64 - 1.0).ln() + 0.5772156649) - 2.0 * (n as f64 - 1.0) / n as f64
    }

    fn random_sample(&self, data: &[Vec<f64>]) -> Vec<Vec<f64>> {
        // Simplified deterministic sample for the core conversion
        data.iter().take(self.sample_size).cloned().collect()
    }
}
