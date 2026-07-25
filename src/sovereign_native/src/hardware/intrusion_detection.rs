//! UBE Sovereign Intrusion Detection System (IDS)
//!
//! Hardware-backed intrusion detection with:
//! - Real-time network monitoring
//! - Behavior analysis
//! - Signature-based detection
//! - Anomaly detection
//! - Automatic response

use std::sync::{Arc, Mutex, RwLock};
use std::collections::{HashMap, VecDeque, HashSet};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::net::{IpAddr, SocketAddr};
use serde::{Serialize, Deserialize};
use crate::hardware::{SovereignHSM, SecurityStatus, HardwareError};
use crate::hardware::anti_tamper::{AntiTamperSystem, TamperEvent, TamperMethod, TamperStatus};
use crate::crypto::blake3::Blake3;

/// Intrusion detection event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntrusionEvent {
    pub timestamp: u64,
    pub event_type: IntrusionEventType,
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    pub severity: f64, // 0.0 to 1.0
    pub confidence: f64, // 0.0 to 1.0
    pub details: String,
    pub payload_hash: Option<Vec<u8>>,
    pub action_taken: IntrusionAction,
    pub hardware_attested: bool,
}

/// Intrusion event types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntrusionEventType {
    /// Network port scan detected
    PortScan,
    /// Brute force attack
    BruteForce,
    /// SQL injection attempt
    SqlInjection,
    /// Cross-site scripting attempt
    XssAttempt,
    /// Buffer overflow attempt
    BufferOverflow,
    /// Denial of service attack
    DosAttack,
    /// Man-in-the-middle attack
    MitmAttack,
    /// Replay attack
    ReplayAttack,
    /// Invalid protocol data
    ProtocolViolation,
    /// Authentication bypass attempt
    AuthBypass,
    /// Privilege escalation attempt
    PrivilegeEscalation,
    /// Malicious payload detected
    MaliciousPayload,
    /// Anomalous behavior
    Anomaly,
    /// Hardwarre tampering
    HardwareTamper,
}

/// Actions taken in response to intrusion
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntrusionAction {
    /// Log and continue monitoring
    LogOnly,
    /// Drop connection
    DropConnection,
    /// Block IP address
    BlockIp,
    /// Throttle connection
    Throttle,
    /// Trigger deception layer
    TriggerDeception,
    /// Quarantine node
    Quarantine,
    /// Trigger self-destruct
    SelfDestruct,
    /// Notify administrators
    NotifyAdmin,
}

/// Network connection tracker
pub struct ConnectionTracker {
    /// Active connections
    active_connections: Arc<RwLock<HashMap<SocketAddr, ConnectionState>>>,
    /// Connection history
    connection_history: Mutex<VecDeque<ConnectionRecord>>,
    /// Blocked IPs
    blocked_ips: Arc<RwLock<HashSet<IpAddr>>>,
    /// Rate limiting tracker
    rate_limiter: RwLock<HashMap<IpAddr, RateLimitState>>,
    /// Max history size
    max_history: usize,
}

/// Connection state
#[derive(Debug, Clone)]
pub struct ConnectionState {
    pub connected_at: u64,
    pub last_activity: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub protocol: String,
    pub authenticated: bool,
    pub public_key: Option<Vec<u8>>,
    pub threat_score: f64,
}

/// Connection record
#[derive(Debug, Clone)]
pub struct ConnectionRecord {
    pub source: SocketAddr,
    pub destination: SocketAddr,
    pub connected_at: u64,
    pub disconnected_at: u64,
    pub duration: u64,
    pub bytes_transferred: u64,
    pub protocol: String,
    pub success: bool,
}

/// Rate limit state
#[derive(Debug, Clone)]
pub struct RateLimitState {
    pub requests: VecDeque<u64>, // Timestamps of requests
    pub last_reset: u64,
    pub blocked_until: Option<u64>,
}

impl ConnectionTracker {
    pub fn new(max_history: usize) -> Arc<Self> {
        Arc::new(Self {
            active_connections: Arc::new(RwLock::new(HashMap::new())),
            connection_history: Mutex::new(VecDeque::with_capacity(max_history)),
            blocked_ips: Arc::new(RwLock::new(HashSet::new())),
            rate_limiter: RwLock::new(HashMap::new()),
            max_history,
        })
    }

    /// Track new connection
    pub fn track_connection(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        protocol: &str,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut connections = self.active_connections.write().unwrap();
        let state = ConnectionState {
            connected_at: now,
            last_activity: now,
            bytes_sent: 0,
            bytes_received: 0,
            protocol: protocol.to_string(),
            authenticated: false,
            public_key: None,
            threat_score: 0.0,
        };

        connections.insert(source, state);
    }

    /// Update connection activity
    pub fn update_activity(&self, source: &SocketAddr, bytes_received: u64, bytes_sent: u64) {
        let mut connections = self.active_connections.write().unwrap();
        if let Some(state) = connections.get_mut(source) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            state.last_activity = now;
            state.bytes_received += bytes_received;
            state.bytes_sent += bytes_sent;
        }
    }

    /// End connection
    pub fn end_connection(&self, source: &SocketAddr) -> Option<ConnectionRecord> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut connections = self.active_connections.write().unwrap();
        if let Some(state) = connections.remove(source) {
            let record = ConnectionRecord {
                source: *source,
                destination: SocketAddr::from(([0, 0, 0, 0], 0)), // Would be set properly
                connected_at: state.connected_at,
                disconnected_at: now,
                duration: now.saturating_sub(state.connected_at),
                bytes_transferred: state.bytes_sent + state.bytes_received,
                protocol: state.protocol,
                success: state.authenticated,
            };

            let mut history = self.connection_history.lock().unwrap();
            if history.len() >= self.max_history {
                history.pop_front();
            }
            history.push_back(record.clone());

            return Some(record);
        }

        None
    }

    /// Check if IP is blocked
    pub fn is_blocked(&self, ip: &IpAddr) -> bool {
        let blocked = self.blocked_ips.read().unwrap();
        blocked.contains(ip)
    }

    /// Block an IP
    pub fn block_ip(&self, ip: IpAddr, duration: Option<Duration>) {
        let mut blocked = self.blocked_ips.write().unwrap();
        blocked.insert(ip);

        // Start a thread to unblock after duration
        if let Some(dur) = duration {
            let blocked_clone = Arc::clone(&self.blocked_ips);
            std::thread::spawn(move || {
                std::thread::sleep(dur);
                let mut blocked = blocked_clone.write().unwrap();
                blocked.remove(&ip);
            });
        }
    }

    /// Check rate limit
    pub fn check_rate_limit(&self, ip: &IpAddr, max_requests: usize, window: Duration) -> Result<(), IntrusionAction> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut rate_limiter = self.rate_limiter.write().unwrap();

        // Clean old requests
        let state = rate_limiter.entry(*ip).or_insert_with(|| RateLimitState {
            requests: VecDeque::new(),
            last_reset: now,
            blocked_until: None,
        });

        // Check if currently blocked
        if let Some(blocked_until) = state.blocked_until {
            if now < blocked_until {
                return Err(IntrusionAction::DropConnection);
            } else {
                state.blocked_until = None;
                state.requests.clear();
            }
        }

        // Remove old requests
        while let Some(oldest) = state.requests.front() {
            if now - oldest > window.as_secs() {
                state.requests.pop_front();
            } else {
                break;
            }
        }

        // Check if rate limited
        if state.requests.len() >= max_requests {
            // Block for remaining window time
            state.blocked_until = Some(now + window.as_secs());
            return Err(IntrusionAction::Throttle);
        }

        // Add current request
        state.requests.push_back(now);

        Ok(())
    }
}

/// Payload analyzer
pub struct PayloadAnalyzer {
    /// Known malicious signatures
    malicious_signatures: HashSet<Vec<u8>>,
    /// Suspicious patterns
    suspicious_patterns: Vec<(Vec<u8>, f64)>, // (pattern, severity)
    /// Content types
    content_types: HashMap<String, ContentTypeInfo>,
}

/// Content type information
#[derive(Debug, Clone)]
pub struct ContentTypeInfo {
    pub expected: bool,
    pub max_size: usize,
    pub allowed_chars: Option<Vec<u8>>,
}

impl PayloadAnalyzer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            malicious_signatures: HashSet::new(),
            suspicious_patterns: Vec::new(),
            content_types: HashMap::new(),
        })
    }

    /// Analyze payload for threats
    pub fn analyze(&self, payload: &[u8], content_type: Option<&str>) -> Vec<IntrusionEvent> {
        let mut events = Vec::new();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // 1. Check against malicious signatures
        let payload_hash = Blake3::hash(payload).to_vec();
        if self.malicious_signatures.contains(&payload_hash) {
            events.push(IntrusionEvent {
                timestamp: now,
                event_type: IntrusionEventType::MaliciousPayload,
                source: None,
                destination: None,
                severity: 1.0,
                confidence: 1.0,
                details: "Known malicious payload detected".to_string(),
                payload_hash: Some(payload_hash.clone()),
                action_taken: IntrusionAction::DropConnection,
                hardware_attested: false,
            });
            return events;
        }

        // 2. Check for suspicious patterns
        for (pattern, severity) in &self.suspicious_patterns {
            if self.contains_pattern(payload, pattern) {
                events.push(IntrusionEvent {
                    timestamp: now,
                    event_type: IntrusionEventType::Anomaly,
                    source: None,
                    destination: None,
                    severity: *severity,
                    confidence: 0.8,
                    details: format!("Suspicious pattern detected: {:?}", String::from_utf8_lossy(pattern)),
                    payload_hash: Some(payload_hash.clone()),
                    action_taken: IntrusionAction::LogOnly,
                    hardware_attested: false,
                });
            }
        }

        // 3. Check SQL injection
        if self.detect_sql_injection(payload) {
            events.push(IntrusionEvent {
                timestamp: now,
                event_type: IntrusionEventType::SqlInjection,
                source: None,
                destination: None,
                severity: 0.9,
                confidence: 0.95,
                details: "SQL injection attempt detected".to_string(),
                payload_hash: Some(payload_hash.clone()),
                action_taken: IntrusionAction::DropConnection,
                hardware_attested: false,
            });
        }

        // 4. Check buffer overflow patterns
        if self.detect_buffer_overflow(payload) {
            events.push(IntrusionEvent {
                timestamp: now,
                event_type: IntrusionEventType::BufferOverflow,
                source: None,
                destination: None,
                severity: 1.0,
                confidence: 0.9,
                details: "Buffer overflow attempt detected".to_string(),
                payload_hash: Some(payload_hash.clone()),
                action_taken: IntrusionAction::DropConnection,
                hardware_attested: false,
            });
        }

        // 5. Check content type validity
        if let Some(ct) = content_type {
            if let Some(info) = self.content_types.get(ct) {
                if !info.expected && info.max_size < payload.len() {
                    events.push(IntrusionEvent {
                        timestamp: now,
                        event_type: IntrusionEventType::ProtocolViolation,
                        source: None,
                        destination: None,
                        severity: 0.7,
                        confidence: 0.8,
                        details: format!("Content type {} with unexpected size: {} > {}", ct, payload.len(), info.max_size),
                        payload_hash: Some(payload_hash.clone()),
                        action_taken: IntrusionAction::DropConnection,
                        hardware_attested: false,
                    });
                }
            }
        }

        events
    }

    /// Check if payload contains pattern
    fn contains_pattern(&self, payload: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() {
            return false;
        }
        payload.windows(pattern.len()).any(|window| window == pattern)
    }

    /// Detect SQL injection patterns
    fn detect_sql_injection(&self, payload: &[u8]) -> bool {
        let payload_str = String::from_utf8_lossy(payload).to_lowercase();
        let patterns = [
            "' or '",
            "' or 1=1",
            "' or '1'='1",
            "select * from",
            "insert into",
            "delete from",
            "drop table",
            "union select",
            "--",
            "/*",
            "xp_",
            "exec ",
            "execute ",
        ];

        patterns.iter().any(|p| payload_str.contains(p))
    }

    /// Detect buffer overflow patterns
    fn detect_buffer_overflow(&self, payload: &[u8]) -> bool {
        // Check for extremely long strings (potential buffer overflow)
        if payload.len() > 1024 * 1024 {
            return true;
        }

        // Check for NOP sled patterns (0x90 0x90 0x90...)
        if payload.len() >= 16 {
            let nop_sled: Vec<u8> = vec![0x90; 16];
            if self.contains_pattern(payload, &nop_sled) {
                return true;
            }
        }

        // Check for repeated patterns (potential heap spray)
        false
    }

    /// Add malicious signature
    pub fn add_malicious_signature(&mut self, signature: Vec<u8>) {
        self.malicious_signatures.insert(signature);
    }

    /// Add suspicious pattern
    pub fn add_suspicious_pattern(&mut self, pattern: Vec<u8>, severity: f64) {
        self.suspicious_patterns.push((pattern, severity));
    }
}

/// Behavior analyzer
pub struct BehaviorAnalyzer {
    /// Baseline behavior profiles
    baselines: HashMap<String, BehaviorProfile>,
    /// Current session data
    sessions: RwLock<HashMap<SocketAddr, BehaviorSession>>,
}

/// Behavior profile for a module/entity
#[derive(Debug, Clone)]
pub struct BehaviorProfile {
    pub avg_request_rate: f64,
    pub avg_request_size: f64,
    pub allowed_operations: HashSet<String>,
    pub typical_patterns: Vec<Vec<u8>>,
}

/// Behavior session for tracking current behavior
#[derive(Debug, Clone)]
pub struct BehaviorSession {
    pub start_time: u64,
    pub request_count: u64,
    pub total_bytes: u64,
    pub last_request_time: u64,
    pub operations: HashMap<String, u64>,
    pub anomaly_score: f64,
}

impl BehaviorAnalyzer {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            baselines: HashMap::new(),
            sessions: RwLock::new(HashMap::new()),
        })
    }

    /// Start tracking a session
    pub fn start_session(&self, addr: SocketAddr, profile: Option<&str>) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let session = BehaviorSession {
            start_time: now,
            request_count: 0,
            total_bytes: 0,
            last_request_time: now,
            operations: HashMap::new(),
            anomaly_score: 0.0,
        };

        self.sessions.write().unwrap().insert(addr, session);

        // If we have a baseline, initialize anomaly detection
        if let Some(profile_name) = profile {
            // Would load baseline and start comparison
        }
    }

    /// Record a request
    pub fn record_request(&self, addr: &SocketAddr, operation: &str, size: usize) -> Vec<IntrusionEvent> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut events = Vec::new();

        let mut sessions = self.sessions.write().unwrap();
        if let Some(session) = sessions.get_mut(addr) {
            session.request_count += 1;
            session.total_bytes += size as u64;
            session.last_request_time = now;
            *session.operations.entry(operation.to_string()).or_insert(0) += 1;

            // Check for anomalies
            events.extend(self.detect_anomalies(session, operation, size, now));
        }

        events
    }

    /// Detect anomalies in behavior
    fn detect_anomalies(
        &self,
        session: &BehaviorSession,
        operation: &str,
        size: usize,
        now: u64,
    ) -> Vec<IntrusionEvent> {
        let mut events = Vec::new();

        // 1. Check request rate
        if session.request_count > 0 {
            let time_elapsed = now.saturating_sub(session.start_time);
            if time_elapsed > 0 {
                let rate = session.request_count as f64 / time_elapsed as f64;
                // If rate > 100 requests per second, flag as suspicious
                if rate > 100.0 {
                    events.push(IntrusionEvent {
                        timestamp: now,
                        event_type: IntrusionEventType::Anomaly,
                        source: None,
                        destination: None,
                        severity: 0.7,
                        confidence: 0.8,
                        details: format!("High request rate: {:.2} req/s", rate),
                        payload_hash: None,
                        action_taken: IntrusionAction::Throttle,
                        hardware_attested: false,
                    });
                }
            }
        }

        // 2. Check request size
        if size > 1024 * 1024 { // > 1MB
            events.push(IntrusionEvent {
                timestamp: now,
                event_type: IntrusionEventType::Anomaly,
                source: None,
                destination: None,
                severity: 0.6,
                confidence: 0.7,
                details: format!("Large request: {} bytes", size),
                payload_hash: None,
                action_taken: IntrusionAction::LogOnly,
                hardware_attested: false,
            });
        }

        // 3. Check unknown operation
        // Would check against baseline if available

        events
    }

    /// End session
    pub fn end_session(&self, addr: &SocketAddr) {
        self.sessions.write().unwrap().remove(addr);
    }

    /// Add baseline profile
    pub fn add_baseline(&mut self, name: String, profile: BehaviorProfile) {
        self.baselines.insert(name, profile);
    }
}

/// Main intrusion detection system
pub struct IntrusionDetectionSystem {
    /// Hardware security module
    hsm: Arc<Mutex<SovereignHSM>>,
    /// Anti-tamper system
    anti_tamper: Arc<AntiTamperSystem>,
    /// Connection tracker
    connection_tracker: Arc<ConnectionTracker>,
    /// Payload analyzer
    payload_analyzer: Arc<PayloadAnalyzer>,
    /// Behavior analyzer
    behavior_analyzer: Arc<BehaviorAnalyzer>,
    /// Event history
    events: Arc<Mutex<Vec<IntrusionEvent>>>,
    /// Configuration
    config: IntrusionDetectionConfig,
}

/// IDS configuration
#[derive(Debug, Clone)]
pub struct IntrusionDetectionConfig {
    pub enabled: bool,
    pub sensitivity: f64, // 0.0 to 1.0
    pub auto_block: bool,
    pub max_events_per_minute: usize,
    pub rate_limit_requests: usize,
    pub rate_limit_window_seconds: u64,
}

impl Default for IntrusionDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sensitivity: 0.7,
            auto_block: true,
            max_events_per_minute: 1000,
            rate_limit_requests: 100,
            rate_limit_window_seconds: 60,
        }
    }
}

impl IntrusionDetectionSystem {
    /// Create a new intrusion detection system
    pub fn new(
        hsm: Arc<Mutex<SovereignHSM>>,
        anti_tamper: Arc<AntiTamperSystem>,
    ) -> Arc<Self> {
        let config = IntrusionDetectionConfig::default();

        let connection_tracker = ConnectionTracker::new(10000);
        let payload_analyzer = PayloadAnalyzer::new();
        let behavior_analyzer = BehaviorAnalyzer::new();

        Arc::new(Self {
            hsm: hsm.clone(),
            anti_tamper: anti_tamper.clone(),
            connection_tracker,
            payload_analyzer,
            behavior_analyzer,
            events: Arc::new(Mutex::new(Vec::new())),
            config,
        })
    }

    /// Initialize the IDS
    pub fn initialize(&self) -> Result<(), HardwareError> {
        // Verify hardware security
        let hsm = self.hsm.lock().unwrap();
        if hsm.status() != crate::hardware::SecurityStatus::Secured {
            return Err(HardwareError::AttestationFailed(
                "HSM not secured".to_string(),
            ));
        }
        drop(hsm);

        // Check anti-tamper status
        if self.anti_tamper.is_compromised() {
            return Err(HardwareError::Tampered(
                "Tampering detected during IDS initialization".to_string(),
            ));
        }

        Ok(())
    }

    /// Monitor a connection
    pub fn monitor_connection(
        &self,
        source: SocketAddr,
        destination: SocketAddr,
        payload: &[u8],
        content_type: Option<&str>,
        protocol: &str,
    ) -> Vec<IntrusionAction> {
        let mut actions = Vec::new();

        if !self.config.enabled {
            return actions;
        }

        // 1. Track connection
        self.connection_tracker.track_connection(source, destination, protocol);

        // 2. Check rate limit
        if let Err(action) = self.connection_tracker.check_rate_limit(
            &source.ip(),
            self.config.rate_limit_requests,
            Duration::from_secs(self.config.rate_limit_window_seconds),
        ) {
            actions.push(action);
        }

        // 3. Analyze payload
        let payload_events = self.payload_analyzer.analyze(payload, content_type);
        for event in payload_events {
            self.log_event(event.clone());
            if event.severity >= 0.8 && self.config.auto_block {
                actions.push(IntrusionAction::DropConnection);
                self.connection_tracker.block_ip(source.ip(), Some(Duration::from_secs(3600)));
            }
            actions.push(event.action_taken);
        }

        // 4. Analyze behavior
        let behavior_events = self.behavior_analyzer.record_request(&source, protocol, payload.len());
        for event in behavior_events {
            self.log_event(event.clone());
            actions.push(event.action_taken);
        }

        // 5. Check hardware tampering
        if self.anti_tamper.is_compromised() {
            let events = self.anti_tamper.get_events();
            for event in events {
                self.log_event(IntrusionEvent {
                    timestamp: event.timestamp,
                    event_type: IntrusionEventType::HardwareTamper,
                    source: None,
                    destination: None,
                    severity: 1.0,
                    confidence: 1.0,
                    details: event.details,
                    payload_hash: None,
                    action_taken: IntrusionAction::SelfDestruct,
                    hardware_attested: true,
                });
            }
            actions.push(IntrusionAction::SelfDestruct);
        }

        // 6. Deduplicate actions
        let mut unique_actions = HashSet::new();
        actions.retain(|a| unique_actions.insert(*a));

        actions
    }

    /// End connection monitoring
    pub fn end_connection(&self, source: &SocketAddr) {
        self.connection_tracker.end_connection(source);
        self.behavior_analyzer.end_session(source);
    }

    /// Log an intrusion event
    fn log_event(&self, event: IntrusionEvent) {
        let mut events = self.events.lock().unwrap();

        // Apply sensitivity filter
        if event.severity * event.confidence >= self.config.sensitivity {
            // Check rate limiting for events
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Simple rate limiting: max events per minute
            let minute_ago = now - 60;
            let recent_events: Vec<_> = events.iter()
                .filter(|e| e.timestamp >= minute_ago)
                .collect();

            if recent_events.len() < self.config.max_events_per_minute {
                events.push(event);
            }
        }
    }

    /// Get all intrusion events
    pub fn get_events(&self) -> Vec<IntrusionEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Get events by severity
    pub fn get_events_by_severity(&self, min_severity: f64) -> Vec<IntrusionEvent> {
        self.events.lock().unwrap()
            .iter()
            .filter(|e| e.severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Get recent events
    pub fn get_recent_events(&self, minutes: u64) -> Vec<IntrusionEvent> {
        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            - (minutes * 60);

        self.events.lock().unwrap()
            .iter()
            .filter(|e| e.timestamp >= cutoff)
            .cloned()
            .collect()
    }

    /// Get blocked IPs
    pub fn get_blocked_ips(&self) -> Vec<IpAddr> {
        self.connection_tracker.blocked_ips.read().unwrap().iter().cloned().collect()
    }

    /// Update configuration
    pub fn update_config(&mut self, config: IntrusionDetectionConfig) {
        self.config = config;
    }

    /// Get configuration
    pub fn get_config(&self) -> &IntrusionDetectionConfig {
        &self.config
    }

    /// Get system status
    pub fn get_status(&self) -> IdsStatus {
        let blocked_count = self.get_blocked_ips().len();
        let events = self.get_events();
        let high_severity = events.iter().filter(|e| e.severity >= 0.8).count();

        IdsStatus {
            enabled: self.config.enabled,
            blocked_ips: blocked_count,
            total_events: events.len(),
            high_severity_events: high_severity,
            hardware_secured: self.hsm.lock().unwrap().status() == crate::hardware::SecurityStatus::Secured,
            tamper_detected: self.anti_tamper.is_compromised(),
        }
    }
}

/// IDS status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsStatus {
    pub enabled: bool,
    pub blocked_ips: usize,
    pub total_events: usize,
    pub high_severity_events: usize,
    pub hardware_secured: bool,
    pub tamper_detected: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ids_creation() {
        let hsm = SovereignHSM::new();
        let anti_tamper = AntiTamperSystem::new(hsm.clone());

        let ids = IntrusionDetectionSystem::new(hsm, anti_tamper);
        assert!(ids.initialize().is_ok());
    }

    #[test]
    fn test_connection_tracking() {
        let tracker = ConnectionTracker::new(100);
        let source = "192.168.1.1:12345".parse().unwrap();
        let dest = "192.168.1.2:8080".parse().unwrap();

        tracker.track_connection(source, dest, "TCP");
        tracker.update_activity(&source, 1024, 512);

        let record = tracker.end_connection(&source);
        assert!(record.is_some());
    }

    #[test]
    fn test_payload_analysis() {
        let analyzer = PayloadAnalyzer::new();
        let payload = b"' OR '1'='1";

        let events = analyzer.analyze(payload, Some("text/plain"));
        assert!(!events.is_empty());

        let has_sql = events.iter().any(|e| e.event_type == IntrusionEventType::SqlInjection);
        assert!(has_sql);
    }

    #[test]
    fn test_rate_limiting() {
        let tracker = ConnectionTracker::new(100);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // First 10 requests should succeed
        for _ in 0..10 {
            assert!(tracker.check_rate_limit(&ip, 100, Duration::from_secs(60)).is_ok());
        }

        // 101st request should fail
        let result = tracker.check_rate_limit(&ip, 100, Duration::from_secs(60));
        assert!(result.is_err());
    }
}
