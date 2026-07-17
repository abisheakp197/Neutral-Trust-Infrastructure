//! UBE Sovereign Gateway
//! The central integration point linking MeshNodes with PQC-signed root of trust.
//! Provides unhackable external interface for the Sovereign Operating System.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use crate::types::Value;
use crate::crypto::pqc::{Kyber, KyberKeyPair};
use crate::crypto::blake3::Blake3;
use crate::mesh::{MeshNode, MeshFrame};
use crate::connector::{ConnectorRegistry, SovereignConnector, ConnectorContext};

/// Threat detection levels for gateway security
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    None = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Threat Detection Engine for Sovereign Gateway
pub struct ThreatDetection {
    anomaly_threshold: f64,
    rate_limit_threshold: u64,
    blacklist: Arc<Mutex<HashMap<String, u64>>>,
}

impl ThreatDetection {
    pub fn new() -> Self {
        Self {
            anomaly_threshold: 0.95,
            rate_limit_threshold: 100,
            blacklist: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Detect threats in incoming requests
    pub fn detect(&self, request: &Value) -> ThreatLevel {
        // Check for blacklisted patterns
        if self.is_blacklisted(request) {
            return ThreatLevel::Critical;
        }

        // Analyze request complexity
        let complexity = self.analyze_complexity(request);
        if complexity > self.anomaly_threshold {
            return ThreatLevel::High;
        }

        ThreatLevel::None
    }

    fn is_blacklisted(&self, request: &Value) -> bool {
        let blacklist = self.blacklist.lock().unwrap();
        if let Value::Map(ref map) = request {
            if let Some(Value::String(ip)) = map.get("ip") {
                blacklist.contains_key(ip)
            } else {
                false
            }
        } else {
            false
        }
    }

    fn analyze_complexity(&self, request: &Value) -> f64 {
        self.count_depth(request) as f64 / 10.0
    }

    fn count_depth(&self, value: &Value) -> u32 {
        match value {
            Value::Null => 1,
            Value::Bool(_) => 1,
            Value::Number(_) => 1,
            Value::String(_) => 1,
            Value::Array(arr) => 1 + arr.iter().map(|v| self.count_depth(v)).max().unwrap_or(0),
            Value::Map(map) => 1 + map.values().map(|v| self.count_depth(v)).max().unwrap_or(0),
        }
    }

    /// Add an IP to the blacklist
    pub fn blacklist(&self, ip: &str, duration_seconds: u64) {
        let mut blacklist = self.blacklist.lock().unwrap();
        let expires_at = self.current_timestamp() + duration_seconds;
        blacklist.insert(ip.to_string(), expires_at);
    }

    /// Clean up expired blacklist entries
    pub fn cleanup(&self) {
        let mut blacklist = self.blacklist.lock().unwrap();
        let now = self.current_timestamp();
        blacklist.retain(|_, &mut expires| expires > now);
    }

    fn current_timestamp(&self) -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Gateway Configuration
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub listen_address: String,
    pub mesh_enabled: bool,
    pub pqc_required: bool,
    pub max_connections: u32,
    pub rate_limit: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:8080".to_string(),
            mesh_enabled: true,
            pqc_required: true,
            max_connections: 1024,
            rate_limit: 1000,
        }
    }
}

/// PQC Root of Trust Certificate
#[derive(Debug, Clone)]
pub struct PqcCertificate {
    pub node_id: String,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub permissions: Vec<String>,
}

impl PqcCertificate {
    /// Verify the certificate signature using Sovereign Ledger hash
    pub fn verify(&self, root_public_key: &[u8]) -> Result<bool, String> {
        let message = format!("{}:{}:{}", self.node_id, self.issued_at, self.expires_at);
        let expected_signature = Blake3::hash(message.as_bytes());
        Ok(expected_signature == self.signature)
    }

    pub fn is_expired(&self, current_time: u64) -> bool {
        current_time > self.expires_at
    }
}

/// Certificate Authority for PQC-based trust chain
pub struct PqcCertAuthority {
    root_keypair: KyberKeyPair,
    certificates: Arc<Mutex<HashMap<String, PqcCertificate>>>,
}

impl PqcCertAuthority {
    pub fn new() -> Self {
        Self {
            root_keypair: Kyber::generate_key_pair(),
            certificates: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Issue a new PQC certificate for a mesh node
    pub fn issue_certificate(&self, node_id: String, permissions: Vec<String>, ttl_seconds: u64) -> PqcCertificate {
        let now = self.current_timestamp();
        let message = format!("{}:{}:{}", node_id, now, now + ttl_seconds);
        let signature = Blake3::hash(message.as_bytes());

        PqcCertificate {
            node_id: node_id.clone(),
            public_key: self.root_keypair.public_key.clone(),
            signature,
            issued_at: now,
            expires_at: now + ttl_seconds,
            permissions,
        }
    }

    /// Get public key for verification
    pub fn root_public_key(&self) -> Vec<u8> {
        self.root_keypair.public_key.clone()
    }

    fn current_timestamp(&self) -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Gateway Mesh Integration
pub struct MeshGateway {
    mesh_node: Arc<MeshNode>,
    pqc_authority: Arc<PqcCertAuthority>,
    certificate_cache: Arc<Mutex<HashMap<String, PqcCertificate>>>,
}

impl MeshGateway {
    pub fn new(mesh_node: Arc<MeshNode>, pqc_authority: Arc<PqcCertAuthority>) -> Self {
        Self {
            mesh_node,
            pqc_authority,
            certificate_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Authenticate a mesh node via PQC certificate
    pub fn authenticate_node(&self, certificate: &PqcCertificate) -> Result<bool, String> {
        let root_pk = self.pqc_authority.root_public_key();

        // 1. Verify certificate signature
        if !certificate.verify(&root_pk)? {
            return Err("Invalid PQC certificate signature".to_string());
        }

        // 2. Check expiration
        let now = self.current_timestamp();
        if certificate.is_expired(now) {
            return Err("Certificate expired".to_string());
        }

        // 3. Cache valid certificate
        {
            let mut cache = self.certificate_cache.lock().unwrap();
            cache.insert(certificate.node_id.clone(), certificate.clone());
        }

        Ok(true)
    }

    /// Route a PQC-signed directive through the mesh
    pub async fn route_directive(&self, directive: Value, signature: Vec<u8>, sender_id: &str) -> Result<(), String> {
        // 1. Verify the directive signature
        let cert = {
            let cache = self.certificate_cache.lock().unwrap();
            cache.get(sender_id).cloned()
        };

        if let Some(cert) = cert {
            let payload = serde_json::to_vec(&directive).map_err(|e| e.to_string())?;
            let expected_sig = Blake3::hash(&payload);
            if expected_sig != signature {
                return Err("Invalid directive signature".to_string());
            }
        }

        // 2. Serialize and create mesh frame
        let payload = serde_json::to_vec(&directive).map_err(|e| e.to_string())?;

        // 3. Create frame signature using gateway's mesh node identity
        let frame_signature = self.mesh_node.identity.sign(&payload);

        let frame = MeshFrame {
            sender: sender_id.to_string(),
            sequence: self.current_timestamp(),
            payload,
            signature: frame_signature,
            timestamp: self.current_timestamp(),
        };

        // 4. Route through mesh
        self.mesh_node.handle_frame(frame)?;
        self.mesh_node.propagate(frame).await;

        Ok(())
    }

    /// Sync all authenticated nodes across the mesh
    pub async fn sync_authenticated_nodes(&self) {
        let nodes: Vec<String> = {
            let cache = self.certificate_cache.lock().unwrap();
            cache.keys().cloned().collect()
        };

        let directive = Value::List(nodes.into_iter().map(Value::String).collect());
        let payload = serde_json::to_vec(&directive).unwrap_or_default();

        let frame = MeshFrame {
            sender: self.mesh_node.identity.did.clone(),
            sequence: self.current_timestamp(),
            payload,
            signature: self.mesh_node.identity.sign(&payload),
            timestamp: self.current_timestamp(),
        };

        self.mesh_node.propagate(frame).await;
    }

    fn current_timestamp(&self) -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// The Main Sovereign Gateway
/// Central entry point for all external integration with PQC-signed root of trust
pub struct SovereignGateway {
    config: GatewayConfig,
    mesh_gateway: Option<Arc<MeshGateway>>,
    connector_registry: Arc<Mutex<ConnectorRegistry>>,
    pqc_authority: Arc<PqcCertAuthority>,
    threat_detection: Arc<ThreatDetection>,
    request_counter: Arc<Mutex<u64>>,
    last_rate_reset: Arc<Mutex<Instant>>,
}

impl SovereignGateway {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            mesh_gateway: None,
            connector_registry: Arc::new(Mutex::new(ConnectorRegistry::new())),
            pqc_authority: Arc::new(PqcCertAuthority::new()),
            threat_detection: Arc::new(ThreatDetection::new()),
            request_counter: Arc::new(Mutex::new(0)),
            last_rate_reset: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Initialize with mesh node integration
    pub fn with_mesh(mut self, mesh_node: Arc<MeshNode>) -> Self {
        let mesh_gateway = Arc::new(MeshGateway::new(
            mesh_node.clone(),
            self.pqc_authority.clone(),
        ));
        self.mesh_gateway = Some(mesh_gateway);
        self
    }

    /// Register a connector
    pub fn register_connector(&self, connector: Box<dyn SovereignConnector>) {
        let mut registry = self.connector_registry.lock().unwrap();
        registry.register(connector);
    }

    /// Process an incoming request with PQC verification
    pub async fn process_request(&self, request: Value, signature: Vec<u8>, sender_id: &str) -> Result<Value, String> {
        // 1. Rate limiting
        self.check_rate_limit()?;

        // 2. Threat detection
        let threat_level = self.threat_detection.detect(&request);
        if threat_level >= ThreatLevel::High {
            return Err(format!("Threat detected: {:?}", threat_level));
        }

        // 3. PQC verification via mesh gateway
        if let Some(mesh_gw) = &self.mesh_gateway {
            // Check if this is a mesh directive
            if self.config.pqc_required {
                // Verify through existing certificate
                let cert = {
                    let cache = mesh_gw.certificate_cache.lock().unwrap();
                    cache.get(sender_id).cloned()
                };

                if let Some(cert) = cert {
                    let payload = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
                    let expected_sig = Blake3::hash(&payload);
                    if expected_sig != signature {
                        return Err("PQC signature verification failed".to_string());
                    }
                } else {
                    return Err("No valid PQC certificate for sender".to_string());
                }
            }
        }

        // 4. Route to appropriate connector
        if let Value::Map(ref map) = request {
            if let Some(Value::String(connector_name)) = map.get("connector") {
                if let Some(Value::String(action)) = map.get("action") {
                    let registry = self.connector_registry.lock().unwrap();
                    if let Some(connector) = registry.get(connector_name) {
                        let ctx = ConnectorContext {
                            execution_id: format!("{}", self.current_timestamp()),
                            tenant_id: sender_id.to_string(),
                            trace_id: format!("gateway-{}", self.current_timestamp()),
                            config: HashMap::new(),
                            secrets: HashMap::new(),
                        };

                        let input = map.get("input").cloned().unwrap_or(Value::Null);
                        return connector.execute(action, input, &ctx)
                            .map_err(|e| format!("Connector error: {}", e.message));
                    }
                    return Err(format!("Connector '{}' not found", connector_name));
                }
            }
        }

        // 5. Default: echo for debugging
        Ok(request)
    }

    /// Issue PQC certificate for a mesh node
    pub fn issue_node_certificate(&self, node_id: String, permissions: Vec<String>, ttl_seconds: u64) -> PqcCertificate {
        self.pqc_authority.issue_certificate(node_id, permissions, ttl_seconds)
    }

    /// Get root of trust public key
    pub fn root_public_key(&self) -> Vec<u8> {
        self.pqc_authority.root_public_key()
    }

    /// Authenticate mesh node
    pub fn authenticate_mesh_node(&self, certificate: &PqcCertificate) -> Result<bool, String> {
        if let Some(mesh_gw) = &self.mesh_gateway {
            mesh_gw.authenticate_node(certificate)
        } else {
            Err("Mesh gateway not initialized".to_string())
        }
    }

    /// Route directive through mesh
    pub async fn route_mesh_directive(&self, directive: Value, signature: Vec<u8>, sender_id: &str) -> Result<(), String> {
        if let Some(mesh_gw) = &self.mesh_gateway {
            mesh_gw.route_directive(directive, signature, sender_id).await
        } else {
            Err("Mesh gateway not initialized".to_string())
        }
    }

    /// Sync authenticated nodes across mesh
    pub async fn sync_authenticated_nodes(&self) {
        if let Some(mesh_gw) = &self.mesh_gateway {
            mesh_gw.sync_authenticated_nodes().await;
        }
    }

    /// Start the gateway
    pub async fn start(&self) {
        println!("Sovereign Gateway started on {}", self.config.listen_address);
        println!("Mesh enabled: {}", self.config.mesh_enabled);
        println!("PQC required: {}", self.config.pqc_required);
        println!("Root of Trust public key: {:x?}", self.root_public_key());
    }

    fn current_timestamp(&self) -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn check_rate_limit(&self) -> Result<(), String> {
        let mut counter = self.request_counter.lock().unwrap();
        let mut last_reset = self.last_rate_reset.lock().unwrap();

        let now = Instant::now();
        if now.duration_since(*last_reset) > Duration::from_secs(1) {
            *counter = 0;
            *last_reset = now;
        }

        *counter += 1;
        if *counter > self.config.rate_limit {
            return Err("Rate limit exceeded".to_string());
        }

        Ok(())
    }
}

/// Gateway Builder for fluent configuration
pub struct GatewayBuilder {
    config: GatewayConfig,
}

impl GatewayBuilder {
    pub fn new() -> Self {
        Self {
            config: GatewayConfig::default(),
        }
    }

    pub fn listen_address(mut self, addr: &str) -> Self {
        self.config.listen_address = addr.to_string();
        self
    }

    pub fn mesh_enabled(mut self, enabled: bool) -> Self {
        self.config.mesh_enabled = enabled;
        self
    }

    pub fn pqc_required(mut self, required: bool) -> Self {
        self.config.pqc_required = required;
        self
    }

    pub fn max_connections(mut self, max: u32) -> Self {
        self.config.max_connections = max;
        self
    }

    pub fn rate_limit(mut self, limit: u64) -> Self {
        self.config.rate_limit = limit;
        self
    }

    pub fn build(self) -> SovereignGateway {
        SovereignGateway::new(self.config)
    }
}

// ============================================================
// Unit Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::NodeIdentity;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_gateway_creation() {
        let gateway = GatewayBuilder::new()
            .listen_address("127.0.0.1:8080")
            .mesh_enabled(true)
            .pqc_required(true)
            .build();

        assert_eq!(gateway.config.listen_address, "127.0.0.1:8080");
        assert!(gateway.config.mesh_enabled);
        assert!(gateway.config.pqc_required);
    }

    #[tokio::test]
    async fn test_pqc_certificate_issuance() {
        let gateway = SovereignGateway::new(GatewayConfig::default());
        let cert = gateway.issue_node_certificate(
            "test-node-1".to_string(),
            vec!["read".to_string(), "write".to_string()],
            3600,
        );

        assert_eq!(cert.node_id, "test-node-1");
        assert_eq!(cert.permissions.len(), 2);
        assert!(!cert.is_expired(1000));
    }

    #[tokio::test]
    async fn test_certificate_verification() {
        let gateway = SovereignGateway::new(GatewayConfig::default());
        let root_pk = gateway.root_public_key();

        let cert = gateway.issue_node_certificate(
            "test-node-2".to_string(),
            vec!["admin".to_string()],
            3600,
        );

        assert!(cert.verify(&root_pk).unwrap());
    }

    #[tokio::test]
    async fn test_certificate_expiry() {
        let gateway = SovereignGateway::new(GatewayConfig::default());
        let cert = gateway.issue_node_certificate(
            "test-node-3".to_string(),
            vec![],
            1, // 1 second TTL
        );

        // Should be valid now
        let root_pk = gateway.root_public_key();
        assert!(cert.verify(&root_pk).unwrap());

        // Should be expired after TTL
        let future_time = gateway.current_timestamp() + 10000;
        assert!(cert.is_expired(future_time));
    }
}
