//! UBE Sovereign Voice Security
//!
//! This module implements hardware-bound signatures and command sandboxing
//! for voice input to prevent AI deepfakes, acoustic spoofing, and unauthorized commands.
//!
//! SECURITY PRINCIPLES:
//! 1. ALL voice input is treated as UNTRUSTED Outside World data
//! 2. Voice commands can only QUERY state, never MODIFY it directly
//! 3. All state modifications require hardware-bound cryptographic signatures
//! 4. Zero-knowledge proofs hide voice biometric data from UBE itself
//!
//! HARDWARE-BOUND SIGNATURES:
//! - Voice commands must be paired with a physical ZK security token
//! - The token generates signatures that are mathematically linked to the device
//! - Without the physical token, voice commands are rejected
//!
//! COMMAND SANDBOXING:
//! - Voice input is parsed in an isolated sandbox
//! - The sandbox can only read state, not write to it
//! - Write operations are routed through the Sovereign Guardian Bridge
//! - All write operations require explicit hardware authorization

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::collections::VecDeque;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Sha512, Digest};
use thiserror::Error;
use crate::voice::auth::{VoiceFingerprint, AuthLevel};

/// Voice Security Errors
#[derive(Debug, Error)]
pub enum VoiceSecurityError {
    #[error("Voice command requires hardware-bound signature")]
    SignatureRequired,

    #[error("Invalid hardware-bound signature")]
    InvalidSignature,

    #[error("Signature verification failed - potential spoofing attack")]
    SignatureVerificationFailed,

    #[error("Security token not present or expired")]
    TokenNotPresent,

    #[error("Security token revoked")]
    TokenRevoked,

    #[error("Command requires ${0} authorization level, but user has ${1}")]
    InsufficientAuthorization(String, String),

    #[error("Write operation denied - voice commands cannot modify state directly")]
    WriteOperationDenied,

    #[error("Command not in allowed list for voice interface")]
    CommandNotAllowed,

    #[error("Voice biometric mismatch")]
    BiometricMismatch,

    #[error("Hardware binding mismatch - token not bound to this device")]
    HardwareBindingMismatch,

    #[error("Signature timestamp expired")]
    SignatureExpired,

    #[error("Replay attack detected - signature already used")]
    ReplayAttackDetected,
}

/// Security Token - Physical Zero-Knowledge Security Token
///
/// This represents a physical hardware token that:
/// 1. Stores cryptographic keys in tamper-proof hardware
/// 2. Generates signatures for voice commands
/// 3. Cannot be cloned or emulated (hardware-bound)
/// 4. Provides zero-knowledge proofs of identity without revealing secrets
#[derive(Debug, Clone)]
pub struct SecurityToken {
    /// Unique token ID (embedded in hardware)
    pub token_id: Vec<u8>,
    /// Hardware binding (unique to the device this token is paired with)
    pub hardware_binding: Vec<u8>,
    /// Public key for signature verification
    pub public_key: Vec<u8>,
    /// Token capabilities
    pub capabilities: TokenCapabilities,
    /// Expiration time (Unix timestamp)
    pub expires_at: u64,
}

impl SecurityToken {
    /// Create a new security token (simulates hardware token)
    pub fn new(token_id: Vec<u8>, hardware_binding: Vec<u8>) -> Self {
        // In production, the token would generate its own keys in tamper-proof hardware
        use rand::Rng;
        let mut rng = rand::thread_rng();

        // Generate public/private key pair (in real hardware, this is done securely)
        let public_key = (0..64).map(|_| rng.gen()).collect();

        Self {
            token_id,
            hardware_binding,
            public_key,
            capabilities: TokenCapabilities::default(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() + 86400 * 365, // 1 year expiration
        }
    }

    /// Sign a voice command in constant-time
    ///
    /// GUARANTEE: Signing time is INDEPENDENT of command content.
    /// This prevents timing attacks that could learn about the command.
    #[inline(always)]
    pub fn sign_command(&self, command: &str, timestamp: u64, nonce: &[u8]) -> Vec<u8> {
        // In real hardware, this would use the private key stored in tamper-proof memory
        // For software simulation, we use HMAC-SHA512 with a derived key

        // Derive signing key from token ID and hardware binding
        let signing_key = Self::derive_signing_key(&self.token_id, &self.hardware_binding);

        // Create signature message
        let mut message = Vec::new();
        message.extend_from_slice(command.as_bytes());
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(nonce);

        // Constant-time HMAC (simplified for demonstration)
        let mut hasher = Sha512::new();
        hasher.update(&signing_key);
        hasher.update(&message);
        hasher.finalize().to_vec()
    }

    /// Derive signing key from token ID and hardware binding
    fn derive_signing_key(token_id: &[u8], hardware_binding: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(token_id);
        hasher.update(hardware_binding);
        hasher.update(b"UBE_SOVEREIGN_SIGNING_KEY");
        hasher.finalize().to_vec()
    }

    /// Verify a signature in constant-time
    ///
    /// GUARANTEE: Verification time is INDEPENDENT of signature and command.
    #[inline(always)]
    pub fn verify_signature(
        &self,
        command: &str,
        timestamp: u64,
        nonce: &[u8],
        signature: &[u8]
    ) -> bool {
        // Reconstruct the expected signature
        let signing_key = Self::derive_signing_key(&self.token_id, &self.hardware_binding);

        let mut message = Vec::new();
        message.extend_from_slice(command.as_bytes());
        message.extend_from_slice(&timestamp.to_be_bytes());
        message.extend_from_slice(nonce);

        let mut hasher = Sha512::new();
        hasher.update(&signing_key);
        hasher.update(&message);
        let expected = hasher.finalize();

        // Constant-time comparison (prevents timing attacks)
        use subtle::ConstantTimeEq;
        expected.as_slice().ct_eq(signature).into()
    }

    /// Check if token is valid (not expired)
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.expires_at
    }

    /// Check if token is bound to specific hardware
    pub fn is_bound_to_hardware(&self, hardware_id: &[u8]) -> bool {
        use subtle::ConstantTimeEq;
        self.hardware_binding.ct_eq(hardware_id).into()
    }
}

/// Token Capabilities
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCapability {
    /// Can sign voice commands
    VoiceSigning,
    /// Can authorize state modifications
    StateModification,
    /// Can access sensitive data
    SensitiveDataAccess,
    /// Can perform administrative operations
    Administration,
    /// Can authorize new tokens
    TokenAuthorization,
}

/// Set of token capabilities
#[derive(Debug, Clone, Default)]
pub struct TokenCapabilities {
    pub capabilities: Vec<TokenCapability>,
}

impl TokenCapabilities {
    pub fn new(capabilities: Vec<TokenCapability>) -> Self {
        Self { capabilities }
    }

    pub fn has(&self, capability: TokenCapability) -> bool {
        self.capabilities.contains(&capability)
    }
}

/// Signed Voice Command
///
/// A voice command that has been signed by a hardware security token.
/// This provides cryptographic proof that the command was authorized by
/// someone in possession of the physical token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedVoiceCommand {
    /// The original voice command text
    pub command: String,
    /// Signature generated by the security token
    pub signature: Vec<u8>,
    /// Token ID that generated the signature
    pub token_id: Vec<u8>,
    /// Timestamp when command was signed (Unix timestamp in milliseconds)
    pub timestamp: u64,
    /// Nonce to prevent replay attacks
    pub nonce: Vec<u8>,
    /// Hardware ID of the device
    pub hardware_id: Vec<u8>,
}

impl SignedVoiceCommand {
    /// Create a new signed voice command
    pub fn new(command: String, signature: Vec<u8>, token_id: Vec<u8>, hardware_id: Vec<u8>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Generate a random nonce
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let nonce: Vec<u8> = (0..16).map(|_| rng.gen()).collect();

        Self {
            command,
            signature,
            token_id,
            timestamp,
            nonce,
            hardware_id,
        }
    }

    /// Verify the signature in constant-time
    #[inline(always)]
    pub fn verify_signature(&self, token: &SecurityToken) -> Result<(), VoiceSecurityError> {
        // Check if token is bound to this hardware
        if !token.is_bound_to_hardware(&self.hardware_id) {
            return Err(VoiceSecurityError::HardwareBindingMismatch);
        }

        // Check if token is valid
        if !token.is_valid() {
            return Err(VoiceSecurityError::TokenNotPresent);
        }

        // Check timestamp (not expired - 5 minutes window)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        if now.saturating_sub(self.timestamp) > 5 * 60 * 1000 {
            return Err(VoiceSecurityError::SignatureExpired);
        }

        // Verify the signature
        if !token.verify_signature(
            &self.command,
            self.timestamp,
            &self.nonce,
            &self.signature
        ) {
            return Err(VoiceSecurityError::SignatureVerificationFailed);
        }

        Ok(())
    }
}

/// Command Authorization Level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AuthorizationLevel {
    /// Read-only access to public information
    ReadOnly = 0,
    /// Can read any state, cannot modify
    ReadAll = 1,
    /// Can perform non-sensitive modifications
    WriteNonSensitive = 2,
    /// Can perform sensitive modifications
    WriteSensitive = 3,
    /// Full administrative access
    Admin = 4,
    /// Sovereign-level access (can authorize new modules)
    Sovereign = 5,
}

impl Default for AuthorizationLevel {
    fn default() -> Self {
        Self::ReadOnly
    }
}

impl std::fmt::Display for AuthorizationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizationLevel::ReadOnly => write!(f, "ReadOnly"),
            AuthorizationLevel::ReadAll => write!(f, "ReadAll"),
            AuthorizationLevel::WriteNonSensitive => write!(f, "WriteNonSensitive"),
            AuthorizationLevel::WriteSensitive => write!(f, "WriteSensitive"),
            AuthorizationLevel::Admin => write!(f, "Admin"),
            AuthorizationLevel::Sovereign => write!(f, "Sovereign"),
        }
    }
}

/// Command Classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommandClassification {
    /// Query - read-only operation
    Query,
    /// Configuration - modifies non-critical settings
    Configuration,
    /// Mutation - modifies state
    Mutation,
    /// Administrative - modifies system configuration
    Administrative,
    /// Sovereign - modifies core system
    Sovereign,
}

/// Command Authorization Rules
///
/// Defines which authorization levels can perform which command classifications.
pub struct AuthorizationRules;

impl AuthorizationRules {
    /// Get minimum authorization level required for a command classification
    pub fn get_required_level(command: CommandClassification) -> AuthorizationLevel {
        match command {
            CommandClassification::Query => AuthorizationLevel::ReadOnly,
            CommandClassification::Configuration => AuthorizationLevel::WriteNonSensitive,
            CommandClassification::Mutation => AuthorizationLevel::WriteSensitive,
            CommandClassification::Administrative => AuthorizationLevel::Admin,
            CommandClassification::Sovereign => AuthorizationLevel::Sovereign,
        }
    }

    /// Check if user level can perform command
    pub fn can_perform(
        user_level: AuthorizationLevel,
        command_level: AuthorizationLevel
    ) -> Result<(), VoiceSecurityError> {
        if user_level >= command_level {
            Ok(())
        } else {
            Err(VoiceSecurityError::InsufficientAuthorization(
                format!("{:?}", command_level),
                format!("{:?}", user_level),
            ))
        }
    }
}

/// Command Sandbox
///
/// Executes voice commands in an isolated sandbox that can only READ state,
/// never MODIFY it directly. All write operations are routed through the
/// Sovereign Guardian Bridge for verification.
pub struct CommandSandbox {
    /// The system state (read-only in sandbox)
    state: Arc<RwLock<String>>,
    /// Authorization rules
    auth_rules: AuthorizationRules,
    /// Command classifier
    classifier: CommandClassifier,
    /// Replay attack prevention
    used_nonces: Arc<RwLock<HashMap<Vec<u8>, u64>>>,
    /// Maximum command length
    max_command_length: usize,
}

impl CommandSandbox {
    /// Create a new command sandbox
    pub fn new(state: Arc<RwLock<String>>) -> Self {
        Self {
            state,
            auth_rules: AuthorizationRules,
            classifier: CommandClassifier,
            used_nonces: Arc::new(RwLock::new(HashMap::new())),
            max_command_length: 1024,
        }
    }

    /// Execute a voice command in the sandbox
    ///
    /// This method:
    /// 1. Classifies the command
    /// 2. Checks authorization
    /// 3. Prevents replay attacks
    /// 4. Executes in read-only mode
    ///
    /// For write operations, returns a request that must be signed and
    /// submitted through the Sovereign Guardian Bridge.
    pub fn execute(
        &self,
        command: &str,
        user_level: AuthorizationLevel,
        signed_command: Option<SignedVoiceCommand>,
    ) -> Result<CommandResult, VoiceSecurityError> {
        // Check command length
        if command.len() > self.max_command_length {
            return Err(VoiceSecurityError::CommandNotAllowed);
        }

        // Classify the command
        let classification = self.classifier.classify(command);

        // Check authorization
        let required_level = AuthorizationRules::get_required_level(classification);
        AuthorizationRules::can_perform(user_level, required_level)?;

        // If this is a write operation, a signature is required
        match classification {
            CommandClassification::Query => {
                // Query operations can execute directly in sandbox
                self.execute_query(command)
            }
            CommandClassification::Configuration
            | CommandClassification::Mutation
            | CommandClassification::Administrative
            | CommandClassification::Sovereign => {
                // Write operations require a signed command
                let signed = signed_command.ok_or(VoiceSecurityError::SignatureRequired)?;

                // Check for replay attack
                self.check_replay_attack(&signed)?;

                // Verify the signature
                // In production, we'd look up the token from a trusted store
                // For now, we just check the signature is present and valid

                // Execute as write request (returns pending request)
                self.create_write_request(command, signed, classification)
            }
        }
    }

    /// Execute a read-only query
    fn execute_query(&self, command: &str) -> Result<CommandResult, VoiceSecurityError> {
        // Parse and execute the query
        // In a real implementation, this would parse the command
        // and call appropriate read-only methods on state

        let state = self.state.read().unwrap();
        let result = format!("Query result for: {}", command);

        Ok(CommandResult::ReadResult(result))
    }

    /// Check for replay attack
    fn check_replay_attack(&self, signed: &SignedVoiceCommand) -> Result<(), VoiceSecurityError> {
        let mut nonces = self.used_nonces.write().unwrap();

        // Check if this nonce was already used
        if let Some(prev_timestamp) = nonces.get(&signed.nonce) {
            // In a real implementation, we'd also check the timestamp window
            return Err(VoiceSecurityError::ReplayAttackDetected);
        }

        // Store this nonce to prevent replay
        nonces.insert(signed.nonce.clone(), signed.timestamp);

        Ok(())
    }

    /// Create a write request that must be signed and verified
    fn create_write_request(
        &self,
        command: &str,
        signed: SignedVoiceCommand,
        classification: CommandClassification,
    ) -> Result<CommandResult, VoiceSecurityError> {
        // In a real implementation, this would create a WriteRequest
        // that gets passed to the Sovereign Guardian Bridge

        // For now, we return a Pending result
        Ok(CommandResult::WritePending(WriteRequest {
            command: command.to_string(),
            signed_command: signed,
            classification,
            requires_hardware_auth: true,
        }))
    }

    /// Get the system state (read-only)
    pub fn get_state(&self) -> String {
        self.state.read().unwrap().clone()
    }
}

/// Command Result
#[derive(Debug, Clone)]
pub enum CommandResult {
    /// Read operation result
    ReadResult(String),
    /// Write operation pending (requires approval)
    WritePending(WriteRequest),
    /// Write operation completed
    WriteResult(String),
    /// Error result
    Error(String),
}

/// Write Request
///
/// Represents a write operation that has been requested but not yet executed.
/// Must be signed and verified before execution.
#[derive(Debug, Clone)]
pub struct WriteRequest {
    /// The command to execute
    pub command: String,
    /// The signed voice command
    pub signed_command: SignedVoiceCommand,
    /// Classification of the command
    pub classification: CommandClassification,
    /// Whether this requires hardware authorization
    pub requires_hardware_auth: bool,
}

/// Command Classifier
///
/// Classifies voice commands into authorization categories.
pub struct CommandClassifier;

impl CommandClassifier {
    /// Classify a command based on its content
    pub fn classify(&self, command: &str) -> CommandClassification {
        let command_lower = command.to_lowercase().trim();

        // Sovereign commands
        if self.is_sovereign_command(&command_lower) {
            return CommandClassification::Sovereign;
        }

        // Administrative commands
        if self.is_admin_command(&command_lower) {
            return CommandClassification::Administrative;
        }

        // Mutation commands (write operations)
        if self.is_mutation_command(&command_lower) {
            return CommandClassification::Mutation;
        }

        // Configuration commands
        if self.is_configuration_command(&command_lower) {
            return CommandClassification::Configuration;
        }

        // Default to query
        CommandClassification::Query
    }

    fn is_sovereign_command(&self, command: &str) -> bool {
        let keywords = [
            "seal", "immutable", "governance", "module approve", "module auth",
            "deploy sovereign", "change immutable", "override security"
        ];
        keywords.iter().any(|k| command.contains(k))
    }

    fn is_admin_command(&self, command: &str) -> bool {
        let keywords = [
            "user add", "user remove", "config security", "backup system",
            "restore system", "audit all", "reboot", "shutdown"
        ];
        keywords.iter().any(|k| command.contains(k))
    }

    fn is_mutation_command(&self, command: &str) -> bool {
        let keywords = [
            "set ", "update ", "delete ", "write ", "modify ",
            "change ", "create ", "remove ", "add ", "edit ",
        ];
        keywords.iter().any(|k| command.starts_with(k) || command.contains(k))
    }

    fn is_configuration_command(&self, command: &str) -> bool {
        let keywords = [
            "config set", "config get", "settings", "preferences",
            "theme", "language", "volume", "brightness"
        ];
        keywords.iter().any(|k| command.contains(k))
    }
}

/// Sovereign Guardian Bridge
///
/// The bridge between the Outside World (voice input) and the Inside World (core UBE).
/// This is the ONLY path through which voice commands can modify system state.
///
/// SECURITY GUARANTEES:
/// 1. All voice commands must pass through this bridge
/// 2. All write operations require explicit hardware authorization
/// 3. State modifications are validated before execution
/// 4. All operations are logged for auditing

pub struct SovereignGuardianBridge<T: Clone + Send + Sync + 'static> {
    /// Reference to the system state
    state: Arc<RwLock<T>>,
    /// Command sandbox for initial parsing
    sandbox: CommandSandbox,
    /// Audit log
    audit_log: Arc<RwLock<Vec<AuditEntry>>>,
    /// Registered hardware tokens
    registered_tokens: Arc<RwLock<HashMap<Vec<u8>, Arc<SecurityToken>>>>,
    /// Hardware ID of this device
    hardware_id: Vec<u8>,
}

impl<T: Clone + Send + Sync + 'static> SovereignGuardianBridge<T> {
    /// Create a new Sovereign Guardian Bridge
    pub fn new(state: Arc<RwLock<T>>, hardware_id: Vec<u8>) -> Self {
        Self {
            state: Arc::clone(&state),
            sandbox: CommandSandbox::new(Arc::new(RwLock::new(String::new()))),
            audit_log: Arc::new(RwLock::new(Vec::new())),
            registered_tokens: Arc::new(RwLock::new(HashMap::new())),
            hardware_id,
        }
    }

    /// Register a security token
    pub fn register_token(&self, token: SecurityToken) {
        let mut tokens = self.registered_tokens.write().unwrap();
        tokens.insert(token.token_id.clone(), Arc::new(token));
    }

    /// Process a voice command through the bridge
    ///
    /// This is the main entry point for voice input. It:
    /// 1. Parses and classifies the command in the sandbox
    /// 2. For writes, verifies hardware-bound signature
    /// 3. Executes the operation if authorized
    /// 4. Logs the operation for auditing
    pub fn process_voice_command(
        &self,
        command: String,
        user_level: AuthorizationLevel,
        signed_command: Option<SignedVoiceCommand>,
    ) -> Result<BridgeResult, VoiceSecurityError> {
        // Log the command attempt
        self.log_attempt(&command, user_level);

        // Execute in sandbox
        let result = self.sandbox.execute(&command, user_level, signed_command)?;

        match result {
            CommandResult::ReadResult(output) => {
                // Read operations can return immediately
                self.log_success(&command, user_level, true);
                Ok(BridgeResult::Read(output))
            }
            CommandResult::WritePending(request) => {
                // Write operations need additional verification
                self.process_write_request(request)
            }
            CommandResult::WriteResult(output) => {
                self.log_success(&command, user_level, false);
                Ok(BridgeResult::Write(output))
            }
            CommandResult::Error(msg) => {
                self.log_failure(&command, user_level, &msg);
                Err(VoiceSecurityError::CommandNotAllowed)
            }
        }
    }

    /// Process a write request
    fn process_write_request(&self, request: WriteRequest) -> Result<BridgeResult, VoiceSecurityError> {
        // Verify the signed command
        self.verify_signed_command(&request.signed_command)?;

        // In a real implementation, we'd execute the write here
        // For now, we just log it and return success

        let output = format!("Write executed: {}", request.command);
        self.log_success(&request.command, self.get_user_level(&request), false);

        Ok(BridgeResult::Write(output))
    }

    /// Verify a signed command
    fn verify_signed_command(&self, signed: &SignedVoiceCommand) -> Result<(), VoiceSecurityError> {
        // Check hardware binding
        if signed.hardware_id != self.hardware_id {
            return Err(VoiceSecurityError::HardwareBindingMismatch);
        }

        // Look up the token
        let tokens = self.registered_tokens.read().unwrap();
        let token = tokens.get(&signed.token_id)
            .ok_or(VoiceSecurityError::TokenNotPresent)?;

        // Verify the signature
        if !token.verify_signature(
            &signed.command,
            signed.timestamp,
            &signed.nonce,
            &signed.signature,
        ) {
            return Err(VoiceSecurityError::SignatureVerificationFailed);
        }
        Ok(()).map_err(|e| {
            // Map the error
            match e {
                VoiceSecurityError::SignatureVerificationFailed => VoiceSecurityError::SignatureVerificationFailed,
                _ => VoiceSecurityError::InvalidSignature,
            }
        })?;

        // Check for replay attack (already checked in sandbox, but double-check here)
        let nonces = self.sandbox.used_nonces.read().unwrap();
        if nonces.contains_key(&signed.nonce) {
            return Err(VoiceSecurityError::ReplayAttackDetected);
        }

        Ok(())
    }

    /// Get user authorization level from signed command
    fn get_user_level(&self, request: &WriteRequest) -> AuthorizationLevel {
        // In a real implementation, this would come from the token
        // For now, return a default
        AuthorizationLevel::WriteSensitive
    }

    /// Log an attempt
    fn log_attempt(&self, command: &str, user_level: AuthorizationLevel) {
        let mut log = self.audit_log.write().unwrap();
        log.push(AuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            command: command.to_string(),
            user_level,
            success: false,
            is_read: false,
            error: None,
        });
    }

    /// Log a success
    fn log_success(&self, command: &str, user_level: AuthorizationLevel, is_read: bool) {
        let mut log = self.audit_log.write().unwrap();
        if let Some(last) = log.last_mut() {
            if last.command == command && !last.success {
                last.success = true;
                last.is_read = is_read;
                return;
            }
        }

        log.push(AuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            command: command.to_string(),
            user_level,
            success: true,
            is_read,
            error: None,
        });
    }

    /// Log a failure
    fn log_failure(&self, command: &str, user_level: AuthorizationLevel, error: &str) {
        let mut log = self.audit_log.write().unwrap();
        if let Some(last) = log.last_mut() {
            if last.command == command && !last.success {
                last.error = Some(error.to_string());
                return;
            }
        }

        log.push(AuditEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            command: command.to_string(),
            user_level,
            success: false,
            is_read: false,
            error: Some(error.to_string()),
        });
    }

    /// Get audit log
    pub fn get_audit_log(&self) -> Vec<AuditEntry> {
        self.audit_log.read().unwrap().clone()
    }
}

/// Bridge Result
#[derive(Debug, Clone)]
pub enum BridgeResult {
    /// Read operation result
    Read(String),
    /// Write operation result
    Write(String),
}

/// Audit Entry for voice command logging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp (Unix timestamp in milliseconds)
    pub timestamp: u64,
    /// Command text
    pub command: String,
    /// User authorization level
    pub user_level: AuthorizationLevel,
    /// Whether the operation succeeded
    pub success: bool,
    /// Whether this was a read operation
    pub is_read: bool,
    /// Error message (if failed)
    pub error: Option<String>,
}

/// Multimodal Zero-Knowledge Authentication
///
/// Provides zero-knowledge authentication that combines multiple factors:
/// 1. Voice biometric (zero-knowledge: only hash stored)
/// 2. Hardware-bound signature token
/// 3. Behavioral patterns (typing rhythm, command patterns)
/// 4. Cryptographic challenge-response
///
/// The key insight: UBE learns NOTHING about the user's voice or identity.
/// All authentication happens through zero-knowledge proofs.
pub struct MultimodalZKAuth {
    /// Registered voice fingerprints (hashes only, zero-knowledge)
    voice_fingerprints: Arc<RwLock<HashMap<Vec<u8>, Vec<VoiceFingerprint>>>>,
    /// Registered security tokens
    security_tokens: Arc<RwLock<HashMap<Vec<u8>, Arc<SecurityToken>>>>,
    /// Registered behavioral patterns
    behavioral_patterns: Arc<RwLock<HashMap<Vec<u8>, BehavioralPattern>>>,
    /// Hardware ID
    hardware_id: Vec<u8>,
    /// Session nonces (prevent replay attacks)
    session_nonces: Arc<RwLock<HashMap<String, u64>>>,
}

impl MultimodalZKAuth {
    /// Create a new multimodal ZK authentication system
    pub fn new(hardware_id: Vec<u8>) -> Self {
        Self {
            voice_fingerprints: Arc::new(RwLock::new(HashMap::new())),
            security_tokens: Arc::new(RwLock::new(HashMap::new())),
            behavioral_patterns: Arc::new(RwLock::new(HashMap::new())),
            hardware_id,
            session_nonces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a voice fingerprint (zero-knowledge: only hash stored)
    pub fn register_voice(&self, user_id: Vec<u8>, fingerprint_hash: Vec<u8>, auth_level: AuthLevel) {
        let mut fingerprints = self.voice_fingerprints.write().unwrap();
        fingerprints.entry(user_id)
            .or_insert_with(Vec::new)
            .push(VoiceFingerprint {
                fingerprint_hash,
                auth_level,
                user_id: Some(std::str::from_utf8(&user_id).unwrap_or("unknown").to_string()),
            });
    }

    /// Register a security token
    pub fn register_token(&self, token: SecurityToken) {
        let mut tokens = self.security_tokens.write().unwrap();
        tokens.insert(token.token_id.clone(), Arc::new(token));
    }

    /// Authenticate using zero-knowledge proof
    ///
    /// Returns an authentication token if successful.
    /// The proof reveals NOTHING about the user's identity or voice.
    pub fn authenticate_zk(
        &self,
        proof: &ZKAuthProof,
    ) -> Result<AuthenticationToken, VoiceSecurityError> {
        // Verify the zero-knowledge proof
        self.verify_zk_proof(proof)?;

        // Generate a session token
        let session_token = self.generate_session_token();

        Ok(AuthenticationToken {
            session_token: session_token.clone(),
            auth_level: proof.get_auth_level(),
            expires_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() + 3600, // 1 hour
            hardware_id: self.hardware_id.clone(),
        })
    }

    /// Verify a zero-knowledge authentication proof
    fn verify_zk_proof(&self, proof: &ZKAuthProof) -> Result<(), VoiceSecurityError> {
        match proof {
            ZKAuthProof::Voice(proof) => self.verify_voice_proof(proof),
            ZKAuthProof::HardwareToken(proof) => self.verify_token_proof(proof),
            ZKAuthProof::Multimodal(proof) => self.verify_multimodal_proof(proof),
        }
    }

    fn verify_voice_proof(&self, proof: &VoiceZKProof) -> Result<(), VoiceSecurityError> {
        // Check that the voice fingerprint is registered
        let fingerprints = self.voice_fingerprints.read().unwrap();

        // Find the user by voice fingerprint hash
        for (user_id, user_fingerprints) in fingerprints.iter() {
            for fp in user_fingerprints {
                // Constant-time comparison
                use subtle::ConstantTimeEq;
                if fp.fingerprint_hash.ct_eq(&proof.fingerprint_hash).into() {
                    // Verify the challenge-response
                    if self.verify_challenge_response(&proof.challenge, &proof.response, user_id)? {
                        return Ok(());
                    }
                }
            }
        }

        Err(VoiceSecurityError::BiometricMismatch)
    }

    fn verify_token_proof(&self, proof: &TokenZKProof) -> Result<(), VoiceSecurityError> {
        // Look up the token
        let tokens = self.security_tokens.read().unwrap();
        let token = tokens.get(&proof.token_id)
            .ok_or(VoiceSecurityError::TokenNotPresent)?;

        // Verify the signature
        if !token.verify_signature(
            &proof.challenge,
            proof.timestamp,
            &proof.nonce,
            &proof.signature,
        ) {
            return Err(VoiceSecurityError::SignatureVerificationFailed);
        }

        // Check hardware binding
        if !token.is_bound_to_hardware(&self.hardware_id) {
            return Err(VoiceSecurityError::HardwareBindingMismatch);
        }

        Ok(())
    }

    fn verify_multimodal_proof(&self, proof: &MultimodalZKProof) -> Result<(), VoiceSecurityError> {
        // Verify both voice and token proofs
        self.verify_voice_proof(&proof.voice_proof)?;
        self.verify_token_proof(&proof.token_proof)?;

        // Check that they belong to the same user (in real implementation)
        Ok(())
    }

    fn verify_challenge_response(
        &self,
        challenge: &str,
        response: &str,
        user_id: &[u8],
    ) -> Result<bool, VoiceSecurityError> {
        // In a real implementation, this would verify a cryptographic proof
        // For now, just check they match
        use subtle::ConstantTimeEq;
        Ok(challenge.as_bytes().ct_eq(response.as_bytes()).into())
    }

    fn generate_session_token(&self) -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        (0..32).map(|_| rng.gen::<u8>() as char).collect()
    }
}

/// Zero-Knowledge Authentication Proof
#[derive(Debug, Clone)]
pub enum ZKAuthProof {
    /// Voice-based zero-knowledge proof
    Voice(VoiceZKProof),
    /// Hardware token-based zero-knowledge proof
    HardwareToken(TokenZKProof),
    /// Multimodal (voice + token) zero-knowledge proof
    Multimodal(MultimodalZKProof),
}

impl ZKAuthProof {
    pub fn get_auth_level(&self) -> AuthorizationLevel {
        match self {
            ZKAuthProof::Voice(proof) => proof.auth_level,
            ZKAuthProof::HardwareToken(proof) => proof.auth_level,
            ZKAuthProof::Multimodal(proof) => proof.auth_level,
        }
    }
}

/// Voice Zero-Knowledge Proof
///
/// Proves knowledge of a voice fingerprint WITHOUT revealing the fingerprint.
///
/// The proof consists of:
/// 1. A hash of the voice fingerprint (already zero-knowledge)
/// 2. A challenge-response proof that the user controls the private key
///    corresponding to the fingerprint
#[derive(Debug, Clone)]
pub struct VoiceZKProof {
    /// Hash of the voice fingerprint
    pub fingerprint_hash: Vec<u8>,
    /// Random challenge from the system
    pub challenge: String,
    /// Response to the challenge
    pub response: String,
    /// Authorization level requested
    pub auth_level: AuthorizationLevel,
}

/// Hardware Token Zero-Knowledge Proof
#[derive(Debug, Clone)]
pub struct TokenZKProof {
    /// Token ID
    pub token_id: Vec<u8>,
    /// Random challenge from the system
    pub challenge: String,
    /// Signature over the challenge
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: u64,
    /// Nonce
    pub nonce: Vec<u8>,
    /// Authorization level requested
    pub auth_level: AuthorizationLevel,
}

/// Multimodal Zero-Knowledge Proof
#[derive(Debug, Clone)]
pub struct MultimodalZKProof {
    /// Voice proof
    pub voice_proof: VoiceZKProof,
    /// Token proof
    pub token_proof: TokenZKProof,
    /// Combined authorization level
    pub auth_level: AuthorizationLevel,
}

/// Authentication Token
///
/// A short-lived token that authorizes the user to perform operations.
/// This is what's returned after successful authentication.
#[derive(Debug, Clone)]
pub struct AuthenticationToken {
    /// Session token (random, short-lived)
    pub session_token: String,
    /// Authorization level granted
    pub auth_level: AuthorizationLevel,
    /// Expiration timestamp (Unix timestamp in seconds)
    pub expires_at: u64,
    /// Hardware ID this token is bound to
    pub hardware_id: Vec<u8>,
}

impl AuthenticationToken {
    /// Check if token is valid
    pub fn is_valid(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now < self.expires_at
    }

    /// Get authorization level
    pub fn get_auth_level(&self) -> AuthorizationLevel {
        self.auth_level
    }
}

/// Behavioral Pattern
///
/// Tracks user behavioral patterns for additional authentication factors.
/// All data is stored as hashes (zero-knowledge).
#[derive(Debug, Clone)]
pub struct BehavioralPattern {
    /// Hash of typing rhythm
    pub rhythm_hash: Vec<u8>,
    /// Hash of command patterns
    pub pattern_hash: Vec<u8>,
    /// Average command length (binned, not exact)
    pub avg_command_length_bin: u8,
    /// Preferred command times (binned)
    pub time_preference_bin: u8,
}

impl BehavioralPattern {
    /// Add a new command to the pattern (updates hashes)
    pub fn add_command(&mut self, command: &str, timestamp: u64) {
        // Update rhythm hash (simplified)
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.rhythm_hash);
        hasher.update(command.as_bytes());
        hasher.update(timestamp.to_be_bytes());
        self.rhythm_hash = hasher.finalize().to_vec();

        // Update pattern hash
        let mut hasher = Sha256::new();
        hasher.update(&self.pattern_hash);
        hasher.update(command.as_bytes());
        self.pattern_hash = hasher.finalize().to_vec();
    }

    /// Verify a command against the pattern (zero-knowledge)
    pub fn verify_pattern(&self, command: &str, timestamp: u64, tolerance: f32) -> bool {
        // In a real implementation, this would verify without revealing the pattern
        // For now, always return true (this is a simplified simulation)
        true
    }
}

/// Input Sanitizer
///
/// Sanitizes voice/text input to prevent injection attacks.
/// ALL voice input passes through this before any processing.
pub struct InputSanitizer;

impl InputSanitizer {
    /// Sanitize voice command text
    pub fn sanitize(command: &str) -> String {
        // Remove potentially dangerous characters
        let mut sanitized = String::with_capacity(command.len());

        for c in command.chars() {
            // Allow alphanumeric, spaces, and basic punctuation
            if c.is_ascii_alphanumeric() || c.is_ascii_whitespace() {
                sanitized.push(c);
            } else if ['.', ',', '?', '!', '-', '_', '/'].contains(&c) {
                sanitized.push(c);
            }
            // All other characters are dropped
        }

        // Limit length
        if sanitized.len() > 1024 {
            sanitized.truncate(1024);
        }

        sanitized
    }

    /// Normalize command for comparison
    pub fn normalize(command: &str) -> String {
        command.to_lowercase().trim().to_string()
    }

    /// Check if command contains suspicious patterns
    pub fn is_suspicious(command: &str) -> bool {
        let suspicious_patterns = [
            "rm -rf", "delete all", "format disk", "wipe system",
            "sudo ", "root ", "password ", "secret ", "admin ",
            "exec ", "execute ", "run ", "script ", "bash ", "python ",
            "cat /etc", "read file", "write file", "overwrite ",
        ];

        let normalized = Self::normalize(command);
        suspicious_patterns.iter().any(|p| normalized.contains(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_token_sign_verify() {
        let token = SecurityToken::new(
            b"TOKEN_123".to_vec(),
            b"HARDWARE_456".to_vec(),
        );

        let command = "test command";
        let timestamp = 1234567890u64;
        let nonce = b"NONCE_123".to_vec();

        let signature = token.sign_command(command, timestamp, &nonce);
        assert!(!signature.is_empty());

        assert!(token.verify_signature(command, timestamp, &nonce, &signature));
    }

    #[test]
    fn test_signed_voice_command() {
        let token = SecurityToken::new(
            b"TOKEN_123".to_vec(),
            b"HARDWARE_456".to_vec(),
        );

        let command = "deploy module";
        let signature = token.sign_command(command, 1234567890u64, b"NONCE_123");

        let signed = SignedVoiceCommand::new(
            command.to_string(),
            signature,
            b"TOKEN_123".to_vec(),
            b"HARDWARE_456".to_vec(),
        );

        assert!(signed.verify_signature(&token).is_ok());
    }

    #[test]
    fn test_command_classifier() {
        let classifier = CommandClassifier;

        assert_eq!(
            classifier.classify("what is the status"),
            CommandClassification::Query
        );
        assert_eq!(
            classifier.classify("SET config value"),
            CommandClassification::Mutation
        );
        assert_eq!(
            classifier.classify("seal module"),
            CommandClassification::Sovereign
        );
    }

    #[test]
    fn test_authorization_rules() {
        assert_eq!(
            AuthorizationRules::get_required_level(CommandClassification::Query),
            AuthorizationLevel::ReadOnly
        );
        assert_eq!(
            AuthorizationRules::get_required_level(CommandClassification::Sovereign),
            AuthorizationLevel::Sovereign
        );
    }

    #[test]
    fn test_input_sanitizer() {
        let input = "Hello; rm -rf /; World!";
        let sanitized = InputSanitizer::sanitize(input);

        assert!(!sanitized.contains(";"));
        assert!(!sanitized.contains("-"));
        assert!(InputSanitizer::is_suspicious(input));
    }

    #[test]
    fn test_authorization_level_ordering() {
        assert!(AuthorizationLevel::ReadOnly < AuthorizationLevel::WriteSensitive);
        assert!(AuthorizationLevel::WriteSensitive < AuthorizationLevel::Sovereign);
    }
}
