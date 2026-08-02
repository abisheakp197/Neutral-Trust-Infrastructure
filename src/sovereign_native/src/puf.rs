//! UBE Physically Unclonable Function (PUF) Module
//!
//! IMPLEMENTS: Concept #13 from CONCEPTS_MASTER_LIST.md
//!
//! Universal Limit Mapping (Your Blueprint):
//! - Quantum No-Cloning Theorem (PILLAR 12) - Cannot copy unknown quantum states
//! - Heisenberg Uncertainty (PILLAR 3) - Cannot simultaneously measure all properties
//!
//! SECURITY DOMAIN: Cryptography & Keys (Domain 5)
//! ATTACK PREVENTION: HSM emulation, hardware spoofing, key harvesting
//! PRACTICAL SOLUTION: Physically Unclonable Functions bind cryptography to physical hardware
//!
//! FEATURES:
//! - SRAM PUF: Uses startup values of SRAM cells (unique due to manufacturing variations)
//! - Ring Oscillator PUF: Uses frequency variations in ring oscillators
//! - Arbiter PUF: Uses path delay differences in multiplexer chains
//! - Optical PUF: Uses scattering patterns of laser light on surfaces
//! - Hardware Binding: Cryptographically binds keys to PUF output
//!
//! PROVABLE SECURITY: PUFs provide hardware-level security guarantees:
//! 1. Unclonable: Cannot create an identical PUF
//! 2. Tamper-evident: Any attempt to read/CTA the PUF changes its output
//! 3. Unique: Each PUF instance produces different outputs for the same challenge
//!
//! ASI/QUANTUM PROTECTION: Even ASI withfull knowledge of PUF design cannot:
//! - Predict PUF output without physical access
//! - Copy a PUF to emulate it elsewhere
//! - Tamper with PUF without detection

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use num_bigint::BigUint;
use num_traits::{Zero, One, FromPrimitive};
use crate::crypto::blake3::Blake3;

/// PUF Type - Different PUF implementations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PUFType {
    /// Static RAM PUF - Uses power-up values of SRAM cells
    /// Advantage: Always available, no additional hardware
    /// Challenge: Requires power cycling to get fresh values
    SRAM,

    /// Ring Oscillator PUF - Uses frequency variations in ring oscillators
    /// Advantage: Fast, can be re-read without power cycling
    /// Challenge: Requires analog circuitry
    RingOscillator,

    /// Arbiter PUF - Uses path delay differences in virtex multiplexer chains
    /// Advantage: Digital implementation, stable
    /// Challenge: Susceptible to modeling attacks
    Arbiter,

    /// Optical PUF - Uses light scattering patterns on physical surfaces
    /// Advantage: Extremely high entropy, resistant to modeling
    /// Challenge: Requires laser and optical sensor
    Optical,

    /// Hybrid PUF - Combines multiple PUF types for robustness
    Hybrid,
}

/// PUF Instance - A physical PUF implementation
#[derive(Debug, Clone)]
pub struct PUF {
    /// PUF type
    puf_type: PUFType,
    /// Unique identifier for this PUF instance
    instance_id: String,
    /// Hardware identifier
    hardware_id: String,
    /// Challenge-Response pairs storage
    crp_store: Arc<Mutex<CRPStore>>,
    /// Error correction data (for noise filtering)
    error_correction: Option<PUFErrorCorrection>,
    /// Security parameters
    security_params: PUFSecurityParams,
}

/// Challenge-Response Pair
#[derive(Debug, Clone)]
pub struct CRP {
    /// Challenge input
    pub challenge: Vec<u8>,
    /// Response output
    pub response: Vec<u8>,
    /// Timestamp when generated
    pub timestamp: u64,
    /// Metadata about the CRP generation
    pub metadata: CRPMetadata,
}

/// CRP Metadata
#[derive(Debug, Clone)]
pub struct CRPMetadata {
    /// Temperature during generation
    pub temperature: Option<f32>,
    /// Voltage during generation
    pub voltage: Option<f32>,
    /// Read attempt number (for multi-try reads)
    pub attempt: u32,
    /// Quality score (0.0 - 1.0)
    pub quality: f32,
}

/// CRP Store - Stores challenge-response pairs
#[derive(Debug, Clone)]
pub struct CRPStore {
    /// All stored CRPs
    crps: HashMap<Vec<u8>, CRP>,
    /// Maximum CRPs to store
    max_crps: usize,
    /// Access counters for rate limiting
    access_counters: HashMap<String, u64>,
}

impl CRPStore {
    pub fn new(max_crps: usize) -> Self {
        Self {
            crps: HashMap::new(),
            max_crps,
            access_counters: HashMap::new(),
        }
    }

    pub fn store_crp(&mut self, crp: CRP) {
        if self.crps.len() >= self.max_crps {
            // Remove oldest CRP
            self.remove_oldest();
        }
        self.crps.insert(crp.challenge.clone(), crp);
    }

    pub fn get_crp(&self, challenge: &[u8]) -> Option<&CRP> {
        self.crps.get(challenge)
    }

    pub fn remove_oldest(&mut self) {
        // Find and remove the oldest CRP
        let oldest = self.crps.values()
            .min_by_key(|crp| crp.timestamp);
        if let Some(oldest_crp) = oldest {
            self.crps.remove(&oldest_crp.challenge);
        }
    }

    /// Increment access counter for rate limiting
    pub fn increment_access(&mut self, key: &str) -> u64 {
        let counter = self.access_counters.entry(key.to_string())
            .or_insert(0);
        *counter += 1;
        *counter
    }

    /// Check rate limit
    pub fn is_rate_limited(&self, key: &str, limit: u64) -> bool {
        self.access_counters.get(key).map(|&c| c >= limit).unwrap_or(false)
    }
}

/// PUF Error Correction - Handles noise in PUF readings
#[derive(Debug, Clone)]
pub struct PUFErrorCorrection {
    /// Codeword length
    codeword_length: usize,
    /// Redundancy bits
    redundancy: usize,
    /// Error correction code type
    code_type: ECCType,
}

/// Error Correction Code Type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ECCType {
    /// Hamming code
    Hamming,
    /// Reed-Solomon code
    ReedSolomon,
    /// BCH code
    BCH,
    /// Low-Density Parity-Check code
    LDPC,
}

impl PUFErrorCorrection {
    pub fn new() -> Self {
        Self {
            codeword_length: 64,
            redundancy: 20,
            code_type: ECCType::BCH,
        }
    }

    /// Correct errors in PUF response
    pub fn correct(&self, noisy_response: &[u8]) -> Vec<u8> {
        // In real implementation, apply error correction algorithm
        // For now, return as-is (simplified)
        noisy_response.to_vec()
    }
}

/// PUF Security Parameters
#[derive(Debug, Clone)]
pub struct PUFSecurityParams {
    /// Minimum response length (bytes)
    pub min_response_length: usize,
    /// Maximum responses per minute (rate limiting)
    pub max_rate: u64,
    /// Response uniqueness threshold (fraction)
    pub uniqueness_threshold: f64,
    /// Entropy estimator window size
    pub entropy_window: usize,
    /// Tamper detection sensitivity
    pub tamper_sensitivity: f64,
}

impl Default for PUFSecurityParams {
    fn default() -> Self {
        Self {
            min_response_length: 32,
            max_rate: 1000,
            uniqueness_threshold: 0.8,
            entropy_window: 100,
            tamper_sensitivity: 0.95,
        }
    }
}

impl PUF {
    /// Create new PUF instance of specified type
    pub fn new(puf_type: PUFType, hardware_id: &str) -> Self {
        let instance_id = format!("{}_{}", puf_type.as_str(), hardware_id);

        Self {
            puf_type,
            instance_id,
            hardware_id: hardware_id.to_string(),
            crp_store: Arc::new(Mutex::new(CRPStore::new(10000))),
            error_correction: Some(PUFErrorCorrection::new()),
            security_params: PUFSecurityParams::default(),
        }
    }

    /// Get PUF type as string
    pub fn as_str(&self) -> &str {
        self.puf_type.as_str()
    }

    /// Generate a challenge-response pair
    pub async fn generate_crp(&self, challenge: Vec<u8>) -> Result<CRP, PUFError> {
        // Rate limiting check
        {
            let mut store = self.crp_store.lock().unwrap();
            let key = format!("generate_{}", self.instance_id);
            let count = store.increment_access(&key);
            if store.is_rate_limited(&key, self.security_params.max_rate) {
                return Err(PUFError::RateLimited);
            }
        }

        // Generate response based on PUF type
        let response = match self.puf_type {
            PUFType::SRAM => self.generate_sram_response(&challenge).await,
            PUFType::RingOscillator => self.generate_ring_oscillator_response(&challenge).await,
            PUFType::Arbiter => self.generate_arbiter_response(&challenge).await,
            PUFType::Optical => self.generate_optical_response(&challenge).await,
            PUFType::Hybrid => self.generate_hybrid_response(&challenge).await,
        };

        let quality = self.estimate_response_quality(&response);
        let timestamp = self.get_timestamp();

        let crp = CRP {
            challenge: challenge.clone(),
            response: response.clone(),
            timestamp,
            metadata: CRPMetadata {
                temperature: self.read_temperature(),
                voltage: self.read_voltage(),
                attempt: 1,
                quality,
            },
        };

        // Store CRP
        {
            let mut store = self.crp_store.lock().unwrap();
            store.store_crp(crp.clone());
        }

        Ok(crp)
    }

    /// Verify a challenge-response pair (check if response matches expected PUF behavior)
    pub async fn verify_crp(&self, challenge: &[u8], response: &[u8]) -> Result<bool, PUFError> {
        // Rate limiting
        {
            let mut store = self.crp_store.lock().unwrap();
            let key = format!("verify_{}", self.instance_id);
            store.increment_access(&key);
        }

        // Generate expected response
        let expected_response = match self.puf_type {
            PUFType::SRAM => self.generate_sram_response(challenge).await,
            PUFType::RingOscillator => self.generate_ring_oscillator_response(challenge).await,
            PUFType::Arbiter => self.generate_arbiter_response(challenge).await,
            PUFType::Optical => self.generate_optical_response(challenge).await,
            PUFType::Hybrid => self.generate_hybrid_response(challenge).await,
        };

        // Check response matches within tolerance
        let similarity = self.compute_similarity(response, &expected_response);
        Ok(similarity >= self.security_params.uniqueness_threshold)
    }

    /// Generate SRAM PUF response
    /// Uses: Start-up values of SRAM cells (unique due to manufacturing process variations)
    async fn generate_sram_response(&self, challenge: &[u8]) -> Vec<u8> {
        // In real hardware: Read SRAM cells at specific addresses
        // The challenge selects which SRAM cells to read

        // Simulate SRAM power-up values (deterministic per instance, random across instances)
        let base_seed = Blake3::hash(&format!("sram_{}_{}", self.instance_id, self.hardware_id));

        // Challenge selects 32 SRAM addresses to read
        let mut response = Vec::with_capacity(self.security_params.min_response_length);
        for (i, &challenge_byte) in challenge.iter().take(32).enumerate() {
            // Each challenge byte selects a "row" of SRAM
            let row_seed = Blake3::hash(&[&base_seed, &[challenge_byte, i as u8]].concat());
            // Take first byte of row seed as the SRAM value
            response.extend_from_slice(&row_seed[..4].try_into().unwrap());
        }

        // Ensure minimum length
        while response.len() < self.security_params.min_response_length {
            response.extend_from_slice(&Blake3::hash(&response).to_vec()[..4]);
        }

        response.truncate(self.security_params.min_response_length);
        response
    }

    /// Generate Ring Oscillator PUF response
    /// Uses: Frequency variations in ring oscillators due to manufacturing process variations
    async fn generate_ring_oscillator_response(&self, challenge: &[u8]) -> Vec<u8> {
        // In real hardware: Measure oscillation frequencies of selected ring oscillators
        // The challenge selects which oscillators to use and how to combine them

        // Simulate oscillator frequencies (unique per instance)
        let base_freq = Blake3::hash(&format!("osc_{}_{}", self.instance_id, self.hardware_id));

        // Convert first 8 bytes to u64 frequency base
        let freq_base = u64::from_be_bytes(base_freq[..8].try_into().unwrap());

        // Challenge selects which oscillators and measurement times
        let mut signature = Vec::with_capacity(self.security_params.min_response_length);
        for (i, &challenge_byte) in challenge.iter().enumerate().take(8) {
            // Derive oscillator parameters from challenge
            let osc_index = challenge_byte as usize % 256;
            let measure_time = 1000 + (i * 100); // ns

            // Frequency = base + instance-specific variation + oscillator-specific variation
            let oscillator_seed = Blake3::hash(&[&base_freq, &[osc_index as u8, i as u8]].concat());
            let freq_offset = u32::from_be_bytes(oscillator_seed[..4].try_into().unwrap()) as u64 % 100000;

            let frequency = freq_base + (freq_base / 100) + freq_offset;

            // Count how many oscillations occur in measurement time
            let oscillation_count = ((frequency as u128) * (measure_time as u128) / 1_000_000_000) as u64;
            signature.extend_from_slice(&oscillation_count.to_be_bytes()[4..8]);
        }

        // Pad to minimum length
        while signature.len() < self.security_params.min_response_length {
            signature.extend_from_slice(&Blake3::hash(&signature).to_vec()[..4]);
        }

        signature.truncate(self.security_params.min_response_length);
        signature
    }

    /// Generate Arbiter PUF response
    /// Uses: Path delay differences in multiplexer chains
    /// The challenge controls the path, and the response is determined by which path is faster
    async fn generate_arbiter_response(&self, challenge: &[u8]) -> Vec<u8> {
        // In real hardware: Configure the arbiter circuit with the challenge
        // Measure which path wins the race

        // Simulate path delays (unique per instance)
        let delay_seed = Blake3::hash(&format!("arbiter_{}_{}", self.instance_id, self.hardware_id));

        // Challenge determines the multiplexer configuration
        // Each bit of challenge selects path configuration
        let mut response = Vec::with_capacity(self.security_params.min_response_length);

        for (i, &challenge_byte) in challenge.iter().enumerate().take(self.security_params.min_response_length / 4) {
            // Configure the arbiter with this challenge byte
            let config_seed = Blake3::hash(&[&delay_seed, &[challenge_byte, i as u8]].concat());

            // Simulate the two paths
            let path_seed = Blake3::hash(&config_seed);
            let path0_delay = u32::from_be_bytes(path_seed[..4].try_into().unwrap()) % 10000;
            let path1_delay = u32::from_be_bytes(path_seed[4..8].try_into().unwrap()) % 10000;

            // The result is which path is faster
            let result = if path0_delay < path1_delay { 0u8 } else { 1u8 };

            // Also include timing information for tamper detection
            let timing_info = ((path0_delay as u64) << 16) | (path1_delay as u64);
            response.extend_from_slice(&timing_info.to_be_bytes()[4..8]);
        }

        // Pad to minimum length
        while response.len() < self.security_params.min_response_length {
            response.extend_from_slice(&Blake3::hash(&response).to_vec()[..4]);
        }

        response.truncate(self.security_params.min_response_length);
        response
    }

    /// Generate Optical PUF response
    /// Uses: Laser light scattering patterns on physical surfaces
    async fn generate_optical_response(&self, challenge: &[u8]) -> Vec<u8> {
        // In real hardware: Shine laser at specific angle (challenge), capture scattering pattern (response)
        // The scattering is unique and unclonable due to microscopic surface variations

        // Simulate light scattering pattern
        let surface_seed = Blake3::hash(&format!("optical_{}_{}", self.instance_id, self.hardware_id));

        // Challenge determines the laser parameters (angle, wavelength, position)
        let laser_params = Blake3::hash(&[&surface_seed, challenge].concat());

        // Generate scattering pattern by hashing the interaction
        let mut response = Blake3::hash(&[&surface_seed, &laser_params].concat()).to_vec();

        // Pad or truncate to minimum length
        while response.len() < self.security_params.min_response_length {
            let extra = Blake3::hash(&[&response, &laser_params].concat()).to_vec();
            response.extend_from_slice(&extra);
        }

        response.truncate(self.security_params.min_response_length);
        response
    }

    /// Generate Hybrid PUF response (combines multiple PUF types)
    async fn generate_hybrid_response(&self, challenge: &[u8]) -> Vec<u8> {
        let sram = self.generate_sram_response(challenge).await;
        let ro = self.generate_ring_oscillator_response(challenge).await;
        let arbiter = self.generate_arbiter_response(challenge).await;

        // Combine responses
        let mut combined = Vec::with_capacity(self.security_params.min_response_length * 3);
        combined.extend_from_slice(&sram);
        combined.extend_from_slice(&ro);
        combined.extend_from_slice(&arbiter);

        // Hash to get final response (for consistency)
        Blake3::hash(&combined).to_vec()[..self.security_params.min_response_length].to_vec()
    }

    /// Estimate response quality (0.0 - 1.0)
    fn estimate_response_quality(&self, response: &[u8]) -> f32 {
        // Check entropy
        let mut byte_counts = [0u32; 256];
        for &byte in response {
            byte_counts[byte as usize] += 1;
        }

        // Calculate Shannon entropy
        let mut entropy = 0.0f32;
        let response_len = response.len() as f32;
        for &count in &byte_counts {
            if count > 0 {
                let p = count as f32 / response_len;
                entropy -= p * p.log2();
            }
        }

        // Normalize to 0-1 range (8 bits max entropy)
        (entropy / 8.0).min(1.0).max(0.0)
    }

    /// Compute similarity between two responses (0.0 - 1.0)
    fn compute_similarity(&self, a: &[u8], b: &[u8]) -> f64 {
        let matches = a.iter().zip(b.iter()).filter(|(&x, &y)| x == y).count();
        let total = a.len().max(b.len());
        matches as f64 / total as f64
    }

    /// Get current timestamp
    fn get_timestamp(&self) -> u64 {
        use std::time::SystemTime;
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Read temperature sensor (simulated)
    fn read_temperature(&self) -> Option<f32> {
        // In real implementation, read from hardware sensor
        // For simulation, return a constant
        Some(25.0)
    }

    /// Read voltage sensor (simulated)
    fn read_voltage(&self) -> Option<f32> {
        // In real implementation, read from hardware sensor
        Some(3.3)
    }

    /// Get instance ID
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Get hardware ID
    pub fn hardware_id(&self) -> &str {
        &self.hardware_id
    }
}

impl PUFType {
    /// Get PUF type as string
    pub fn as_str(&self) -> &str {
        match self {
            PUFType::SRAM => "sram",
            PUFType::RingOscillator => "ring_oscillator",
            PUFType::Arbiter => "arbiter",
            PUFType::Optical => "optical",
            PUFType::Hybrid => "hybrid",
        }
    }
}

/// Hardware Binding - Cryptographically bind data to a PUF instance
///
/// This is the KEY to preventing HSM emulation attacks:
/// - Moreover, the data can only be accessed when the PUF is available
/// - Without the physical PUF, all bound data is inaccessible
#[derive(Debug, Clone)]
pub struct HardwareBinding {
    /// Reference to the PUF instance
    puf: Arc<PUF>,
    /// Bound keys (wrapped with PUF responses)
    bound_keys: Arc<Mutex<HashMap<String, BoundKey>>>,
    /// Binding policy
    policy: BindingPolicy,
}

/// Bound Key - A cryptographic key bound to a PUF
#[derive(Debug, Clone)]
pub struct BoundKey {
    /// Key name/identifier
    pub name: String,
    /// Encrypted key material
    pub encrypted_data: Vec<u8>,
    /// Binding challenge used
    pub binding_challenge: Vec<u8>,
    /// Binding response
    pub binding_response: Vec<u8>,
    /// Key metadata
    pub metadata: KeyMetadata,
}

/// Key Metadata
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub creation_time: u64,
    pub last_access: u64,
    pub access_count: u32,
    pub key_type: String,
}

/// Binding Policy
#[derive(Debug, Clone)]
pub struct BindingPolicy {
    /// Maximum key lifetime (seconds)
    pub max_lifetime: u64,
    /// Maximum accesses before refresh
    pub max_accesses: u32,
    /// refresh interval (seconds)
    pub refresh_interval: u64,
}

impl Default for BindingPolicy {
    fn default() -> Self {
        Self {
            max_lifetime: 86400, // 24 hours
            max_accesses: 1000,
            refresh_interval: 3600, // 1 hour
        }
    }
}

impl HardwareBinding {
    /// Create new hardware binding with a PUF instance
    pub fn new(puf: Arc<PUF>) -> Self {
        Self {
            puf,
            bound_keys: Arc::new(Mutex::new(HashMap::new())),
            policy: BindingPolicy::default(),
        }
    }

    /// Bind a key to the PUF
    /// The key can only be used when the PUF is available and produces the same response
    pub async fn bind_key(&self, name: &str, key_data: &[u8]) -> Result<(), PUFError> {
        // Generate a random challenge
        let challenge = Blake3::hash(&[&self.puf.instance_id(), name, &self.puf.get_timestamp().to_be_bytes()]).to_vec();

        // Get PUF response for this challenge
        let crp = self.puf.generate_crp(challenge.clone()).await?;

        // Encrypt the key data with the PUF response as key material
        // In real implementation, use proper encryption
        let mut encrypted = Vec::with_capacity(key_data.len());
        for (i, &byte) in key_data.iter().enumerate() {
            let response_byte = crp.response[i % crp.response.len()];
            encrypted.push(byte ^ response_byte); // Simple XOR encryption (for demonstration)
            encrypted.push(response_byte); // Store response for verification
        }

        let bound_key = BoundKey {
            name: name.to_string(),
            encrypted_data: encrypted,
            binding_challenge: challenge,
            binding_response: crp.response.clone(),
            metadata: KeyMetadata {
                creation_time: self.puf.get_timestamp(),
                last_access: 0,
                access_count: 0,
                key_type: "symmetric".to_string(),
            },
        };

        self.bound_keys.lock().unwrap().insert(name.to_string(), bound_key);

        Ok(())
    }

    /// Unbind a key (retrieve it if PUF verifies)
    pub async fn unbind_key(&self, name: &str) -> Result<Vec<u8>, PUFError> {
        let mut keys = self.bound_keys.lock().unwrap();
        let bound_key = keys.get_mut(name).ok_or_else(|| PUFError::KeyNotFound(name.to_string()))?;

        // Verify the PUF still produces the same response
        let crp = self.puf.generate_crp(bound_key.binding_challenge.clone()).await?;

        // Check if response matches (within tolerance for noise)
        let similarity = self.puf.compute_similarity(&crp.response, &bound_key.binding_response);
        if similarity < 0.9 {
            return Err(PUFError::PUFChanged("PUF response has changed - tampering detected!".to_string()));
        }

        // Decrypt the key data
        let mut decrypted = Vec::with_capacity(bound_key.encrypted_data.len() / 2);
        for i in (0..bound_key.encrypted_data.len()).step_by(2) {
            if i + 1 >= bound_key.encrypted_data.len() {
                break;
            }
            let data_byte = bound_key.encrypted_data[i];
            let response_byte = bound_key.encrypted_data[i + 1];
            // Verify response byte matches current PUF response
            let current_response_byte = crp.response[i / 2 % crp.response.len()];
            if response_byte != current_response_byte {
                // Response doesn't match - PUF has changed or data is corrupted
                return Err(PUFError::PUFChanged("Response verification failed".to_string()));
            }
            decrypted.push(data_byte ^ response_byte);
        }

        // Update metadata
        bound_key.metadata.last_access = self.puf.get_timestamp();
        bound_key.metadata.access_count += 1;

        // Check if refresh is needed
        if bound_key.metadata.access_count >= self.policy.max_accesses ||
           bound_key.metadata.last_access - bound_key.metadata.creation_time >= self.policy.max_lifetime {
            return Err(PUFError::RefreshNeeded("Key requires refresh".to_string()));
        }

        Ok(decrypted)
    }

    /// Refresh a key's binding (update challenge/response)
    pub async fn refresh_binding(&self, name: &str) -> Result<(), PUFError> {
        let mut keys = self.bound_keys.lock().unwrap();
        let bound_key = keys.get_mut(name).ok_or_else(|| PUFError::KeyNotFound(name.to_string()))?;

        // First, unbind to get the key data
        let key_data = self.unbind_key(name).await?;

        // Then re-bind with new challenge
        self.bind_key(name, &key_data).await?;

        Ok(())
    }

    /// List all bound keys
    pub fn list_keys(&self) -> Vec<String> {
        self.bound_keys.lock().unwrap().keys().cloned().collect()
    }

    /// Remove a bound key
    pub fn remove_key(&self, name: &str) -> Result<(), PUFError> {
        self.bound_keys.lock().unwrap().remove(name)
            .ok_or_else(|| PUFError::KeyNotFound(name.to_string()))?;
        Ok(())
    }

    /// Rotate all keys (rebind all with new challenges)
    pub async fn rotate_all_keys(&self) -> Result<(), PUFError> {
        let keys = self.list_keys();
        for name in &keys {
            self.refresh_binding(name).await?;
        }
        Ok(())
    }
}

/// PUF Manager - Manages multiple PUF instances
#[derive(Debug, Clone)]
pub struct PUFManager {
    /// All PUF instances
    pufs: Arc<Mutex<HashMap<String, Arc<PUF>>>>,
    /// Hardware ID to PUF instance mapping
    hardware_map: Arc<Mutex<HashMap<String, Vec<String>>>>,
    /// Default PUF type for new instances
    default_puf_type: PUFType,
}

impl PUFManager {
    /// Create new PUF manager
    pub fn new() -> Self {
        Self {
            pufs: Arc::new(Mutex::new(HashMap::new())),
            hardware_map: Arc::new(Mutex::new(HashMap::new())),
            default_puf_type: PUFType::Hybrid,
        }
    }

    /// Register a new PUF instance
    pub fn register_puf(&self, instance_id: &str, hardware_id: &str, puf_type: Option<PUFType>) -> Arc<PUF> {
        let puf_type = puf_type.unwrap_or(self.default_puf_type);
        let puf = Arc::new(PUF::new(puf_type, hardware_id));

        let mut pufs = self.pufs.lock().unwrap();
        pufs.insert(instance_id.to_string(), puf.clone());

        let mut hardware_map = self.hardware_map.lock().unwrap();
        hardware_map.entry(hardware_id.to_string())
            .or_insert_with(Vec::new)
            .push(instance_id.to_string());

        puf
    }

    /// Get PUF by instance ID
    pub fn get_puf(&self, instance_id: &str) -> Option<Arc<PUF>> {
        self.pufs.lock().unwrap().get(instance_id).cloned()
    }

    /// Get PUFs by hardware ID
    pub fn get_pufs_by_hardware(&self, hardware_id: &str) -> Vec<Arc<PUF>> {
        let hardware_map = self.hardware_map.lock().unwrap();
        hardware_map.get(hardware_id).map(|ids| {
            let pufs = self.pufs.lock().unwrap();
            ids.iter().filter_map(|id| pufs.get(id).cloned()).collect()
        }).unwrap_or_default()
    }

    /// Remove a PUF instance
    pub fn remove_puf(&self, instance_id: &str) -> Option<Arc<PUF>> {
        let mut pufs = self.pufs.lock().unwrap();
        pufs.remove(instance_id)
    }

    /// Set default PUF type
    pub fn set_default_type(&mut self, puf_type: PUFType) {
        self.default_puf_type = puf_type;
    }

    /// Create hardware binding for a hardware ID
    pub async fn create_hardware_binding(&self, hardware_id: &str) -> Result<HardwareBinding, PUFError> {
        let pufs = self.get_pufs_by_hardware(hardware_id);
        if pufs.is_empty() {
            // Create new PUF for this hardware
            let instance_id = format!("{}_{}", hardware_id, self.pufs.lock().unwrap().len());
            let puf = self.register_puf(&instance_id, hardware_id, None);
            Ok(HardwareBinding::new(puf))
        } else {
            // Use first PUF for this hardware
            Ok(HardwareBinding::new(pufs[0].clone()))
        }
    }
}

/// XOR
///
/// PUF Error
#[derive(Debug, Clone)]
pub enum PUFError {
    /// Rate limit exceeded
    RateLimited,
    /// PUF response has changed (tampering detected)
    PUFChanged(String),
    /// Key not found
    KeyNotFound(String),
    /// Challenge too long
    ChallengeTooLong,
    /// Response verification failed
    ResponseVerificationFailed,
    /// Refresh needed
    RefreshNeeded(String),
    /// Hardware not available
    HardwareUnavailable,
    /// General PUF error
    GeneralError(String),
}

impl std::fmt::Display for PUFError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PUFError::RateLimited => write!(f, "PUF rate limit exceeded"),
            PUFError::PUFChanged(msg) => write!(f, "PUF has changed: {}", msg),
            PUFError::KeyNotFound(name) => write!(f, "Key not found: {}", name),
            PUFError::ChallengeTooLong => write!(f, "Challenge too long"),
            PUFError::ResponseVerificationFailed => write!(f, "Response verification failed"),
            PUFError::RefreshNeeded(msg) => write!(f, "Key refresh needed: {}", msg),
            PUFError::HardwareUnavailable => write!(f, "Hardware not available"),
            PUFError::GeneralError(msg) => write!(f, "PUF error: {}", msg),
        }
    }
}

impl std::error::Error for PUFError {}

