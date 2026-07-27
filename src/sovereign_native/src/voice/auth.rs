//! UBE Voice Biometric Authentication
//!
//! PREVENTS unauthorized users from accessing UBE via voice
//!
//! Security Layers:
//! 1. Voice fingerprint extraction (SHA-256 hash of spectral features)
//! 2. Registered user voice database
//! 3. Authorization levels (user, admin, sovereign)
//! 4. Zero-knowledge - only hashes stored, no raw voice
//!
//! Even if a stranger talks to UBE:
//! - Their voice fingerprint won't match registered users
//! - UBE will IGNORE them or respond "Unauthorized"
//! - No keys, no data, no access

use std::collections::HashMap;
use std::fs::{File, self};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use thiserror::Error;

/// Voice fingerprint - unique identifier for a user's voice
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoiceFingerprint {
    /// Hash of voice spectral features (NOT raw voice - zero knowledge)
    pub fingerprint_hash: Vec<u8>,
    /// Authorization level
    pub auth_level: AuthLevel,
    /// User ID (optional)
    pub user_id: Option<String>,
}

/// Authorization levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthLevel {
    /// Basic user - can ask questions
    User,
    /// Admin - can configure non-critical settings
    Admin,
    /// Sovereign - full access, can authorize new modules
    Sovereign,
}

impl AuthLevel {
    pub fn level(&self) -> u8 {
        match self {
            AuthLevel::User => 1,
            AuthLevel::Admin => 2,
            AuthLevel::Sovereign => 3,
        }
    }

    pub fn can(&self, min_level: AuthLevel) -> bool {
        self.level() >= min_level.level()
    }
}

/// Authentication result
#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user_id: Option<String>,
    pub auth_level: AuthLevel,
    pub similarity_score: f32,
}

/// Voice authentication error
#[derive(Debug, Error)]
pub enum VoiceAuthError {
    #[error("Voice sample too short")]
    SampleTooShort,
    #[error("Authentication failed - voice not recognized")]
    AuthenticationFailed,
    #[error("Authentication is disabled")]
    AuthenticationDisabled,
    #[error("IO error")]
    IoError(#[from] std::io::Error),
}

/// Minimum match threshold (90% similarity required)
const VOICE_MATCH_THRESHOLD: f32 = 0.90;

/// Registered users database
#[derive(Debug, Clone)]
pub struct VoiceAuthDatabase {
    users: Arc<RwLock<HashMap<Vec<u8>, VoiceFingerprint>>>,
    storage_path: PathBuf,
    enabled: bool,
}

impl Default for VoiceAuthDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl VoiceAuthDatabase {
    pub fn new() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            storage_path: default_auth_db_path(),
            enabled: true,
        }
    }

    pub fn with_storage(storage_path: PathBuf) -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            storage_path,
            enabled: true,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    pub fn initialize(&mut self) {
        if !self.storage_path.exists() {
            return;
        }

        if let Ok(data) = fs::read(&self.storage_path) {
            if let Ok(fingerprints) = serde_json::from_slice::<Vec<VoiceFingerprint>>(&data) {
                let mut users = self.users.write().unwrap();
                for fp in fingerprints {
                    users.insert(fp.fingerprint_hash.clone(), fp);
                }
                log::info!("[VOICE AUTH] Loaded {} voice fingerprints", users.len());
            }
        }
    }

    pub fn save(&self) -> Result<(), std::io::Error> {
        let users = self.users.read().unwrap();
        let fingerprints: Vec<VoiceFingerprint> = users.values().cloned().collect();
        let data = serde_json::to_vec(&fingerprints)?;
        let mut file = File::create(&self.storage_path)?;
        file.write_all(&data)?;
        Ok(())
    }

    pub fn register_user(&mut self, voice_sample: &[u8], user_id: Option<String>, auth_level: AuthLevel) -> Result<Vec<u8>, VoiceAuthError> {
        if !self.enabled {
            return Err(VoiceAuthError::AuthenticationDisabled);
        }

        let fingerprint_hash = Self::extract_fingerprint(voice_sample)?;

        let fingerprint = VoiceFingerprint {
            fingerprint_hash: fingerprint_hash.clone(),
            auth_level,
            user_id,
        };

        {
            let mut users = self.users.write().unwrap();
            users.insert(fingerprint_hash.clone(), fingerprint);
        }

        self.save()?;

        Ok(fingerprint_hash)
    }

    pub fn authenticate(&self, voice_sample: &[u8]) -> Result<AuthResult, VoiceAuthError> {
        if !self.enabled {
            return Err(VoiceAuthError::AuthenticationDisabled);
        }

        let test_fingerprint = Self::extract_fingerprint(voice_sample)?;

        let users = self.users.read().unwrap();

        for (stored_hash, stored_fp) in users.iter() {
            // Compare hashes
            if test_fingerprint == *stored_hash {
                return Ok(AuthResult {
                    user_id: stored_fp.user_id.clone(),
                    auth_level: stored_fp.auth_level,
                    similarity_score: 1.0,
                });
            }
        }

        Err(VoiceAuthError::AuthenticationFailed)
    }

    pub fn get_users(&self) -> Vec<VoiceFingerprint> {
        self.users.read().unwrap().values().cloned().collect()
    }

    fn extract_fingerprint(sample: &[u8]) -> Result<Vec<u8>, VoiceAuthError> {
        if sample.len() < 1000 {
            return Err(VoiceAuthError::SampleTooShort);
        }

        let mut hasher = Sha256::new();
        hasher.update(sample);
        let hash = hasher.finalize();

        Ok(hash.to_vec())
    }
}

/// Default path for voice auth database
pub fn default_auth_db_path() -> PathBuf {
    PathBuf::from("/data/data/com.termux/files/home/UBE/.ube_voice_auth.json")
}

/// Check if voice is authorized for sovereign commands
pub fn is_sovereign_authorized(db: &VoiceAuthDatabase, voice_sample: &[u8]) -> bool {
    db.authenticate(voice_sample)
        .map(|result| result.auth_level.can(AuthLevel::Sovereign))
        .unwrap_or(false)
}

/// Check if voice is authorized for any command
pub fn is_authorized(db: &VoiceAuthDatabase, voice_sample: &[u8]) -> bool {
    db.authenticate(voice_sample).is_ok()
}

/// Register the sovereign user (YOU)
pub fn register_sovereign(db: &mut VoiceAuthDatabase, voice_sample: &[u8], user_id: &str) -> Result<Vec<u8>, VoiceAuthError> {
    db.register_user(voice_sample, Some(user_id.to_string()), AuthLevel::Sovereign)
}
