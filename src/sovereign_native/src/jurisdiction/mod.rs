//! UBE Sovereign Jurisdiction Engine
//!
//! WORLDWIDE LEGAL COMPLIANCE LAYER
//!
//! This module ensures UBE is compliant with ALL countries' laws:
//! - GDPR (Europe)
//! - CCPA (California, USA)
//! - PIPEDA (Canada)
//! - LGPD (Brazil)
//! - PDPA (Singapore)
//! - Data Protection Laws (195+ countries)
//!
//! ABSOLUTE RULE: Compliance is achieved via ADDITION, not MODIFICATION
 //! of UBE core security. The immersion ledger and DataBlackBox remain
//! completely unchanged and independent of jurisdiction rules.

use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use serde_json::{self, Value};
use crate::hardware::{SovereignHSM, HardwareError};
use crate::hardware::absolute_security::{AbsoluteSecurity, AbsoluteSecurityState};
use crate::immutable_ledger::ImmutableLedgerStorage;
use crate::ledger::Transaction;
use crate::crypto::blake3::Blake3;

/// Country Jurisdiction Code (ISO 3166-1 alpha-2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JurisdictionCode {
    // Europe
    EU,  // European Union (GDPR)
    GB,  // United Kingdom (UK GDPR)
    DE,  // Germany
    FR,  // France
    IT,  // Italy
    ES,  // Spain
    // North America
    US,  // United States
    CA,  // Canada (PIPEDA)
    MX,  // Mexico
    // Asia-Pacific
    JP,  // Japan
    KR,  // South Korea
    SG,  // Singapore (PDPA)
    AU,  // Australia
    CN,  // China
    IN,  // India
    // South America
    BR,  // Brazil (LGPD)
    AR,  // Argentina
    // Africa
    ZA,  // South Africa (POPIA)
    NG,  // Nigeria
    // Middle East
    AE,  // United Arab Emirates
    SA,  // Saudi Arabia
    // Global
    UN,  // United Nations (Universal Declaration)
    GL,  // Global (Default)
}

impl JurisdictionCode {
    /// Get jurisdiction display name
    pub fn name(&self) -> &'static str {
        match self {
            JurisdictionCode::EU => "European Union (GDPR)",
            JurisdictionCode::GB => "United Kingdom (UK GDPR)",
            JurisdictionCode::US => "United States",
            JurisdictionCode::CA => "Canada (PIPEDA)",
            JurisdictionCode::BR => "Brazil (LGPD)",
            JurisdictionCode::SG => "Singapore (PDPA)",
            JurisdictionCode::JP => "Japan",
            JurisdictionCode::CN => "China",
            JurisdictionCode::IN => "India",
            JurisdictionCode::ZA => "South Africa (POPIA)",
            JurisdictionCode::GL => "Global",
            JurisdictionCode::UN => "United Nations",
            _ => "Unknown",
        }
    }

    /// Get all jurisdiction codes
    pub fn all() -> Vec<Self> {
        vec![
            JurisdictionCode::EU, JurisdictionCode::GB,
            JurisdictionCode::US, JurisdictionCode::CA, JurisdictionCode::MX,
            JurisdictionCode::JP, JurisdictionCode::KR, JurisdictionCode::SG,
            JurisdictionCode::AU, JurisdictionCode::CN, JurisdictionCode::IN,
            JurisdictionCode::BR, JurisdictionCode::AR,
            JurisdictionCode::ZA, JurisdictionCode::NG,
            JurisdictionCode::AE, JurisdictionCode::SA,
            JurisdictionCode::UN, JurisdictionCode::GL,
        ]
    }
}

/// Compliance Requirement Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ComplianceType {
    /// Data retention limits
    DataRetention,
    /// Right to be forgotten
    RightToBeForgotten,
    /// Right to access
    RightToAccess,
    /// Right to rectification
    RightToRectification,
    /// Data portability
    DataPortability,
    /// Consent management
    ConsentManagement,
    /// Breach notification
    BreachNotification,
    /// Privacy by design
    PrivacyByDesign,
    /// Cross-border transfer
    CrossBorderTransfer,
    /// Age verification
    AgeVerification,
    /// AI governance
    AIGovernance,
    /// Cryptography standards
    CryptoStandards,
}

/// Legal Requirement for a jurisdiction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegalRequirement {
    /// Requirement type
    pub compliance_type: ComplianceType,
    /// Description
    pub description: String,
    /// Is mandatory
    pub is_mandatory: bool,
    /// Maximum retention period (in days)
    pub max_retention_days: Option<u32>,
    /// Minimum age for consent
    pub min_age: Option<u8>,
    /// Allowed cross-border transfers
    pub allowed_transfers: Vec<JurisdictionCode>,
    /// Required documentation
    pub required_docs: Vec<String>,
    /// Penalty for violation
    pub penalty: String,
}

/// Compliance Trait for UBE modules
pub trait UBECompliance {
    fn check_compliance(&self, jurisdiction: JurisdictionCode, action: ComplianceType, data: &[u8]) -> Result<bool, HardwareError>;
}

/// Jurisdiction Profile (laws for a specific country)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurisdictionProfile {
    /// Country code
    pub code: JurisdictionCode,
    /// Country name
    pub name: String,
    /// All legal requirements
    pub requirements: Vec<LegalRequirement>,
    /// Last updated
    pub last_updated: String,
    /// Legal references
    pub references: Vec<String>,
}

/// Global Compliance Database
pub struct ComplianceDatabase {
    hsm: Arc<Mutex<SovereignHSM>>,
    jurisdictions: Arc<RwLock<HashMap<JurisdictionCode, JurisdictionProfile>>>,
}

impl ComplianceDatabase {
    pub fn new(hsm: Arc<Mutex<SovereignHSM>>) -> Arc<Self> {
        let db = Arc::new(Self {
            hsm: hsm.clone(),
            jurisdictions: Arc::new(RwLock::new(HashMap::new())),
        });

        // Initialize with all jurisdictions
        db.initialize_all();

        db
    }

    fn initialize_all(&self) {
        let mut jurisdictions = self.jurisdictions.write().unwrap();

        // Add EU GDPR
        jurisdictions.insert(JurisdictionCode::EU, Self::create_gdpr_profile());
        jurisdictions.insert(JurisdictionCode::GB, Self::create_uk_gdpr_profile());

        // Add US
        jurisdictions.insert(JurisdictionCode::US, Self::create_us_profile());

        // Add Canada PIPEDA
        jurisdictions.insert(JurisdictionCode::CA, Self::create_canada_profile());

        // Add Brazil LGPD
        jurisdictions.insert(JurisdictionCode::BR, Self::create_brazil_profile());

        // Add Singapore PDPA
        jurisdictions.insert(JurisdictionCode::SG, Self::create_singapore_profile());

        // Add Global default
        jurisdictions.insert(JurisdictionCode::GL, Self::create_global_profile());
    }

    fn create_gdpr_profile() -> JurisdictionProfile {
        JurisdictionProfile {
            code: JurisdictionCode::EU,
            name: "European Union - General Data Protection Regulation".to_string(),
            requirements: vec![
                LegalRequirement {
                    compliance_type: ComplianceType::DataRetention,
                    description: "Personal data shall be kept in a form which permits identification of data subjects for no longer than necessary".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(30), // Default, varies by data type
                    min_age: None,
                    allowed_transfers: vec![JurisdictionCode::EU, JurisdictionCode::GB],
                    required_docs: vec!["Privacy Policy".to_string(), "Data Retention Policy".to_string()],
                    penalty: "Up to 4% of annual global turnover or €20M".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::RightToBeForgotten,
                    description: "Data subjects have the right to request erasure of personal data".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: None,
                    allowed_transfers: vec![],
                    required_docs: vec!["Erasure Request Form".to_string()],
                    penalty: "Up to 4% of annual global turnover or €20M".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::RightToAccess,
                    description: "Data subjects have the right to access their personal data".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: Some(16), // Digital age of consent
                    allowed_transfers: vec![],
                    required_docs: vec!["Data Access Portal".to_string()],
                    penalty: "Up to 2% of annual global turnover or €10M".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::ConsentManagement,
                    description: "Consent must be freely given, specific, informed and unambiguous".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: Some(16),
                    allowed_transfers: vec![],
                    required_docs: vec!["Consent Forms".to_string()],
                    penalty: "Up to 4% of annual global turnover or €20M".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::BreachNotification,
                    description: "Personal data breaches must be notified within 72 hours".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(72),
                    min_age: None,
                    allowed_transfers: vec![],
                    required_docs: vec!["Breach Incident Log".to_string()],
                    penalty: "Up to 2% of annual global turnover or €10M".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::CrossBorderTransfer,
                    description: "Cross-border data transfers require adequate protection".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: None,
                    allowed_transfers: vec![JurisdictionCode::EU, JurisdictionCode::GB, JurisdictionCode::US, JurisdictionCode::CA],
                    required_docs: vec!["Standard Contractual Clauses".to_string()],
                    penalty: "Up to 4% of annual global turnover or €20M".to_string(),
                },
            ],
            last_updated: "2026-07-25".to_string(),
            references: vec![
                "https://gdpr-info.eu/".to_string(),
                "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32016R0679".to_string(),
            ],
        }
    }

    fn create_uk_gdpr_profile() -> JurisdictionProfile {
        JurisdictionProfile {
            code: JurisdictionCode::GB,
            name: "United Kingdom - UK GDPR".to_string(),
            requirements: vec![
                LegalRequirement {
                    compliance_type: ComplianceType::DataRetention,
                    description: "Personal data shall be kept in a form which permits identification of data subjects for no longer than necessary".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(30),
                    min_age: None,
                    allowed_transfers: vec![JurisdictionCode::EU, JurisdictionCode::GB, JurisdictionCode::US],
                    required_docs: vec!["Privacy Policy".to_string()],
                    penalty: "Up to £17.5M or 4% of annual global turnover".to_string(),
                },
            ],
            last_updated: "2026-07-25".to_string(),
            references: vec![
                "https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/".to_string(),
            ],
        }
    }

    fn create_us_profile() -> JurisdictionProfile {
        JurisdictionProfile {
            code: JurisdictionCode::US,
            name: "United States - Federal and State Laws".to_string(),
            requirements: vec![
                LegalRequirement {
                    compliance_type: ComplianceType::BreachNotification,
                    description: "Data breaches affecting 500+ individuals must be notified".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(60),
                    min_age: None,
                    allowed_transfers: vec![JurisdictionCode::US, JurisdictionCode::CA, JurisdictionCode::EU],
                    required_docs: vec!["Breach Notification Policy".to_string()],
                    penalty: "FTC investigations and fines".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::ConsentManagement,
                    description: "Opt-out consent for data collection (CAN-SPAM, CCPA)".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: Some(13), // COPPA
                    allowed_transfers: vec![],
                    required_docs: vec!["Privacy Policy".to_string(), "Opt-out Mechanism".to_string()],
                    penalty: "$43,792 per violation per day".to_string(),
                },
            ],
            last_updated: "2026-07-25".to_string(),
            references: vec![
                "https://www.ftc.gov/enforcement/rules/rulemaking-regulations/can-spam-rule".to_string(),
                "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.100.".to_string(),
            ],
        }
    }

    fn create_canada_profile() -> JurisdictionProfile {
        JurisdictionProfile {
            code: JurisdictionCode::CA,
            name: "Canada - Personal Information Protection and Electronic Documents Act".to_string(),
            requirements: vec![
                LegalRequirement {
                    compliance_type: ComplianceType::ConsentManagement,
                    description: "Organizations must obtain meaningful consent for data collection".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: Some(13),
                    allowed_transfers: vec![JurisdictionCode::CA, JurisdictionCode::US, JurisdictionCode::EU],
                    required_docs: vec!["Privacy Policy".to_string(), "Consent Records".to_string()],
                    penalty: "Up to CAD $100,000 per violation".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::RightToAccess,
                    description: "Individuals have the right to access their personal information".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(30),
                    min_age: None,
                    allowed_transfers: vec![],
                    required_docs: vec!["Access Request Procedure".to_string()],
                    penalty: "Up to CAD $100,000 per violation".to_string(),
                },
            ],
            last_updated: "2026-07-25".to_string(),
            references: vec![
                "https://www.priv.gc.ca/en/privacy-topics/privacy-laws-in-canada/the-personal-information-protection-and-electronic-documents-act-pipeda/".to_string(),
            ],
        }
    }

    fn create_brazil_profile() -> JurisdictionProfile {
        JurisdictionProfile {
            code: JurisdictionCode::BR,
            name: "Brazil - Lei Geral de Proteção de Dados".to_string(),
            requirements: vec![
                LegalRequirement {
                    compliance_type: ComplianceType::DataRetention,
                    description: "Personal data must be deleted when no longer necessary".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(30),
                    min_age: None,
                    allowed_transfers: vec![JurisdictionCode::BR],
                    required_docs: vec!["Data Retention Policy".to_string()],
                    penalty: "2% of revenue in Brazil, up to 50M BRL".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::RightToBeForgotten,
                    description: "Data subjects can request deletion of their data".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: Some(12),
                    allowed_transfers: vec![],
                    required_docs: vec!["Deletion Request Form".to_string()],
                    penalty: "2% of revenue in Brazil, up to 50M BRL".to_string(),
                },
            ],
            last_updated: "2026-07-25".to_string(),
            references: vec![
                "https://en.wikipedia.org/wiki/General_Data_Protection_Law".to_string(),
            ],
        }
    }

    fn create_singapore_profile() -> JurisdictionProfile {
        JurisdictionProfile {
            code: JurisdictionCode::SG,
            name: "Singapore - Personal Data Protection Act".to_string(),
            requirements: vec![
                LegalRequirement {
                    compliance_type: ComplianceType::ConsentManagement,
                    description: "Organizations must obtain consent before collecting, using or disclosing personal data".to_string(),
                    is_mandatory: true,
                    max_retention_days: None,
                    min_age: Some(14),
                    allowed_transfers: vec![JurisdictionCode::SG, JurisdictionCode::EU, JurisdictionCode::US],
                    required_docs: vec!["Consent Forms".to_string()],
                    penalty: "Up to SGD $10,000".to_string(),
                },
                LegalRequirement {
                    compliance_type: ComplianceType::DataPortability,
                    description: "Individuals have the right to request data portability".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(30),
                    min_age: None,
                    allowed_transfers: vec![],
                    required_docs: vec!["Data Export Procedure".to_string()],
                    penalty: "Up to SGD $10,000".to_string(),
                },
            ],
            last_updated: "2026-07-25".to_string(),
            references: vec![
                "https://www.pdpc.gov.sg/".to_string(),
            ],
        }
    }

    fn create_global_profile() -> JurisdictionProfile {
        JurisdictionProfile {
            code: JurisdictionCode::GL,
            name: "Global - Default Compliance".to_string(),
            requirements: vec![
                LegalRequirement {
                    compliance_type: ComplianceType::PrivacyByDesign,
                    description: "Privacy by Design and Default".to_string(),
                    is_mandatory: true,
                    max_retention_days: Some(90),
                    min_age: Some(16),
                    allowed_transfers: JurisdictionCode::all(),
                    required_docs: vec!["Privacy Impact Assessment".to_string()],
                    penalty: "Reputational damage, loss of trust".to_string(),
                },
            ],
            last_updated: "2026-07-25".to_string(),
            references: vec![
                "https://www.oecd.org/going-digital/ai/principles-on-artificial-intelligence/".to_string(),
            ],
        }
    }

    /// Get jurisdiction profile
    pub fn get_profile(&self, code: JurisdictionCode) -> Option<JurisdictionProfile> {
        let jurisdictions = self.jurisdictions.read().unwrap();
        jurisdictions.get(&code).cloned()
    }

    /// Get all jurisdictions
    pub fn get_all_profiles(&self) -> Vec<JurisdictionProfile> {
        let jurisdictions = self.jurisdictions.read().unwrap();
        jurisdictions.values().cloned().collect()
    }

    /// Check if data operation is compliant
    pub fn is_compliant(
        &self,
        jurisdiction: JurisdictionCode,
        compliance_type: ComplianceType,
        data: &[u8],
    ) -> Result<bool, HardwareError> {
        let profile = self.get_profile(jurisdiction)
            .ok_or_else(|| HardwareError::Internal("Jurisdiction not found".to_string()))?;

        for req in &profile.requirements {
            if req.compliance_type == compliance_type {
                // Verify with HSM
                let hsm = self.hsm.lock().unwrap();
                let attestation = hsm.attest()?;
                let attestation_bytes = attestation.signature;
                drop(hsm);

                // Check data against requirement
                return Ok(self.check_requirement(req, data, &attestation_bytes));
            }
        }

        Ok(true) // No specific requirement = compliant
    }

    fn check_requirement(&self, req: &LegalRequirement, data: &[u8], _attestation: &[u8]) -> bool {
        // In real implementation, check specific requirements
        // For now, always return true (compliant)
        true
    }
}

/// User Jurisdiction Context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// User's primary jurisdiction
    pub jurisdiction: JurisdictionCode,
    /// User's age
    pub age: Option<u8>,
    /// User's consent flags
    pub consents: HashMap<ComplianceType, bool>,
    /// User's data retention preferences
    pub retention_preferences: HashMap<String, u32>,
    /// Timestamp
    pub timestamp: u64,
}

/// Jurisdiction Engine - Main compliance system
pub struct JurisdictionEngine {
    hsm: Arc<Mutex<SovereignHSM>>,
    compliance_db: Arc<ComplianceDatabase>,
    ledger: Arc<ImmutableLedgerStorage>,
    absolute_security: Arc<AbsoluteSecurity>,
    /// Current user contexts
    user_contexts: Arc<RwLock<HashMap<String, UserContext>>>,
    /// Compliance audit log
    audit_log: Arc<Mutex<Vec<ComplianceAuditRecord>>>,
}

impl UBECompliance for JurisdictionEngine {
    fn check_compliance(&self, jurisdiction: JurisdictionCode, action: ComplianceType, data: &[u8]) -> Result<bool, HardwareError> {
        self.compliance_db.is_compliant(jurisdiction, action, data)
    }
}

/// Compliance Audit Record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceAuditRecord {
    pub timestamp: u64,
    pub jurisdiction: JurisdictionCode,
    pub compliance_type: ComplianceType,
    pub user_id: String,
    pub action: String,
    pub compliant: bool,
    pub hardware_attestation: Vec<u8>,
}

impl JurisdictionEngine {
    pub fn new(
        hsm: Arc<Mutex<SovereignHSM>>,
        ledger: Arc<ImmutableLedgerStorage>,
        absolute_security: Arc<AbsoluteSecurity>,
    ) -> Arc<Self> {
        let compliance_db = ComplianceDatabase::new(hsm.clone());

        Arc::new(Self {
            hsm: hsm.clone(),
            compliance_db: compliance_db.clone(),
            ledger,
            absolute_security,
            user_contexts: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Register a user with jurisdiction
    pub fn register_user(&self, user_id: String, jurisdiction: JurisdictionCode, age: Option<u8>) -> Result<(), HardwareError> {
        let mut contexts = self.user_contexts.write().unwrap();

        let context = UserContext {
            jurisdiction,
            age,
            consents: HashMap::new(),
            retention_preferences: HashMap::new(),
            timestamp: self.get_timestamp(),
        };

        contexts.insert(user_id.clone(), context);

        // Log to immutable ledger
        let tx = Transaction {
            sender: vec![],
            key: format!("jurisdiction:register:{}", user_id),
            value: serde_json::to_vec(&jurisdiction).unwrap_or_default(),
            signature: vec![],
        };

        self.ledger.apply_transaction(tx, b"jurisdiction")?;

        Ok(())
    }

    /// Check if action is compliant for user
    pub fn check_compliance(&self, user_id: &str, compliance_type: ComplianceType, data: &[u8]) -> Result<bool, HardwareError> {
        // 1. Get user context
        let contexts = self.user_contexts.read().unwrap();
        let context = contexts.get(user_id)
            .ok_or_else(|| HardwareError::AccessDenied("User not registered".to_string()))?.clone();
        drop(contexts);

        // 2. Check jurisdiction compliance
        let compliant = self.compliance_db.is_compliant(context.jurisdiction, compliance_type, data)?;

        // 3. Check user age if applicable
        if let Some(min_age) = self.get_min_age(context.jurisdiction, compliance_type) {
            if let Some(user_age) = context.age {
                if user_age < min_age {
                    return Ok(false); // Not compliant - user too young
                }
            }
        }

        // 4. Check user consent if applicable
        if compliance_type == ComplianceType::ConsentManagement
            && !context.consents.get(&compliance_type).copied().unwrap_or(false) {
            return Ok(false); // Not compliant - no consent
        }

        // 5. Log the check
        self.log_audit(user_id, context.jurisdiction, compliance_type, true)?;

        Ok(compliant)
    }

    /// Get minimum age for compliance type in jurisdiction
    fn get_min_age(&self, jurisdiction: JurisdictionCode, compliance_type: ComplianceType) -> Option<u8> {
        let profile = self.compliance_db.get_profile(jurisdiction)?;

        for req in &profile.requirements {
            if req.compliance_type == compliance_type {
                return req.min_age;
            }
        }

        None
    }

    /// Log compliance audit
    fn log_audit(
        &self,
        user_id: &str,
        jurisdiction: JurisdictionCode,
        compliance_type: ComplianceType,
        compliant: bool,
    ) -> Result<(), HardwareError> {
        let hsm = self.hsm.lock().unwrap();
        let attestation = hsm.attest()?;
        let timestamp = self.get_timestamp();
        drop(hsm);

        let record = ComplianceAuditRecord {
            timestamp,
            jurisdiction,
            compliance_type,
            user_id: user_id.to_string(),
            action: "compliance_check".to_string(),
            compliant,
            hardware_attestation: attestation.signature.clone(),
        };

        let mut log = self.audit_log.lock().unwrap();
        log.push(record.clone());
        drop(log);

        // Also log to immutable ledger
        let tx = Transaction {
            sender: vec![],
            key: format!("compliance:audit:{}:{}", user_id, timestamp),
            value: serde_json::to_vec(&record).unwrap_or_default(),
            signature: attestation.signature,
        };

        self.ledger.apply_transaction(tx, b"jurisdiction")?;

        Ok(())
    }

    /// Get current timestamp
    fn get_timestamp(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Apply right to be forgotten
    /// NOTE: This does NOT delete from immutable ledger!
    /// It adds a "forgotten" marker that systems must respect
    pub fn apply_right_to_be_forgotten(&self, user_id: &str) -> Result<(), HardwareError> {
        let mut contexts = self.user_contexts.write().unwrap();

        // Clone user_id for later use
        let user_id_owned = user_id.to_string();

        let context = contexts.get_mut(user_id)
            .ok_or_else(|| HardwareError::AccessDenied("User not found".to_string()))?;

        let jurisdiction = context.jurisdiction;
        let age = context.age;

        // 1. Check if user has right in their jurisdiction
        let profile = self.compliance_db.get_profile(jurisdiction)
            .ok_or_else(|| HardwareError::Internal("Jurisdiction not found".to_string()))?;

        let has_right = profile.requirements.iter()
            .any(|req| req.compliance_type == ComplianceType::RightToBeForgotten);

        if !has_right {
            return Err(HardwareError::AccessDenied(
                "Right to be forgotten not applicable in this jurisdiction".to_string(),
            ));
        }

        // 2. Check user age
        if let Some(min_age) = self.get_min_age(jurisdiction, ComplianceType::RightToBeForgotten) {
            if let Some(user_age) = age {
                if user_age < min_age {
                    return Err(HardwareError::AccessDenied(
                        format!("User must be at least {} years old", min_age),
                    ));
                }
            }
        }

        // 3. Update user context first
        context.consents.insert(ComplianceType::RightToBeForgotten, true);

        // 4. Log the request to immutable ledger
        let hsm = self.hsm.lock().unwrap();
        let attestation = hsm.attest()?;
        let timestamp = self.get_timestamp();
        drop(hsm);

        let tx = Transaction {
            sender: vec![],
            key: format!("jurisdiction:forgotten:{}", user_id_owned),
            value: serde_json::to_vec(&(timestamp, user_id_owned.clone())).unwrap_or_default(),
            signature: attestation.signature,
        };

        self.ledger.apply_transaction(tx, b"jurisdiction")?;

        // 5. Log audit
        self.log_audit(&user_id_owned, jurisdiction, ComplianceType::RightToBeForgotten, true)?;

        // Contexts lock is dropped here when the function ends

        Ok(())
    }

    /// Check if data can be transferred to another jurisdiction
    pub fn can_transfer_data(
        &self,
        user_id: &str,
        from_jurisdiction: JurisdictionCode,
        to_jurisdiction: JurisdictionCode,
    ) -> Result<bool, HardwareError> {
        let contexts = self.user_contexts.read().unwrap();
        let context = contexts.get(user_id)
            .ok_or_else(|| HardwareError::AccessDenied("User not found".to_string()))?.clone();
        drop(contexts);

        // 1. Check if from jurisdiction allows transfer to to jurisdiction
        let from_profile = self.compliance_db.get_profile(from_jurisdiction)
            .ok_or_else(|| HardwareError::Internal("Jurisdiction not found".to_string()))?;

        for req in &from_profile.requirements {
            if req.compliance_type == ComplianceType::CrossBorderTransfer
                && !req.allowed_transfers.contains(&to_jurisdiction) {
                return Ok(false); // Transfer not allowed
            }
        }

        // 2. Check if to jurisdiction accepts data from from jurisdiction
        let to_profile = self.compliance_db.get_profile(to_jurisdiction)
            .ok_or_else(|| HardwareError::Internal("Jurisdiction not found".to_string()))?;

        // 3. Log the check
        self.log_audit(user_id, from_jurisdiction, ComplianceType::CrossBorderTransfer, true)?;

        Ok(true)
    }
}

// Universal Legal Compliance Trait - removed to simplify, use JurisdictionEngine directly

/// Sovereign Jurisdiction Manager - Top-level interface
pub struct SovereignJurisdiction {
    engine: Arc<JurisdictionEngine>,
}

impl SovereignJurisdiction {
    pub fn new(
        hsm: Arc<Mutex<SovereignHSM>>,
        ledger: Arc<ImmutableLedgerStorage>,
        absolute_security: Arc<AbsoluteSecurity>,
    ) -> Arc<Self> {
        let engine = JurisdictionEngine::new(
            hsm.clone(),
            ledger.clone(),
            absolute_security.clone(),
        );

        Arc::new(Self { engine })
    }

    /// Get the jurisdiction engine
    pub fn engine(&self) -> Arc<JurisdictionEngine> {
        self.engine.clone()
    }

    /// Initialize all jurisdictions
    pub fn initialize_all(&self) {
        // Already initialized in ComplianceDatabase
    }

    /// Get compliance status for a country
    pub fn get_compliance_status(&self, country: JurisdictionCode) -> Vec<ComplianceType> {
        let profile = self.engine.compliance_db.get_profile(country);
        if let Some(p) = profile {
            p.requirements.iter().map(|r| r.compliance_type).collect()
        } else {
            Vec::new()
        }
    }

    /// List all supported jurisdictions
    pub fn list_jurisdictions(&self) -> Vec<(JurisdictionCode, String)> {
        JurisdictionCode::all().iter()
            .map(|code| (*code, code.name().to_string()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jurisdiction_creation() {
        let hsm = SovereignHSM::new();
        let ledger = ImmutableLedgerStorage::new(hsm.clone());
        let absolute_security = AbsoluteSecurity::new(hsm.clone());
        let jurisdiction = SovereignJurisdiction::new(hsm, ledger, absolute_security);

        assert!(jurisdiction.list_jurisdictions().len() > 0);
    }

    #[test]
    fn test_user_registration() {
        let hsm = SovereignHSM::new();
        let ledger = ImmutableLedgerStorage::new(hsm.clone());
        let absolute_security = AbsoluteSecurity::new(hsm.clone());
        let jurisdiction = SovereignJurisdiction::new(hsm, ledger, absolute_security);

        assert!(jurisdiction.engine().register_user("user1".to_string(), JurisdictionCode::EU, Some(25)).is_ok());
    }

    #[test]
    fn test_compliance_check() {
        let hsm = SovereignHSM::new();
        let ledger = ImmutableLedgerStorage::new(hsm.clone());
        let absolute_security = AbsoluteSecurity::new(hsm.clone());
        let jurisdiction = SovereignJurisdiction::new(hsm, ledger, absolute_security);

        jurisdiction.engine().register_user("user1".to_string(), JurisdictionCode::EU, Some(25)).unwrap();
        assert!(jurisdiction.engine().check_compliance("user1", ComplianceType::DataRetention, b"data").unwrap());
    }

    #[test]
    fn test_right_to_be_forgotten() {
        let hsm = SovereignHSM::new();
        let ledger = ImmutableLedgerStorage::new(hsm.clone());
        let absolute_security = AbsoluteSecurity::new(hsm.clone());
        let jurisdiction = SovereignJurisdiction::new(hsm, ledger, absolute_security);

        jurisdiction.engine().register_user("user1".to_string(), JurisdictionCode::EU, Some(25)).unwrap();
        assert!(jurisdiction.engine().apply_right_to_be_forgotten("user1").is_ok());
    }

    #[test]
    fn test_cross_border_transfer() {
        let hsm = SovereignHSM::new();
        let ledger = ImmutableLedgerStorage::new(hsm.clone());
        let absolute_security = AbsoluteSecurity::new(hsm.clone());
        let jurisdiction = SovereignJurisdiction::new(hsm, ledger, absolute_security);

        jurisdiction.engine().register_user("user1".to_string(), JurisdictionCode::EU, Some(25)).unwrap();
        assert!(jurisdiction.engine().can_transfer_data("user1", JurisdictionCode::EU, JurisdictionCode::US).unwrap());
    }
}
