#![allow(unsafe_op_in_unsafe_fn)]

use crate::{ActionRequest, CapabilityToken, Caveat, CaveatType, PqcKeyPair, TrustEngine};
use ed25519_dalek::Signer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(name = "TrustEngine")]
pub struct PyTrustEngine {
    pub inner: TrustEngine,
}

impl Default for PyTrustEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[pymethods]
impl PyTrustEngine {
    #[new]
    pub fn new() -> Self {
        PyTrustEngine {
            inner: TrustEngine::new(),
        }
    }

    pub fn grant(&mut self, actor: String, capability: String) {
        self.inner.grant(&actor, &capability);
    }

    pub fn register_issuer_key(
        &mut self,
        issuer: String,
        public_key_bytes: Vec<u8>,
    ) -> PyResult<()> {
        self.inner
            .register_issuer_key(issuer, public_key_bytes)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// Pins the ML-DSA-87 public key that identifies `actor`.
    ///
    /// Required before a PQC-signed request from `actor` can be allowed: the
    /// engine only authorizes a signature made by the key pinned here, so a
    /// caller cannot self-sign with a key of its own choosing.
    #[pyo3(signature = (actor, public_key_bytes, workload_measurement_hash=None))]
    pub fn register_pqc_identity_key(
        &mut self,
        actor: String,
        public_key_bytes: Vec<u8>,
        workload_measurement_hash: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .register_pqc_identity_key(actor, public_key_bytes, workload_measurement_hash)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// Binds an expected workload measurement to `actor` without changing its key.
    pub fn register_workload_measurement(
        &mut self,
        actor: String,
        measurement_hash: String,
    ) -> PyResult<()> {
        self.inner
            .register_workload_measurement(actor, measurement_hash)
            .map_err(pyo3::exceptions::PyValueError::new_err)
    }

    /// Removes the expected workload measurement for `actor`, if any.
    pub fn remove_workload_measurement(&mut self, actor: String) -> Option<String> {
        self.inner.remove_workload_measurement(&actor)
    }

    /// Removes the pinned ML-DSA-87 identity key for `actor`, returning the
    /// removed key bytes if one was pinned.
    pub fn remove_pqc_identity_key(&mut self, actor: String) -> Option<Vec<u8>> {
        self.inner.remove_pqc_identity_key(&actor)
    }

    /// Returns the pinned ML-DSA-87 public key for `actor`, if any.
    pub fn pqc_identity_key(&self, actor: String) -> Option<Vec<u8>> {
        self.inner.pqc_identity_keys.get(&actor).cloned()
    }

    pub fn revoke_token(&mut self, token_id: String) {
        self.inner.revoke_token(&token_id);
    }

    pub fn register_voter_key(&mut self, voter_id: String, public_key_bytes: Vec<u8>) {
        self.inner.register_voter_key(&voter_id, public_key_bytes);
    }

    pub fn evaluate(&self, req_json: String) -> PyResult<String> {
        let req: ActionRequest = serde_json::from_str(&req_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid ActionRequest JSON: {}", e))
        })?;
        let decision = self.inner.evaluate(&req);
        serde_json::to_string(&decision).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize decision: {}", e))
        })
    }

    /// Evaluates a request with time-based caveats checked against `now_rfc3339`.
    ///
    /// Pinning the evaluation time keeps a decision consistent with the instant
    /// the request was received, instead of whatever the clock reads after the
    /// verification work finishes.
    ///
    /// `observed_measurement` is the digest the *caller* read from the runtime,
    /// not the value in the request. Actors bound to a workload are denied when
    /// it is omitted.
    #[pyo3(signature = (req_json, now_rfc3339, observed_measurement=None))]
    pub fn evaluate_at(
        &self,
        req_json: String,
        now_rfc3339: String,
        observed_measurement: Option<String>,
    ) -> PyResult<String> {
        let req: ActionRequest = serde_json::from_str(&req_json).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Invalid ActionRequest JSON: {}", e))
        })?;
        let now = chrono::DateTime::parse_from_rfc3339(&now_rfc3339)
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Invalid RFC 3339 evaluation time: {}",
                    e
                ))
            })?
            .with_timezone(&chrono::Utc);
        let decision = self
            .inner
            .evaluate_with_measurement(&req, observed_measurement.as_deref(), now);
        serde_json::to_string(&decision).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize decision: {}", e))
        })
    }

    /// RFC 6962 inclusion proof for one audit event: `(batch_root, siblings)`.
    ///
    /// Returns `None` when the batch or sequence is unknown, so callers cannot
    /// mistake a missing proof for a valid one.
    pub fn audit_inclusion_proof(
        &self,
        batch_index: usize,
        sequence: u64,
    ) -> Option<(String, Vec<(String, String)>)> {
        self.inner
            .audit_inclusion_proof(batch_index, sequence)
            .map(|(root, siblings)| {
                let proof = siblings
                    .into_iter()
                    .map(|sibling| {
                        let position = match sibling.position {
                            crate::merkle::MerkleSiblingPosition::Left => "left",
                            crate::merkle::MerkleSiblingPosition::Right => "right",
                            crate::merkle::MerkleSiblingPosition::Promoted => "promoted",
                        };
                        (position.to_string(), sibling.sha256)
                    })
                    .collect();
                (root, proof)
            })
    }
}

#[pyclass(name = "PqcKeyPair")]
pub struct PyPqcKeyPair {
    pub inner: PqcKeyPair,
}

impl Default for PyPqcKeyPair {
    fn default() -> Self {
        Self::generate()
    }
}

#[pymethods]
impl PyPqcKeyPair {
    #[new]
    pub fn generate() -> Self {
        PyPqcKeyPair {
            inner: PqcKeyPair::generate(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> String {
        let sig = self.inner.sign(message);
        hex::encode(&sig.signature)
    }

    pub fn sign_bytes(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message).signature
    }

    pub fn verify(&self, message: &[u8], signature_hex: String) -> bool {
        if let Ok(sig_bytes) = hex::decode(&signature_hex) {
            let sig = crate::PqcSignature {
                algorithm: self.inner.algorithm.clone(),
                signature: sig_bytes,
            };
            self.inner.public_key.verify(message, &sig)
        } else {
            false
        }
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> PyResult<(String, String, String)> {
        let container = self
            .inner
            .encrypt(&self.inner.public_key, plaintext)
            .map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Encryption error: {}", e))
            })?;
        Ok((
            hex::encode(&container.ciphertext),
            hex::encode(&container.nonce),
            hex::encode(&container.ephemeral_pqc_pk),
        ))
    }

    pub fn encrypt_to_recipient(
        &self,
        recipient_key_bytes: &[u8],
        recipient_kyber_bytes: &[u8],
        plaintext: &[u8],
    ) -> PyResult<Vec<u8>> {
        let recipient_pk = crate::PqcPublicKey {
            algorithm: self.inner.algorithm.clone(),
            key_bytes: recipient_key_bytes.to_vec(),
            kyber_public_key_bytes: recipient_kyber_bytes.to_vec(),
        };
        let container = self.inner.encrypt(&recipient_pk, plaintext).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Encryption error: {}", e))
        })?;
        serde_json::to_vec(&container).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Serialization error: {}", e))
        })
    }

    pub fn decrypt(
        &self,
        ciphertext_hex: String,
        nonce_hex: String,
        ephemeral_pqc_pk_hex: String,
    ) -> PyResult<Vec<u8>> {
        let ciphertext = hex::decode(&ciphertext_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {}", e))
        })?;
        let nonce = hex::decode(&nonce_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {}", e))
        })?;
        let ephemeral_pqc_pk = hex::decode(&ephemeral_pqc_pk_hex).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {}", e))
        })?;
        let container = crate::PqcEncryptedContainer {
            algorithm: format!("{}-Kyber1024-ChaCha20Poly1305", self.inner.algorithm),
            ephemeral_pqc_pk,
            nonce,
            ciphertext,
        };
        self.inner.decrypt(&container).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decryption error: {}", e))
        })
    }

    pub fn decrypt_container(&self, encrypted_container_bytes: &[u8]) -> PyResult<Vec<u8>> {
        let container: crate::PqcEncryptedContainer =
            serde_json::from_slice(encrypted_container_bytes).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("Deserialization error: {}", e))
            })?;
        self.inner.decrypt(&container).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("Decryption error: {}", e))
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.inner.public_key.key_bytes)
    }

    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key.key_bytes.clone()
    }

    pub fn get_kyber_public_key_bytes(&self) -> Vec<u8> {
        self.inner.kyber_public_key_bytes.clone()
    }
}


/// Ed25519 key pair used to issue and sign capability tokens.
///
/// The engine pins this public key with `register_issuer_key`, so a token is
/// only honoured when it is signed by the key the engine already trusts.
#[pyclass(name = "Ed25519KeyPair")]
pub struct PyEd25519KeyPair {
    signing_key: ed25519_dalek::SigningKey,
}

#[pymethods]
impl PyEd25519KeyPair {
    #[new]
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        PyEd25519KeyPair {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&seed),
        }
    }

    /// Rebuilds a key pair from the 32 raw bytes of an Ed25519 private key.
    #[staticmethod]
    pub fn from_private_key_bytes(private_key_bytes: Vec<u8>) -> PyResult<Self> {
        let bytes: [u8; 32] = private_key_bytes.as_slice().try_into().map_err(|_| {
            PyValueError::new_err("Ed25519 private key must be exactly 32 bytes")
        })?;
        Ok(PyEd25519KeyPair {
            signing_key: ed25519_dalek::SigningKey::from_bytes(&bytes),
        })
    }

    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.signing_key.to_bytes().to_vec()
    }

    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.signing_key.verifying_key().to_bytes().to_vec()
    }

    pub fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        self.signing_key.sign(&message).to_bytes().to_vec()
    }
}

/// Builds and signs a capability token that carries caveats.
///
/// The caveat set is what turns a grant into a bounded grant: a token without
/// caveats authorises everything the actor could do otherwise.
#[pyclass(name = "TokenBuilder")]
pub struct PyTokenBuilder {
    id: String,
    root_actor: String,
    capability: String,
    caveats: Vec<Caveat>,
}

impl PyTokenBuilder {
    fn token(&self) -> CapabilityToken {
        CapabilityToken {
            id: self.id.clone(),
            root_actor: self.root_actor.clone(),
            capability: self.capability.clone(),
            caveats: self.caveats.clone(),
            signature: Vec::new(),
        }
    }
}

#[pymethods]
impl PyTokenBuilder {
    #[new]
    pub fn new(id: String, root_actor: String, capability: String) -> Self {
        PyTokenBuilder {
            id,
            root_actor,
            capability,
            caveats: Vec::new(),
        }
    }

    /// Denies when the request's `risk_score` is at or above `threshold_bps`
    /// (basis points: 6500 is 0.65).
    pub fn risk_below(&mut self, threshold_bps: u32) -> PyResult<()> {
        if threshold_bps > 10_000 {
            return Err(PyValueError::new_err(
                "threshold_bps must be 0..=10000 (basis points, 6500 is 0.65)",
            ));
        }
        self.caveats.push(Caveat {
            location: None,
            condition: CaveatType::RiskBelow(threshold_bps),
        });
        Ok(())
    }

    pub fn expires(&mut self, timestamp_rfc3339: String) -> PyResult<()> {
        if chrono::DateTime::parse_from_rfc3339(&timestamp_rfc3339).is_err() {
            return Err(PyValueError::new_err(
                "timestamp must be RFC 3339, e.g. 2027-01-01T00:00:00Z",
            ));
        }
        self.caveats.push(Caveat {
            location: None,
            condition: CaveatType::Expires(timestamp_rfc3339),
        });
        Ok(())
    }

    pub fn max_executions(&mut self, max: u64) {
        self.caveats.push(Caveat {
            location: None,
            condition: CaveatType::MaxExecutions(max),
        });
    }

    pub fn value_limit(&mut self, max: u64, currency: String) {
        self.caveats.push(Caveat {
            location: None,
            condition: CaveatType::ValueLimit(max, currency),
        });
    }

    pub fn path_restricted(&mut self, prefix: String) {
        self.caveats.push(Caveat {
            location: None,
            condition: CaveatType::PathRestricted(prefix),
        });
    }

    /// The unsigned token as JSON, useful for inspection before signing.
    pub fn build_json(&self) -> PyResult<String> {
        serde_json::to_string(&self.token())
            .map_err(|e| PyValueError::new_err(format!("token serialization failed: {}", e)))
    }

    /// Signs the token with the issuer's 32-byte Ed25519 private key and
    /// returns it as JSON, ready to place in a request's `token` field.
    pub fn sign(&self, private_key_bytes: Vec<u8>) -> PyResult<String> {
        let key = PyEd25519KeyPair::from_private_key_bytes(private_key_bytes)?;
        let mut token = self.token();
        token.signature = key.sign(token.message_to_sign());
        serde_json::to_string(&token)
            .map_err(|e| PyValueError::new_err(format!("token serialization failed: {}", e)))
    }
}

#[pymodule]
fn ube_foundation(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTrustEngine>()?;
    m.add_class::<PyPqcKeyPair>()?;
    m.add_class::<PyEd25519KeyPair>()?;
    m.add_class::<PyTokenBuilder>()?;
    Ok(())
}
