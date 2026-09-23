use pyo3::prelude::*;
use crate::{TrustEngine, ActionRequest, PqcKeyPair};

#[pyclass(name = "TrustEngine")]
pub struct PyTrustEngine {
    pub inner: TrustEngine,
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

    pub fn revoke_token(&mut self, token_id: String) {
        self.inner.revoke_token(&token_id);
    }

    pub fn register_voter_key(&mut self, voter_id: String, public_key_bytes: Vec<u8>) {
        self.inner.register_voter_key(&voter_id, public_key_bytes);
    }

    pub fn evaluate(&self, req_json: String) -> PyResult<String> {
        let req: ActionRequest = serde_json::from_str(&req_json)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid ActionRequest JSON: {}", e)))?;
        let decision = self.inner.evaluate(&req);
        serde_json::to_string(&decision)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Failed to serialize decision: {}", e)))
    }
}

#[pyclass(name = "PqcKeyPair")]
pub struct PyPqcKeyPair {
    pub inner: PqcKeyPair,
}

#[pymethods]
impl PyPqcKeyPair {
    #[new]
    pub fn generate() -> Self {
        PyPqcKeyPair {
            inner: PqcKeyPair::generate(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.inner.sign(message).signature
    }

    pub fn verify(&self, message: &[u8], signature_bytes: &[u8]) -> bool {
        let sig = crate::PqcSignature {
            algorithm: self.inner.algorithm.clone(),
            signature: signature_bytes.to_vec(),
        };
        self.inner.public_key.verify(message, &sig)
    }

    pub fn encrypt(&self, recipient_key_bytes: &[u8], recipient_kyber_bytes: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
        let recipient_pk = crate::PqcPublicKey {
            algorithm: self.inner.algorithm.clone(),
            key_bytes: recipient_key_bytes.to_vec(),
            kyber_public_key_bytes: recipient_kyber_bytes.to_vec(),
        };
        let container = self.inner.encrypt(&recipient_pk, plaintext)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encryption error: {}", e)))?;
        serde_json::to_vec(&container)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Serialization error: {}", e)))
    }

    pub fn decrypt(&self, encrypted_container_bytes: &[u8]) -> PyResult<Vec<u8>> {
        let container: crate::PqcEncryptedContainer = serde_json::from_slice(encrypted_container_bytes)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Deserialization error: {}", e)))?;
        self.inner.decrypt(&container)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption error: {}", e)))
    }

    pub fn get_public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key.key_bytes.clone()
    }

    pub fn get_kyber_public_key_bytes(&self) -> Vec<u8> {
        self.inner.kyber_public_key_bytes.clone()
    }
}

#[pymodule]
fn ube_foundation(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyTrustEngine>()?;
    m.add_class::<PyPqcKeyPair>()?;
    Ok(())
}
