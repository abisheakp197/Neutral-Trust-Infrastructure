# Complete Python API Report for `ube_foundation`

This report provides a comprehensive overview and reference for the Python bindings of `ube_foundation` (built using PyO3 and Maturin).

---

## Task 1: Rust Source Analysis (`ube-foundation/src/python_bindings.rs`)

### Python Classes Exported
The Python module exports two main classes:
1. **`TrustEngine`** (mapped from Rust `PyTrustEngine` wrapper over `crate::TrustEngine`)
2. **`PqcKeyPair`** (mapped from Rust `PyPqcKeyPair` wrapper over `crate::PqcKeyPair`)

### Class Methods & Signatures

#### `TrustEngine`
- **Constructor**: `TrustEngine()` (`#[new] pub fn new() -> Self`)
- **`grant(actor: str, capability: str) -> None`** (`pub fn grant(&mut self, actor: String, capability: String)`)
- **`revoke_token(token_id: str) -> None`** (`pub fn revoke_token(&mut self, token_id: String)`)
- **`register_voter_key(voter_id: str, public_key_bytes: bytes) -> None`** (`pub fn register_voter_key(&mut self, voter_id: String, public_key_bytes: Vec<u8>)`)
- **`evaluate(req_json: str) -> str`** (`pub fn evaluate(&self, req_json: String) -> PyResult<String>`)

#### `PqcKeyPair`
- **Constructor**: `PqcKeyPair()` (`#[new] pub fn generate() -> Self`)
- **`sign(message: bytes) -> str`**: Returns hex-encoded signature string. (`pub fn sign(&self, message: &[u8]) -> String`)
- **`sign_bytes(message: bytes) -> bytes`**: Returns raw signature bytes. (`pub fn sign_bytes(&self, message: &[u8]) -> Vec<u8>`)
- **`verify(message: bytes, signature_hex: str) -> bool`**: Verifies signature against hex string. (`pub fn verify(&self, message: &[u8], signature_hex: String) -> bool`)
- **`encrypt(plaintext: bytes) -> (str, str, str)`**: Encrypts plaintext using self public key. Returns tuple `(ciphertext_hex, nonce_hex, ephemeral_pqc_pk_hex)`. (`pub fn encrypt(&self, plaintext: &[u8]) -> PyResult<(String, String, String)>`)
- **`encrypt_to_recipient(recipient_key_bytes: bytes, recipient_kyber_bytes: bytes, plaintext: bytes) -> bytes`**: Encrypts plaintext to recipient's public key & Kyber public key bytes. Returns JSON-serialized `PqcEncryptedContainer` as bytes. (`pub fn encrypt_to_recipient(&self, recipient_key_bytes: &[u8], recipient_kyber_bytes: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>>`)
- **`decrypt(ciphertext_hex: str, nonce_hex: str, ephemeral_pqc_pk_hex: str) -> bytes`**: Decrypts hex components back to plaintext bytes. (`pub fn decrypt(&self, ciphertext_hex: String, nonce_hex: String, ephemeral_pqc_pk_hex: String) -> PyResult<Vec<u8>>`)
- **`decrypt_container(encrypted_container_bytes: bytes) -> bytes`**: Decrypts serialized `PqcEncryptedContainer` JSON bytes back to plaintext bytes. (`pub fn decrypt_container(&self, encrypted_container_bytes: &[u8]) -> PyResult<Vec<u8>>`)
- **`public_key_hex() -> str`**: Returns hex string of Dilithium5 public key. (`pub fn public_key_hex(&self) -> String`)
- **`get_public_key_bytes() -> bytes`**: Returns raw bytes of Dilithium5 public key. (`pub fn get_public_key_bytes(&self) -> Vec<u8>`)
- **`get_kyber_public_key_bytes() -> bytes`**: Returns raw bytes of Kyber1024 public key. (`pub fn get_kyber_public_key_bytes(&self) -> Vec<u8>`)

### Free Functions Exported (`#[pyfunction]`)
None. There are no free functions exported via `#[pyfunction]`. Only classes `TrustEngine` and `PqcKeyPair` are exported in `#[pymodule]`.

---

## Task 2: `PqcKeyPair` Source & Constructor Confirmation

### Exact Rust Code Definition
```rust
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
        let container = self.inner.encrypt(&self.inner.public_key, plaintext)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Encryption error: {}", e)))?;
        Ok((
            hex::encode(&container.ciphertext),
            hex::encode(&container.nonce),
            hex::encode(&container.ephemeral_pqc_pk),
        ))
    }

    pub fn encrypt_to_recipient(&self, recipient_key_bytes: &[u8], recipient_kyber_bytes: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
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

    pub fn decrypt(&self, ciphertext_hex: String, nonce_hex: String, ephemeral_pqc_pk_hex: String) -> PyResult<Vec<u8>> {
        let ciphertext = hex::decode(&ciphertext_hex)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {}", e)))?;
        let nonce = hex::decode(&nonce_hex)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {}", e)))?;
        let ephemeral_pqc_pk = hex::decode(&ephemeral_pqc_pk_hex)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Hex decode error: {}", e)))?;
        let container = crate::PqcEncryptedContainer {
            algorithm: format!("{}-Kyber1024-ChaCha20Poly1305", self.inner.algorithm),
            ephemeral_pqc_pk,
            nonce,
            ciphertext,
        };
        self.inner.decrypt(&container)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption error: {}", e)))
    }

    pub fn decrypt_container(&self, encrypted_container_bytes: &[u8]) -> PyResult<Vec<u8>> {
        let container: crate::PqcEncryptedContainer = serde_json::from_slice(encrypted_container_bytes)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Deserialization error: {}", e)))?;
        self.inner.decrypt(&container)
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Decryption error: {}", e)))
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
```

### Constructor Analysis
- In Rust, `generate()` is attributed with `#[new]`.
- In PyO3, `#[new]` designates the class constructor invoked when calling standard Python initialization: `keypair = PqcKeyPair()`.
- **Is there a method named `generate()` on the Python class?** **No.** `PqcKeyPair.generate()` does not exist as an attribute or method on the Python class object. The standard class constructor `PqcKeyPair()` is used to construct instances, which internally calls the Rust `generate()` function.

Exposed Python methods on `PqcKeyPair`:
1. `decrypt`
2. `decrypt_container`
3. `encrypt`
4. `encrypt_to_recipient`
5. `get_kyber_public_key_bytes`
6. `get_public_key_bytes`
7. `public_key_hex`
8. `sign`
9. `sign_bytes`
10. `verify`

---

## Task 3: `TrustEngine` Source & Method Confirmation

### Exact Rust Code Definition
```rust
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
```

### Constructor & Exposed Methods
- **Constructor**: `engine = TrustEngine()` (mapped from `#[new] pub fn new() -> Self`)
- Exposed Python Methods:
  1. `grant(actor: str, capability: str) -> None`
  2. `revoke_token(token_id: str) -> None`
  3. `register_voter_key(voter_id: str, public_key_bytes: bytes) -> None`
  4. `evaluate(req_json: str) -> str`

---

## Task 4: Runtime Inspection Outputs

Commands run locally against built extension module:

### Command 1: Module Directory
```bash
python3 -c "import ube_foundation; print(dir(ube_foundation))"
```
**Output:**
```
['PqcKeyPair', 'TrustEngine', '__all__', '__builtins__', '__cached__', '__doc__', '__file__', '__loader__', '__name__', '__package__', '__path__', '__spec__', 'ube_foundation']
```

### Command 2: `PqcKeyPair` Directory
```bash
python3 -c "from ube_foundation import PqcKeyPair; print(dir(PqcKeyPair))"
```
**Output:**
```
['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'decrypt', 'decrypt_container', 'encrypt', 'encrypt_to_recipient', 'get_kyber_public_key_bytes', 'get_public_key_bytes', 'public_key_hex', 'sign', 'sign_bytes', 'verify']
```

### Command 3: `PqcKeyPair` Help
```bash
python3 -c "from ube_foundation import PqcKeyPair; help(PqcKeyPair)"
```
**Output:**
```
Help on class PqcKeyPair in module builtins:

class PqcKeyPair(object)
 |  Methods defined here:
 |
 |  decrypt(self, /, ciphertext_hex, nonce_hex, ephemeral_pqc_pk_hex)
 |
 |  decrypt_container(self, /, encrypted_container_bytes)
 |
 |  encrypt(self, /, plaintext)
 |
 |  encrypt_to_recipient(self, /, recipient_key_bytes, recipient_kyber_bytes, plaintext)
 |
 |  get_kyber_public_key_bytes(self, /)
 |
 |  get_public_key_bytes(self, /)
 |
 |  public_key_hex(self, /)
 |
 |  sign(self, /, message)
 |
 |  sign_bytes(self, /, message)
 |
 |  verify(self, /, message, signature_hex)
 |
 |  ----------------------------------------------------------------------
 |  Static methods defined here:
 |
 |  __new__(*args, **kwargs)
 |      Create and return a new object.  See help(type) for accurate signature.
```

### Command 4: `TrustEngine` Directory
```bash
python3 -c "from ube_foundation import TrustEngine; print(dir(TrustEngine))"
```
**Output:**
```
['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'evaluate', 'grant', 'register_voter_key', 'revoke_token']
```

---

## Task 5: Python API Usage Guide

### Constructing `PqcKeyPair`
Standard constructor instantiation:
```python
from ube_foundation import PqcKeyPair

keypair = PqcKeyPair()
```

### Constructing `TrustEngine`
Standard constructor instantiation:
```python
from ube_foundation import TrustEngine

engine = TrustEngine()
```

### Complete Working Python Sample Code

```python
import json
from ube_foundation import TrustEngine, PqcKeyPair

# ==========================================
# 1. TrustEngine Usage Example
# ==========================================
print("--- TrustEngine Example ---")
engine = TrustEngine()

# Grant capability to an actor
engine.grant("agent-001", "filesystem:write")

# Revoke a token ID
engine.revoke_token("token-revoked-999")

# Register a consensus voter public key
voter_pk = b"\x01" * 32
engine.register_voter_key("voter-node-1", voter_pk)

# Evaluate an ActionRequest JSON
action_request = {
    "id": "req-101",
    "actor": "agent-001",
    "capability": "filesystem:write",
    "action": "write_file",
    "input": {"path": "/tmp/output.txt", "content": "hello world"},
}
request_json = json.dumps(action_request)
decision_json = engine.evaluate(request_json)
print("Policy Decision Output:", decision_json)


# ==========================================
# 2. PqcKeyPair Usage Example
# ==========================================
print("\n--- PqcKeyPair Example ---")
alice_keys = PqcKeyPair()
bob_keys = PqcKeyPair()

# Retrieve public keys
print("Alice Dilithium5 PK (hex):", alice_keys.public_key_hex()[:32] + "...")
alice_pk_bytes = alice_keys.get_public_key_bytes()
alice_kyber_bytes = alice_keys.get_kyber_public_key_bytes()

# Post-Quantum Digital Signatures
message = b"Authenticate Action Request #101"
sig_hex = alice_keys.sign(message)
print("Signature Hex:", sig_hex[:32] + "...")

is_valid = alice_keys.verify(message, sig_hex)
print("Signature Valid:", is_valid)

# Self-Encryption (ChaCha20Poly1305 + Kyber1024)
secret_payload = b"Top Secret Payload"
ct_hex, nonce_hex, epk_hex = alice_keys.encrypt(secret_payload)
decrypted_payload = alice_keys.decrypt(ct_hex, nonce_hex, epk_hex)
print("Decrypted Self-Encrypted Payload:", bytes(decrypted_payload).decode())

# Recipient Encryption (Alice encrypts to Bob)
bob_pk_bytes = bob_keys.get_public_key_bytes()
bob_kyber_bytes = bob_keys.get_kyber_public_key_bytes()

container_bytes = alice_keys.encrypt_to_recipient(
    bob_pk_bytes, bob_kyber_bytes, secret_payload
)
bob_decrypted = bob_keys.decrypt_container(container_bytes)
print("Bob Decrypted Container Payload:", bytes(bob_decrypted).decode())
```
