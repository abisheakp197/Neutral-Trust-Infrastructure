# Neutral Trust Infrastructure (NTI) - Developer Quickstart Guide

Get up and running with **Neutral Trust Infrastructure (NTI)** in minutes.

---

## Installation Options

### Option A: Rust Crate (`ube-foundation`)

Add `ube-foundation` to your `Cargo.toml`:

```toml
[dependencies]
ube-foundation = { path = "./ube-foundation" }
tokio = { version = "1", features = ["full"] }
serde_json = "1.0"
```

### Option B: Python Package (`pip`)

Install the Python SDK with PyO3 native bindings:

```bash
cd ube-foundation
pip install .
```

---

## 1. Python SDK Quickstart

### Evaluate Agent Capability & Post-Quantum Signatures

```python
import json
from ube_foundation import TrustEngine, PqcKeyPair

# 1. Initialize the Trust Engine
engine = TrustEngine()

# Grant capability to an AI agent
engine.grant("agent_finance_bot", "transfer_funds")

# 2. Create an Action Request
request = {
    "id": "req-tx-1001",
    "actor": "agent_finance_bot",
    "capability": "transfer_funds",
    "action": "execute",
    "input": {"amount": 500, "currency": "USD"},
    "signature": None,
    "pqc_signature": None,
    "public_key": None,
    "pqc_public_key": None,
    "token": None,
    "identity_claim": None
}

# 3. Evaluate Request
decision_json = engine.evaluate(json.dumps(request))
decision = json.loads(decision_json)

print(f"Policy Decision: {decision['decision']}")  # Output: Allow
print(f"Reason: {decision['reason']}")              # Output: granted

# 4. Generate Post-Quantum Cryptographic KeyPair (CRYSTALS-Dilithium5 & Kyber1024)
pqc_keys = PqcKeyPair.generate()
message = b"Authorize High-Value Automated Agent Trade"

# Sign with Dilithium5
signature = pqc_keys.sign(message)
is_valid = pqc_keys.verify(message, signature)
print(f"Dilithium5 Signature Valid: {is_valid}")  # Output: True
```

---

## 2. Rust Crate Quickstart

### Core Trust Engine Evaluation & PQC Encryption

```rust
use ube_foundation::{TrustEngine, ActionRequest, PqcKeyPair, Decision};
use serde_json::json;

#[tokio::main]
async fn main() {
    // 1. Initialize Trust Engine
    let mut engine = TrustEngine::new();
    engine.grant("agent_alpha", "data_processing");

    // 2. Build Action Request
    let req = ActionRequest {
        id: "req-1".into(),
        actor: "agent_alpha".into(),
        capability: "data_processing".into(),
        action: "read".into(),
        input: json!({"dataset": "analytics_2026"}),
        signature: None,
        pqc_signature: None,
        public_key: None,
        pqc_public_key: None,
        token: None,
        identity_claim: None,
    };

    // 3. Evaluate Request
    let decision = engine.evaluate(&req);
    assert_eq!(decision.decision, Decision::Allow);
    println!("Evaluation Passed: {:?}", decision.reason);

    // 4. Hybrid Post-Quantum Key Encapsulation (Kyber1024 + ChaCha20Poly1305)
    let alice = PqcKeyPair::generate();
    let bob = PqcKeyPair::generate();

    let secret_payload = b"Top Secret Autonomous Agent Directive";
    let encrypted = alice.encrypt(&bob.public_key, secret_payload).unwrap();
    let decrypted = bob.decrypt(&encrypted).unwrap();

    println!("Decrypted Payload: {}", String::from_utf8(decrypted).unwrap());
}
```

---

## 3. Running Demos & Examples

Run the included production examples in Rust:

```bash
# Capability & Token Governance Demo
cargo run --example capability_demo

# Inter-Agent Mesh Discovery & Handshake Demo
cargo run --example mesh_demo

# Autonomous Agent Multi-Step Plan Execution
cargo run --example planning_demo

# Decentralized Trust Marketplace Demo
cargo run --example trust_marketplace_demo
```

---

## 4. Running Test Suites

Ensure 100% test pass rate across all security, fuzzing, and compliance tests:

```bash
cd ube-foundation

# Run Rust unit, integration, and adversarial fuzz tests
cargo test

# Run Python SDK integration tests
python3 python_tests/test_python_sdk.py
```
