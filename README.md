# Neutral Trust Infrastructure (NTI)
### Post-Quantum Cryptographic Trust & Governance Layer for Autonomous Agent Ecosystems

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE.md)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)]()
[![PQC Standard](https://img.shields.io/badge/PQC-NIST%20Dilithium5%20%26%20Kyber1024-purple.svg)]()
[![SDKs](https://img.shields.io/badge/SDK-Rust%20%26%20Python-orange.svg)]()

---

## What is Neutral Trust Infrastructure?

**Neutral Trust Infrastructure (NTI)** (built in `ube-foundation`) is a production-grade, zero-trust cryptographic governance runtime engineered for enterprise autonomous AI agents. As enterprise organizations deploy AI agents to execute financial transactions, access healthcare records, manage cloud infrastructure, and orchestrate multi-agent workflows, NTI provides the cryptographically verifiable security boundary required to prevent unauthorized execution, identity spoofing, and prompt injection attacks.

NTI secures all agent capability checks, state transitions, inter-agent mesh handshakes, and BFT consensus votes with **NIST-standardized Post-Quantum Cryptography (PQC)**: Level 5 **CRYSTALS-Dilithium5** digital signatures and Level 4 **CRYSTALS-Kyber1024** Key Encapsulation Mechanisms (KEM).

---

## Enterprise Key Features

* **🛡️ NIST Post-Quantum Cryptography (PQC):** Native support for CRYSTALS-Dilithium5 detached digital signatures and CRYSTALS-Kyber1024 hybrid envelope encryption paired with ChaCha20Poly1305.
* **⚡ Zero-Trust Capability Tokens & Caveats:** Dynamic, verifiable token evaluation with contextual constraints (`Expires`, `MaxExecutions`, `ValueLimit`, `PathRestricted`).
* **🤝 Byzantine Fault Tolerant (BFT) Multi-Agent Consensus:** Threshold-based consensus vote signature checks with voter identity binding and outcome determinism verification.
* **📜 Merkle-Chained State Audit Trails & Recovery:** Full audit log history chaining with SHA-256 Merkle tree batching, automatic persistence, and crash recovery history integrity checks (`verify_history()`).
* **🔄 Key Rotation Lifecycle:** Built-in key rotation routines (`AgentMeshNode::rotate_key` / `PqcKeyPair::rotate`) for archived verifying key retention.
* **🔒 Hardened Network API:** Default 2MB payload body limits to defend against resource exhaustion DoS attacks, accompanied by TLS API endpoint support.
* **🐍 Polyglot SDK Support:** Native Rust engine (`ube-foundation`) and PyO3 Python bindings (`pip install ube-foundation`).

---

## Architecture Overview

```
                      ┌──────────────────────────────────────┐
                      │    Enterprise AI Agent Application   │
                      └──────────────────┬───────────────────┘
                                         │ Action Request
                                         ▼
                      ┌──────────────────────────────────────┐
                      │    NTI Trust Engine Runtime          │
                      ├──────────────────────────────────────┤
                      │  • Dilithium5 Signature Verification │
                      │  • Ed25519 Identity Validation       │
                      │  • Dynamic Caveat Interpreter        │
                      │  • Token Revocation & Expiry Check   │
                      └──────────────────┬───────────────────┘
                                         │ Policy Decision
                                         ▼
                 ┌───────────────────────┴──────────────────────┐
                 │                                              │
                 ▼ Allow                                        ▼ Deny
      ┌─────────────────────┐                       ┌─────────────────────┐
      │  Execute Capability │                       │  Block Execution &  │
      │  & Record Audit Log │                       │  Log Security Event │
      └─────────────────────┘                       └─────────────────────┘
```

---

## Quickstart

### Python SDK (`pip`)

```bash
cd ube-foundation
pip install .
```

```python
import json
from ube_foundation import TrustEngine, PqcKeyPair

engine = TrustEngine()
engine.grant("agent_finance", "transfer_funds")

request = {
    "id": "tx-1",
    "actor": "agent_finance",
    "capability": "transfer_funds",
    "action": "execute",
    "input": {"amount": 500},
    "signature": None, "pqc_signature": None, "public_key": None,
    "pqc_public_key": None, "token": None, "identity_claim": None
}

decision = json.loads(engine.evaluate(json.dumps(request)))
print("Policy Decision:", decision["decision"]) # Output: Allow

pqc = PqcKeyPair.generate()
sig = pqc.sign(b"Authorize Trade")
print("PQC Dilithium5 Signature Valid:", pqc.verify(b"Authorize Trade", sig))
```

### Rust Crate (`Cargo.toml`)

```rust
use ube_foundation::{TrustEngine, ActionRequest, Decision};
use serde_json::json;

let mut engine = TrustEngine::new();
engine.grant("agent_alpha", "data_read");

let req = ActionRequest {
    id: "req-1".into(),
    actor: "agent_alpha".into(),
    capability: "data_read".into(),
    action: "read".into(),
    input: json!({}),
    signature: None, pqc_signature: None, public_key: None,
    pqc_public_key: None, token: None, identity_claim: None,
};

let decision = engine.evaluate(&req);
assert_eq!(decision.decision, Decision::Allow);
```

For complete integration details, see [QUICKSTART.md](QUICKSTART.md) and [WHITEPAPER.md](WHITEPAPER.md).

---

## Verification & Testing

Run all test suites across unit tests, adversarial fuzzing, and Python SDK bindings:

```bash
cd ube-foundation

# Run Rust unit, integration, and fuzz tests
cargo test

# Run Python SDK unit tests
python3 python_tests/test_python_sdk.py
```

---

## Documentation Links

* [Technical Whitepaper & Architecture Specification](WHITEPAPER.md)
* [Developer Quickstart Guide](QUICKSTART.md)
* [Implementation Status & Audit Log](IMPLEMENTATION_STATUS.md)

---

## License

Distributed under the MIT License. See [LICENSE.md](LICENSE.md) for details.
