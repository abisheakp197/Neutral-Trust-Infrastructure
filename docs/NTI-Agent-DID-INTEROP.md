# NTI x Agent-DID Interoperability

**Status:** Draft for review
**Scope:** Cross-project integration between Neutral Trust Infrastructure (NTI) and Agent-DID
**Audience:** Principal architects, cryptographic reviewers, and implementers of both projects

---

This document defines how an NTI receipt and an Agent-DID identity compose at invocation time. The two layers are strictly independent and are combined by a verifier using a strict AND gate; neither layer trusts the other's result.

## 1. Receipt Referencing Agent-DID

The NTI receipt envelope binds the action to the agent's decentralized identifier. It includes:

* An `agent_did` field containing the **resolved DID string** (for example, `did:webvh:...`).
* A `verification_method` field pointing to the **specific public key fragment** within that DID document (for example, `#key-1`).

The ML-DSA-87 signature over the receipt is bound to the **SHA-256 hash of the payload** and to the **specific key authorized by the delegation chain**. In other words, the signature is valid only when produced by the key named in `verification_method`, and that key must be the one the delegation chain authorizes for the action.

```json
{
  "receipt_id": "rcpt-20261106-4417-a2b1",
  "agent_did": "did:webvh:QmExampleAgentDidString",
  "verification_method": "did:webvh:QmExampleAgentDidString#key-1",
  "payload_sha256": "9f2c...e1",
  "delegation_chain_root": "a71b...3d",
  "algorithm": "ML-DSA-87",
  "signature": "3046022100c8...ml_dsa_87_signature..."
}
```

## 2. Resource Verifier Checks

The resource verifier performs two logically separate sets of checks. They are never merged, and neither substitutes for the other.

### Layer 0 - from Agent-DID

The verifier resolves the DID to ensure the key is:

* **Valid** - the DID document resolves and the `verification_method` fragment exists.
* **Not revoked** - the key has not been revoked in the DID document or its revocation registry.
* **Matching the VC issuer** - the resolved key matches the issuer asserted by the Verifiable Credential.

### Layer 1 - from NTI

The verifier independently checks the NTI proofs:

* **Merkle proof** - confirms the delegation chain has not been tampered with.
* **ML-DSA-87 signature** - proves the agent actually executed the action under the authorized scope.

## 3. Failure Behavior (Fail-Closed)

Neither side falls back to the other's result. The composition is a **strict AND gate**: both Layer 0 and Layer 1 MUST pass.

* If **Agent-DID fails to resolve the key**, the **NTI sidecar immediately refuses to sign the receipt**.
* If **NTI fails to generate a valid Merkle proof**, the **resource verifier rejects the action**, regardless of how valid the Agent-DID identity is.

| Agent-DID (Layer 0) | NTI (Layer 1) | Outcome |
| :--- | :--- | :--- |
| Pass | Pass | Accept |
| Fail | Pass | Reject - sidecar refuses to sign; verifier rejects |
| Pass | Fail | Reject - verifier rejects on invalid Merkle proof |
| Fail | Fail | Reject |

## 4. Next Steps

Once this design is approved by Agent-DID, NTI will build:

1. An **optional integration package**, delivered **outside the core SDK**, so the core `ube-foundation` surface stays unchanged.
2. A **cross-project test vector** exercising the full sequence:

   `VC issued -> action attempted -> delegation verified -> receipt signed -> both proofs checked`

---

## Feedback

Raised as a cross-project interoperability proposal. Please comment on this document or the associated pull request.
