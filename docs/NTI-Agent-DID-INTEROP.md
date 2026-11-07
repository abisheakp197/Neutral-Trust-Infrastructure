# NTI x Agent-DID Interoperability

**Status:** Draft for review (rev 2 - addresses Agent-DID cryptographic review)
**Scope:** Cross-project integration between Neutral Trust Infrastructure (NTI) and Agent-DID
**Audience:** Principal architects, cryptographic reviewers, and implementers of both projects

---

This document defines how an NTI receipt and an Agent-DID identity compose at invocation time. The two layers are strictly independent and are combined by a verifier using a strict AND gate; neither layer trusts the other's result.

> **Revision note (rev 2).** This revision fixes five critical cryptographic defects raised by Edison Duran (Agent-DID): ML-DSA-87 key binding (Section 1.1), signing-time validity of `did:webvh` keys (Section 2.1), the `assertionMethod` verification relationship (Section 2.1), separation of DID authorization from VC issuer checks (Section 2.1), and corrected DID / signature examples (Sections 1.2 and 4.3).

## 1. Receipt Referencing Agent-DID

The NTI receipt envelope binds the action to the agent's decentralized identifier. It includes:

* An `agent_did` field containing the **resolved DID string** in the canonical `did:webvh:{SCID}:{domain}` form.
* A `verification_method` field pointing to the **specific public key fragment** within that DID document (for example, `#ml-dsa-87-1`).

The ML-DSA-87 signature over the receipt is bound to the **SHA-256 hash of the payload** and to the **specific key authorized by the delegation chain**. In other words, the signature is valid only when produced by the key named in `verification_method`, and that key must be the one the delegation chain authorizes for the action.

### 1.1 Key Binding: ML-DSA-87 Keys MUST Be Published in the DID Document

Agent-DID documents today publish **Ed25519** verification methods. Ed25519 is used for DID authentication and for the verifiable mapping; it is **not** the algorithm that signs NTI receipts. NTI receipts are signed with **ML-DSA-87** (FIPS 204 / CRYSTALS-Dilithium5).

Therefore, publishing only Ed25519 keys is insufficient for an NTI verifier. The rule is:

> **The ML-DSA-87 public key that verifies an NTI receipt MUST be discoverable from the agent's DID document.** A verifier MUST NOT accept an ML-DSA-87 key that cannot be resolved from the DID.

Two conforming binding patterns are permitted. The verifier MUST support **Pattern A**; **Pattern B** is permitted only when the Agent-DID document explicitly links the external mapping.

**Pattern A - ML-DSA-87 verification method directly in the DID document (preferred).**

The DID document carries a verification method with `type: "Multikey"` and a `publicKeyMultibase` encoding the ML-DSA-87 (Dilithium5) public key under the multicodec code `0x1211`. The `verification_method` fragment in the receipt points directly at this entry.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "did:webvh:z6MkExampleSCID1234567890:agents.example.com",
  "verificationMethod": [
    {
      "id": "did:webvh:z6MkExampleSCID1234567890:agents.example.com#ml-dsa-87-1",
      "type": "Multikey",
      "controller": "did:webvh:z6MkExampleSCID1234567890:agents.example.com",
      "publicKeyMultibase": "uz..."
    }
  ],
  "authentication": ["#ed25519-auth-1"],
  "assertionMethod": [
    "did:webvh:z6MkExampleSCID1234567890:agents.example.com#ml-dsa-87-1"
  ]
}
```

**Pattern B - ML-DSA-87 key linked via a separate verifiable mapping.**

When the ML-DSA-87 key cannot live in the DID document (for example, rotation or custody constraints), the DID document MUST contain a `service` entry (or an equivalent verification-method reference) that links to a **verifiable mapping**. The mapping is a Verifiable Credential or Verifiable Presentation that (a) is issued by the DID's controller, (b) is signed by a key listed under `assertionMethod` in the DID document, and (c) asserts the ML-DSA-87 verification method and its multibase key.

**Verifier resolution procedure (normative).** To resolve the ML-DSA-87 verification method the verifier MUST:

1. Resolve `agent_did` and confirm the DID document is valid at the current log entry (see Section 2.1).
2. Resolve the fragment named by `verification_method`.
3. Require that the resolved entry is an ML-DSA-87 (`Multikey` / multicodec `0x1211`) key. If it is an Ed25519 key, the receipt is invalid: Ed25519 keys can never verify an ML-DSA-87 receipt.
4. If the key is present directly (Pattern A), use it. If the entry instead links to an external mapping (Pattern B), fetch and verify the mapping: the mapping's issuer MUST equal the DID controller, and the mapping MUST be signed by a key listed under `assertionMethod`.
5. Require that the ML-DSA-87 key is listed under `assertionMethod` (see Section 2.1).
6. Confirm that the ML-DSA-87 key was valid at the signing time recorded in the receipt (see Section 2.1).

### 1.2 Receipt Envelope Example

```json
{
  "receipt_id": "rcpt-20261106-4417-a2b1",
  "agent_did": "did:webvh:z6MkExampleSCID1234567890:agents.example.com",
  "verification_method": "did:webvh:z6MkExampleSCID1234567890:agents.example.com#ml-dsa-87-1",
  "payload_sha256": "9f2c...e1",
  "delegation_chain_root": "a71b...3d",
  "signed_at": "2026-11-06T14:17:02Z",
  "algorithm": "ML-DSA-87",
  "signature": "ml-dsa-87:2592:2f7a...c04b"
}
```

* `agent_did` MUST be the canonical `did:webvh:{SCID}:{domain}` identifier, where `{SCID}` is the self-certifying identifier derived from the DID log genesis entry.
* `signature` is the raw ML-DSA-87 signature, tagged `ml-dsa-87:{length}:{hex}`. It is **not** DER-encoded ECDSA and MUST NOT be encoded or interpreted as an ASN.1 DER structure. The tag and length let the verifier reject malformed or truncated signatures before invoking the verifier.
* `signed_at` is the RFC 3339 timestamp at which the signature was produced. The verifier uses this value to check signing-time validity (Section 2.1).

## 2. Resource Verifier Checks

The resource verifier performs three logically separate sets of checks. They are never merged, and none substitutes for another.

### 2.1 Layer 0a - DID Authorization (Agent-DID)

The verifier resolves the DID and confirms the **agent's DID authorized the key**. These checks answer "did this DID authorize this key to act?"

* **Valid at signing time** - the DID document resolves, and the `verification_method` fragment existed at `signed_at`.
* **Signing-time validity** - the verifier MUST evaluate validity **as of `signed_at`**, not merely at the current time. For `did:webvh` this means the verifier MUST read the DID log and confirm that, at `signed_at`, the key was present, active, and not yet revoked. A key that is valid *now* but was not valid at `signed_at` (for example, a key created after the receipt, or one revoked before it) MUST be rejected. This prevents backdating.
* **Not revoked** - the key was not revoked at `signed_at`. Revocation is determined from the DID log and any referenced revocation registry; a revocation entry that takes effect after `signed_at` does not invalidate a signature made before it.
* **Correct verification relationship** - the key MUST be listed under `assertionMethod` in the DID document (as evaluated at `signed_at`). Keys listed only under `authentication` or `keyAgreement` MUST NOT be used to verify receipts. A key under `keyAgreement` is valid for key agreement only and is invalid for signing receipts.

### 2.2 Layer 0b - VC Issuer Identity (Agent-DID / Verifiable Credentials)

This is a **distinct** check from Layer 0a and answers a different question: "who issued the Verifiable Credential?" The verifier MUST NOT conflate the two.

* **Issuer resolution** - resolve the `issuer` of the VC and confirm the issuer's DID document is valid and the issuer key is authorized for assertion at the VC's issuance time.
* **Issuer != agent** - the VC issuer and the acting agent MAY be different entities. The verifier records both independently; a valid VC issuer does not by itself authorize the agent, and a DID-authorized agent key does not by itself validate the VC.

### 2.3 Layer 1 - from NTI

The verifier independently checks the NTI proofs:

* **Merkle proof** - confirms the delegation chain has not been tampered with.
* **ML-DSA-87 signature** - proves the agent actually executed the action under the authorized scope. The signature MUST be verified with the ML-DSA-87 key resolved in Layer 0a, using the raw tagged encoding defined in Section 1.2.

## 3. Failure Behavior (Fail-Closed)

Neither side falls back to the other's result. The composition is a **strict AND gate**: Layer 0a, Layer 0b, and Layer 1 MUST all pass.

* If **Agent-DID fails to resolve the key** (or the key is not an ML-DSA-87 key under `assertionMethod`, or was not valid at `signed_at`), the **NTI sidecar immediately refuses to sign the receipt**.
* If **the VC issuer check (Layer 0b) fails**, the **resource verifier rejects the action**, even when the DID authorized the key.
* If **NTI fails to generate a valid Merkle proof**, the **resource verifier rejects the action**, regardless of how valid the Agent-DID identity is.

| DID Authorization (Layer 0a) | VC Issuer (Layer 0b) | NTI (Layer 1) | Outcome |
| :--- | :--- | :--- | :--- |
| Pass | Pass | Pass | Accept |
| Fail | Pass | Pass | Reject - sidecar refuses to sign; verifier rejects |
| Pass | Fail | Pass | Reject - verifier rejects on issuer mismatch |
| Pass | Pass | Fail | Reject - verifier rejects on invalid Merkle proof |
| Fail | Fail | Fail | Reject |

## 4. Worked Example (did:webvh, ML-DSA-87)

### 4.1 Identifier

```text
did:webvh:z6MkExampleSCID1234567890:agents.example.com
```

The `{SCID}` (`z6MkExampleSCID1234567890`) is derived from the genesis entry of the DID log; the `{domain}` (`agents.example.com`) hosts `/.well-known/did.jsonl`.

### 4.2 Signing-time resolution

1. Fetch the DID log from `https://agents.example.com/.well-known/did.jsonl`.
2. Walk the log to the entry active at `signed_at` (`2026-11-06T14:17:02Z`).
3. Confirm `#ml-dsa-87-1` was present, under `assertionMethod`, and not revoked at that time.

### 4.3 Signature encoding

```text
algorithm:   ML-DSA-87
encoding:    raw bytes, hex-encoded, tagged as ml-dsa-87:{length}:{hex}
example:     ml-dsa-87:2592:2f7a...c04b
```

The signature is the raw ML-DSA-87 output. It is **not** a DER-encoded ECDSA signature, and verifiers MUST reject any receipt whose `signature` field is ASN.1 DER or otherwise not in the tagged ML-DSA-87 form.

## 5. Next Steps

Once this design is approved by Agent-DID, NTI will build:

1. An **optional integration package**, delivered **outside the core SDK**, so the core `ube-foundation` surface stays unchanged.
2. A **cross-project test vector** exercising the full sequence:

   `VC issued -> action attempted -> delegation verified -> receipt signed -> DID authorization + issuer + both proofs checked`

---

## Feedback

Raised as a cross-project interoperability proposal. Please comment on this document or the associated pull request.
