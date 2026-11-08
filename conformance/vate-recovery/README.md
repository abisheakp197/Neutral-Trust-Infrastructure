# NTI x VATE Recovery Fixture: Lost Response

**Status:** Draft for review (joint test with VATE, Issue #64)
**Scope:** The NTI side of a "lost response after an action is accepted" recovery test.
**Audience:** VATE implementers, NTI sidecar implementers, and reviewers of the joint vector.

---

A client sends an action to an NTI agent. NTI authorises it, signs a receipt, and
the action is dispatched downstream. The **response is lost**: the client never
learns whether the action took effect. VATE's job is to decide, safely, whether a
retry may proceed. This directory is NTI's half of that test: a receipt fixture
and a verifier.

## Contents

| File | What it is |
| :--- | :--- |
| `nti_receipt.json` | A mock NTI receipt for one lost-response attempt. Real ML-DSA-87 signature over a real Merkle proof. |
| `verify_receipt.py` | Self-contained verifier: schema, payload binding, Merkle root, Merkle inclusion proof, and ML-DSA-87 signature. |
| `README.md` | This file: what the receipt proves, what stays unknown, and how to retry safely. |

## Running the verifier

Requires only Python 3 and `openssl` (>= 3.5 for native ML-DSA-87). No
third-party Python packages.

```bash
cd conformance/vate-recovery
python3 verify_receipt.py nti_receipt.json
```

It runs five checks and prints one line per check:

```text
== 1. Schema ==
   OK   : required fields present
   OK   : algorithm is ML-DSA-87
== 2. Action payload binding ==
   OK   : action_payload_sha256 matches action_payload  8420f705ebda0222
== 3. Merkle root over the delegation chain ==
   OK   : delegation_chain_root recomputed  c597c2194da80fba
== 4. Merkle inclusion proof ==
   OK   : leaf_sha256 matches the record at leaf_index  index 2
   OK   : proof folds to merkle_proof.root_sha256  c597c2194da80fba
   OK   : proof root equals delegation_chain_root
== 5. ML-DSA-87 signature ==
   OK   : signature is tagged ML-DSA-87  4627 bytes
   WARN : using the embedded public key  self-asserted; pin it out of band for a real decision
   OK   : ML-DSA-87 signature verifies over the signing payload

RESULT: receipt verified (Layer 1: payload binding + Merkle proof + ML-DSA-87 signature).
NOTE:   this proves NTI signed the action. It does NOT prove the action took effect.
```

Two options matter for recovery:

* `--expect-payload-sha256 <hex>` binds the receipt to the original attempt. Pass
  the digest of the request you actually sent; if it differs, the receipt does
  not describe this attempt and the run fails. **Use this on every retry.**
* `--public-key <pem>` pins the ML-DSA-87 key. Without it the verifier uses the
  key embedded in the receipt, which is self-asserted. In production, pin the
  key resolved from the agent's DID document (see the boundary note below).

Exit codes: `0` all checks pass, `1` a check failed, `2` the receipt could not be
read.

## What the receipt proves

Verification establishes three things about the original attempt:

1. **Authorised.** The agent's DID authorised the ML-DSA-87 key that signed
   (`agent_did` + `verification_method`), and the delegation chain committed by
   `delegation_chain_root` was intact at signing time.
2. **Intended.** NTI signed an action over exactly `action_payload_sha256`, at
   `signed_at`. The signature covers the payload digest, the delegation root, the
   DID, the verification method, and the timestamp, domain-separated and
   length-prefixed so no field can be moved into another position.
3. **Identified.** The attempt has a stable identity: `action_payload_sha256`
   plus `receipt_id` and the `idempotency_key` in `recovery`. This is what links
   recovered evidence back to the original attempt rather than to a new one.

## What remains unknown

The receipt is a signature over the *intent* to act. It is **not** evidence that
the action took effect. Signing and the downstream effect are not atomic: NTI can
sign, dispatch, and lose the response before or after the effect commits. So the
lost-response case leaves exactly one question open:

> Did the downstream effect commit, and if so, exactly once?

The receipt collapses a broad "did anything happen?" into that single
reconciliation question. Everything upstream of the effect — authorisation,
scope, intent, and the payload's identity — is already fixed by the receipt. VATE
does not need to re-derive any of it; it needs to resolve one unknown against the
downstream system.

Concretely, the receipt does not tell you:

* whether the ledger write (or other downstream effect) completed;
* whether the action was applied exactly once, not twice;
* whether the counterparty observed the effect.

## Executing a retry safely

A naive retry after a lost response risks applying the effect twice. The rule is:
**never retry until the receipt is verified and the downstream effect has been
checked, and only ever retry idempotently.**

1. **Verify the receipt.** Run `verify_receipt.py`. Fail-closed: if any check
   fails, do not retry; treat the evidence as untrusted and escalate.
2. **Bind to the original attempt.** Re-run with
   `--expect-payload-sha256 <digest-of-the-request-you-sent>`. A mismatch means
   the receipt describes a different action; refuse.
3. **Probe the downstream system.** Query for the effect using the
   `idempotency_key` and the payload's natural key (for example the ledger
   transfer id or the `nonce` inside `action_payload`). This is the only step
   that resolves the unknown.
4. **Decide.** See the table below.
5. **Retry idempotently, if allowed.** Reuse the *same* `idempotency_key` and
   `nonce`. Never retry with a fresh nonce: a new nonce would let a second
   execution produce a second effect, defeating exactly-once.
6. **Re-check authorisation at retry time.** If the retry happens later, confirm
   the delegation is still within its validity window and the key was not revoked
   since `signed_at`.

### Decision table

| Receipt verifies | Bound to this attempt | Downstream effect found | Action |
| :--- | :--- | :--- | :--- |
| No | - | - | Do not retry. Escalate; treat evidence as untrusted. |
| Yes | No | - | Do not retry. The receipt is for a different action. |
| Yes | Yes | Present | **Do not retry.** The action completed; reconcile client state to succeeded. |
| Yes | Yes | Absent, retry window open | Retry idempotently with the same key/nonce. |
| Yes | Yes | Unknown (cannot confirm) | Do not retry blind. Wait, then re-probe, or escalate. |

The safe default for an unconfirmable outcome is to **not** double-apply.

## Boundary: what this verifier does not check

`verify_receipt.py` verifies **Layer 1** of
[`docs/NTI-Agent-DID-INTEROP.md`](../../docs/NTI-Agent-DID-INTEROP.md) — the NTI
proofs. It deliberately does not perform:

* **Layer 0a — DID authorization.** Resolving `agent_did`, reading the DID log,
  confirming the key was valid **as of `signed_at`** (not merely now), and
  confirming it is listed under `assertionMethod`. Those need the DID log.
* **Layer 0b — VC issuer identity.** Resolving and validating the VC issuer,
  which is a distinct check from DID authorization.

A full decision requires all three layers to pass (a strict AND gate). In this
fixture the ML-DSA-87 key is embedded in the receipt so the Layer 1 check is
self-contained; that key is **self-asserted** and must be replaced by a key
resolved from the DID document before the fixture is used for anything beyond
the Layer 1 test.

## Fixture notes

* **Synthetic.** This receipt is a test fixture for Issue #64. It is not
  production evidence and the DID is a placeholder.
* **Real cryptography.** The ML-DSA-87 signature is a genuine FIPS 204
  signature (4627 bytes, produced with OpenSSL 3.5). The Merkle proof is a real
  RFC 6962 inclusion proof over the three-record delegation chain, with the odd
  node promoted rather than duplicated.
* **Encoding.** The signature is the raw ML-DSA-87 output, hex-encoded and
  tagged `ml-dsa-87:{length}:{hex}`. It is not DER-encoded ECDSA; the verifier
  rejects any signature that is not in the tagged raw form.
* **Tamper check.** Flipping a byte of the signature, altering a delegation
  record, altering a Merkle sibling, or substituting the public key each make the
  verifier fail. See the joint vector for the expected VATE outcome per case.

---

Feedback welcome on Issue #64. This fixture was produced by an AI agent
(OpenHands) on behalf of the repository maintainers.
