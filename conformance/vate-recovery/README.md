# NTI x VATE Recovery Fixture: Lost Response

**Status:** Draft for review (joint test with VATE, Issue #64). The receipt schema and the NTI-to-VATE mapping are **proposed**, not agreed: they are still under discussion in Issue #64.
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
| `nti_receipt.json` | A mock NTI receipt for one lost-response attempt, in a proposed schema (see Status). Real ML-DSA-87 signature over a real Merkle proof. Bound to the VATE case 01 operation `demo.create_file_set` (exact resource and file contents). |
| `verify_receipt.py` | Self-contained verifier: schema, payload binding, Merkle root, Merkle inclusion proof, and ML-DSA-87 signature. The signature binds the authoritative identifiers (`receipt_id`, `recovery.attempt_id`, `recovery.idempotency_key`). |
| `generate_fixture.py` | Rebuilds the fixture from source (fresh key, exact VATE action, real Merkle proof) so the signature and binding can be checked independently. `--signed-at` aligns to the VATE timeline; `--tamper` emits the wrong-operation / wrong-attempt negative cases. |
| `README.md` | This file: what the receipt proves, what stays unknown, and how to recover the original result safely. |

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
   OK   : authoritative identifiers present  receipt_id, recovery.attempt_id, recovery.idempotency_key
== 2. Action payload binding ==
   OK   : action_payload_sha256 matches action_payload  ed93f6175b8d0430
== 3. Merkle root over the delegation chain ==
   OK   : delegation_chain_root recomputed  b8eaad91f6911a30
== 4. Merkle inclusion proof ==
   OK   : leaf_sha256 matches the record at leaf_index  index 2
   OK   : proof folds to merkle_proof.root_sha256  b8eaad91f6911a30
   OK   : proof root equals delegation_chain_root
== 5. ML-DSA-87 signature ==
   OK   : signature is tagged ML-DSA-87  4627 bytes
   WARN : using the embedded public key  self-asserted; pin it out of band for a real decision
   OK   : ML-DSA-87 signature verifies over the signing payload  binds identifiers + DID + delegation root + payload digest + time

RESULT: receipt verified (Layer 1: payload binding + Merkle proof + ML-DSA-87 signature).
NOTE:   this proves NTI signed the action. It does NOT prove the action took effect.
```

Two options matter for recovery:

* `--expect-payload-sha256 <hex>` binds the receipt to the original attempt. Pass
  the digest of the request you actually sent; if it differs, the receipt does
  not describe this attempt and the run fails. **Use this whenever you verify a
  recovered attempt.**
* `--public-key <pem>` pins the ML-DSA-87 key. Without it the verifier uses the
  key embedded in the receipt, which is self-asserted. In production, pin the
  key resolved from the agent's DID document (see the boundary note below).

Exit codes: `0` all checks pass, `1` a check failed, `2` the receipt could not be
read.

## Reproducing the Fixture

`nti_receipt.json` is committed with a signature over a disposable key, so its
bytes are only as trustworthy as the file. `generate_fixture.py` rebuilds the
fixture from source so anyone can regenerate it and **independently verify the
signature and the binding**, rather than trusting the committed copy:

```bash
cd conformance/vate-recovery
python3 generate_fixture.py --signed-at "2026-10-25T00:00:00Z" --out-dir ./pinned
python3 verify_receipt.py ./pinned/nti_receipt.json
```

The script writes `nti_receipt.json` and `test_key.pem` into `--out-dir`, signs
the canonical signing payload with a fresh key, and reuses the verifier's own
primitives (`canon`, the RFC 6962 Merkle functions, and `signing_payload`), so
the producer and the checker cannot drift. With no `--signed-at` it reproduces
the committed fixture exactly: the default `2026-11-08T06:31:07Z` yields the same
`action_payload_sha256` (`ed93f6175b8d0430…`) and the same VATE resource and file
contents.

`--signed-at` moves the receipt onto the **VATE timeline**. The original VATE
attempt is dated **2026-10-25** (`observed_at` = `2026-10-25T00:00:00Z`), so pass
`--signed-at "2026-10-25T00:00:00Z"` to align the two sides. The action's
`requested_at` and the delegation `issued_at` values are derived from the signing
instant, so the whole timeline shifts consistently.

### Negative cases (`--tamper`)

Larry's review asked for the "wrong operation" and "wrong attempt" cases. Pass
`--tamper` to emit them alongside a valid receipt:

```bash
python3 generate_fixture.py --signed-at "2026-10-25T00:00:00Z" --tamper all --out-dir ./pinned
```

| File | What it is |
| :--- | :--- |
| `nti_receipt.json` | The valid receipt for the attempt. |
| `nti_receipt.tampered.wrong-operation.json` | The same attempt, but the action is a different operation (`demo.delete_file_set`, different `resource`). |
| `nti_receipt.tampered.wrong-attempt.json` | A different attempt of the same operation (new `nonce`, new `attempt_id`/`idempotency_key`). |

Each tampered receipt is **re-signed**, so it is internally consistent and its
signature verifies: a signature check alone cannot reject it. That is the point.
A receiver catches these only by *binding*: comparing `action_payload_sha256`
against the request it actually sent (`--expect-payload-sha256`), and comparing
the signed identifiers against the attempt it recorded.

```bash
# The valid receipt is accepted when bound to its own digest.
python3 verify_receipt.py ./pinned/nti_receipt.json \
    --expect-payload-sha256 "$(python3 -c 'import json;print(json.load(open("./pinned/nti_receipt.json"))["action_payload_sha256"])')"

# Both tampered receipts verify standalone, but are rejected when bound:
python3 verify_receipt.py ./pinned/nti_receipt.tampered.wrong-operation.json \
    --expect-payload-sha256 <digest-of-the-request-you-sent>   # exit 1
python3 verify_receipt.py ./pinned/nti_receipt.tampered.wrong-attempt.json \
    --expect-payload-sha256 <digest-of-the-request-you-sent>   # exit 1
```

**Algorithm.** The script signs with **ML-DSA-87**, matching the receipt schema
and `verify_receipt.py`. The task brief called for an Ed25519 keypair; NTI
receipts are not Ed25519, and an Ed25519 signature can never verify against them.
`--algorithm ed25519` exists only for experimentation and prints a warning that
the result is not a conforming NTI receipt.

## What the receipt proves

Verification establishes three things about the original attempt:

1. **Signed by the claimed key.** The ML-DSA-87 signature verifies over the
   signing payload, which binds `agent_did` and `verification_method`. **In this
   fixture the key is embedded in the receipt and is self-asserted**: Layer 1
   proves only that *a* key signed, not that the DID authorised it. Layer 0a
   (see the boundary note below) is what establishes authorisation.
2. **Intended.** NTI signed an action over exactly `action_payload_sha256`, at
   `signed_at`. The signature covers the payload digest, the delegation root, the
   DID, the verification method, the timestamp, **and the authoritative
   identifiers** (`receipt_id`, `recovery.attempt_id`, `recovery.idempotency_key`),
   domain-separated and length-prefixed so no field can be moved into another
   position. Altering any bound field, including an identifier, makes the
   signature fail.
3. **Identified.** The attempt has a stable identity: `action_payload_sha256`
   plus `receipt_id` and the `idempotency_key` in `recovery`. Because those
   identifiers are signed, they are authoritative: they cannot be swapped for a
   different attempt's identifiers without breaking the signature. This is what
   links recovered evidence back to the original attempt rather than to a new one.

**What the receipt does not prove.** It is not evidence that the agent was
authorised to act (Layer 0a), and it is not evidence that the action took effect.
DID authorisation, signing-time key validity, and VC issuer identity are separate
checks (Layer 0a/0b) that this fixture does not perform.

## What remains unknown

The receipt is a signature over the *intent* to act. It is **not** evidence that
the action took effect. Signing and the downstream effect are not atomic: NTI can
sign, dispatch, and lose the response before or after the effect commits. So the
lost-response case leaves exactly one question open:

> Did the downstream effect commit, and if so, exactly once?

The receipt collapses a broad "did anything happen?" into that single
reconciliation question. Everything upstream of the effect — scope, intent, and
the payload's identity — is already fixed by the receipt. VATE does not need to
re-derive any of it; it needs to resolve one unknown against the downstream
system.

Concretely, the receipt does not tell you:

* whether the file-set creation (or other downstream effect) completed;
* whether the action was applied exactly once, not twice;
* whether the counterparty observed the effect.

## Recovering the original result

**This first trial is recovery-only: no outcome authorises a fresh execution.**
A missing response, or a lookup that returns "not found", does not establish that
the action did not happen. It leaves the outcome unresolved, and the correct
action is to preserve that unresolved outcome, not to retry.

1. **Verify the receipt.** Run `verify_receipt.py`. Fail-closed: if any check
   fails, treat the evidence as untrusted, preserve the current record, and
   escalate.
2. **Bind to the original attempt.** Re-run with
   `--expect-payload-sha256 <digest-of-the-request-you-sent>`. A mismatch means
   the receipt describes a different action; reject the linkage and preserve the
   original record.
3. **Probe the downstream system.** Query for the effect using the
   `idempotency_key` and the payload's natural key (the `resource` and file names
   inside `action_payload`). This is the observation that resolves the unknown.
4. **Decide.** See the table below. For this trial the decision never authorises
   a new dispatch.

### Decision table

| Receipt verifies | Bound to this attempt | Downstream effect found | Action |
| :--- | :--- | :--- | :--- |
| No | - | - | Do not retry. Escalate; treat evidence as untrusted. |
| Yes | No | - | Do not retry. The receipt is for a different action; reject the linkage. |
| Yes | Yes | Present | **Do not retry.** The action completed; reconcile client state to succeeded, retaining the earlier unknown observation. |
| Yes | Yes | Absent, retry window open | **Do not retry. Preserve unresolved outcome.** |
| Yes | Yes | Unknown (cannot confirm) | **Do not retry. Preserve unresolved outcome.** |

The safe default for an unconfirmable outcome is to **preserve the unresolved
outcome**; absence alone does not establish non-execution.

## Boundary: Layer 1 vs Layer 0

This verifier covers **Layer 1** only. The two layers are distinct checks and are
not substitutes for one another:

* **Layer 1 (performed here).** The signature and integrity checks: the payload
  digest binding, the Merkle root and inclusion proof, and the ML-DSA-87
  signature over the signing payload.
* **Layer 0 (not performed here).** Authorisation and issuer checks that require
  external material — the DID log and the VC — and therefore cannot be done from
  the receipt alone.

> This fixture verifies Layer 1 integrity (signature and Merkle proof) ONLY. It
> does not verify DID authorization or key validity (Layer 0a) and does not
> establish permission to act.

Concretely, this script does **not** perform:

* **Layer 0a — DID authorization.** Resolving `agent_did`, reading the DID log,
  confirming the key was valid **as of `signed_at`** (not merely now), and
  confirming it is listed under `assertionMethod`. Those need the DID log.
* **Layer 0b — VC issuer identity.** Resolving and validating the VC issuer,
  which is a distinct check from DID authorization.

A full decision requires both layers to pass (a strict AND gate): a valid
Layer 1 signature proves *some* key signed, but only Layer 0 establishes that the
DID authorised that key. In this fixture the ML-DSA-87 key is embedded in the
receipt so the Layer 1 check is self-contained; that key is **self-asserted** and
must be replaced by a key resolved from the DID document (and checked under
Layer 0) before the fixture is used for anything beyond the Layer 1 test.

## Fixture notes

* **Synthetic.** This receipt is a test fixture for Issue #64. It is not
  production evidence and the DID is a placeholder.
* **Bound to the VATE operation.** The receipt describes the VATE case 01
  operation `demo.create_file_set` with the same resource
  (`urn:vate:handoff:store-…:resource-…`) and the same file contents
  (`first.txt`, `second.txt`), so both sides describe the same action. The NTI
  digest basis (`action_payload_sha256`) is preserved separately from VATE's
  request digest; the two are not interchangeable.
* **Real cryptography.** The ML-DSA-87 signature is a genuine FIPS 204
  signature (4627 bytes, produced with OpenSSL 3.5). The Merkle proof is a real
  RFC 6962 inclusion proof over the three-record delegation chain, with the odd
  node promoted rather than duplicated.
* **Encoding.** The signature is the raw ML-DSA-87 output, hex-encoded and
  tagged `ml-dsa-87:{length}:{hex}`. It is not DER-encoded ECDSA; the verifier
  rejects any signature that is not in the tagged raw form.
* **Bound identifiers.** The signature payload binds `receipt_id`,
  `recovery.attempt_id`, and `recovery.idempotency_key` (domain
  `nti-vate-receipt-v2:`) alongside the DID, key, delegation root, payload
  digest, and timestamp. Altering or removing any of them fails verification.
* **Tamper check.** Flipping a byte of the signature, altering a delegation
  record, altering a Merkle sibling, substituting the public key, or altering any
  bound identifier (`receipt_id`, `recovery.attempt_id`,
  `recovery.idempotency_key`) each make the verifier fail. For the
  wrong-operation and wrong-attempt cases — which stay validly signed and must be
  caught by binding rather than by the signature — regenerate them with
  `generate_fixture.py --tamper all` (see "Reproducing the Fixture"). See the
  joint vector for the expected VATE outcome per case.

---

Feedback welcome on Issue #64. This fixture was produced by an AI agent
(OpenHands) on behalf of the repository maintainers.
