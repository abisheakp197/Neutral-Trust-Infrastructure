# NTI x Agent-DID Interop Conformance Vectors

This directory holds the test artifacts Edison Duran (Agent-DID) and Tymofii
(APS creator) requested to independently verify NTI's interop claims. The APS
side is pinned to **`agent-passport-system 8.0.1`**, implementing
**`draft-pidlisnyi-aps-04`** sections **4.1–4.3**.

The vectors exercise the verification rules in
[`docs/NTI-Agent-DID-INTEROP.md`](../../docs/NTI-Agent-DID-INTEROP.md) (rev 2):
ML-DSA-87 key binding, signing-time key validity for `did:webvh`, the
`assertionMethod` verification relationship, the separation of DID
authorization from VC issuer checks, and the `did:webvh:{SCID}:{domain}` format.

## Contents

| File | What it is |
| :--- | :--- |
| `APS_DELEGATION_FORMAT.json` | A sample Agent Permission Scope (APS) delegation: the object that is signed and hashed into the receipt. Defines the canonicalization, the ML-DSA-87 signature encoding, and the APS boundary. |
| `test_cases.json` | The seven cases (five from Edison, two from Tymofii), each with an input (a `did:webvh` DID log + delegation) and an expected decision. |
| `README.md` | This file. |

## The APS boundary — read this first

`agent-passport-system 8.0.1` implements the APS chain verification in
`draft-pidlisnyi-aps-04` sections 4.1–4.3. Within that boundary it does two
things:

1. Resolves the **issuer's** key **at `issued_at`** through a **caller-supplied
   resolver** (sections 4.1–4.2).
2. Verifies the delegation signature and the delegation digest / chain linkage
   (section 4.3).

It does **not** inspect the DID document directly. In particular, APS:

* does not fetch or parse the DID document;
* does not resolve a `did:webvh` DID log or read its time windows;
* does not check the verification relationship of a key
  (`assertionMethod` / `keyAgreement` / `capabilityDelegation`);
* does not check DID deactivation.

**APS requires a caller-supplied resolver to check the issuer's key at
`issued_at`.** The resolver is not built into APS. If the caller does not supply
one, the issuer-key check cannot run and MUST be reported as **`not_exercised`**.

### Checks the pinned implementation does not perform are `not_exercised`, never a pass

Every check in a case's `expected.checks` block is one of `pass`, `fail`, or
`not_exercised`. A check outside the APS boundary — anything that requires
reading the DID document — MUST be reported as **`not_exercised`** and MUST NOT
be counted as a pass. A case whose target check is outside the boundary is a
**spec-level vector**: it pins the decision a full NTI verifier must reach, but
it is not exercised by `agent-passport-system 8.0.1`.

Five of the seven cases (2, 3, 4, 6, and the relationship half of 7) target
DID-document checks outside the APS boundary. Only cases 1 and 5 exercise APS
end to end.

## Scope — synthetic fixtures

**Everything here is a synthetic fixture.** The DIDs use the reserved-looking
SCIDs `z6MkExampleAgentSCID...` and `z6MkExampleIssuerSCID...`, the public keys
are placeholders (`uz2G...MLDSA87_PUBLIC_KEY...9k`), and the signatures are
truncated (`ml-dsa-87:4627:5c1b9e...`). These vectors pin the *format* and the
*decision* an implementation must reach. They are not production evidence, and a
signature placeholder is not a real signature.

The `did_log` entries in `test_cases.json` are a reduced form of a real
`did:webvh` log: they keep the fields a full verifier must read (`valid_from`,
`valid_until`, `verificationMethod`, the verification relationships, and
`deactivated`) and drop the log's hash-chain and proof fields. The decision
depends only on the retained fields.

## Prerequisites

* Python 3.10+
* `agent-passport-system` pinned to exactly `8.0.1`
* A caller-supplied key resolver (APS does not provide one; see the boundary
  section above)

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install "agent-passport-system==8.0.1"
```

Pin the exact version. Results from any other build are out of scope for this
conformance set.

## Run

Point the runner at this directory. Supply a resolver that maps
`(issuer_did, issued_at)` to the issuer's verification methods. The runner
applies the APS checks inside the boundary, marks DID-document checks as
`not_exercised`, and compares the result to `expected`.

```bash
python3 run_conformance.py \
  --aps agent-passport-system==8.0.1 \
  --spec draft-pidlisnyi-aps-04 \
  --resolver ./my_resolver.py \
  --vectors conformance/agent-did-interop/test_cases.json
```

Expected output shape:

```text
case-1-valid-key                          accept  OK                              PASS (aps)
case-2-key-rotated-before-signing         reject  KEY_NOT_VALID_AT_SIGNING_TIME   NOT EXERCISED (aps)
case-3-deactivated-did                    reject  DID_DEACTIVATED                 NOT EXERCISED (aps)
case-4-key-only-under-keyAgreement        reject  WRONG_VERIFICATION_RELATIONSHIP NOT EXERCISED (aps)
case-5-delegation-modified-after-signing  reject  DELEGATION_TAMPERED_AFTER_SIGNING PASS (aps)
case-6-key-only-under-capabilityDelegation reject WRONG_VERIFICATION_RELATIONSHIP NOT EXERCISED (aps)
case-7-key-only-under-assertionMethod     accept  OK                              NOT EXERCISED (aps)

aps: 2/7 exercised and passing; 5/7 not_exercised (spec-level, DID-document checks)
```

A case is counted as an APS pass only when its target check is inside the APS
boundary and both the `decision` and the `reason_code` match. A `not_exercised`
case is reported as such, never as a pass.

### Minimal harness

If you would rather wire APS in yourself:

```python
import json, pathlib
from agent_passport_system import ApsChainVerifier   # agent-passport-system 8.0.1

vectors = json.loads(pathlib.Path("conformance/agent-did-interop/test_cases.json").read_text())
verifier = ApsChainVerifier(resolver=my_resolver)    # resolver is CALLER-SUPPLIED

for case in vectors["cases"]:
    inp = case["input"]
    result = verifier.verify_delegation(
        delegation=inp["delegation"],
        issuer_did=vectors["reference"]["issuer_did"],
        issued_at=vectors["reference"]["issued_at"],   # APS checks the issuer key here
        # APS does NOT accept a DID document or a did:webvh log.
    )
    if case["aps_exercised"]:
        assert result.decision == case["expected"]["decision"], case["id"]
        assert result.reason_code == case["expected"]["reason_code"], case["id"]
    else:
        # Outside the APS boundary: record the spec-level expectation, do not
        # count it as an APS pass.
        print(case["id"], "not_exercised by APS -> spec expects",
              case["expected"]["decision"], case["expected"]["reason_code"])
```

Two things to note:

1. APS checks the **issuer** key at `issued_at`, not the **agent** key at
   `signed_at`. The agent-key/signing-time checks in cases 2–4 are outside the
   APS boundary.
2. APS never sees the DID document, so it cannot apply the verification
   relationship rules in cases 4, 6, and 7.

## The seven cases

| # | Case | Input | Expected decision | Reason code | APS |
| :- | :--- | :--- | :--- | :--- | :--- |
| 1 | Valid key | Key active at `signed_at`, under `assertionMethod`, digest matches | accept | `OK` | exercised |
| 2 | Key rotated out before signing | `#ml-dsa-87-1` retired at 12:00:00Z; receipt signed 14:17:02Z | reject | `KEY_NOT_VALID_AT_SIGNING_TIME` | not_exercised |
| 3 | Deactivated DID | Log deactivated at 13:00:00Z, before `signed_at` | reject | `DID_DEACTIVATED` | not_exercised |
| 4 | Key only under `keyAgreement` | Key active but absent from `assertionMethod` | reject | `WRONG_VERIFICATION_RELATIONSHIP` | not_exercised |
| 5 | Delegation modified after signing | Valid key; `scope.actions` gained `ledger.admin` post-signature | reject | `DELEGATION_TAMPERED_AFTER_SIGNING` | exercised |
| 6 | Key only under `capabilityDelegation` | Key active but absent from `assertionMethod` | reject | `WRONG_VERIFICATION_RELATIONSHIP` | not_exercised |
| 7 | Key only under `assertionMethod` | Key active and listed only under `assertionMethod` | accept | `OK` | not_exercised |

Cases 6 and 7 were requested by Tymofii (APS creator). Case 6 completes the
relationship matrix started by case 4; case 7 is its positive counterpart.

### Why these seven

* **Case 1** is the positive control. Without it, a verifier that rejects
  everything would look correct.
* **Case 2** is the backdating test. The *replacement* key `#ml-dsa-87-2` is
  valid at the current time, so a verifier that ignores the log's time windows
  accepts a signature made with a key that had already been rotated out.
* **Case 3** is the terminal-state test. Deactivation precedes and overrides
  key-level checks; even a still-present key must be refused after it.
* **Case 4** is the `keyAgreement` verification-relationship test.
* **Case 5** is the integrity test. DID authorization passes, so this case
  isolates the NTI Layer 1 check: the delegation digest no longer matches the
  signed `delegation_chain_root`.
* **Case 6** is the `capabilityDelegation` verification-relationship test.
  `capabilityDelegation` is an object-capability relationship, not a signing
  relationship; a capability-delegation key must never verify a receipt.
* **Case 7** is the positive relationship test: a key listed only under
  `assertionMethod` is exactly what a receipt-signing key must be.

## Reporting results

Send back a machine-readable result per case (`id`, `decision`, `reason_code`,
per-check status, APS version, and the raw resolver output). Report checks
outside the APS boundary as `not_exercised`. Cases 2–4 and 6–7 are the ones that
distinguish a correct full verifier from a permissive one, but they are not
exercised by `agent-passport-system 8.0.1`; a pass on case 1 alone does not
establish interop conformance.

## License

Apache-2.0, same as the rest of this repository.
