# NTI x Agent-DID Interop Conformance Vectors

This directory holds the test artifacts Edison Duran (Agent-DID) requested to
independently verify NTI's interop claims. They are pinned to
**`agent-did-sdk 1.0.0-rc.4`**.

The vectors exercise the verification rules in
[`docs/NTI-Agent-DID-INTEROP.md`](../../docs/NTI-Agent-DID-INTEROP.md) (rev 2):
ML-DSA-87 key binding, signing-time key validity for `did:webvh`, the
`assertionMethod` verification relationship, the separation of DID
authorization from VC issuer checks, and the `did:webvh:{SCID}:{domain}` format.

## Contents

| File | What it is |
| :--- | :--- |
| `APS_DELEGATION_FORMAT.json` | A sample Agent Permission Scope (APS) delegation: the object that is signed and hashed into the receipt. Defines the canonicalization and ML-DSA-87 signature encoding. |
| `test_cases.json` | The five cases Edison requested, each with an input (a `did:webvh` DID log + delegation) and an expected decision. |
| `README.md` | This file. |

## Scope — read this

**Everything here is a synthetic fixture.** The DIDs use the reserved-looking
SCIDs `z6MkExampleAgentSCID...` and `z6MkExampleIssuerSCID...`, the public keys
are placeholders (`uz2G...MLDSA87_PUBLIC_KEY...9k`), and the signatures are
truncated (`ml-dsa-87:4627:5c1b9e...`). These vectors pin the *format* and the
*decision* an SDK must reach. They are not production evidence, and a signature
placeholder is not a real signature.

The `did_log` entries in `test_cases.json` are a reduced form of a real
`did:webvh` log: they keep the fields the verifier must read (`valid_from`,
`valid_until`, `verificationMethod`, the verification relationships, and
`deactivated`) and drop the log's hash-chain and proof fields. The decision
depends only on the retained fields.

## Prerequisites

* Python 3.10+
* `agent-did-sdk` pinned to exactly `1.0.0-rc.4`

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install "agent-did-sdk==1.0.0-rc.4"
```

Pin the exact version. A pre-release (`rc`) will not be selected by a bare
`pip install agent-did-sdk`, and results from any other build are out of scope
for this conformance set.

## Run

Point the runner at this directory. The runner resolves each case's DID as of
the case's `signed_at`, resolves the ML-DSA-87 verification method, applies the
verification relationships, and compares its decision to `expected.decision`.

```bash
python3 run_conformance.py \
  --sdk agent-did-sdk==1.0.0-rc.4 \
  --vectors conformance/agent-did-interop/test_cases.json
```

Expected output shape:

```text
case-1-valid-key                        accept  OK                                   PASS
case-2-key-rotated-before-signing       reject  KEY_NOT_VALID_AT_SIGNING_TIME      PASS
case-3-deactivated-did                  reject  DID_DEACTIVATED                      PASS
case-4-key-only-under-keyAgreement      reject  WRONG_VERIFICATION_RELATIONSHIP     PASS
case-5-delegation-modified-after-signing reject DELEGATION_TAMPERED_AFTER_SIGNING  PASS

5/5 passed
```

A case passes only when both the `decision` and the `reason_code` match the
`expected` block.

### Minimal harness

If you would rather wire the SDK in yourself, each case needs three calls:

```python
import json, pathlib
from agent_did_sdk import DidResolver, verify_delegation   # agent-did-sdk 1.0.0-rc.4

vectors = json.loads(pathlib.Path("conformance/agent-did-interop/test_cases.json").read_text())
resolver = DidResolver()

for case in vectors["cases"]:
    inp = case["input"]
    doc = resolver.resolve_at(
        inp["delegation"].get("subject", vectors["reference"]["agent_did"]),
        at=inp["signed_at"],            # <-- must resolve the log AS OF signing time
        log=inp["did_log"],
    )
    vm = resolver.resolve_verification_method(doc, vectors["reference"]["verification_method"])
    result = verify_delegation(
        did_document=doc,
        verification_method=vm,
        delegation=inp["delegation"],
        relationship="assertionMethod",  # keys under keyAgreement must be rejected
    )
    assert result.decision == case["expected"]["decision"], case["id"]
    assert result.reason_code == case["expected"]["reason_code"], case["id"]
```

The two calls that matter most for this conformance set are:

1. `resolve_at(..., at=signed_at)` — a plain "resolve now" call will pass case 2
   and case 3 incorrectly. The DID MUST be resolved at the signing instant.
2. `verify_delegation(..., relationship="assertionMethod")` — a verifier that
   accepts any listed key will pass case 4 incorrectly.

## The five cases

| # | Case | Input | Expected decision | Reason code |
| :- | :--- | :--- | :--- | :--- |
| 1 | Valid key | Key active at `signed_at`, under `assertionMethod`, digest matches | accept | `OK` |
| 2 | Key rotated out before signing | `#ml-dsa-87-1` retired at 12:00:00Z; receipt signed 14:17:02Z | reject | `KEY_NOT_VALID_AT_SIGNING_TIME` |
| 3 | Deactivated DID | Log deactivated at 13:00:00Z, before `signed_at` | reject | `DID_DEACTIVATED` |
| 4 | Key only under `keyAgreement` | Key active but absent from `assertionMethod` | reject | `WRONG_VERIFICATION_RELATIONSHIP` |
| 5 | Delegation modified after signing | Valid key; `scope.actions` gained `ledger.admin` post-signature | reject | `DELEGATION_TAMPERED_AFTER_SIGNING` |

### Why these five

* **Case 1** is the positive control. Without it, a verifier that rejects
  everything would score 4/5.
* **Case 2** is the backdating test. The *replacement* key `#ml-dsa-87-2` is
  valid at the current time, so a verifier that ignores the log's time windows
  accepts a signature made with a key that had already been rotated out.
* **Case 3** is the terminal-state test. Deactivation precedes and overrides
  key-level checks; even a still-present key must be refused after it.
* **Case 4** is the verification-relationship test. `keyAgreement` and
  `assertionMethod` are different capabilities; a key-agreement key must never
  verify a receipt signature.
* **Case 5** is the integrity test. DID authorization passes, so this case
  isolates the NTI Layer 1 check: the delegation digest no longer matches the
  signed `delegation_chain_root`.

## Reporting results

Send back a machine-readable result per case (`id`, `decision`, `reason_code`,
SDK version, and the raw resolver output). Cases 2–5 are the ones that
distinguish a correct verifier from a permissive one; a pass on case 1 alone
does not establish interop conformance.

## License

Apache-2.0, same as the rest of this repository.
