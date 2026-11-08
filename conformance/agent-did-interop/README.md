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

Note: These vectors have not been verified against the Agent-DID SDK by the Agent-DID maintainers. Cases 6 and 7 represent expected NTI behavior, and DID authorization remains marked as `not_exercised`.

## Contents

| File | What it is |
| :--- | :--- |
| `APS_DELEGATION_FORMAT.json` | A sample APS authority-delegation record, exactly conformant to the `AuthorityDelegationV1` wire schema. This is the object APS parses and verifies. |
| `test_cases.json` | The seven cases (five from Edison, two from Tymofii), each with an input (a `did:webvh` DID log + a delegation reference) and an expected decision. |
| `README.md` | This file. |

## Install

`agent-passport-system` is published on npm. Install the pinned version:

```bash
npm install agent-passport-system@8.0.1
```

Results from any other version are out of scope for this conformance set. The
package is ESM (`"type": "module"`), so use `import` (a `.mjs` file, or
`"type": "module"` in your `package.json`).

## The APS wire schema (why the fixtures look the way they do)

`parseAuthorityDelegationJson(source)` validates the record against the
**closed** `AuthorityDelegationV1` schema. "Closed" means an exact-key object:
no extra keys, no missing keys. The recognition fields are checked first and
must be strings:

```ts
// agent-passport-system@8.0.1 dist/src/v2/authority-delegation/types.d.ts
const AUTHORITY_DELEGATION_RECORD_TYPE = 'aps:authority-delegation:v1';
const AUTHORITY_DELEGATION_VERSION = '1.0';

interface AuthorityDelegationV1 {
  record_type: typeof AUTHORITY_DELEGATION_RECORD_TYPE; // string
  version: typeof AUTHORITY_DELEGATION_VERSION;         // string
  parent_delegation_id: string | null;
  issuer: string;
  subject: string;
  verification_method: string;
  issued_at: string;
  nonce: string;                                        // 32 lowercase hex
  authority: AuthorityVectorV1;                         // exactly 7 facets
  delegation_id: string;                                // sha256:<64 hex>
  signature: string;                                    // 128 lowercase hex (Ed25519)
}
```

A non-string `record_type` or `version` is reported as **`SCHEMA_INVALID`**:

```text
authority delegation wire invalid: SCHEMA_INVALID
```

Field rules the fixtures obey, all enforced by the pinned package:

| Field | Rule |
| :--- | :--- |
| `record_type` | string, exactly `aps:authority-delegation:v1` |
| `version` | string, exactly `1.0` |
| `delegation_id` | string, `sha256:` + 64 lowercase hex; a content address over the body |
| `parent_delegation_id` | `null`, or `sha256:` + 64 lowercase hex |
| `issuer` / `subject` / `verification_method` | non-empty strings |
| `issued_at` | canonical UTC millisecond timestamp (`2026-11-06T14:00:00.000Z`) |
| `nonce` | 32 lowercase hex characters |
| `signature` | 128 lowercase hex characters (raw 64-byte Ed25519 signature) |
| `authority` | exactly the seven facets: `scope`, `spend`, `depth`, `time`, `reputation`, `values`, `reversibility` |

**APS uses Ed25519, not ML-DSA-87.** The APS authority-delegation signature is a
raw 64-byte Ed25519 signature (128 hex characters). ML-DSA-87 is NTI's receipt
algorithm and appears in the DID logs, not in the APS delegation record.

The records in these fixtures are genuine: they were produced with
`issueAuthorityDelegation`, and they parse and verify under the pinned package
(`verifyAuthorityDelegation` returns `state: "valid"`).

## The APS boundary — read this first

`agent-passport-system 8.0.1` implements the APS chain verification in
`draft-pidlisnyi-aps-04` sections 4.1–4.3. Within that boundary it does three
things:

1. Parses and validates the record against the closed v1 schema.
2. Resolves the **issuer's** key **at `issued_at`** through a **caller-supplied
   resolver** (sections 4.1–4.2).
3. Verifies the `delegation_id` content address and the Ed25519 signature
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

Each case also records `expected.aps_verifier_result`, the exact state and
failure codes the pinned package returns for that case (for example, case 2
returns `valid` because APS never reads the DID log).

Five of the seven cases (2, 3, 4, 6, and the relationship half of 7) target
DID-document checks outside the APS boundary. Only cases 1 and 5 exercise APS
end to end.

## Scope — synthetic fixtures

**Everything here is a synthetic fixture.** The DIDs use the reserved-looking
SCIDs `z6MkExampleAgentSCID...` and `z6MkExampleIssuerSCID...`, and the DID-log
public keys are placeholders (`uz2G...MLDSA87_PUBLIC_KEY...9k`). The APS
signature is real and self-consistent, but it is over a throwaway key generated
for these fixtures; the matching public key is published in
`test_cases.json` under `reference.issuer_public_key_hex` purely so the record
can be verified. These vectors pin the *format* and the *decision* an
implementation must reach. They are not production evidence.

The `did_log` entries in `test_cases.json` are a reduced form of a real
`did:webvh` log: they keep the fields a full verifier must read (`valid_from`,
`valid_until`, `verificationMethod`, the verification relationships, and
`deactivated`) and drop the log's hash-chain and proof fields. The decision
depends only on the retained fields.

## Run

Point your runner at this directory. For each case, take the delegation named by
`input.delegation_ref` from the `delegations` map, parse it with the pinned
package, and verify it. APS needs `now` and a resolver; the resolver returns the
issuer's public key for `(issuer, verification_method, issued_at)`.

```js
import { parseAuthorityDelegationJson, verifyAuthorityDelegation } from 'agent-passport-system';
import fs from 'node:fs';

const vectors = JSON.parse(fs.readFileSync('conformance/agent-did-interop/test_cases.json', 'utf8'));
const issuerKey = vectors.reference.issuer_public_key_hex;

for (const c of vectors.cases) {
  const record = parseAuthorityDelegationJson(
    JSON.stringify(vectors.delegations[c.input.delegation_ref]),
  );
  const result = verifyAuthorityDelegation(record, {
    now: vectors.reference.aps_now,
    resolveVerificationKey: () => issuerKey,   // caller-supplied
    trustRoot: () => true,
    resolveRevocation: () => 'active',
  });
  const expected = c.expected.aps_verifier_result;
  const match = result.state === expected.state &&
    JSON.stringify(result.failures.map((f) => f.code)) === JSON.stringify(expected.failure_codes);
  if (c.aps_exercised) {
    console.log(c.id, match ? 'PASS' : 'FAIL', result.state);
  } else {
    // Outside the APS boundary: the record still parses and verifies, but the
    // case's target check (a DID-document check) is not performed by APS.
    console.log(c.id, 'not_exercised by APS -> spec expects',
      c.expected.decision, c.expected.reason_code);
  }
}
```

Expected output shape:

```text
case-1-valid-key                          PASS          valid
case-2-key-rotated-before-signing         not_exercised by APS -> spec expects reject KEY_NOT_VALID_AT_SIGNING_TIME
case-3-deactivated-did                    not_exercised by APS -> spec expects reject DID_DEACTIVATED
case-4-key-only-under-keyAgreement        not_exercised by APS -> spec expects reject WRONG_VERIFICATION_RELATIONSHIP
case-5-delegation-modified-after-signing  PASS          invalid (ID_MISMATCH)
case-6-key-only-under-capabilityDelegation not_exercised by APS -> spec expects reject WRONG_VERIFICATION_RELATIONSHIP
case-7-key-only-under-assertionMethod     not_exercised by APS -> spec expects accept OK

aps: 2/7 exercised and passing; 5/7 not_exercised (spec-level, DID-document checks)
```

A case is counted as an APS pass only when its target check is inside the APS
boundary and both the `decision` and the `reason_code` match. A `not_exercised`
case is reported as such, never as a pass.

### Standalone fixture

`APS_DELEGATION_FORMAT.json` is the `aps-delegation-valid-v1` record on its own,
so you can parse it directly:

```js
import { parseAuthorityDelegationJson } from 'agent-passport-system';
import fs from 'node:fs';
const record = parseAuthorityDelegationJson(
  fs.readFileSync('conformance/agent-did-interop/APS_DELEGATION_FORMAT.json', 'utf8'),
);
console.log(record.record_type, record.version, record.delegation_id);
// aps:authority-delegation:v1 1.0 sha256:...
```

## The seven cases

| # | Case | Input | Expected decision | Reason code | APS |
| :- | :--- | :--- | :--- | :--- | :--- |
| 1 | Valid key | Key active at `signed_at`, under `assertionMethod`, record verifies | accept | `OK` | exercised |
| 2 | Key rotated out before signing | `#ml-dsa-87-1` retired at 12:00:00Z; receipt signed 14:17:02Z | reject | `KEY_NOT_VALID_AT_SIGNING_TIME` | not_exercised |
| 3 | Deactivated DID | Log deactivated at 13:00:00Z, before `signed_at` | reject | `DID_DEACTIVATED` | not_exercised |
| 4 | Key only under `keyAgreement` | Key active but absent from `assertionMethod` | reject | `WRONG_VERIFICATION_RELATIONSHIP` | not_exercised |
| 5 | Delegation modified after signing | Valid key; grants gained `ledger:admin` post-signature | reject | `DELEGATION_TAMPERED_AFTER_SIGNING` | exercised |
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
* **Case 5** is the integrity test. The `delegation_id` is a content address, so
  editing the scope after signing makes the recomputed id disagree with the
  stored one; APS reports `ID_MISMATCH`.
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
