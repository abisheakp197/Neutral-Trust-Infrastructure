# Candidate core fix for issue #20

Apply `issuer-and-quorum.patch` to Neutral-Trust-Infrastructure commit
`308fd1c95f2c2f975e8b6b6c5e7ccba0e4d7b203` with `git apply --check` then `git apply`.
The two original regression assertions are preserved unchanged in the patch.

Capability tokens now require a trusted local issuer key, a valid strict Ed25519
signature, and a local grant authorizing that issuer for the token capability.
Configure `register_issuer_key(issuer, public_key_bytes)` and `grant(issuer, capability)`
through the administrative API. A request's own public key cannot establish issuer
trust. Existing persisted states default to no trusted issuers until configured.
Unsigned tokens are intentionally no longer accepted. Local explicit grants remain
available. The Python wrapper exposes the same issuer-key registration method.

## 0.1.9: PQC identity-key binding

A valid ML-DSA-87 signature proves possession of a key, not authorization to act
as a particular actor. Before 0.1.9 the engine accepted any request whose PQC
signature verified against the key the request itself carried, so any caller
could generate a key pair, self-sign, and be allowed.

`TrustEngine::register_pqc_identity_key(actor, public_key_bytes)` pins the key
that identifies an actor. A PQC-signed request is now allowed only when the
presented `pqc_public_key` is byte-identical to the pinned key. An unbound actor,
a mismatched key, or a bare key with no signature is denied. Registration
rejects malformed keys so a bad pin fails at configuration time rather than at
enforcement time. Pinned keys are part of the persisted state.

Operators must call `register_pqc_identity_key` for every actor that signs with
PQC. Actors that authorize only through Ed25519 signatures or issuer-signed
capability tokens are unaffected.

## 0.1.9: RFC 6962 Merkle audit root

The audit batch root is now an RFC 6962 Merkle Tree Hash over the ordered event
hashes, with leaf and node domain separation (`nti-s5-leaf-v1:`,
`nti-s5-node-v1:`, matching `conformance/witness/README.md`). On an odd level
the last node is promoted unchanged rather than duplicated. Duplication made the
tree for `n` leaves collide with the tree for `n + 1` leaves, so a proof for one
batch could verify against another.

`TrustEngine::audit_inclusion_proof(batch_index, sequence)` returns an RFC 6962
inclusion proof for a single recorded decision, and
`merkle::verify_inclusion` folds it to the batch root in constant time. A test
reproduces the pinned S5 root from `conformance/witness/RESULTS.json` to keep the
Rust root and the Python witness generator from drifting apart.

## 0.1.9: policy timing

Time-based caveats are evaluated against an explicit `now` rather than a clock
read taken partway down the verification path, so a decision reflects the moment
the request was evaluated. `evaluate_at(request, now)` and
`CaveatInterpreter::verify_all_at(..., now)` take that instant as a parameter;
`evaluate` and `record` read the clock once at the top and pass it down.

Caveats now fail closed. A `ValueLimit` with a missing or non-integer `amount`, a
`PathRestricted` with a missing `path`, and a `MaxExecutions` without a capability
token are violations. Previously a missing field defaulted to `0` or `""`, which
silently satisfied the caveat.

Quorum shortfalls now return an error before module dispatch. Module errors and
result disagreement return errors without falling back to another execution.
This fixes local module threshold enforcement; it does not establish Byzantine
validator independence or implement consensus-before-effect. Selected modules still
execute before their results can be compared. No runtime halt or rollback claim
is made by this patch.

CI keeps the pinned failing baseline and separately applies and tests this patch,
including existing core tests, positive controls, issuer authentication, tampering,
persistence, eligible-module counts, and error/disagreement paths. Build evidence
is retained by GitHub Actions. The patch is a candidate until CI has completed.
