# NTI Witness Evidence Package

This directory is the fixed location where external witnesses (such as
HORIZON SHIELD) recompute and verify the cryptographic state of Neutral Trust
Infrastructure. It is published via GitHub Pages from `docs/witness/`.

Treat every file here as an input you re-derive, not as a claim you accept.

## Contents

| File | What it is |
| :--- | :--- |
| `MANIFEST.json` | SHA-256 of the witness generator, the sample evidence fixture, and NTI's native test scripts. |
| `RESULTS.json` | NTI's native suite outcomes, plus the S4/S5/S6 seal values. |
| `PUBLIC_KEY.pem` | Ed25519 public key used for both the package signature and the S6 seal. |
| `SIGNATURE.sig` | 64-byte Ed25519 signature over `RESULTS.json` followed by `MANIFEST.json` (raw bytes, concatenated, no separator). |
| `verify.sh` | Self-contained verifier: package signature, S4/S5/S6 seals, and all manifest hashes. |
| `sign.sh` | Re-signs the package with the private key (supplied out of band; never committed). |

## The S4 / S5 / S6 seals

This is NTI's own native implementation, licensed Apache-2.0 with the rest of
the repository. It shares no code with any external conformance kit. The
generator is `conformance/witness_generator/generate_seals.py`.

| Seal | Field in `RESULTS.json` | Construction |
| :--- | :--- | :--- |
| **S4** file integrity | `S4_file_integrity` | SHA-256 of each evidence artifact, in declared order. |
| **S5** evidence root | `S5_evidence_root` | Merkle root over the S4 digests. SHA-256, RFC-6962-style, with leaf/node domain separation (`nti-s5-leaf-v1:`, `nti-s5-node-v1:`). Odd nodes are promoted unchanged. |
| **S6** seal | `S6_hmac_seal` | Ed25519 **signature** over the S5 root. |

**A note on the name.** The field is called `S6_hmac_seal` to match the witness
specification, but the construction is an asymmetric Ed25519 *signature*, not an
HMAC. An HMAC needs a shared secret, and a witness cannot verify an HMAC without
holding that same secret — which would defeat independent verification. A
signature is verified with the public key alone, so that is what S6 uses. The
`construction` field inside `S6_hmac_seal` states this explicitly.

## How to verify

```bash
cd docs/witness
./verify.sh /path/to/Neutral-Trust-Infrastructure
```

It checks three things:

1. The package signature over `RESULTS.json || MANIFEST.json`.
2. The S4/S5/S6 seals — recomputing the artifact digests, the Merkle root, and
   verifying the S6 seal signature against `PUBLIC_KEY.pem`.
3. The SHA-256 of every file listed in `MANIFEST.json`.

To check the package signature by hand:

```bash
cat RESULTS.json MANIFEST.json > /tmp/to_sign.bin
openssl pkeyutl -verify -pubin -inkey PUBLIC_KEY.pem -rawin \
  -in /tmp/to_sign.bin -sigfile SIGNATURE.sig
```

## Regenerating the seals

```bash
python3 conformance/witness_generator/generate_seals.py \
  --evidence conformance/witness_generator/sample_evidence.json \
  --key /path/to/private.pem \
  --out docs/witness
```

## Scope — read this

**The seals are computed over a synthetic fixture.**
`conformance/witness_generator/sample_evidence.json` is a dummy agent-action
record created for testing. `RESULTS.json` marks it as `SYNTHETIC`. These seals
prove the *mechanism* works end to end; they are **not** seals over production
evidence. Do not present them as such.

The `suites` block in `RESULTS.json` is separate and real: NTI's native Rust
suite (33 tests) and Python SDK suite (2 tests), run under rustc/cargo 1.90.0
with native bindings built by maturin 1.9.6.

**The public key has no external trust anchor.** The private key is not
published, so a valid signature proves the files are intact — not who produced
them. For a real witness relationship, publish this key out-of-band and document
its custody.

**Apache-2.0.** The generator and all files here are licensed under the
repository's Apache-2.0 `LICENSE`.
