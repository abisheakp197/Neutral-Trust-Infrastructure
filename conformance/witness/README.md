# NTI Witness Evidence Package

This directory is the **fixed location** where external witnesses (such as
HORIZON SHIELD) recompute and verify the cryptographic state of Neutral Trust
Infrastructure. A published copy is served from `docs/witness/` via GitHub Pages.

Treat every file here as an input you re-derive, not as a claim you accept.

## Contents

| File | What it is |
| :--- | :--- |
| `MANIFEST.json` | SHA-256 hashes of the NTI conformance/test scripts and of the external ASL conformance vectors, pinned to exact commits. |
| `RESULTS.json` | Recorded outcomes of the conformance suites. Read the scope note below. |
| `PUBLIC_KEY.pem` | The Ed25519 public key used to sign the two JSON files. |
| `SIGNATURE.sig` | 64-byte Ed25519 signature over `RESULTS.json` followed by `MANIFEST.json` (raw bytes, concatenated, no separator). |
| `verify.sh` | Self-contained verifier: checks the signature and recomputes the NTI hashes. |
| `sign.sh` | Re-signs with the private key (supplied out of band; never committed). |
| `build_witness.py` | Regenerates the manifest and results from a real run. |
| `vendor/` | Provenance record for the S4/S5/S6 scripts (see below). |

## How to verify

```bash
cd conformance/witness
./verify.sh /path/to/Neutral-Trust-Infrastructure
```

It (1) verifies `SIGNATURE.sig` against `PUBLIC_KEY.pem`, and (2) recomputes the
SHA-256 of every NTI file listed in `MANIFEST.json`.

To check the signature by hand:

```bash
cat RESULTS.json MANIFEST.json > /tmp/nti_to_sign.bin
openssl pkeyutl -verify -pubin -inkey PUBLIC_KEY.pem -rawin \
  -in /tmp/nti_to_sign.bin -sigfile SIGNATURE.sig
```

## Scope of `RESULTS.json` — read this

The NTI suites were run in a provisioned environment and passed:

| Suite | Result |
| :--- | :--- |
| NTI Rust tests (`cargo test --locked --lib --tests`) | 33 passed, 0 failed |
| NTI Python SDK tests (native bindings, maturin 1.9.6) | 2 passed, 0 failed |
| `cargo build --locked` | ok |
| `cargo check --features python` | ok |
| ASL conformance vectors (external kit) | 45 cases, 0 failures |

Three limits apply:

1. **S4, S5 and S6 were NOT run.** They are invariants of the separate Agent
   Safety Layer (ASL) project, and their test scripts live only in the private,
   non-Apache-2.0 repository `Raja549h/helper`, which returns HTTP 404. They
   could not be vendored, so `RESULTS.json` records them as `NOT_RUN`. See
   `vendor/S4_S5_S6_PROVENANCE.md`. **No result here covers S4/S5/S6.**

2. **The ASL vector run tests ASL fixtures, not NTI code.** NTI's CI clones the
   external kit and runs its verifier. Pinning the kit's hashes detects drift;
   it is not a conformance claim about NTI.

3. **The public key has no external trust anchor.** The private key is not
   published, so a valid signature proves the two JSON files are intact — not
   who produced them. For a real witness relationship, publish this key
   out-of-band and document its custody.

## Regenerating

```bash
python3 conformance/witness/build_witness.py     # rewrite manifest + results
WITNESS_KEY=/path/to/private.pem conformance/witness/sign.sh   # re-sign
```

After any change to a hashed file, regenerate the manifest, results and
signature together, or verification will (correctly) fail.
