# NTI Witness Evidence Package

This directory is the fixed location where external witnesses (such as
HORIZON SHIELD) recompute and verify the cryptographic state of Neutral Trust
Infrastructure. A published copy is served from `docs/witness/` via GitHub Pages.

Treat every file here as an input you re-derive, not as a claim you accept.

## Contents

| File | What it is |
| :--- | :--- |
| `MANIFEST.json` | SHA-256 hashes of NTI's native test scripts and build manifests, pinned to an exact commit. |
| `RESULTS.json` | Recorded outcomes of NTI's native Rust and Python suites. |
| `PUBLIC_KEY.pem` | The Ed25519 public key used to sign the two JSON files. |
| `SIGNATURE.sig` | 64-byte Ed25519 signature over `RESULTS.json` followed by `MANIFEST.json` (raw bytes, concatenated, no separator). |
| `verify.sh` | Self-contained verifier: checks the signature and recomputes the hashes. |
| `sign.sh` | Re-signs with the private key (supplied out of band; never committed). |
| `build_witness.py` | Regenerates the manifest and results from a real run. |

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

## Scope

This package covers NTI's own test suites only.

| Suite | Result |
| :--- | :--- |
| NTI Rust tests (`cargo test --locked --lib --tests`, rustc 1.90.0) | 33 passed, 0 failed |
| NTI Python SDK tests (native bindings, maturin 1.9.6) | 2 passed, 0 failed |
| `cargo build --locked` | ok |
| `cargo check --features python` | ok |

Two limits apply:

1. **No third-party or external conformance suite is included or referenced.**
   Every artifact hashed in `MANIFEST.json` is part of this repository.

2. **The public key has no external trust anchor.** The private key is not
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
