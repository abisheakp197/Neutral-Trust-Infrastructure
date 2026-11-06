# NTI Witness Evidence Package

This directory is the **fixed, stable location** where external witnesses (such as
HORIZON SHIELD) can independently recompute and verify the cryptographic state of
Neutral Trust Infrastructure.

If you are a witness, treat the files here as inputs you re-derive, not as claims
you accept.

## Contents

| File | What it is |
| :--- | :--- |
| `MANIFEST.json` | SHA-256 hashes of the NTI conformance/test scripts and of the external ASL conformance vectors, plus the exact commit they were taken from. |
| `RESULTS.json` | The recorded outcome of the conformance suites. See the important warning below. |
| `PUBLIC_KEY.pem` | The Ed25519 public key used to sign the two JSON files. The private key is **not** in this repository and is not published. |
| `SIGNATURE.sig` | A 64-byte Ed25519 signature over the raw bytes of `RESULTS.json` followed by the raw bytes of `MANIFEST.json` (concatenated, no separator). |
| `verify.sh` | A self-contained script that checks the signature and recomputes the NTI hashes. |

## How to verify

```bash
cd conformance/witness
./verify.sh /path/to/Neutral-Trust-Infrastructure
```

The script (1) verifies `SIGNATURE.sig` against `PUBLIC_KEY.pem`, and (2)
recomputes the SHA-256 of every NTI file listed in `MANIFEST.json` and compares it.

To check the signature by hand:

```bash
cat RESULTS.json MANIFEST.json > /tmp/nti_to_sign.bin
openssl pkeyutl -verify -pubin -inkey PUBLIC_KEY.pem -rawin \
  -in /tmp/nti_to_sign.bin -sigfile SIGNATURE.sig
```

## Important: what this package does and does not prove

Read this before you rely on `RESULTS.json`.

1. **No NTI conformance test was executed to produce `RESULTS.json`.** The
   environment that generated this package had no Rust toolchain, no network
   access to crates.io, and could not build the native Python bindings. Every
   NTI suite is therefore recorded as `NOT_RUN`, and `overall_status` is
   `NOT_RUN`. The file is signed, but a valid signature only proves the file
   was not altered — it does **not** make the results meaningful. A witness
   must re-run the suites in a provisioned environment.

2. **S4, S5 and S6 are not in this repository.** They are named invariants of
   the separate Agent Safety Layer (ASL) project. Their test scripts live in the
   private ASL source repository (`Raja549h/helper`), which is not publicly
   readable, so no hashes for them could be computed. `MANIFEST.json` records
   this explicitly under `s4_s5_s6_test_scripts`.

3. **The ASL vectors are a third-party artifact.** NTI's CI clones
   `Raja549h/asl-conformance-kit` and runs its verifier. Those vectors test the
   ASL protocol fixtures, not NTI code. Pinning their hashes here detects drift;
   it is not a conformance claim about NTI.

4. **A signature from a freshly generated, unpublished key is not
   independent verification.** It only shows the two JSON files are intact.
   There is no trust anchor binding `PUBLIC_KEY.pem` to NTI. For a real witness
   relationship, the public key must be published out-of-band and its custody
   documented.

## Regenerating

The package is regenerated from a checkout with:

```bash
python3 conformance/witness/build_witness.py   # if present
```

After any change to the hashed files, the manifest, results and signature must
be regenerated together, or verification will (correctly) fail.
