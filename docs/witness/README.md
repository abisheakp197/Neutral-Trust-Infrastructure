# NTI Witness Evidence Package

This directory is the fixed location where external witnesses (such as
HORIZON SHIELD) recompute and verify the cryptographic state of Neutral Trust
Infrastructure. It is published via GitHub Pages from `docs/witness/`.

Treat every file here as an input you re-derive, not as a claim you accept.

## Contents

| File | What it is |
| :--- | :--- |
| `MANIFEST.json` | SHA-256 of the witness generator, the sample evidence fixture, and NTI's native test scripts, plus `key_url` and `key_history`. |
| `RESULTS.json` | NTI's native suite outcomes, plus the S4/S5/S6 seal values. |
| `PUBLIC_KEY.pem` | Ed25519 public key used for both the package signature and the S6 seal. |
| `SIGNATURE.sig` | 64-byte Ed25519 signature over a domain-separated, length-prefixed encoding of `RESULTS.json` and `MANIFEST.json` (each file digested separately). |
| `verify.sh` | Self-contained verifier: package signature, S4/S5/S6 seals, manifest hashes, and key fingerprint. |
| `sign.sh` | Re-signs the package with the private key (supplied out of band; never committed). |

## The S4 / S5 / S6 seals

This is NTI's own native implementation, licensed Apache-2.0 with the rest of
the repository. It shares no code with any external conformance kit. The
generator is `conformance/witness_generator/generate_seals.py`.

| Seal | Field in `RESULTS.json` | Construction |
| :--- | :--- | :--- |
| **S4** file integrity | `S4_file_integrity` | SHA-256 of each evidence artifact, in declared order. |
| **S5** evidence root | `S5_evidence_root` | Merkle Tree Hash over the S4 digests. SHA-256, RFC 6962, with leaf/node domain separation (`nti-s5-leaf-v1:`, `nti-s5-node-v1:`). On an odd level the last node is **promoted unchanged**, never duplicated. |
| **S6** seal | `S6_hmac_seal` | Ed25519 **signature** over the S5 root **and the leaf count and the ordered artifact names**. |

**A note on the name.** The field is called `S6_hmac_seal` to match the witness
specification, but the construction is an asymmetric Ed25519 *signature*, not an
HMAC. An HMAC needs a shared secret, and a witness cannot verify an HMAC without
holding that same secret — which would defeat independent verification. A
signature is verified with the public key alone, so that is what S6 uses. The
`construction` field inside `S6_hmac_seal` states this explicitly.

## Cryptographic hardening

The packaging logic was hardened against four structural weaknesses. Each fix
is enforced by `generate_seals.py`, recomputed independently by `verify.sh`, and
recorded in `MANIFEST.json`.

1. **Package signature — length-prefix and domain separation.** The old
   signature covered `RESULTS.json` concatenated with `MANIFEST.json`, with no
   separator. A newline could be moved from the end of one file to the start of
   the other without changing the concatenated bytes. The signature now covers:

   ```text
   b"nti-witness-package-v2:" || uint32_be(file_count) || for each file:
       uint32_be(len(name_utf8)) || name_utf8 || SHA-256(file_bytes)
   ```

   Each file is digested on its own, so bytes cannot be moved between files.
   `MANIFEST.json` records this under `signature.canonical_form`.

2. **Merkle tree — odd-node promotion, not duplication.** On an odd level the
   last node is promoted unchanged (RFC 6962's Merkle Tree Hash). Duplicating it
   would let two different leaf sets collapse to the same root. The rule is
   recorded under `S5_evidence_root.odd_node_rule`.

3. **S6 — root, leaf count, and artifact names are all bound.** The old seal
   signed only the 32-byte root, leaving the leaf count and the artifact names
   unbound (names are not hashed into the Merkle leaves). S6 now signs the root,
   the leaf count, and the ordered artifact names, so a valid root cannot be
   presented for a different artifact set, and a name cannot be swapped. The
   binding is recorded under `S6_hmac_seal.signed_over`.

4. **Trust anchor — `key_url`.** `MANIFEST.json` carries a `key_url` pointing at
   the GitHub Pages location of `PUBLIC_KEY.pem`, so a witness can fetch the key
   out of band instead of trusting a copy shipped inside the package.

## Key history and rotation

`MANIFEST.json` carries a `key_history` block. Each entry records the Ed25519
key's `fingerprint_sha256` (SHA-256 of the DER SPKI public key), its `status`
(`active` or `retired`), and the validity window. When the signing key changes,
the generator marks the previous key `retired` and adds the new key, so a
rotation is recorded rather than silently replacing the old key. The published
`PUBLIC_KEY.pem` is regenerated from the signing key on every run, and
`signature.public_key_fingerprint_sha256` states which key signed the package.

## How to verify

```bash
cd docs/witness
./verify.sh /path/to/Neutral-Trust-Infrastructure
```

It checks four things:

1. The package signature over the domain-separated, length-prefixed encoding of
   `RESULTS.json` and `MANIFEST.json`.
2. The S4/S5/S6 seals — recomputing the artifact digests, the Merkle root
   (promoting odd nodes), and verifying the S6 seal signature against
   `PUBLIC_KEY.pem`.
3. The SHA-256 of every file listed in `MANIFEST.json`.
4. That the published `PUBLIC_KEY.pem` matches
   `signature.public_key_fingerprint_sha256`.

To check the package signature by hand:

```bash
python3 - docs/witness > /tmp/to_sign.bin <<'PY'
import hashlib, pathlib, struct, sys
here = pathlib.Path(sys.argv[1])
DOMAIN = b"nti-witness-package-v2:"
def u32(n): return struct.pack(">I", n)
files = [(n, (here / n).read_bytes()) for n in ("RESULTS.json", "MANIFEST.json")]
out = bytearray(DOMAIN) + u32(len(files))
for name, raw in files:
    nb = name.encode()
    out += u32(len(nb)) + nb + hashlib.sha256(raw).digest()
sys.stdout.buffer.write(bytes(out))
PY
openssl pkeyutl -verify -pubin -inkey docs/witness/PUBLIC_KEY.pem -rawin \
  -in /tmp/to_sign.bin -sigfile docs/witness/SIGNATURE.sig
```

## Regenerating the seals

```bash
python3 conformance/witness_generator/generate_seals.py \
  --evidence conformance/witness_generator/sample_evidence.json \
  --key /path/to/private.pem \
  --out docs/witness
```

The generator refreshes `RESULTS.json` and `MANIFEST.json`, republishes
`PUBLIC_KEY.pem` from the signing key, updates `key_history`, and writes
`SIGNATURE.sig`.

## Scope — read this

**The seals are computed over a synthetic fixture.**
`conformance/witness_generator/sample_evidence.json` is a dummy agent-action
record created for testing. `RESULTS.json` marks it as `SYNTHETIC`. These seals
prove the *mechanism* works end to end; they are **not** seals over production
evidence. Do not present them as such.

The `suites` block in `RESULTS.json` is separate and real: NTI's native Rust
suite (33 tests) and Python SDK suite (2 tests), run under rustc/cargo 1.90.0
with native bindings built by maturin 1.9.6.

**The trust anchor is `key_url`.** `MANIFEST.json` points at the GitHub Pages
location of `PUBLIC_KEY.pem`, so a witness can fetch the key out of band. The
private key is not published, so a valid signature proves the files are intact
under that key — not who holds it. For a real witness relationship, pin the
`key_url` and record the key's custody.

**Apache-2.0.** The generator and all files here are licensed under the
repository's Apache-2.0 `LICENSE`.
