#!/usr/bin/env bash
# Re-sign RESULTS.json and MANIFEST.json with the witness private key.
# The private key is NOT in this repository and must be supplied out of band.
# Usage: WITNESS_KEY=/path/to/private.pem ./sign.sh
#
# The signature is domain-separated and length-prefixed: each file is digested
# on its own, so a byte cannot be moved from one file into another. See
# package_signature_input() in conformance/witness_generator/generate_seals.py.
#
# To regenerate the seals and the key fingerprint as well, prefer
# generate_seals.py, which recomputes the seals, refreshes the manifest, and
# signs in one step.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${WITNESS_KEY:?set WITNESS_KEY to the witness private key path}"

python3 - "$HERE" > "$HERE/.to_sign.bin" <<'PY'
import hashlib, pathlib, struct, sys
here = pathlib.Path(sys.argv[1])
DOMAIN_PACKAGE = b"nti-witness-package-v2:"
def u32(n): return struct.pack(">I", n)
files = [("RESULTS.json", (here / "RESULTS.json").read_bytes()),
         ("MANIFEST.json", (here / "MANIFEST.json").read_bytes())]
out = bytearray(DOMAIN_PACKAGE) + u32(len(files))
for name, raw in files:
    nb = name.encode("utf-8")
    out += u32(len(nb)) + nb + hashlib.sha256(raw).digest()
sys.stdout.buffer.write(bytes(out))
PY

openssl pkeyutl -sign -inkey "$WITNESS_KEY" -rawin -in "$HERE/.to_sign.bin" -out "$HERE/SIGNATURE.sig"
rm -f "$HERE/.to_sign.bin"
echo "signed -> $HERE/SIGNATURE.sig"
