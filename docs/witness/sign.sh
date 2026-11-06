#!/usr/bin/env bash
# Re-sign RESULTS.json || MANIFEST.json with the witness private key.
# The private key is NOT in this repository and must be supplied out of band.
# Usage: WITNESS_KEY=/path/to/private.pem ./sign.sh
#
# To regenerate the seals as well, prefer generate_seals.py, which recomputes
# the seals, refreshes the manifest, and signs in one step.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${WITNESS_KEY:?set WITNESS_KEY to the witness private key path}"
cat "$HERE/RESULTS.json" "$HERE/MANIFEST.json" > "$HERE/.to_sign.bin"
openssl pkeyutl -sign -inkey "$WITNESS_KEY" -rawin -in "$HERE/.to_sign.bin" -out "$HERE/SIGNATURE.sig"
rm -f "$HERE/.to_sign.bin"
echo "signed -> $HERE/SIGNATURE.sig"
