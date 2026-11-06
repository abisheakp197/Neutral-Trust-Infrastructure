#!/usr/bin/env bash
# Re-sign RESULTS.json || MANIFEST.json with the witness private key.
# The private key is NOT in this repository and must be supplied out of band.
# Usage: WITNESS_KEY=/path/to/private.pem ./sign.sh
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
: "${WITNESS_KEY:?set WITNESS_KEY to the witness private key path}"
TMP="$(mktemp)"
cat "$HERE/RESULTS.json" "$HERE/MANIFEST.json" > "$TMP"
openssl pkeyutl -sign -inkey "$WITNESS_KEY" -rawin -in "$TMP" -out "$HERE/SIGNATURE.sig"
rm -f "$TMP"
echo "signed -> $HERE/SIGNATURE.sig"
