#!/usr/bin/env bash
# Independent verification of the NTI witness evidence package.
# Requires: openssl, sha256sum, git.
# Usage: ./verify.sh [path-to-NTI-checkout]   (default: ../../)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${1:-$(cd "$HERE/../.." && pwd)}"
fail=0

echo "== 1. Verify the Ed25519 signature over RESULTS.json || MANIFEST.json =="
TMP="$(mktemp)"
cat "$HERE/RESULTS.json" "$HERE/MANIFEST.json" > "$TMP"
if openssl pkeyutl -verify -pubin -inkey "$HERE/PUBLIC_KEY.pem" -rawin \
     -in "$TMP" -sigfile "$HERE/SIGNATURE.sig" >/dev/null 2>&1; then
  echo "   OK: signature valid"
else
  echo "   FAIL: signature does not verify"; fail=1
fi
rm -f "$TMP"

echo "== 2. Recompute hashes of the NTI test scripts in the manifest =="
python3 - "$HERE/MANIFEST.json" "$REPO" <<'PY'
import hashlib, json, pathlib, sys
manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
repo = pathlib.Path(sys.argv[2])
bad = 0
for entry in manifest.get("nti_test_scripts", []):
    p = repo / entry["path"]
    if not p.exists():
        print(f"   MISSING: {entry['path']}"); bad += 1; continue
    ok = hashlib.sha256(p.read_bytes()).hexdigest() == entry["sha256"]
    print(f"   {'OK  ' if ok else 'FAIL'}: {entry['path']}")
    bad += 0 if ok else 1
print("   all NTI hashes match" if bad == 0 else f"   {bad} mismatch(es)")
sys.exit(1 if bad else 0)
PY
[ $? -ne 0 ] && fail=1

echo "== 3. Recompute hashes of the external ASL conformance vectors =="
echo "   These live in Raja549h/asl-conformance-kit, not in this repository."
echo "     git clone https://github.com/Raja549h/asl-conformance-kit && cd asl-conformance-kit"
echo "     git checkout $(python3 -c "import json;print(json.load(open('$HERE/MANIFEST.json'))['external_conformance_vectors']['source_commit'])")"
echo "     sha256sum conformance/vectors/*.json conformance/verify_vectors.py"
echo "     python conformance/verify_vectors.py   # expect: checked 45 vector cases, 0 failures"

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: signature + NTI hashes verified."; else echo "RESULT: VERIFICATION FAILED."; fi
exit "$fail"
