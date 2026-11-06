#!/usr/bin/env bash
# Independent verification of the NTI witness evidence package.
# Requires: openssl, python3.
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
  echo "   OK: package signature valid"
else
  echo "   FAIL: package signature does not verify"; fail=1
fi
rm -f "$TMP"

echo "== 2. Recompute the S4/S5/S6 seals and the S6 seal signature =="
python3 - "$HERE" "$REPO" <<'PY'
import hashlib, json, pathlib, subprocess, sys, tempfile

here, repo = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
d = json.loads((here / "RESULTS.json").read_text())
bad = 0
L, N = b"nti-s5-leaf-v1:", b"nti-s5-node-v1:"

# S4: recompute each artifact digest from the evidence file.
ev_path = repo / d["seal_scope"]["evidence_file"]
ev_bytes = ev_path.read_bytes()
ev = json.loads(ev_bytes)
by_name = {"evidence_package.json": hashlib.sha256(ev_bytes).hexdigest()}
by_name.update({a["name"]: hashlib.sha256(a["content_utf8"].encode()).hexdigest()
                for a in ev.get("artifacts", [])})
for e in d["S4_file_integrity"]:
    ok = by_name.get(e["name"]) == e["sha256"]
    print(f"   S4 {'OK  ' if ok else 'FAIL'}: {e['name']}")
    bad += 0 if ok else 1

# S5: recompute the Merkle root.
lv = [hashlib.sha256(L + bytes.fromhex(e["sha256"])).digest() for e in d["S4_file_integrity"]]
while len(lv) > 1:
    lv = [hashlib.sha256(N + lv[i] + (lv[i+1] if i+1 < len(lv) else lv[i])).digest()
          for i in range(0, len(lv), 2)]
root = lv[0].hex()
ok = root == d["S5_evidence_root"]["merkle_root_sha256"]
print(f"   S5 {'OK  ' if ok else 'FAIL'}: merkle root {root}")
bad += 0 if ok else 1

# S6: verify the seal signature over the S5 root with the public key.
with tempfile.TemporaryDirectory() as td:
    (pathlib.Path(td) / "r").write_bytes(bytes.fromhex(root))
    (pathlib.Path(td) / "s").write_bytes(bytes.fromhex(d["S6_hmac_seal"]["seal_hex"]))
    p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                        str(here / "PUBLIC_KEY.pem"), "-rawin",
                        "-in", f"{td}/r", "-sigfile", f"{td}/s"], capture_output=True)
ok = p.returncode == 0
print(f"   S6 {'OK  ' if ok else 'FAIL'}: Ed25519 seal over S5 root")
bad += 0 if ok else 1

sys.exit(1 if bad else 0)
PY
[ $? -ne 0 ] && fail=1

echo "== 3. Recompute the SHA-256 of every file listed in MANIFEST.json =="
python3 - "$HERE" "$REPO" <<'PY'
import hashlib, json, pathlib, sys
here, repo = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
m = json.loads((here / "MANIFEST.json").read_text())
entries = list(m.get("nti_test_scripts", [])) + list(m.get("witness_generator", []))
bad = 0
for e in entries:
    p = repo / e["path"]
    if not p.exists():
        print(f"   MISSING: {e['path']}"); bad += 1; continue
    ok = hashlib.sha256(p.read_bytes()).hexdigest() == e["sha256"]
    print(f"   {'OK  ' if ok else 'FAIL'}: {e['path']}")
    bad += 0 if ok else 1
print("   all manifest hashes match" if bad == 0 else f"   {bad} mismatch(es)")
sys.exit(1 if bad else 0)
PY
[ $? -ne 0 ] && fail=1

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: signature + seals + hashes verified."; else echo "RESULT: VERIFICATION FAILED."; fi
exit "$fail"
