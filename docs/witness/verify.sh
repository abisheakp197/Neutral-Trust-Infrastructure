#!/usr/bin/env bash
# Independent verification of the NTI witness evidence package.
# Requires: openssl, python3.
# Optional: cargo + python native bindings, to re-run and re-check the suite
#           transcript digests (step 5 is reported as SKIP without them).
# Usage: ./verify.sh [path-to-NTI-checkout]   (default: ../..)
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${1:-$(cd "$HERE/../.." && pwd)}"
fail=0

echo "== 1. Verify the Ed25519 package signature (domain-separated, length-prefixed) =="
python3 - "$HERE" <<'PY'
import hashlib, pathlib, struct, subprocess, sys, tempfile
here = pathlib.Path(sys.argv[1])
DOMAIN_PACKAGE = b"nti-witness-package-v2:"

def u32(n): return struct.pack(">I", n)
def sha256(b): return hashlib.sha256(b).digest()

files = [("RESULTS.json", (here / "RESULTS.json").read_bytes()),
         ("MANIFEST.json", (here / "MANIFEST.json").read_bytes())]
msg = bytearray(DOMAIN_PACKAGE)
msg += u32(len(files))
for name, raw in files:
    nb = name.encode("utf-8")
    msg += u32(len(nb)) + nb + sha256(raw)

with tempfile.TemporaryDirectory() as td:
    (pathlib.Path(td) / "m").write_bytes(bytes(msg))
    p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                        str(here / "PUBLIC_KEY.pem"), "-rawin",
                        "-in", f"{td}/m", "-sigfile", str(here / "SIGNATURE.sig")],
                       capture_output=True)
if p.returncode == 0:
    print("   OK: package signature valid")
    sys.exit(0)
print("   FAIL: package signature does not verify")
sys.exit(1)
PY
[ $? -ne 0 ] && fail=1

echo "== 2. Recompute the S4/S5/S6 seals and the S6 seal signature =="
python3 - "$HERE" "$REPO" <<'PY'
import hashlib, json, pathlib, struct, subprocess, sys, tempfile

here, repo = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
d = json.loads((here / "RESULTS.json").read_text())
bad = 0
L, N = b"nti-s5-leaf-v1:", b"nti-s5-node-v1:"
DOMAIN_S6 = b"nti-s6-seal-v2:"

def u32(n): return struct.pack(">I", n)

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

# S5: recompute the Merkle root (RFC 6962: promote the odd node, never duplicate).
lv = [hashlib.sha256(L + bytes.fromhex(e["sha256"])).digest() for e in d["S4_file_integrity"]]
while len(lv) > 1:
    nxt = [hashlib.sha256(N + lv[i] + lv[i + 1]).digest() for i in range(0, len(lv) - 1, 2)]
    if len(lv) % 2 == 1:
        nxt.append(lv[-1])
    lv = nxt
root = lv[0].hex()
ok = root == d["S5_evidence_root"]["merkle_root_sha256"]
print(f"   S5 {'OK  ' if ok else 'FAIL'}: merkle root {root}")
bad += 0 if ok else 1

# S6: verify the seal signature over root || leaf_count || artifact names.
names = [e["name"] for e in d["S4_file_integrity"]]
leaf_count = d["S5_evidence_root"]["leaf_count"]
if leaf_count != len(d["S4_file_integrity"]):
    print(f"   S6 FAIL: leaf_count {leaf_count} != {len(d['S4_file_integrity'])} S4 entries"); bad += 1
names_bytes = json.dumps(names, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
msg = DOMAIN_S6 + bytes.fromhex(root) + u32(leaf_count) + u32(len(names_bytes)) + names_bytes
with tempfile.TemporaryDirectory() as td:
    (pathlib.Path(td) / "m").write_bytes(msg)
    (pathlib.Path(td) / "s").write_bytes(bytes.fromhex(d["S6_hmac_seal"]["seal_hex"]))
    p = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey",
                        str(here / "PUBLIC_KEY.pem"), "-rawin",
                        "-in", f"{td}/m", "-sigfile", f"{td}/s"], capture_output=True)
ok = p.returncode == 0
print(f"   S6 {'OK  ' if ok else 'FAIL'}: Ed25519 seal over root + leaf_count + artifact names")
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

echo "== 4. Published public key matches the signature fingerprint in MANIFEST.json =="
python3 - "$HERE" <<'PY'
import hashlib, json, pathlib, subprocess, sys
here = pathlib.Path(sys.argv[1])
m = json.loads((here / "MANIFEST.json").read_text())
want = m.get("signature", {}).get("public_key_fingerprint_sha256")
if not want:
    print("   FAIL: MANIFEST.json has no signature.public_key_fingerprint_sha256"); sys.exit(1)
der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(here / "PUBLIC_KEY.pem"),
                      "-outform", "DER"], capture_output=True).stdout
got = hashlib.sha256(der).hexdigest()
ok = got == want
print(f"   {'OK  ' if ok else 'FAIL'}: key fingerprint {got}")
sys.exit(0 if ok else 1)
PY
[ $? -ne 0 ] && fail=1

echo "== 5. Re-run the suites and compare transcript digests =="
python3 - "$HERE" "$REPO" <<'PY'
import hashlib, json, pathlib, re, shutil, subprocess, sys

here, repo = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
m = json.loads((here / "MANIFEST.json").read_text())
bound = m.get("suite_evidence_logs", {})
if not bound:
    print("   SKIP: MANIFEST.json has no suite_evidence_logs")
    sys.exit(0)

def cargo_bin():
    return shutil.which("cargo") or str(pathlib.Path.home() / ".cargo" / "bin" / "cargo")

def run(argv):
    p = subprocess.run(argv, cwd=str(repo), capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr

def strip_timing(line):
    return re.sub(r"(finished in|Ran \d+ tests in) [0-9.]+s", r"\1 <t>", line).strip()

def canonical(kind, transcript):
    lines = [l.strip() for l in transcript.splitlines()]
    if kind in ("cargo_test", "python_unittest"):
        kept = []
        for s in lines:
            if re.match(r"^test[ _].+\.\.\. (ok|FAILED|ERROR|ignored)$", s):
                kept.append(s)
            elif (s.startswith("test result:") or s.startswith("Ran ")
                  or s == "OK" or s.startswith("FAILED (")):
                kept.append(strip_timing(s))
        return "\n".join(sorted(kept)) + "\n"
    errors = sum(1 for s in lines if s.startswith("error"))
    finished = any(s.startswith("Finished") for s in lines)
    return f"finished={finished}\nerror_lines={errors}\n"

manifest_rel = "ube-foundation/Cargo.toml"
py_dir = "ube-foundation/python_tests"
cmds = {
    "cargo_test": (["cargo", "test", "--locked", "--manifest-path", manifest_rel,
                    "--lib", "--tests", "--", "--nocapture"], "cargo_test", True),
    "cargo_build": (["cargo", "build", "--locked", "--manifest-path", manifest_rel], "cargo_build", True),
    "cargo_check_python": (["cargo", "check", "--locked", "--manifest-path", manifest_rel,
                            "--features", "python"], "cargo_check", True),
    "python_unittest": (["python3", "-m", "unittest", "discover", "-s", py_dir, "-v"],
                        "python_unittest", False),
}

have_cargo = shutil.which("cargo") is not None or pathlib.Path(cargo_bin()).exists()
bad = skipped = 0
for name, entry in bound.items():
    argv, kind, needs_cargo = cmds[name]
    if needs_cargo and not have_cargo:
        print(f"   SKIP: {name} (cargo not on PATH)")
        skipped += 1
        continue
    if argv[0] == "cargo":
        argv = [cargo_bin()] + argv[1:]
    code, transcript = run(argv)
    got = hashlib.sha256(canonical(kind, transcript).encode("utf-8")).hexdigest()
    want = entry["output_sha256"]
    ok = got == want and code == 0
    print(f"   {'OK  ' if ok else 'FAIL'}: {name} transcript digest {got[:16]} "
          f"(bound {want[:16]}, exit {code})")
    bad += 0 if ok else 1

if bad:
    print(f"   {bad} suite transcript mismatch(es)")
elif skipped:
    print(f"   {skipped} suite(s) skipped (no cargo); no mismatches in the rest")
else:
    print("   all suite transcript digests match")
sys.exit(1 if bad else 0)
PY
[ $? -ne 0 ] && fail=1

echo
if [ "$fail" -eq 0 ]; then echo "RESULT: signature + seals + hashes + key fingerprint + suite digests verified."; else echo "RESULT: VERIFICATION FAILED."; fi
exit "$fail"
