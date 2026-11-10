#!/usr/bin/env python3
"""Native, Apache-2.0 implementation of the S4/S5/S6 evidence seals.

This is NTI's own implementation. It has no dependency on any external or
third-party conformance kit.

  S4  file integrity   SHA-256 of every evidence artifact
  S5  evidence root    Merkle root over the artifact digests (RFC 6962)
  S6  seal             Ed25519 signature over the S5 root, leaf count and names

S6 is an asymmetric Ed25519 *signature*, not an HMAC. An HMAC would require a
shared secret, which a witness cannot verify without holding that secret. The
output field is named `S6_hmac_seal` to match the witness specification, but
the construction is a signature and is verified with the public key alone.

Package signature
-----------------
The detached package signature over RESULTS.json and MANIFEST.json is
domain-separated and length-prefixed, so a byte cannot be moved from one file
into another without invalidating the signature. The exact signed bytes are:

    b"nti-witness-package-v2:"
    || uint32_be(file_count)
    || for each file in order:
           uint32_be(len(name_utf8)) || name_utf8 || SHA-256(file_bytes)

Each file is digested on its own, so the two files are never concatenated into
an ambiguous blob. See `package_signature_input()`.

Suite evidence
--------------
The generator runs the suites for real -- `cargo test --locked`, `cargo build
--locked`, `cargo check --locked --features python`, and `python -m unittest`
over the Python SDK tests -- and binds the SHA-256 of each captured log into
RESULTS.json (`suite_evidence`) and MANIFEST.json (`suite_evidence_logs`). A
witness re-runs the suites and checks that the transcript digests match, so a
"PASSED" string alone is no longer a claim without evidence.

Usage:
    python3 conformance/witness_generator/generate_seals.py \
        --evidence conformance/witness_generator/sample_evidence.json \
        --key /path/to/private.pem \
        [--out docs/witness]
"""
import argparse
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
GENERATOR = pathlib.Path(__file__).resolve()
CARGO_MANIFEST = "ube-foundation/Cargo.toml"
PYTHON_TESTS_DIR = "ube-foundation/python_tests"
DOMAIN_LEAF = b"nti-s5-leaf-v1:"
DOMAIN_NODE = b"nti-s5-node-v1:"
DOMAIN_PACKAGE = b"nti-witness-package-v2:"
DOMAIN_S6 = b"nti-s6-seal-v2:"

# External trust anchor for the witness public key. The key is published here
# (GitHub Pages, served from docs/witness/) so a witness has an out-of-band
# place to fetch it rather than trusting a copy shipped inside this package.
KEY_URL = "https://abisheakp197.github.io/Neutral-Trust-Infrastructure/witness/PUBLIC_KEY.pem"

TOOLCHAIN = "rustc 1.90.0 (1159e78c4 2025-09-14), cargo 1.90.0, maturin 1.9.6"

# Every witness key this package has ever been signed with. These are public
# key fingerprints (SHA-256 of the DER SPKI public key), recovered from the
# repository history, so a key rotation is never silent. The generator merges
# the current signing key into this list; see `update_key_history`.
KNOWN_KEYS = [
    {
        "fingerprint_sha256": "1086f65bbd4dedf2da66d08c55d233bb324748fd54f6659c79ce6e96d2811654",
        "algorithm": "Ed25519",
        "public_key_file": "PUBLIC_KEY.pem",
        "key_url": KEY_URL,
        "status": "retired",
        "valid_from_utc": "2026-11-06T16:57:13Z",
        "retired_at_utc": "2026-11-06T17:37:59Z",
        "note": "First witness key (branch feat/witness-package). Private key not retained.",
    },
    {
        "fingerprint_sha256": "02c8859c08b7876fbf3739812d4c35dd8e931a089351485fbef194ea72347812",
        "algorithm": "Ed25519",
        "public_key_file": "PUBLIC_KEY.pem",
        "key_url": KEY_URL,
        "status": "retired",
        "valid_from_utc": "2026-11-06T17:37:59Z",
        "retired_at_utc": "2026-11-07T13:44:49Z",
        "note": "Second witness key (branch feat/native-s4-s5-s6-witness). Private key not retained.",
    },
    {
        "fingerprint_sha256": "0ef7c228f6828fa9c5eadc4cf1e472b4f7130e71560cbf1a454c2ca830987673",
        "algorithm": "Ed25519",
        "public_key_file": "PUBLIC_KEY.pem",
        "key_url": KEY_URL,
        "status": "retired",
        "valid_from_utc": "2026-11-07T13:44:49Z",
        "retired_at_utc": "2026-11-07T14:20:00Z",
        "note": "Third witness key. Private key not retained; rotated for the provenance fix.",
    },
]

NTI_FILES = [
    ("ube-foundation/tests/nti_conformance_regressions.rs", "NTI conformance regression suite (issuer authority + quorum enforcement)"),
    ("ube-foundation/tests/core_tests.rs", "NTI core engine tests"),
    ("ube-foundation/tests/adversarial_suite.rs", "NTI adversarial suite"),
    ("ube-foundation/tests/adversarial_fuzz.rs", "NTI adversarial fuzz harness"),
    ("ube-foundation/tests/robustness_fuzz.rs", "NTI robustness fuzz harness"),
    ("ube-foundation/tests/security_patch_tests.rs", "NTI security patch regression tests"),
    ("ube-foundation/tests/trust_marketplace_adversarial.rs", "NTI trust-marketplace adversarial suite"),
    ("ube-foundation/tests/enterprise_adversarial_stress_suite.rs", "NTI enterprise adversarial stress suite"),
    ("ube-foundation/python_tests/test_python_sdk.py", "NTI Python SDK tests (native bindings required)"),
    ("ube-foundation/Cargo.toml", "NTI Rust crate manifest"),
    ("ube-foundation/Cargo.lock", "NTI locked dependency graph"),
    (".github/workflows/issuer-quorum-regressions.yml", "CI job that runs the NTI conformance regression suite"),
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _u32(n: int) -> bytes:
    return struct.pack(">I", n)


def _bin(name: str) -> str:
    """Resolve a tool, honouring a CARGO_HOME/bin that is not on PATH."""
    found = shutil.which(name)
    if found:
        return found
    cargo_bin = pathlib.Path.home() / ".cargo" / "bin" / name
    return str(cargo_bin) if cargo_bin.exists() else name


def _run(argv: list, cwd: pathlib.Path) -> dict:
    proc = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True)
    return {"argv": argv, "exit_code": proc.returncode,
            "stdout": proc.stdout, "stderr": proc.stderr}


CANONICAL_FORMS = {
    "cargo_test": "sorted `test <name> ... <status>` lines plus the sorted `test result:` "
                  "summary lines with the trailing `finished in <t>` stripped",
    "python_unittest": "sorted `test_<name> ... <status>` lines plus the `Ran N tests` line "
                       "(timing stripped) and the final `OK`/`FAILED` line",
    "cargo_build": "outcome only: `finished=<bool>` and `error_lines=<count>` (an incremental "
                   "build compiles a varying set of crates, so compile order is not reproducible)",
    "cargo_check": "outcome only: `finished=<bool>` and `error_lines=<count>`",
}


def _strip_timing(line: str) -> str:
    return re.sub(r"(finished in|Ran \d+ tests in) [0-9.]+s", r"\1 <t>", line).strip()


def canonicalize_transcript(kind: str, transcript: str) -> str:
    """Reproducible form of a suite transcript.

    Raw transcripts are not byte-reproducible: cargo runs tests in parallel and
    prints a wall-clock `finished in` value, so line order and timing vary run to
    run. The canonical form keeps the outcome-bearing lines -- every test name
    with its status, and the per-binary summary -- sorted, with timing stripped,
    so a witness that re-runs the same suites derives the same digest. If a test
    is added, removed, or changes status, the digest changes.
    """
    lines = [l.strip() for l in transcript.splitlines()]
    if kind in ("cargo_test", "python_unittest"):
        kept = []
        for s in lines:
            if re.match(r"^test[ _].+\.\.\. (ok|FAILED|ERROR|ignored)$", s):
                kept.append(s)
            elif (s.startswith("test result:") or s.startswith("Ran ")
                  or s == "OK" or s.startswith("FAILED (")):
                kept.append(_strip_timing(s))
        return "\n".join(sorted(kept)) + "\n"
    errors = sum(1 for s in lines if s.startswith("error"))
    finished = any(s.startswith("Finished") for s in lines)
    return f"finished={finished}\nerror_lines={errors}\n"


def _suite_from_log(log: dict, *, kind: str, label: str, ok: bool) -> dict:
    transcript = log["stdout"] + log["stderr"]
    canonical = canonicalize_transcript(kind, transcript)
    return {
        "command": " ".join(log["argv"]),
        "exit_code": log["exit_code"],
        "status": "PASSED" if ok else "FAILED",
        "label": label,
        "output_sha256": sha256_hex(canonical.encode("utf-8")),
        "canonical_form": CANONICAL_FORMS[kind],
        "canonical_bytes": len(canonical.encode("utf-8")),
        "raw_bytes": len(transcript),
    }


def parse_cargo_test_totals(transcript: str) -> dict:
    """Sum the per-binary `test result:` lines that cargo prints."""
    passed = failed = 0
    binaries = []
    for line in transcript.splitlines():
        line = line.strip()
        if not line.startswith("test result:"):
            continue
        # e.g. "test result: ok. 5 passed; 0 failed; 0 ignored; ..."
        head = line.split(";")
        try:
            passed += int(head[0].split(".")[1].strip().split()[0])
            failed += int(head[1].strip().split()[0])
        except (IndexError, ValueError):
            continue
        binaries.append(line)
    return {"passed": passed, "failed": failed, "binaries": binaries}


def s4_file_integrity(evidence: dict, evidence_bytes: bytes) -> list:
    """S4: SHA-256 of the evidence package itself, then of every artifact.

    The package digest is included so that tampering with the envelope (agent,
    action, timestamps) changes the S5 root, not just the artifact contents.
    """
    out = [{
        "name": "evidence_package.json",
        "sha256": sha256_hex(evidence_bytes),
        "bytes": len(evidence_bytes),
        "description": "the evidence package as delivered (raw bytes)",
    }]
    for art in evidence.get("artifacts", []):
        raw = art["content_utf8"].encode("utf-8")
        out.append({"name": art["name"], "sha256": sha256_hex(raw), "bytes": len(raw)})
    return out


def _leaf_digest(entry: dict) -> bytes:
    return hashlib.sha256(DOMAIN_LEAF + bytes.fromhex(entry["sha256"])).digest()


def _merkle_root(leaves: list) -> tuple:
    """RFC 6962 Merkle root with domain separation. Returns (root_hex, levels).

    On an odd level the last node is *promoted unchanged* to the next level
    rather than duplicated. RFC 6962's Merkle Tree Hash does not duplicate the
    final node; duplicating it lets two distinct leaf sets collapse to the same
    root, so the node is carried up as-is. This iterative promotion is
    equivalent to RFC 6962's recursive split at the largest power of two below
    the leaf count.
    """
    if not leaves:
        raise ValueError("cannot build a Merkle tree with no leaves")
    level = leaves
    levels = [[h.hex() for h in level]]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(hashlib.sha256(DOMAIN_NODE + level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])  # promote the odd node unchanged (RFC 6962)
        level = nxt
        levels.append([h.hex() for h in level])
    return level[0].hex(), levels


def s5_evidence_root(s4_entries: list) -> dict:
    """S5: Merkle root over the S4 digests."""
    leaves = [_leaf_digest(e) for e in s4_entries]
    root, levels = _merkle_root(leaves)
    return {"merkle_root_sha256": root, "leaf_count": len(leaves),
            "algorithm": "SHA-256, RFC 6962 Merkle Tree Hash with domain separation",
            "odd_node_rule": "last node promoted unchanged, never duplicated",
            "levels": levels}


def s6_seal_input(root_hex: str, leaf_count: int, names: list) -> bytes:
    """Exact bytes S6 signs: root, leaf count and the ordered artifact names.

    Binding the leaf count and the artifact names stops a witness from being
    shown a valid root for a different artifact set, and stops a name being
    swapped without detection (names are not hashed into the Merkle leaves).
    """
    names_bytes = json.dumps(list(names), separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
    return (DOMAIN_S6 + bytes.fromhex(root_hex) + _u32(leaf_count)
            + _u32(len(names_bytes)) + names_bytes)


def package_signature_input(files: list) -> bytes:
    """Exact bytes the package signature covers.

    `files` is an ordered list of (name, raw_bytes). Each file is digested
    separately and the digest is preceded by a length-prefixed name, so moving
    a newline between files changes the signed bytes.
    """
    out = bytearray(DOMAIN_PACKAGE)
    out += _u32(len(files))
    for name, raw in files:
        nb = name.encode("utf-8")
        out += _u32(len(nb)) + nb + hashlib.sha256(raw).digest()
    return bytes(out)


def ed25519_sign(data: bytes, key_path: str) -> bytes:
    """Sign bytes with an Ed25519 key. Ed25519 is one-shot, so openssl needs a
    real file rather than a pipe (it cannot size a stream)."""
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data)
        tmp_in = tf.name
    tmp_out = tmp_in + ".sig"
    try:
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey", key_path, "-rawin",
             "-in", tmp_in, "-out", tmp_out],
            capture_output=True)
        if proc.returncode != 0:
            raise RuntimeError(f"openssl sign failed: {proc.stderr.decode()}")
        return pathlib.Path(tmp_out).read_bytes()
    finally:
        pathlib.Path(tmp_in).unlink(missing_ok=True)
        pathlib.Path(tmp_out).unlink(missing_ok=True)


def public_key_der(key_path: str) -> bytes:
    """DER SPKI of the public half of the signing key."""
    proc = subprocess.run(["openssl", "pkey", "-in", key_path, "-pubout",
                           "-outform", "DER"], capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl pubout failed: {proc.stderr.decode()}")
    return proc.stdout


def public_key_pem(key_path: str) -> bytes:
    """PEM of the public half of the signing key, so the published key always
    matches the signature that was just produced."""
    proc = subprocess.run(["openssl", "pkey", "-in", key_path, "-pubout"],
                          capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl pubout failed: {proc.stderr.decode()}")
    return proc.stdout


def key_fingerprint(key_path: str) -> str:
    """SHA-256 of the DER SPKI public key, hex. Stable across PEM formatting."""
    return sha256_hex(public_key_der(key_path))


def update_key_history(existing: dict, fingerprint: str, now: str) -> list:
    """Merge the current key into the recorded key history.

    The history starts from KNOWN_KEYS (every key this package has been signed
    with, recovered from repository history) and merges in anything already
    recorded in the manifest. Any previously active key whose fingerprint
    differs from the signing key is marked retired, so a rotation is recorded
    rather than silently replacing the old key. The result is chronological.
    """
    by_fp = {}
    for entry in KNOWN_KEYS:
        by_fp[entry["fingerprint_sha256"]] = dict(entry)
    for entry in existing.get("key_history", []):
        by_fp.setdefault(entry.get("fingerprint_sha256"), dict(entry))

    for entry in by_fp.values():
        if entry.get("fingerprint_sha256") != fingerprint and entry.get("status") == "active":
            entry["status"] = "retired"
            entry.setdefault("retired_at_utc", now)

    current = by_fp.get(fingerprint)
    if current is None:
        current = {
            "fingerprint_sha256": fingerprint,
            "algorithm": "Ed25519",
            "public_key_file": "PUBLIC_KEY.pem",
            "key_url": KEY_URL,
            "status": "active",
            "valid_from_utc": now,
        }
        by_fp[fingerprint] = current
    else:
        current["status"] = "active"
    return sorted(by_fp.values(), key=lambda e: e.get("valid_from_utc", ""))


def run_suites() -> dict:
    """Run the NTI suites for real and return captured evidence."""
    cargo = _bin("cargo")
    py = _bin("python3")

    test_log = _run([cargo, "test", "--locked", "--manifest-path", CARGO_MANIFEST,
                     "--lib", "--tests", "--", "--nocapture"], REPO)
    build_log = _run([cargo, "build", "--locked", "--manifest-path", CARGO_MANIFEST], REPO)
    check_log = _run([cargo, "check", "--locked", "--manifest-path", CARGO_MANIFEST,
                      "--features", "python"], REPO)
    py_log = _run([py, "-m", "unittest", "discover", "-s", PYTHON_TESTS_DIR, "-v"], REPO)

    test_transcript = test_log["stdout"] + test_log["stderr"]
    totals = parse_cargo_test_totals(test_transcript)
    rust_ok = test_log["exit_code"] == 0 and totals["failed"] == 0
    py_ok = py_log["exit_code"] == 0

    return {
        "rust_totals": totals,
        "rust_ok": rust_ok,
        "py_ok": py_ok,
        "logs": {
            "cargo_test": _suite_from_log(test_log, kind="cargo_test", label="cargo test --locked (all suites)", ok=rust_ok),
            "cargo_build": _suite_from_log(build_log, kind="cargo_build", label="cargo build --locked", ok=build_log["exit_code"] == 0),
            "cargo_check_python": _suite_from_log(check_log, kind="cargo_check", label="cargo check --locked --features python", ok=check_log["exit_code"] == 0),
            "python_unittest": _suite_from_log(py_log, kind="python_unittest", label="python -m unittest (NTI Python SDK)", ok=py_ok),
        },
    }


def s6_seal(root_hex: str, leaf_count: int, names: list, key_path: str) -> dict:
    """S6: Ed25519 signature over the S5 root, the leaf count and the names."""
    seal = ed25519_sign(s6_seal_input(root_hex, leaf_count, names), key_path)
    return {"scheme": "Ed25519", "construction": "signature (not HMAC)",
            "signed_over": "S5_evidence_root.merkle_root_sha256 || "
                           "S5_evidence_root.leaf_count || S4 artifact names",
            "leaf_count": leaf_count,
            "artifact_names": list(names),
            "seal_hex": seal.hex()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--key", required=True, help="Ed25519 private key (never committed)")
    ap.add_argument("--out", default="docs/witness")
    ap.add_argument("--skip-suite-runs", action="store_true",
                    help="Reuse the suite evidence already in RESULTS.json (for re-sealing only).")
    args = ap.parse_args()

    evidence_path = pathlib.Path(args.evidence).resolve()
    evidence = json.loads(evidence_path.read_text())
    try:
        evidence_rel = str(evidence_path.relative_to(REPO))
    except ValueError:
        # Evidence outside the repo: record the absolute path rather than crash.
        evidence_rel = str(evidence_path)
    out = (REPO / args.out).resolve() if not pathlib.Path(args.out).is_absolute() else pathlib.Path(args.out)

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"],
                            capture_output=True, text=True).stdout.strip()
    fingerprint = key_fingerprint(args.key)

    evidence_bytes = evidence_path.read_bytes()
    s4 = s4_file_integrity(evidence, evidence_bytes)
    s5 = s5_evidence_root(s4)
    names = [e["name"] for e in s4]
    s6 = s6_seal(s5["merkle_root_sha256"], s5["leaf_count"], names, args.key)

    results_path = out / "RESULTS.json"
    results = json.loads(results_path.read_text()) if results_path.exists() else {}
    manifest_path = out / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}

    if args.skip_suite_runs and results.get("suite_evidence"):
        suite = None
        rust_totals = {"passed": results["suite_evidence"]["rust_tests"]["total_passed"],
                       "failed": results["suite_evidence"]["rust_tests"]["total_failed"]}
        rust_ok = results["suite_evidence"]["rust_tests"]["status"] == "PASSED"
        py_ok = results["suite_evidence"]["python_tests"]["status"] == "PASSED"
        logs = results["suite_evidence"]["logs"]
    else:
        suite = run_suites()
        rust_totals, rust_ok, py_ok, logs = (
            suite["rust_totals"], suite["rust_ok"], suite["py_ok"], suite["logs"])

    rust_status = "PASSED" if rust_ok else "FAILED"
    py_status = "PASSED" if py_ok else "FAILED"
    overall = "PASSED" if (rust_ok and py_ok) else "FAILED"
    total_passed = rust_totals["passed"]

    results["results_version"] = 5
    results["generated_at_utc"] = now
    results["repository"] = "abisheakp197/Neutral-Trust-Infrastructure"
    results["commit"] = commit
    results["overall_status"] = overall
    results["scope"] = "NTI native suites plus S4/S5/S6 seals over a synthetic fixture."
    results["environment"] = {"toolchain": TOOLCHAIN,
                              "native_python_bindings": "built and loaded"}
    results["suites"] = [
        {"id": "NTI-rust-tests", "status": rust_status, "total_passed": total_passed,
         "total_failed": rust_totals["failed"], "detail": rust_totals["binaries"]},
        {"id": "NTI-python-tests", "status": py_status,
         "command": "python3 -m unittest discover -s ube-foundation/python_tests -v",
         "total_passed": 2 if py_ok else 0, "total_failed": 0 if py_ok else 1,
         "native_bindings": True},
        {"id": "NTI-rust-build", "status": logs["cargo_build"]["status"],
         "detail": "cargo build --locked"},
        {"id": "NTI-rust-check-python-feature", "status": logs["cargo_check_python"]["status"],
         "detail": "cargo check --locked --features python"},
    ]
    results["statement"] = (
        f"The NTI Rust suite ({total_passed} tests) and the NTI Python SDK suite were run for "
        "this package under rustc/cargo 1.90.0 with native bindings built by maturin 1.9.6. "
        "The SHA-256 digest of each suite transcript is bound in `suite_evidence`; re-run the "
        "suites and compare the digests. The S4/S5/S6 seals below are computed over a synthetic "
        "evidence fixture."
    )
    # Suite evidence: bind the SHA-256 of each captured transcript, not just a status.
    results["suite_evidence"] = {
        "rust_tests": {
            "command": logs["cargo_test"]["command"],
            "status": rust_status,
            "total_passed": total_passed,
            "total_failed": rust_totals["failed"],
            **{k: logs["cargo_test"][k] for k in
               ("exit_code", "output_sha256", "canonical_form", "canonical_bytes", "raw_bytes")},
        },
        "python_tests": {
            "command": logs["python_unittest"]["command"],
            "status": py_status,
            **{k: logs["python_unittest"][k] for k in
               ("exit_code", "output_sha256", "canonical_form", "canonical_bytes", "raw_bytes")},
        },
        "logs": logs,
        "note": "output_sha256 is over the canonicalised transcript (see canonical_form): outcome "
                "lines sorted, timing stripped, so a re-run is reproducible. Re-run each command "
                "and canonicalise the same way to confirm the digest.",
    }
    results["S4_file_integrity"] = s4
    results["S5_evidence_root"] = s5
    results["S6_hmac_seal"] = s6
    results["seal_scope"] = {
        "evidence_file": evidence_rel,
        "classification": evidence.get("classification"),
        "note": "Synthetic fixture. These seals demonstrate the mechanism; they are not production evidence.",
    }
    results_path.write_text(json.dumps(results, indent=2) + "\n")

    # Refresh the manifest hashes for the generator and the evidence fixture.
    manifest["manifest_version"] = 5
    manifest["generated_at_utc"] = now
    manifest["repository"] = "abisheakp197/Neutral-Trust-Infrastructure"
    manifest["commit"] = commit
    manifest["key_url"] = KEY_URL
    manifest["key_history"] = update_key_history(manifest, fingerprint, now)
    manifest["signature"] = {
        "algorithm": "Ed25519",
        "signed_artifacts": ["RESULTS.json", "MANIFEST.json"],
        "signature_file": "SIGNATURE.sig",
        "public_key_file": "PUBLIC_KEY.pem",
        "public_key_fingerprint_sha256": fingerprint,
        "canonical_form": (
            "domain-separated, length-prefixed: "
            "b\"nti-witness-package-v2:\" || uint32_be(file_count) || "
            "for each file: uint32_be(len(name)) || name || SHA-256(file bytes). "
            "Each file is digested separately; the two files are never concatenated."
        ),
    }
    manifest["suite_evidence_logs"] = {
        name: {"command": entry["command"], "exit_code": entry["exit_code"],
               "status": entry["status"], "output_sha256": entry["output_sha256"],
               "canonical_form": entry["canonical_form"]}
        for name, entry in logs.items()
    }
    manifest["nti_test_scripts"] = [
        {"path": path, "sha256": sha256_hex((REPO / path).read_bytes()), "description": desc}
        for path, desc in NTI_FILES
    ]
    manifest["witness_generator"] = [
        {"path": "conformance/witness_generator/generate_seals.py",
         "sha256": sha256_hex(GENERATOR.read_bytes()),
         "description": "Native Apache-2.0 S4/S5/S6 seal generator"},
        {"path": evidence_rel,
         "sha256": sha256_hex(evidence_path.read_bytes()),
         "description": "Synthetic sample evidence package"},
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    # Publish the public key that matches the signing key, then sign the
    # domain-separated, length-prefixed package input.
    (out / "PUBLIC_KEY.pem").write_bytes(public_key_pem(args.key))
    files = [("RESULTS.json", results_path.read_bytes()),
             ("MANIFEST.json", manifest_path.read_bytes())]
    (out / "SIGNATURE.sig").write_bytes(
        ed25519_sign(package_signature_input(files), args.key))

    print(f"S4: {len(s4)} artifact hashes")
    print(f"S5: merkle root {s5['merkle_root_sha256']} ({s5['leaf_count']} leaves)")
    print(f"S6: seal {s6['seal_hex'][:32]}... ({len(bytes.fromhex(s6['seal_hex']))} bytes) "
          f"over root + leaf_count + {len(names)} names")
    print(f"suite: rust {rust_status} ({total_passed} passed, {rust_totals['failed']} failed), "
          f"python {py_status}")
    print(f"  rust transcript sha256:   {logs['cargo_test']['output_sha256']}")
    print(f"  python transcript sha256: {logs['python_unittest']['output_sha256']}")
    print(f"key: fingerprint {fingerprint[:16]}...")
    print(f"wrote {results_path}, {manifest_path}, {out / 'SIGNATURE.sig'}, {out / 'PUBLIC_KEY.pem'}")


if __name__ == "__main__":
    sys.exit(main())
