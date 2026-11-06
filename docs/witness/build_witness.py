#!/usr/bin/env python3
"""Regenerate MANIFEST.json and RESULTS.json for the NTI witness package.

This script does not run the suites. It records results that were produced by a
provisioned run (Rust 1.90.0 + maturin), transcribed into RUN_RESULTS below.
Run it from the repository root, then re-sign with sign.sh.
"""
import datetime
import hashlib
import json
import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "conformance" / "witness"

# --- Recorded from the provisioned run. Update only from a real run. ---
TOOLCHAIN = "rustc 1.90.0 (1159e78c4 2025-09-14), cargo 1.90.0"
RUN_RESULTS = {
    "rust_suites": [
        {"binary": "unittests src/lib.rs", "passed": 1, "failed": 0},
        {"binary": "tests/adversarial_fuzz.rs", "passed": 4, "failed": 0},
        {"binary": "tests/adversarial_suite.rs", "passed": 5, "failed": 0},
        {"binary": "tests/core_tests.rs", "passed": 5, "failed": 0},
        {"binary": "tests/enterprise_adversarial_stress_suite.rs", "passed": 4, "failed": 0},
        {"binary": "tests/nti_conformance_regressions.rs", "passed": 2, "failed": 0},
        {"binary": "tests/robustness_fuzz.rs", "passed": 3, "failed": 0},
        {"binary": "tests/security_patch_tests.rs", "passed": 5, "failed": 0},
        {"binary": "tests/trust_marketplace_adversarial.rs", "passed": 4, "failed": 0},
    ],
    "python_suites": {"module": "ube-foundation/python_tests/test_python_sdk.py", "ran": 2, "failures": 0, "errors": 0, "native_bindings": True},
    "asl_vectors": {"cases_checked": 45, "failures": 0, "note": "Run against the public ASL kit; tests ASL fixtures, not NTI code."},
    "rust_build": "ok",
    "rust_check_python_feature": "ok",
    "python_wheel_build": "ok (ube_foundation-0.1.7-cp310-abi3-manylinux_2_38_x86_64.whl)",
}

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
    (".github/workflows/asl-conformance.yml", "CI job that runs the external ASL vector verifier"),
    (".github/workflows/issuer-quorum-regressions.yml", "CI job that runs the conformance regression suite"),
]

ASL_VECTOR_FILES = [
    "conformance/vectors/canonical.json",
    "conformance/vectors/hashing.json",
    "conformance/vectors/tokens.json",
    "conformance/vectors/audit.json",
    "conformance/vectors/attestation_v1.json",
    "conformance/vectors/boundary_v1.json",
    "conformance/verify_vectors.py",
    "conformance/verifier_public_key.json",
]


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def git(args, cwd=REPO):
    return subprocess.run(["git", "-C", str(cwd)] + args, capture_output=True, text=True).stdout.strip()


def main():
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit = git(["rev-parse", "HEAD"])
    kit = pathlib.Path("/tmp/asl-kit")

    manifest = {
        "manifest_version": 2,
        "generated_at_utc": now,
        "repository": "abisheakp197/Neutral-Trust-Infrastructure",
        "commit": commit,
        "purpose": "Cryptographic evidence package for independent external witnesses to recompute and verify NTI's cryptographic state.",
        "signature": {
            "algorithm": "Ed25519",
            "signed_artifacts": ["RESULTS.json", "MANIFEST.json"],
            "signature_file": "SIGNATURE.sig",
            "public_key_file": "PUBLIC_KEY.pem",
            "canonical_form": "raw bytes of RESULTS.json concatenated with raw bytes of MANIFEST.json, in that order, no separator",
        },
        "nti_test_scripts": [{"path": p, "sha256": sha256(REPO / p), "description": d} for p, d in NTI_FILES],
        "vendor_records": [
            {"path": "conformance/witness/vendor/S4_S5_S6_PROVENANCE.md", "sha256": sha256(OUT / "vendor/S4_S5_S6_PROVENANCE.md")},
            {"path": "conformance/witness/vendor/S4_S5_S6_RECORD.json", "sha256": sha256(OUT / "vendor/S4_S5_S6_RECORD.json")},
        ],
        "external_conformance_vectors": {
            "source_repository": "Raja549h/asl-conformance-kit",
            "source_commit": git(["rev-parse", "HEAD"], cwd=kit) if kit.exists() else None,
            "note": "Not vendored into NTI. Hashes pinned so a witness can detect drift.",
            "files": [{"path": f, "sha256": sha256(kit / f)} for f in ASL_VECTOR_FILES] if kit.exists() else [],
        },
        "s4_s5_s6_test_scripts": {
            "status": "NOT_VENDORED",
            "record": "conformance/witness/vendor/S4_S5_S6_PROVENANCE.md",
            "reason": "Scripts live only in the private, non-Apache-2.0 repository Raja549h/helper; not obtainable for vendoring.",
        },
    }

    results = {
        "results_version": 2,
        "generated_at_utc": now,
        "repository": "abisheakp197/Neutral-Trust-Infrastructure",
        "commit": commit,
        "overall_status": "PASSED",
        "environment": {
            "toolchain": TOOLCHAIN,
            "native_python_bindings": "built and loaded (maturin 1.9.6)",
        },
        "suites": [
            {"id": "NTI-rust-tests", "status": "PASSED", "total_passed": sum(s["passed"] for s in RUN_RESULTS["rust_suites"]), "total_failed": 0, "detail": RUN_RESULTS["rust_suites"]},
            {"id": "NTI-python-tests", "status": "PASSED", **RUN_RESULTS["python_suites"]},
            {"id": "NTI-rust-build", "status": "PASSED", "detail": RUN_RESULTS["rust_build"]},
            {"id": "NTI-rust-check-python-feature", "status": "PASSED", "detail": RUN_RESULTS["rust_check_python_feature"]},
            {"id": "ASL-vectors", "status": "PASSED_EXTERNALLY", **RUN_RESULTS["asl_vectors"]},
            {"id": "S4", "status": "NOT_RUN", "reason": "Script is in the private repository Raja549h/helper; not obtainable."},
            {"id": "S5", "status": "NOT_RUN", "reason": "Script is in the private repository Raja549h/helper; not obtainable."},
            {"id": "S6", "status": "NOT_RUN", "reason": "No S6 definition exists in the public ASL conformance kit."},
        ],
        "statement": ("The NTI Rust and Python suites passed under rustc 1.90.0 with native bindings. "
                      "S4/S5/S6 were NOT run and are not covered by any result here. "
                      "The ASL vector run tests ASL fixtures, not NTI code."),
    }

    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (OUT / "RESULTS.json").write_text(json.dumps(results, indent=2) + "\n")
    print("wrote MANIFEST.json and RESULTS.json")


if __name__ == "__main__":
    main()
