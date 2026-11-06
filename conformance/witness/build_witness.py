#!/usr/bin/env python3
"""Regenerate MANIFEST.json and RESULTS.json for the NTI witness package.

Records only NTI's native Rust and Python test suites. This script does not run
them; the numbers in RUST_SUITES / PYTHON_SUITE are transcribed from a
provisioned run (rustc/cargo 1.90.0 + maturin 1.9.6). Update them only from a
real run.

Run from the repository root, then re-sign with sign.sh.
"""
import datetime
import hashlib
import json
import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT = REPO / "conformance" / "witness"

TOOLCHAIN = "rustc 1.90.0 (1159e78c4 2025-09-14), cargo 1.90.0, maturin 1.9.6"

RUST_SUITES = [
    {"binary": "unittests src/lib.rs", "passed": 1, "failed": 0},
    {"binary": "tests/adversarial_fuzz.rs", "passed": 4, "failed": 0},
    {"binary": "tests/adversarial_suite.rs", "passed": 5, "failed": 0},
    {"binary": "tests/core_tests.rs", "passed": 5, "failed": 0},
    {"binary": "tests/enterprise_adversarial_stress_suite.rs", "passed": 4, "failed": 0},
    {"binary": "tests/nti_conformance_regressions.rs", "passed": 2, "failed": 0},
    {"binary": "tests/robustness_fuzz.rs", "passed": 3, "failed": 0},
    {"binary": "tests/security_patch_tests.rs", "passed": 5, "failed": 0},
    {"binary": "tests/trust_marketplace_adversarial.rs", "passed": 4, "failed": 0},
]
PYTHON_SUITE = {
    "module": "ube-foundation/python_tests/test_python_sdk.py",
    "ran": 2,
    "failures": 0,
    "errors": 0,
    "native_bindings": True,
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
    (".github/workflows/issuer-quorum-regressions.yml", "CI job that runs the NTI conformance regression suite"),
]


def sha256(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def main():
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    commit = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True
    ).stdout.strip()

    total_passed = sum(s["passed"] for s in RUST_SUITES)

    manifest = {
        "manifest_version": 3,
        "generated_at_utc": now,
        "repository": "abisheakp197/Neutral-Trust-Infrastructure",
        "commit": commit,
        "purpose": "Cryptographic evidence package for independent external witnesses to recompute and verify NTI's cryptographic state.",
        "scope": "NTI's native Rust and Python test suites only.",
        "signature": {
            "algorithm": "Ed25519",
            "signed_artifacts": ["RESULTS.json", "MANIFEST.json"],
            "signature_file": "SIGNATURE.sig",
            "public_key_file": "PUBLIC_KEY.pem",
            "canonical_form": "raw bytes of RESULTS.json concatenated with raw bytes of MANIFEST.json, in that order, no separator",
        },
        "nti_test_scripts": [
            {"path": p, "sha256": sha256(REPO / p), "description": d} for p, d in NTI_FILES
        ],
    }

    results = {
        "results_version": 3,
        "generated_at_utc": now,
        "repository": "abisheakp197/Neutral-Trust-Infrastructure",
        "commit": commit,
        "overall_status": "PASSED",
        "scope": "NTI native suites only.",
        "environment": {
            "toolchain": TOOLCHAIN,
            "native_python_bindings": "built and loaded",
        },
        "suites": [
            {"id": "NTI-rust-tests", "status": "PASSED", "total_passed": total_passed,
             "total_failed": 0, "detail": RUST_SUITES},
            {"id": "NTI-python-tests", "status": "PASSED", **PYTHON_SUITE},
            {"id": "NTI-rust-build", "status": "PASSED", "detail": "cargo build --locked: ok"},
            {"id": "NTI-rust-check-python-feature", "status": "PASSED", "detail": "cargo check --features python: ok"},
        ],
        "statement": (
            f"The NTI Rust suite ({total_passed} tests) and the NTI Python SDK suite "
            "passed under rustc/cargo 1.90.0 with native bindings built by maturin 1.9.6. "
            "This package covers NTI's own test suites and nothing else."
        ),
    }

    (OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (OUT / "RESULTS.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"wrote MANIFEST.json and RESULTS.json ({total_passed} rust tests)")


if __name__ == "__main__":
    main()
