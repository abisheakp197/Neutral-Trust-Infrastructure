import hashlib, json, subprocess, pathlib, datetime

REPO = pathlib.Path("/workspace/project/Neutral-Trust-Infrastructure")
OUT = REPO / "conformance" / "witness"
OUT.mkdir(parents=True, exist_ok=True)

def sha256(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

COMMIT = subprocess.run(["git","-C",str(REPO),"rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
NOW = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# ---- NTI-side artifacts (real, hashed from this checkout) ----
nti_files = [
    ("ube-foundation/tests/nti_conformance_regressions.rs", "NTI conformance regression suite (issuer authority + quorum enforcement)"),
    ("ube-foundation/tests/core_tests.rs", "NTI core engine tests"),
    ("ube-foundation/tests/adversarial_suite.rs", "NTI adversarial suite"),
    ("ube-foundation/tests/adversarial_fuzz.rs", "NTI adversarial fuzz harness"),
    ("ube-foundation/tests/robustness_fuzz.rs", "NTI robustness fuzz harness"),
    ("ube-foundation/tests/security_patch_tests.rs", "NTI security patch regression tests"),
    ("ube-foundation/tests/trust_marketplace_adversarial.rs", "NTI trust-marketplace adversarial suite"),
    ("ube-foundation/tests/enterprise_adversarial_stress_suite.rs", "NTI enterprise adversarial stress suite"),
    ("ube-foundation/python_tests/test_python_sdk.py", "NTI Python SDK tests (native bindings required)"),
    ("ube-foundation/Cargo.toml", "NTI Rust crate manifest (pins ed25519-dalek, pqcrypto-dilithium)"),
    ("ube-foundation/Cargo.lock", "NTI locked dependency graph"),
    (".github/workflows/asl-conformance.yml", "CI job that runs the external ASL vector verifier"),
    (".github/workflows/issuer-quorum-regressions.yml", "CI job that runs the conformance regression suite"),
]

# ---- External ASL conformance vectors (real, hashed from the public kit clone) ----
KIT = pathlib.Path("/tmp/asl-kit")
kit_commit = subprocess.run(["git","-C",str(KIT),"rev-parse","HEAD"],capture_output=True,text=True).stdout.strip()
vector_files = [
    "conformance/vectors/canonical.json",
    "conformance/vectors/hashing.json",
    "conformance/vectors/tokens.json",
    "conformance/vectors/audit.json",
    "conformance/vectors/attestation_v1.json",
    "conformance/vectors/boundary_v1.json",
    "conformance/verify_vectors.py",
    "conformance/verifier_public_key.json",
]

manifest = {
    "manifest_version": 1,
    "generated_at_utc": NOW,
    "repository": "abisheakp197/Neutral-Trust-Infrastructure",
    "commit": COMMIT,
    "branch": "conformance/witness-package",
    "purpose": "Cryptographic evidence package for independent external witnesses to recompute and verify NTI's conformance state.",
    "signature": {
        "algorithm": "Ed25519",
        "signed_artifacts": ["MANIFEST.json", "RESULTS.json"],
        "signature_file": "SIGNATURE.sig",
        "public_key_file": "PUBLIC_KEY.pem",
        "signing_script": "verify.sh",
        "note": "The signature is produced over the raw bytes of RESULTS.json followed by the raw bytes of MANIFEST.json, in that order, concatenated with no separator."
    },
    "nti_test_scripts": [
        {"path": p, "sha256": sha256(REPO / p), "description": d} for p, d in nti_files
    ],
    "external_conformance_vectors": {
        "source_repository": "Raja549h/asl-conformance-kit",
        "source_commit": kit_commit,
        "note": "These are the only public conformance test vectors referenced by NTI's CI. They are not vendored into NTI; hashes are pinned here so a witness can detect drift.",
        "files": [{"path": f, "sha256": sha256(KIT / f)} for f in vector_files],
    },
    "s4_s5_s6_test_scripts": {
        "status": "UNAVAILABLE",
        "note": ("S4, S5 and S6 are named invariants in the Agent Safety Layer (ASL) project, "
                 "not in this repository. Their test scripts live in the private ASL source "
                 "repository (Raja549h/helper at commit 8e8961b733e49cc0ce814132a89b399aa982b097), "
                 "which is not publicly readable. No hashes can be computed for them here."),
        "references": {
            "S4": "Thresholds are quiet on ordinary traffic, but the tripwire still fires.",
            "S5": "Every kill path still fires the complete cascade.",
            "S6": "Not defined in the public ASL conformance kit revision.",
        },
    },
}

(OUT / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n")

results = {
    "results_version": 1,
    "generated_at_utc": NOW,
    "repository": "abisheakp197/Neutral-Trust-Infrastructure",
    "commit": COMMIT,
    "overall_status": "NOT_RUN",
    "environment": {
        "rust_toolchain": "ABSENT (cargo/rustup not installed)",
        "python": "3.x present",
        "native_python_bindings": "NOT_LOADABLE (ube_foundation module absent; requires maturin build)",
        "network_to_crates_io": "BLOCKED",
    },
    "suites": [
        {"id": "S4", "status": "NOT_RUN", "reason": "Test script resides in private repository Raja549h/helper; not obtainable from this environment."},
        {"id": "S5", "status": "NOT_RUN", "reason": "Test script resides in private repository Raja549h/helper; not obtainable from this environment."},
        {"id": "S6", "status": "NOT_RUN", "reason": "No S6 definition found in the public ASL conformance kit revision."},
        {"id": "ASL-vectors", "status": "PASSED_EXTERNALLY", "detail": "checked 45 vector cases, 0 failures (run on the public kit at commit %s; not a test of NTI code)." % kit_commit},
        {"id": "NTI-rust-tests", "status": "NOT_RUN", "reason": "No Rust toolchain available and crates.io is unreachable."},
        {"id": "NTI-python-tests", "status": "NOT_RUN", "reason": "Native bindings cannot be built without a Rust toolchain."},
    ],
    "statement": ("No NTI conformance test was executed in the environment that produced this file. "
                  "These results are NOT evidence of NTI conformance and MUST NOT be presented as such. "
                  "A witness must re-run the suites in a provisioned environment before relying on any claim."),
}
(OUT / "RESULTS.json").write_text(json.dumps(results, indent=2) + "\n")
print("wrote MANIFEST.json and RESULTS.json")
