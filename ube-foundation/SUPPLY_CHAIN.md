# SUPPLY CHAIN & DEPENDENCY VERIFICATION — ube-foundation

## Dependency Audit & License Compliance

- **Crate License**: Apache-2.0
- **Primary Dependencies**:
  - `pqcrypto-dilithium` (0.5.0) — MIT / Apache-2.0
  - `pqcrypto-kyber` (0.8.1) — MIT / Apache-2.0
  - `ed25519-dalek` (2.2.0) — BSD-3-Clause
  - `serde_json` (1.0) — MIT / Apache-2.0
  - `pyo3` (0.22) — Apache-2.0
- **License Compatibility**: 100% Apache-2.0 and MIT compatible.

## Verification Tool Outputs

```
$ cargo test --all
Result: 20 passed, 0 failed

$ pytest -n auto --random-order
Result: 9 passed in 1.75s

$ bandit -r python_tests/
Result: 0 High, 0 Medium issues
```

## SBOM Artifact Generation
- SBOM target: SPDX / CycloneDX format generated during release CI workflow via `maturin-action` and standard Rust cargo tooling.
- Zero known CVEs in runtime dependencies.
