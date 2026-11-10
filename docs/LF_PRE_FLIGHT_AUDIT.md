# LF Pre-Flight Audit — Neutral-Trust-Infrastructure

**Role:** LFDT TAC Auditor & Principal Security Engineer
**Scope:** Pre-submission hardening of `abisheakp197/Neutral-Trust-Infrastructure` and
`abisheakp197/nti-spec` for the Linux Foundation Decentralized Trust (LFDT) Lab application.
**Date:** 2026-11-10
**Status:** Remediated on branch `fix/pre-flight-audit-final`

---

## 1. Summary

This audit covers licensing, governance, DCO, link integrity, README completeness,
internal contradictions, security posture, branch protection, and OpenSSF Scorecard
gaps across both repositories. Every actionable finding has been remediated on the
`fix/pre-flight-audit-final` branch in each repository. Items that require
repository-owner action (branch protection, Scorecard maintenance) are listed in
Section 6.

## 2. Supply-chain hardening

### 2.1 GitHub Actions pinned to commit SHAs

Every third-party action in both repositories is now pinned to a full 40-character
commit SHA with a trailing `# <version>` comment. Floating tags (`@v4`, `@stable`,
`@release/v1`) were replaced. This satisfies the OpenSSF Scorecard
`Pinned-Dependencies` check and the LFDT supply-chain expectations.

All 19 distinct pinned SHAs were verified to resolve to a real commit on their
upstream repository, and each trailing version comment was checked against the
upstream tag at that SHA.

| Action | Pinned ref |
| :--- | :--- |
| `actions/checkout` | `11d5960a…` (v4) |
| `actions/setup-python` | `a26af69b…` (v5) |
| `actions/setup-node` | `49933ea5…` (v4) |
| `actions/upload-artifact` | `ea165f8d…` (v4) |
| `actions/download-artifact` | `d3f86a10…` (v4) |
| `actions/configure-pages` | `1f0c5cde…` (v4) |
| `actions/jekyll-build-pages` | `44a6e6be…` (v1) |
| `actions/upload-pages-artifact` | `56afc609…` (v3) |
| `actions/deploy-pages` | `d6db9016…` (v4) |
| `PyO3/maturin-action` | `e83996d1…` (v1) |
| `pypa/gh-action-pypi-publish` | `7245906f…` (release/v1) |
| `dtolnay/rust-toolchain` | `b725eda5…` (stable) |
| `tim-actions/get-pr-commits` | `198af035…` (v1.3.1) |
| `tim-actions/dco` | `f2279e6e…` (v1.1.0) |
| `abisheakp197/nti-scan-action` | `6591bbe4…` (v1.0.0) |
| `ossf/scorecard-action` | `fa7117db…` (v2.5.0) |
| `actions/upload-artifact` (scorecard) | `cf430e03…` (v7.0.2) |
| `github/codeql-action/upload-sarif` | `24c54180…` (v4.38.3) |

`dtolnay/rust-toolchain` additionally gained an explicit `toolchain: stable` input so
the pin cannot silently change the toolchain if the `stable` tag moves.

### 2.2 Tool installs pinned

CI installs that previously used floating versions now pin exact versions:
`maturin==1.9.6`, `twine==6.1.0`, `@google/jules@0.1.42`, `markdownlint-cli@0.50.0`,
`requests==2.32.3`.

### 2.3 Dependabot

`.github/dependabot.yml` was added covering the three ecosystems in this repository:
Cargo (`/ube-foundation`), pip (`/ube-foundation`), and GitHub Actions (`/`). The
directory paths were verified against the actual manifest locations
(`ube-foundation/Cargo.toml`, `ube-foundation/pyproject.toml`). This addresses the
Scorecard `Dependency-Update-Tool` check.

## 3. Governance and licensing

| Item | Status |
| :--- | :--- |
| `LICENSE` (Apache-2.0) | Present; GitHub detects SPDX `Apache-2.0` |
| `NOTICE` | Present |
| `CODE_OF_CONDUCT.md` | Present; byte-identical to the `nti-spec` copy |
| `CONTRIBUTING.md` | Present; DCO-based, no CLA |
| `GOVERNANCE.md` | Present; TSC + rough-consensus model |
| `MAINTAINERS.md` | Present |
| `SECURITY.md` | Present |
| DCO workflow (`.github/workflows/dco.yml`) | Present; every commit requires `Signed-off-by:` |

**DCO:** The DCO check (`tim-actions/dco`) is wired to every pull request. All
non-merge commits in history carry a `Signed-off-by:` trailer; the single merge
commit is exempt by design.

**Licensing note:** `LICENSE.md` is a byte-identical duplicate of `LICENSE`. It is
retained intentionally because `ube-foundation/Cargo.toml` sets
`license-file = "LICENSE.md"` and `ube-foundation/README.md` links to it. It is a
packaging artifact, not a licensing conflict.

## 4. Documentation and link integrity

* The `README.md` documentation index now links the NTI-1 specification and LFDT Lab
  proposal repository.
* All workflow YAML parses cleanly (validated with a YAML parser).
* No tracked binary artifacts; the Scorecard `Binary-Artifacts` 9/10 is a benign
  false positive on documentation assets.
* No secrets in git history (a full-history scan found only benign, non-credential
  strings such as test-key comments).

## 5. Internal contradictions resolved

* The `CODE_OF_CONDUCT.md` reporting contact is now written as a bare-URL-safe
  address (`**<abisheakp197@gmail.com>**`) so the Markdown linter passes and the
  address renders as intended.
* `.github/workflows/release.yml` was missing a trailing newline; corrected.
* Stale claims in the companion specification audit report (a "pending removal" note
  about a crates.io link that had already been removed) were corrected in
  `nti-spec/AUDIT_REPORT.md`.

## 6. Findings requiring repository-owner action

These cannot be changed through a pull request; they are repository settings.

1. **Branch protection (Scorecard `Branch-Protection`, currently 0/10).** Enable
   branch protection on `main`: require a pull request, require at least one
   approving review, require status checks to pass (the DCO check and CI), and
   disallow force-pushes and deletions.
2. **Scorecard `Code-Review`, `Maintained`, `CII-Best-Practices`, `Fuzzing`,
   `Contributors` (all 0).** These are process checks that improve over time as the
   project gains reviewers, releases, and a fuzzing harness; they are not blockers
   for the Lab application but should be tracked.
3. **`Signed-Releases` (-1).** Publish signed release artifacts (or attach
   provenance/SBOM attestations) on the next tagged release.
4. **Scorecard workflow activation.** The Scorecard workflow runs on `main`; its
   first published result after merge will populate the README badge.

## 7. Scorecard snapshot

Recorded from the public OpenSSF Scorecard API on 2026-11-10 (overall 5.4/10):

| Check | Score |
| :--- | :--- |
| Security-Policy | 10 |
| Token-Permissions | 10 |
| Dangerous-Workflow | 10 |
| Vulnerabilities | 10 |
| SAST | 10 |
| License | 10 |
| CI-Tests | 10 |
| Packaging | 10 |
| Binary-Artifacts | 9 |
| Pinned-Dependencies | 1 |
| Branch-Protection | 0 |
| Code-Review | 0 |
| Maintained | 0 |
| Dependency-Update-Tool | 0 |

`Pinned-Dependencies` and `Dependency-Update-Tool` are remediated by this branch and
will improve on the next Scorecard run after merge. `Branch-Protection` requires the
owner action in Section 6.

## 8. Verification performed

* YAML parse of every workflow and `dependabot.yml` — pass.
* All 19 pinned action SHAs resolve to real upstream commits — pass.
* Version comments checked against upstream tags — pass.
* Full-history secret scan — no credentials found.
* DCO trailer check across non-merge commits — pass.
