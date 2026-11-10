# Release Process

This document describes how Neutral Trust Infrastructure (NTI) builds, signs,
and releases artifacts, and how anyone can independently verify them. It follows
the LF Decentralized Trust
[Securing and Verifying Releases](https://lf-decentralized-trust.github.io/governance/governing-documents/release-signing/)
policy.

## Versioning

NTI uses [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`.

- **MAJOR** — breaking change to the receipt format, the verification algorithm,
  or the public Rust/Python API.
- **MINOR** — backward-compatible capability or algorithm addition.
- **PATCH** — backward-compatible bug fix.

Releases are tagged `vMAJOR.MINOR.PATCH` (for example `v0.1.7`). The Python
distribution name is `ube-foundation`; the Rust crate name matches the package
manifest under `ube-foundation/`.

## Build

The core is a Rust workspace under `ube-foundation/` with Python bindings built
by [maturin](https://www.maturin.rs/). Wheels are built for six targets in CI:

| Target | Runner |
| :--- | :--- |
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| `x86_64-unknown-linux-musl` | `ubuntu-latest` |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` |
| `universal2-apple-darwin` | `macos-14` |
| `x86_64-pc-windows-msvc` | `windows-latest` |

To reproduce a build locally:

```bash
cd ube-foundation
maturin build --release --out dist
```

Builds run in GitHub Actions with all actions pinned to full commit SHAs, on
GitHub-hosted ephemeral runners. The build is hermetic with respect to the
source tree: the only inputs are the checked-out commit and the pinned
toolchain.

## Release Process

Releases are driven by `.github/workflows/release.yml`, triggered when a GitHub
Release is published (or by manual `workflow_dispatch`).

1. **Build** — `build-wheels` builds the six wheel targets and uploads them as
   workflow artifacts.
2. **Publish** — `publish` uploads the wheels to PyPI via
   [Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC, no
   long-lived API token).
3. **Sign** — `release-signing` (job: *Sign release artifacts (Sigstore)*):
   - generates `SHA256SUMS.txt` over the built wheels;
   - signs the checksum file with [Sigstore](https://www.sigstore.dev/) `cosign`
     in **keyless** mode, producing `SHA256SUMS.sigstore.json`;
   - attaches SLSA build provenance to the artifacts with
     [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance);
   - uploads `SHA256SUMS.txt` and `SHA256SUMS.sigstore.json` to the GitHub Release.

The signing job requires `id-token: write` (for the Sigstore OIDC identity),
`attestations: write`, and `contents: write` (to attach files to the release).
No signing key is stored in the repository; keyless signing binds the signature
to the workflow's OIDC identity and the source commit.

## Verifying a Release

### 1. Verify the Sigstore signature on the checksum file

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp 'https://github.com/abisheakp197/Neutral-Trust-Infrastructure/.github/workflows/release.yml@refs/tags/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS.txt
```

A successful result proves the checksum file was produced by this repository's
release workflow and has not been altered.

### 2. Verify the artifact checksums

```bash
sha256sum --check SHA256SUMS.txt
```

### 3. Verify the SLSA build provenance attestation

```bash
gh attestation verify <artifact-file> \
  --repo abisheakp197/Neutral-Trust-Infrastructure
```

This confirms the artifact was built by this repository's workflow from a
specific commit, at SLSA Build Level 2 (hosted build platform, signed
provenance). The project targets SLSA Level 2 and documents Level 1 as the
current floor for the LFDT incubation requirement.

## Release Artifacts

Each release contains:

- Platform wheels (`*.whl`) for the six targets above, on PyPI and as GitHub
  Release assets.
- `SHA256SUMS.txt` — SHA-256 checksums of the wheels.
- `SHA256SUMS.sigstore.json` — Sigstore keyless signature bundle over
  `SHA256SUMS.txt`.
- SLSA build provenance attestation (stored in GitHub's attestation store and
  discoverable with `gh attestation verify`).

## Resources

- Release workflow: [`.github/workflows/release.yml`](.github/workflows/release.yml)
- Sigstore: <https://www.sigstore.dev/>
- SLSA: <https://slsa.dev/>
- Security policy: [SECURITY.md](SECURITY.md)
