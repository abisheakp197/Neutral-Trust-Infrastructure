# Neutral Trust Infrastructure — Implementation Status

This document is the engineering source of truth for the current
implementation state of Universal Trust Layer.

The purpose of this document is to prevent incomplete, simulated,
placeholder, mocked, or AI-generated functionality from being presented
as implemented security infrastructure.

## Status Definitions

### REAL

The functionality is actually implemented in production code and has
meaningful tests demonstrating the intended behavior.

### PARTIAL

Real code exists, but one or more required behaviors, security checks,
failure paths, or tests are incomplete.

### PLACEHOLDER

The architectural structure exists, but the actual implementation is
missing or represented by a stub, empty value, mock, or TODO.

### NOT IMPLEMENTED

The functionality does not currently exist.

### EXPERIMENTAL

The functionality exists for research or testing but must not be
represented as production-ready.

---

# Current Implementation

## REAL — Implemented

### Capability Tokens

- [x] CapabilityToken implementation
- [x] Ed25519 signature verification
- [x] Serialized-message verification
- [x] Public-key deserialization and verification

### Caveats

- [x] CaveatInterpreter
- [x] Expiry enforcement
- [x] Maximum-execution enforcement
- [x] Value-limit enforcement
- [x] Path-restriction enforcement
- [x] Caveats evaluated against actual request data

### Audit

- [x] TrustEngine event recording
- [x] Hash-chained audit history
- [x] Previous-event hash linking
- [x] Audit-history verification
- [x] Merkle-root generation

### Merkle

- [x] SHA-256 Merkle-root computation
- [x] Pairwise tree construction

### Reputation

- [x] Reputation updates
- [x] Weighted running-average scoring
- [x] Cold-start probation behavior
- [x] Provider tie-breaking logic

### Credentials

- [x] Credential verification
- [x] Revocation verification
- [x] Revocation signer validation
- [x] Cross-verifier revocation rejection

### Agent Mesh

- [x] X25519 key exchange
- [x] Handshake initiation
- [x] Handshake response
- [x] Signed handshake response structure

### BFT Consensus

- [x] BFT vote identity authentication
- [x] Ed25519 vote-signature verification
- [x] Protection against forged votes
- [x] Protection against duplicate/multiple votes from one identity

### Vote Network Endpoint

- [x] Sign outgoing votes
- [x] Attach valid identity signature
- [x] Verify received vote signatures
- [x] Reject unsigned votes
- [x] Reject malformed signatures
- [x] Test forged-vote rejection

### Network API

- [x] HTTP API
- [x] `/execute`
- [x] `/handshake`
- [x] `/peers`
- [x] `/vote`
- [x] API connection to orchestration logic

---

# PARTIAL — Real Code but Incomplete

## Peer Discovery

- [ ] Verify peer handshake signatures
- [ ] Authenticate discovered peer identity
- [ ] Validate handshake freshness
- [ ] Protect against replay
- [ ] Reject invalid peer signatures
- [ ] Test malicious peer discovery

Current limitation:

Peer discovery currently accepts a handshake response without completing
the required signature verification.

## Air-Gap Bundles

- [ ] Generate real bundle signature
- [ ] Verify bundle signature
- [ ] Bind signature to bundle contents
- [ ] Reject modified bundles
- [ ] Reject invalid signatures
- [ ] Test replay and tampering behavior

Current limitation:

The current exported bundle contains an empty signature placeholder.

---

# PLACEHOLDER / NOT IMPLEMENTED

## Post-Quantum Cryptography

Current status:

NOT IMPLEMENTED.

The existing PQC-related code only checks the declared algorithm name
and does not perform actual post-quantum cryptographic verification.

Therefore the project must NOT claim:

- PQC implemented
- PQC verified
- PQC secure
- PQC production-ready
- PQC-ready today

until genuine cryptographic verification exists and is tested.

---

# Required Evidence for Security Features

A security-sensitive feature must not be marked REAL merely because:

- the code compiles;
- a type exists;
- an interface exists;
- a function exists;
- a comment says it is implemented;
- an AI agent claims it is implemented;
- a happy-path test passes.

A security-sensitive feature should normally require:

1. Real implementation.
2. Positive tests.
3. Negative tests.
4. Invalid-input tests.
5. Authentication-boundary tests.
6. Authorization-boundary tests where applicable.
7. Failure-path tests.
8. Adversarial tests where applicable.
9. Clear documented assumptions.
10. Independent review for critical security components.

---

# AI Engineering Rules

AI coding agents may assist development but their claims are not
evidence of implementation.

AI-generated code must be treated as untrusted until reviewed.

Agents MUST NOT:

- claim a placeholder is implemented;
- replace missing cryptography with mock cryptography;
- silently remove security checks;
- weaken verification to make tests pass;
- create fake tests that only reproduce implementation behavior;
- mark TODO code as complete;
- claim production readiness without evidence;
- claim security guarantees that have not been demonstrated;
- invent completed functionality;
- modify security assumptions without explicitly reporting them.

Every AI-generated change must report:

- files changed;
- behavior implemented;
- tests added;
- tests executed;
- test results;
- known limitations;
- remaining TODOs;
- security assumptions.

---

# Contributor Rules

Contributors must work against clearly defined engineering tasks.

A contributor should NOT implement unrelated features simply to increase
the apparent feature count.

For security-critical work:

- preserve existing security properties;
- prefer explicit failure over silent fallback;
- never use empty signatures as successful authentication;
- never accept unverifiable identity claims;
- never replace real verification with algorithm-name checks;
- never disable a security check merely to make a test pass;
- add negative tests for newly introduced security boundaries.

---

# Feature Completion Rule

A feature is complete only when its required behavior is implemented,
tested, documented, and reviewed to the level appropriate for its risk.

If any required security property is missing, the feature remains
PARTIAL.

---

# Repository Truth Rule

The implementation status in this document must reflect the actual
repository.

When implementation changes:

1. Update this document.
2. Update relevant tests.
3. Update documentation.
4. Remove obsolete claims.
5. Clearly identify newly implemented functionality.

The repository must never intentionally represent planned or
placeholder functionality as completed functionality.

---

# Gap-Driven Development

New development should begin from a documented gap.

Each proposed contribution should identify:

- Problem
- Threat or failure mode
- Current behavior
- Required behavior
- Security assumptions
- Implementation location
- Tests required
- Acceptance criteria

No feature should be added solely because it sounds impressive.

---

# Security Status

This project must not claim to be secure, production-ready, formally
verified, or suitable for critical infrastructure merely because the
components listed as REAL exist.

Security claims require appropriate testing, review, threat modeling,
and independent assessment.

This document describes implementation status only.
