Universal Trust Layer — Contributor Engineering Roadmap

Mission

Universal Trust Layer is being built as trust infrastructure for systems that need to make, authorize, execute, verify, and audit decisions safely.

The goal is not to build a collection of demos or isolated features.

The goal is to build a reliable trust core that can eventually support infrastructure-scale systems.

Contributors should therefore focus on making the existing system real, secure, testable, recoverable, and production-grade before adding unnecessary features.

---

1. CONTRIBUTION MODEL

There are three levels of contribution.

Level 1 — FIX

Find something that is broken, incomplete, unsafe, misleading, or insufficiently tested.

Process:

1. Identify the problem.
2. Open or claim an issue.
3. Explain the security/engineering impact.
4. Implement the fix.
5. Add or update tests.
6. Run the complete relevant test suite.
7. Document the change.
8. Submit a pull request.
9. Maintainers review the implementation.
10. Merge only after the acceptance criteria are satisfied.

---

Level 2 — IMPROVE

Find an existing subsystem that works but is not strong enough for serious infrastructure use.

Process:

1. Identify the limitation.
2. Explain why it matters.
3. Propose the improvement.
4. Define the interface and behavior.
5. Implement it.
6. Add adversarial and regression tests.
7. Benchmark if performance is relevant.
8. Document compatibility implications.
9. Submit a pull request.
10. Maintainers review and merge.

---

Level 3 — INVENT

Contributors may eventually propose completely new modules.

However, new modules must solve a real infrastructure problem.

Do not propose a module simply because it sounds technically interesting.

A new module proposal must contain:

1. Real-world problem.
2. Threat model.
3. Trust/security assumptions.
4. Proposed architecture.
5. Inputs.
6. Outputs.
7. Interfaces/contracts.
8. Failure behavior.
9. Recovery behavior.
10. Audit requirements.
11. Privacy considerations.
12. Tests.
13. Adversarial tests.
14. Performance requirements where relevant.
15. Clear acceptance criteria.

New modules require architectural review before implementation.

---

2. ENGINEERING PRINCIPLES

All contributors should follow these principles.

Security over convenience

If a shortcut weakens trust guarantees, do not use the shortcut simply to make the implementation easier.

Explicit trust

Do not assume that an identity, vote, token, peer, or message is authentic.

Authentication and authorization must be explicitly verified.

Fail closed for security decisions

When the system cannot establish that an operation is trustworthy, the default should not silently become permission.

No fake implementations

Do not leave placeholders that look like production security.

Examples:

- Empty signatures.
- Fake cryptographic verification.
- Algorithm-name checks without cryptographic verification.
- Tests that claim security properties they do not actually test.
- Security documentation describing functionality that does not exist.

If something is not implemented, clearly label it as NOT IMPLEMENTED.

Every security property must be testable

A security claim should have a corresponding test.

Deterministic behavior

The same valid input and state should produce predictable results unless randomness is explicitly part of the design.

Auditability

Important trust decisions should produce verifiable evidence.

Recovery

Infrastructure cannot depend on process memory alone.

State must eventually have a defined persistence and recovery model.

Minimal coupling

Modules should communicate through explicit interfaces/contracts rather than hidden dependencies.

Backward compatibility

Changes to public interfaces and trust semantics must be deliberate and documented.

---

3. DEVELOPER TRACKS

The project is divided into the following engineering tracks.

Priority levels:

CRITICAL = security or trust-core blocker.

HIGH = required for serious infrastructure use.

MEDIUM = important production engineering.

---

TRACK 1 — CRYPTOGRAPHY AND AUTHENTICITY

Priority: CRITICAL

Owner profile:

Cryptography / Rust / security engineer.

Primary responsibility:

Make sure identities, tokens, votes, messages, and cryptographic claims are actually authenticated.

Tasks

1.1 Capability token authenticity

The repository contains CapabilityToken verification using Ed25519.

Verify that every security-sensitive path that accepts a capability token actually calls cryptographic verification.

Do not rely only on:

- capability name
- expiration
- caveats
- token structure

A token must be authenticated before it is trusted.

Acceptance criteria:

- Invalid signature is rejected.
- Modified token is rejected.
- Wrong public key is rejected.
- Valid signature is accepted.
- Expired token is rejected.
- Revoked token is rejected.
- Tests cover all cases.
- No production path bypasses token signature verification.

---

1.2 Action request authentication

Review all paths accepting ActionRequest objects.

Determine exactly when signatures are mandatory.

Security-sensitive remote operations must not become trusted simply because the signature field is missing.

Acceptance criteria:

- Define which requests require authentication.
- Reject malformed signatures.
- Reject signatures from the wrong identity.
- Test modified requests.
- Test missing signatures.
- Test valid signatures.

---

1.3 PQC implementation

The current code contains a Dilithium/PQC algorithm check but the actual cryptographic verification is not implemented.

Do not describe this as completed PQC security.

Choose one:

A. Implement real PQC verification using a maintained, audited cryptographic implementation.

OR

B. Remove/reframe the PQC claim until real verification exists.

Acceptance criteria:

- Real cryptographic verification exists, OR the unsupported claim is removed.
- Invalid PQC signatures fail.
- Modified messages fail.
- Correct signatures pass.
- Dependencies are documented.
- Security assumptions are documented.

---

1.4 Cryptographic key lifecycle

Define:

- key generation
- key storage
- key rotation
- key revocation
- key expiration
- identity replacement
- compromised-key handling

Acceptance criteria:

- Key lifecycle is documented.
- Tests cover rotation and revocation.
- Old keys cannot unexpectedly authorize new operations.

---

TRACK 2 — CONSENSUS AND DISTRIBUTED TRUST

Priority: CRITICAL

Owner profile:

Distributed systems / consensus / Rust engineer.

Primary responsibility:

Make distributed trust decisions cryptographically authenticated and deterministic.

Tasks

2.1 Authenticate consensus votes

Current consensus logic counts votes but does not properly verify who created each vote.

The network vote endpoint currently has an empty signature placeholder.

Implement real vote authentication.

Acceptance criteria:

- Every remote vote has an authenticated identity.
- Vote signatures are verified.
- Invalid signatures are rejected.
- Forged voter identities are rejected.
- Duplicate/unauthorized voters cannot increase consensus.
- Tests cover forged votes.
- Tests cover modified votes.
- Tests cover duplicate votes.

---

2.2 Define voter authorization

Authentication alone is not enough.

Define:

- who is allowed to vote
- what capabilities voters require
- how voter identity is established
- how revoked voters are handled
- how membership changes

Acceptance criteria:

- Unauthorized identities cannot participate.
- Revoked identities cannot participate.
- Membership rules are explicit.
- Tests cover unauthorized voters.

---

2.3 Define consensus failure behavior

The orchestrator currently has fallback behavior when consensus is not reached.

Review whether falling back to another module is acceptable for a trust decision.

Define exact behavior for:

- insufficient votes
- conflicting votes
- unavailable voters
- timeout
- invalid vote
- malicious voter
- network partition

Acceptance criteria:

- Consensus failure behavior is explicitly defined.
- Security-sensitive actions fail safely.
- No silent trust downgrade occurs.
- Tests cover every failure mode.

---

2.4 Replay protection for votes

Votes must not be reusable in another decision.

Introduce appropriate:

- request IDs
- decision IDs
- nonces
- timestamps/epochs
- domain separation

Acceptance criteria:

- Replayed votes are rejected.
- Votes from another decision cannot be reused.
- Tests demonstrate replay rejection.

---

TRACK 3 — SECURE NETWORKING AND MESH

Priority: CRITICAL

Owner profile:

Network security / distributed systems / Rust engineer.

Primary responsibility:

Secure communication between Trust Layer nodes.

Tasks

3.1 Verify peer handshake signatures

The system performs X25519 key exchange.

The peer discovery path must also authenticate the peer identity and handshake response.

Acceptance criteria:

- Handshake response signatures are verified.
- Modified handshake messages are rejected.
- Unknown identities are rejected according to policy.
- Key exchange cannot silently establish trust with an unauthenticated peer.

---

3.2 Secure peer discovery

Review:

- peer identity
- peer authorization
- endpoint validation
- replay protection
- duplicate peers
- revoked peers
- malicious peers

Acceptance criteria:

- Peer identity is authenticated.
- Revoked peers are rejected.
- Replay attacks are rejected.
- Invalid peer data cannot corrupt trust state.

---

3.3 Network API security

Review:

- /execute
- /handshake
- /peers
- /vote

Implement appropriate:

- authentication
- authorization
- request size limits
- rate limiting
- timeouts
- malformed-input handling
- secure error responses

Acceptance criteria:

- Unauthorized remote execution is rejected.
- Oversized requests are rejected.
- Malformed requests do not crash the service.
- Requests cannot bypass trust checks through the API layer.

---

3.4 Transport security

Define the production transport model.

Possible requirements include:

- authenticated encrypted transport
- certificate/public-key identity
- secure key exchange
- peer authorization

The exact mechanism must be selected based on the architecture rather than added blindly.

---

TRACK 4 — AUDIT, PROVENANCE AND INTEGRITY

Priority: HIGH

Owner profile:

Rust / cryptography / storage engineer.

Primary responsibility:

Ensure trust decisions can be independently verified after the fact.

Tasks

4.1 Global audit sequence

The current audit sequence is derived from the in-memory event count.

Review behavior across batch commits and restarts.

Define a globally monotonic event sequence or another explicit ordering model.

Acceptance criteria:

- Sequence semantics are documented.
- Events cannot unexpectedly reuse sequence numbers.
- Restart/recovery behavior is defined.
- Tests cover batching and restart.

---

4.2 Audit persistence

The current trust engine keeps important state in memory.

Design persistent storage for:

- events
- hashes
- batches
- Merkle roots
- decisions
- identities
- revocations

Acceptance criteria:

- State survives process restart.
- Corruption is detected.
- Integrity verification works after recovery.
- Recovery tests exist.

---

4.3 Crash recovery

Test failures during:

- event creation
- batch creation
- persistence
- network communication
- consensus
- execution

Acceptance criteria:

- Partial operations have defined recovery behavior.
- Corrupted state is detected.
- Trust state does not silently become inconsistent.

---

4.4 Audit export

Audit data should be exportable in a verifiable format.

Define:

- format
- version
- integrity metadata
- signatures
- verification procedure

---

TRACK 5 — AUTHORIZATION, CAVEATS AND POLICY

Priority: HIGH

Owner profile:

Security / authorization / Rust engineer.

Primary responsibility:

Make authorization decisions precise and resistant to bypass.

Tasks

5.1 Caveat value limits

Review value-limit enforcement.

Ensure units/currency are not silently ignored.

Acceptance criteria:

- Units are explicit.
- Currency is explicit where required.
- Invalid values are rejected.
- Tests cover boundary conditions.

---

5.2 Missing-value handling

Review cases where missing request fields become default values.

Security-sensitive missing data should not automatically become safe values.

Acceptance criteria:

- Required fields are explicit.
- Missing security-critical values are rejected.
- Tests cover missing fields.

---

5.3 Path restrictions

Review path caveats.

Simple prefix checks can create path-confusion problems.

Example class of problem:

Allowed path:

/data/app

Potentially problematic path:

/data/application

Define secure path authorization using appropriate canonicalization and boundary checking.

Also review:

- ../ traversal
- symlinks
- relative paths
- absolute paths
- platform-specific path behavior

Acceptance criteria:

- Path traversal tests exist.
- Prefix-confusion tests exist.
- Symlink behavior is defined.
- Canonicalization behavior is defined.

---

5.4 Policy engine

Document and test the policy evaluation order.

Define precedence between:

- identity
- capability
- caveat
- policy
- risk
- revocation
- consensus
- execution

Acceptance criteria:

- Evaluation order is documented.
- Conflicting policies have deterministic behavior.
- Tests cover conflicts.

---

TRACK 6 — EXECUTION AND MODULE BOUNDARIES

Priority: HIGH

Owner profile:

Rust systems engineer / sandboxing engineer.

Primary responsibility:

Prevent trusted decisions from becoming unsafe execution.

Tasks

6.1 Module isolation

Review SystemModule filesystem access.

Define what a module is allowed to access.

Acceptance criteria:

- Module permissions are explicit.
- Unauthorized filesystem access is rejected.
- Tests attempt access outside allowed boundaries.

---

6.2 Path sandboxing

Secure operations such as:

- write_file
- list_dir

against:

- path traversal
- symlinks
- unauthorized directories
- unexpected filesystem behavior

---

6.3 Resource limits

Define limits for:

- execution time
- memory
- CPU
- output size
- retries
- network access
- filesystem operations

Acceptance criteria:

- Limits are configurable.
- Exceeding a limit produces a controlled failure.
- Tests cover resource exhaustion.

---

6.4 Idempotency

Infrastructure operations must define what happens when the same operation is submitted twice.

Acceptance criteria:

- Operations have an idempotency strategy.
- Duplicate requests do not unexpectedly produce duplicate side effects.
- Tests cover repeated execution.

---

6.5 Rollback/recovery

Define what can be undone and what cannot.

Every module should document:

- action
- side effect
- verification
- rollback/recovery strategy

---

TRACK 7 — SECURITY TESTING AND FUZZING

Priority: CRITICAL

Owner profile:

Security researcher / fuzzing / Rust testing engineer.

Primary responsibility:

Try to break the Trust Layer.

This contributor should not only confirm that the system works.

They should actively attempt to make it fail.

Tasks

7.1 Signature attacks

Test:

- invalid signatures
- modified messages
- wrong keys
- empty signatures
- truncated signatures
- malformed keys
- replayed signatures

---

7.2 Token attacks

Test:

- forged tokens
- modified tokens
- expired tokens
- revoked tokens
- wrong capability
- caveat bypass
- malformed serialization

---

7.3 Consensus attacks

Test:

- forged voters
- duplicate voters
- replayed votes
- conflicting votes
- unauthorized voters
- malicious voters
- missing voters
- network partitions

---

7.4 Network attacks

Test:

- malformed requests
- oversized requests
- handshake manipulation
- replay
- unauthorized peers
- invalid peer identities
- connection exhaustion

---

7.5 Filesystem attacks

Test:

- ../ traversal
- absolute paths
- symlink attacks
- prefix confusion
- unauthorized directories
- malformed paths

---

7.6 Property-based testing

Where appropriate, use property-based tests for:

- serialization
- hashing
- Merkle trees
- audit chains
- caveat evaluation
- consensus logic

---

7.7 Fix overclaiming tests

Review existing tests.

A test must prove the property it claims to prove.

If a test says "replay is rejected", it must actually submit a replay and assert rejection.

If a test says "signature verification works", it must test invalid and valid signatures.

---

TRACK 8 — AIR-GAP AND OFFLINE TRUST

Priority: HIGH

Owner profile:

Cryptography / distributed systems / secure systems engineer.

Tasks

8.1 AirGapBundle authentication

The current export path contains an empty signature placeholder.

Implement real signing or clearly mark the feature as incomplete.

Acceptance criteria:

- Bundle is authenticated.
- Modified bundle is rejected.
- Wrong signer is rejected.
- Replay protection is defined.

---

8.2 Offline verification

Define how a disconnected system verifies:

- identity
- bundle authenticity
- integrity
- version
- revocation state
- synchronization state

---

8.3 Secure synchronization

Review registry synchronization.

Do not rely only on matching a Merkle root without authenticating the source and synchronization context.

---

TRACK 9 — PRODUCTION ARCHITECTURE AND INTEGRATION

Priority: MEDIUM -> HIGH

Owner profile:

Senior systems architect / platform engineer.

Primary responsibility:

Turn independent subsystems into a coherent infrastructure product.

Tasks

9.1 Versioned contracts

Define stable interfaces between:

- identity
- authorization
- policy
- risk
- consensus
- execution
- verification
- audit
- networking
- persistence

---

9.2 Configuration model

Define production configuration for:

- security mode
- consensus thresholds
- network settings
- storage
- limits
- identities
- policies

Avoid hidden hard-coded security behavior.

---

9.3 Observability

Define safe operational visibility:

- health
- metrics
- errors
- decision outcomes
- latency
- consensus status
- storage status

Do not leak sensitive trust data unnecessarily.

---

9.4 Deployment model

Define how the Trust Layer can eventually run as:

- local infrastructure
- server
- cluster
- edge node
- isolated environment

The architecture should not depend unnecessarily on one cloud provider.

---

9.5 Compatibility and upgrades

Define:

- protocol version
- state version
- migration strategy
- backward compatibility
- incompatible upgrade handling

---

4. CONTRIBUTOR DEVELOPMENT ORDER

Do not build everything randomly.

Recommended order:

PHASE 1 — IMPLEMENTATION TRUTH

First identify everything that is:

- implemented
- partial
- placeholder
- undocumented
- falsely claimed as complete

No new major features until this map is accurate.

---

PHASE 2 — CRITICAL SECURITY

Priority order:

1. Token authentication.
2. Action authentication.
3. Consensus vote authentication.
4. Peer authentication.
5. Replay protection.
6. Network API security.
7. PQC implementation or removal of false claims.
8. AirGap authentication.

---

PHASE 3 — SECURITY TESTING

After fixes:

1. Unit tests.
2. Integration tests.
3. Adversarial tests.
4. Fuzzing.
5. Regression tests.
6. Failure injection.

Every security fix must have a regression test.

---

PHASE 4 — AUDIT AND PERSISTENCE

Build:

1. Persistent audit state.
2. Crash recovery.
3. Global ordering.
4. Verifiable audit export.
5. Recovery testing.

---

PHASE 5 — EXECUTION SAFETY

Secure:

1. Module boundaries.
2. Filesystem access.
3. Resource limits.
4. Idempotency.
5. Rollback/recovery.
6. Failure handling.

---

PHASE 6 — NETWORK AND DISTRIBUTED OPERATION

Harden:

1. Peer identity.
2. Secure transport.
3. Peer authorization.
4. Consensus.
5. Synchronization.
6. Partition/failure behavior.

---

PHASE 7 — INTEGRATION

Connect all components through stable contracts.

Test the complete trust flow:

INPUT
→ IDENTITY
→ AUTHORIZATION
→ POLICY
→ RISK
→ CONSENSUS
→ EXECUTION
→ VERIFICATION
→ AUDIT
→ RECOVERY

---

PHASE 8 — INDEPENDENT SECURITY REVIEW

Before claiming production readiness:

- attempt to break the system
- review cryptographic assumptions
- review authorization boundaries
- review network trust
- review persistence
- review execution isolation
- review documentation claims

---

PHASE 9 — NEW MODULES

Only after the existing trust core is sufficiently hardened should contributors begin proposing major new modules.

New modules must solve real infrastructure problems.

---

5. NEW MODULE PROPOSAL STANDARD

A contributor proposing a new module must submit:

Problem

What real infrastructure problem does this solve?

Users

Who needs it?

Threat model

Who can attack it?

What can they control?

What must they not be able to do?

Trust assumptions

What does the module trust?

What does it refuse to trust?

Inputs

What enters the module?

Decision / Processing

What does it do?

Outputs

What does it produce?

Interfaces

How does it communicate with the existing Trust Layer?

Security

What prevents bypass?

Audit

What evidence is recorded?

Failure

What happens when something goes wrong?

Recovery

How does the system recover?

Testing

What normal, malicious, and failure cases are tested?

Acceptance criteria

What measurable conditions prove that the module is complete?

---

6. MODULE DESIGN RULE

Every module should follow the basic model:

INPUT
→ VALIDATE
→ TRUST/POLICY DECISION
→ ACTION
→ VERIFY
→ AUDIT
→ RECOVER/ROLLBACK WHERE POSSIBLE

Modules must not bypass the trust core simply because direct implementation is easier.

---

7. CONTRIBUTOR ROLES

The project can be divided among contributors as follows.

Developer 1 — Cryptography

Own:

- tokens
- signatures
- identities
- PQC
- key lifecycle

Priority: CRITICAL

---

Developer 2 — Consensus

Own:

- votes
- voter authentication
- consensus rules
- replay protection
- distributed decision behavior

Priority: CRITICAL

---

Developer 3 — Networking

Own:

- peer discovery
- handshake authentication
- network API
- transport
- rate limits
- network security

Priority: CRITICAL

---

Developer 4 — Security Testing

Own:

- adversarial tests
- fuzzing
- attack simulations
- regression tests
- security-property verification

Priority: CRITICAL

---

Developer 5 — Audit/Persistence

Own:

- event store
- audit chain
- persistence
- recovery
- audit export
- crash consistency

Priority: HIGH

---

Developer 6 — Authorization/Policy

Own:

- capabilities
- caveats
- policy engine
- path restrictions
- authorization semantics

Priority: HIGH

---

Developer 7 — Execution/Sandbox

Own:

- module isolation
- filesystem safety
- resource limits
- idempotency
- rollback/recovery

Priority: HIGH

---

Developer 8 — Air-Gap

Own:

- offline bundles
- signing
- offline verification
- synchronization

Priority: HIGH

---

Developer 9 — Architecture/Integration

Own:

- contracts
- versioning
- configuration
- observability
- deployment
- integration

Priority: MEDIUM → HIGH

---

8. HOW CONTRIBUTORS SHOULD WORK

Do not directly modify unrelated subsystems.

For every contribution:

1. Read the relevant architecture/documentation.
2. Find the existing implementation.
3. Understand the current behavior.
4. Open or claim an issue.
5. Define the security/engineering problem.
6. Make the smallest correct architectural change.
7. Add tests.
8. Run tests.
9. Document behavior.
10. Submit a pull request.
11. Explain security implications.
12. Wait for review.
13. Address review feedback.
14. Merge only after acceptance criteria are satisfied.

---

9. PULL REQUEST REQUIREMENTS

Every serious pull request should explain:

What changed?

Short technical description.

Why?

What problem does it solve?

Security impact

Does it change:

- authentication?
- authorization?
- cryptography?
- trust?
- network behavior?
- execution?
- auditability?

Tests

List tests added or modified.

Failure cases

Explain how invalid input behaves.

Compatibility

Explain whether existing behavior changes.

Documentation

Update documentation when behavior or interfaces change.

---

10. WHAT CONTRIBUTORS SHOULD NOT DO

Do not:

- add fake cryptography
- leave security placeholders without clearly marking them
- bypass authentication
- weaken authorization to make tests pass
- silently change trust semantics
- introduce unnecessary dependencies
- create hidden global state
- add major features without architectural review
- claim production readiness without evidence
- write tests that only test the happy path
- remove failing security tests instead of fixing the underlying problem
- make unrelated changes in the same pull request

---

11. DEFINITION OF DONE

A feature is not considered complete merely because the code compiles.

A security-sensitive feature is complete only when:

- implementation exists
- interfaces are defined
- security assumptions are documented
- failure behavior is defined
- tests exist
- adversarial tests exist where applicable
- regression tests exist
- documentation matches reality
- no known placeholder remains
- relevant reviewers approve it

---

12. LONG-TERM CONTRIBUTOR PATH

The project should evolve in this order:

FIX
↓
HARDEN
↓
TEST
↓
PERSIST
↓
INTEGRATE
↓
VERIFY
↓
INDEPENDENTLY REVIEW
↓
RELEASE TRUST CORE
↓
IDENTIFY REAL INFRASTRUCTURE PROBLEMS
↓
PROPOSE NEW MODULES
↓
REVIEW
↓
PROTOTYPE
↓
ADVERSARIAL TEST
↓
PRODUCTION IMPLEMENTATION

---

13. CORE PRINCIPLE FOR NEW CONTRIBUTORS

Do not ask:

"What cool feature can I add?"

Ask:

"What real trust problem prevents infrastructure systems from safely operating, and can Universal Trust Layer solve it?"

The best contribution is not necessarily the largest contribution.

The best contribution is one that makes the Trust Layer more trustworthy, more verifiable, more resilient, or more useful for real infrastructure.

---

14. PROJECT STANDARD

Universal Trust Layer should remain:

- security-first
- implementation-driven
- auditable
- testable
- modular
- interoperable
- recoverable
- resistant to unauthorized trust
- honest about implementation status

Build the foundation first.

Then build the systems that depend on it.
