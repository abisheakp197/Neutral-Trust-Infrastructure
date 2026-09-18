# Neutral Trust Infrastructure (NTI)

[![License: PolyForm Shield 1.0.0](https://img.shields.io/badge/License-PolyForm_Shield_1.0.0-6A5ACD.svg)](LICENSE.md)
[![Language: Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg)](#getting-started)

**A cryptographic trust and accountability layer for autonomous agents—built for the machine-to-machine world we are actually entering.**

---

### Commercial & Source-Available Notice
Neutral Trust Infrastructure is published under the **PolyForm Shield License 1.0.0** (Source-Available / Non-Compete).

* **Open Access:** Free for personal, academic, research, and non-competing internal operational use.
* **Commercial Protection:** Managed SaaS offerings, commercial cloud hosting, or competing commercial implementations require an enterprise license.
* **Contributions:** All external contributors must sign the Contributor License Agreement (CLA) in `CONTRIBUTING.md` prior to merging pull requests.

---

## Why This Exists

We are entering a decade where software doesn't just run—it acts. Autonomous agents will negotiate on our behalf, move money, write and deploy code, execute physical actions, and coordinate with third-party agents running on infrastructure we do not control.

Right now, the tools securing that world are the same ones built for humans clicking buttons: API keys, OAuth tokens, and firewalls. None of them answer the actual question that matters when a machine acts autonomously: 

> **"How do I mathematically prove an autonomous agent executed its precise authorization policy—and nothing more?"**

That is the problem NTI exists to solve. Not "AI safety" in the abstract—that is not a claim any single codebase can make. The specific, buildable, provable problem: **give any two agents, or an agent and a human, a way to verify identity, verify authority, and verify outcome cryptographically rather than on promises.**

---

## What This Is Not

To be completely direct up front:

* **This is not a claim that any system can constrain a superintelligence.** Nobody can honestly claim that today, and any project that does is selling a story, not software.
* **This is not "AI safety" in the philosophical sense.** It is applied cryptography and distributed systems, aimed at a narrow, solvable problem: authority delegation and outcome verification between autonomous actors.
* **This is not finished.** Every component below is explicitly labeled by what it actually does right now versus what is structurally incomplete.

---

## What Is Real, Right Now (Verified by Code)

These features are implemented, tested, and functionally working in the current codebase:

* **Capability Tokens with Scoped Caveats:** Every action an agent takes can be gated by an expiring, cryptographically signed token declaring exactly what it is allowed to do (expiry time, max executions, value limits, path restrictions). This is a real Macaroon-style delegation model.
* **Ed25519 Cryptography:** Built-in public-key signature verification on tokens, identity claims, and network requests.
* **Tamper-Evident Audit Chains:** Sequential decision logging backed by Merkle trees, featuring a functional `verify_history()` routine that dynamically recomputes and verifies hash chains to catch history tampering.
* **Cold-Start Reputation Engine:** A non-calcifying network selection algorithm ensuring new, unproven providers get a randomized chance to be selected alongside established high-reputation nodes.
* **Cross-Verifier Revocation Protection:** One verifier cannot revoke another verifier's credential; the codebase checks signature authority on revocation notices before honoring them.
* **X25519 Key Exchange:** Diffie-Hellman handshakes between agents for real key exchange with signed mutual responses.
* **Working HTTP API Engine:** Built using `warp`, exposing live `/execute`, `/handshake`, `/peers`, and `/vote` endpoints wired directly into core orchestration logic.

---

## Structurally Present but Incomplete (Where You Come In)

This is the highest-leverage place for a systems engineer or cryptographer to contribute:

1. **BFT-Style Consensus Verification:** Consensus logic counts votes and checks outcome hashes, but does not yet verify the cryptographic signature of each voter key. The Byzantine fault tolerance structure is present; signature verification needs wiring.
2. **Signed `/vote` Endpoints:** The network `/vote` route constructs and transmits vote objects with an unpopulated signature field. It requires active signing against the voter's identity key.
3. **Handshake Peer Verification:** Peer discovery via handshake accepts identity claims but does not yet enforce signature validation on the initial response receipt.
4. **Air-Gap Bundle Signing:** State export bundles contain Merkle roots and batch structures, but digital signature generation on the exported bundle is currently a placeholder.

---

## Strategic Roadmap: Post-Quantum Cryptography (PQC)

The codebase currently evaluates `"Dilithium5"` as a string identifier—this is a structural placeholder, not post-quantum verification. 

Actual PQC integration (CRYSTALS-Dilithium, Kyber) is a core goal of this project. If you are an experienced applied cryptographer who wants to implement production PQC in Rust, this crate is ready for your contribution.

---

## Who This Is For

* **Systems & Distributed Engineers:** Who want to solve consensus, networking, and fault-tolerance problems with real adversarial stakes.
* **Applied Cryptographers:** Who want to transition a project from "structurally ready" to "cryptographically sound"—signing, PQC, zero-knowledge proofs, and threshold schemes.
* **AI Agent Builders:** Who need verifiable proof of what external agents executed versus what they claimed to execute.
* **Core Contributors:** Who want ground-floor ownership on an infrastructure protocol from the start.

---

## Why I'm Building This (Founder's Vision)

Agent-to-agent trust will be one of the foundational infrastructure layers of the next decade—the way TCP/IP and HTTPS were foundational to the early web.

Here is the straightforward plan:

1. **Contributor License Agreement:** Contributions are submitted under the CLA in `CONTRIBUTING.md`.
2. **Commercial Direction:** NTI is run as a commercially protected, source-available project under the founding team.
3. **Real Ownership:** Meaningful, early contributions—code, architecture, cryptography, testing—lead directly to conversations regarding equity, founding roles, and ownership as NTI scales into an enterprise company.

---

## Getting Started

```bash
# Clone the repository
git clone [https://github.com/abisheakp197/Neutral-Trust-Infrastructure.git](https://github.com/abisheakp197/Neutral-Trust-Infrastructure.git)
cd Neutral-Trust-Infrastructure/ube-foundation

# Build project and run test suite
cargo build
cargo test

# Run local demonstration suites
cargo run --example capability_demo
cargo run --example agent_demo
cargo run --example mesh_demo
cargo run --example trust_marketplace_demo
cargo run --example planning_demo
