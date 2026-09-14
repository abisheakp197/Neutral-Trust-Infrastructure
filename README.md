# Universal Trust Layer (UTL)

A cryptographic trust and accountability layer for autonomous agents — built in the open, from day one, for the world we're actually entering.

## Why this exists

We are entering a decade where software doesn't just run — it acts. Agents will negotiate on our behalf, move money, write and deploy code, make decisions with real consequences, and coordinate with other agents we've never met, built by people we'll never meet, running on infrastructure we don't control.

Right now, the tools securing that world are the same ones built for humans clicking buttons: API keys, OAuth tokens, firewalls. None of them answer the actual question that matters when a machine acts autonomously — "how do I know it did what it said it would do, and nothing more?"

That is the problem this project exists to solve. Not "make AI safe" in the abstract — that's not a claim any single codebase can honestly make. The specific, buildable, provable problem: give any two agents, or an agent and a human, a way to verify identity, verify authority, and verify outcome — cryptographically, not on promises.

If you're a developer reading this, here's the honest pitch: this is early. Real parts of it work today. Some parts are scaffolding waiting for someone like you to finish. That's not a weakness I'm hiding — it's the actual invitation.

## What this is not

Being direct about this up front, because the space is full of it right now:

- This is not a claim that any system can constrain a superintelligence. Nobody can honestly claim that today, and any project that does is selling you a story, not software.
- This is not "AI safety" in the philosophical sense. It's applied cryptography and distributed systems, aimed at a specific, narrow, solvable problem: authority and outcome verification between autonomous actors.
- This is not finished. Below, every component is labeled by what it actually does right now — not what it's meant to eventually do. If you only read one section, read that one.

## What's real, right now (verified by reading the code, not the pitch)

These are implemented, tested, and functionally working in the current codebase:

- Capability tokens with scoped, verifiable caveats — every action an agent takes can be gated by an expiring, cryptographically signed token that declares exactly what it's allowed to do (expiry time, max executions, value limits, path restrictions). This is a real Macaroon-style delegation model, not a design doc.
- Ed25519 signature verification on tokens, identity claims, and requests — actual public-key cryptography, properly implemented, not stubbed.
- A tamper-evident audit hash chain — every recorded decision links to the hash of the one before it, batched into Merkle-rooted groups, with a verify_history() function that actually recomputes and checks every hash. If someone tampers with history, this catches it.
- A working reputation system with a genuine cold-start mechanism — new, unproven providers get a real, randomized chance to be selected even against established high-reputation ones, so the network doesn't calcify around early incumbents.
- Cross-verifier revocation protection — one verifier cannot revoke another verifier's credential; the code checks the actual signature on the revocation notice before honoring it.
- X25519 Diffie-Hellman handshakes between agents for real key exchange, with signed responses.
- A working HTTP API (via warp) exposing /execute, /handshake, /peers, and /vote endpoints, wired to real orchestration logic underneath — not mockups.

Run the demos yourself:

cd ube-foundation
cargo run --example capability_demo
cargo run --example agent_demo
cargo run --example mesh_demo
cargo run --example trust_marketplace_demo
cargo run --example planning_demo
cargo test

If something here doesn't work as described, that's a bug report, not a surprise — open an issue.

## What's structurally present but incomplete (this is where you come in)

This is the honest middle ground, and it's also the highest-leverage place for a contributor to start:

- BFT-style consensus voting counts votes and checks agreement on outcome hashes, but does not yet verify the cryptographic signature of each voter. The shape of Byzantine fault tolerance is there; the security isn't wired in yet.
- The network /vote endpoint constructs and transmits a vote object with an empty, unsigned signature field. It needs real signing against the voter's identity key before it can be trusted over an untrusted network.
- Peer discovery via handshake accepts a peer's identity claim without yet verifying the signature on the response. This is the next thing standing between "peers can talk" and "peers can trust who they're talking to."
- Air-gap bundle export has the right structure (Merkle root, batch, signature field) but the signature itself is a placeholder — it doesn't sign anything yet.

If you're a systems or cryptography engineer looking for a meaningful first contribution, any one of these four is a real, scoped, valuable piece of work — not a toy issue.

## What's an explicit, honest goal — not yet true

Post-quantum cryptography (PQC). The code currently checks that a declared algorithm name equals "Dilithium5" as a string — that is not post-quantum verification, and I'm not going to pretend it is. Actual PQC (Dilithium, Kyber) integration is a real goal of this project, not a marketing checkbox, and it's one of the most valuable places an experienced cryptography contributor could make an immediate, visible difference. If this is your area, this is your invitation.

Claiming this is "PQC-ready" today would be exactly the kind of overstatement that makes serious engineers stop reading. So instead: it's on the roadmap, it matters, and it's unclaimed. Take it.

## Who this is for

If you recognize yourself in one of these, keep reading:

- Systems and distributed-systems engineers who want to work on real consensus, networking, and fault-tolerance problems with actual adversarial stakes, not academic toy examples.
- Applied cryptographers who want to take a project from "structurally ready" to "cryptographically sound" — signing, PQC, zero-knowledge proofs, threshold schemes — and see their work matter to something being built in the open.
- AI agent builders who are already running into the exact problem this solves: your agents call other people's agents, and right now you have no real way to verify what they did versus what they claim they did.
- Early-stage engineers who want ownership on a project from near-zero, not a fork of someone else's roadmap — where a well-scoped PR on the consensus-signing gap above could become the foundation others build on.

## Bring what I haven't thought of

Everything above is scoped to gaps I already know about. That's not the ceiling — it's the floor.

If you look at this problem — verifiable trust between autonomous agents — and see an angle, a primitive, or an entire approach I haven't considered, that's not out of scope. This project doesn't need more hands finishing my list; it needs people who see something in this space that I don't. Open an issue, propose it, argue for it even if it means ripping out something I built. The goal was never "my design, executed by others" — it's the strongest, most real version of this problem getting solved, however that happens.

## Why I'm building this, and why in the open

I'm one person. I can't build the whole trust infrastructure this future needs by myself, and pretending otherwise would slow this down, not speed it up. So this is being built in the open, honestly, from the start — not as a growth hack, not as a bait-and-switch.

Here's the actual, stated plan, so nobody joining this is surprised later:

- The core trust layer — identity, capability tokens, outcome verification, consensus — stays open. This is the part that needs to be trusted by everyone, which means it needs to be inspectable by everyone. A trust protocol that isn't open source is asking people to trust it on faith, which defeats the entire point.
- The business, when it exists, will be built on top of this layer — hosted infrastructure, enterprise compliance tooling, managed deployments, support — the same way most successful open infrastructure companies have built sustainable businesses without ever taking back what the community built together.
- Anyone who contributes meaningfully early is not free labor for someone else's exit. Real contribution — code, review, design, testing — earns real ownership conversations as this moves toward being a company, not just a thank-you in a commit log.

I want to be direct about the ambition here, because I think false modesty wastes everyone's time: I think agent-to-agent trust is going to be one of the foundational infrastructure layers of the next decade, the way TCP/IP and HTTPS were foundational to the internet nobody could have built alone. I don't know yet exactly what this becomes. Neither did the people who started building the protocols we now take for granted. What I do know is that it has to be real, it has to be honest about what it is at every stage, and it has to be built by more hands than mine.

If that's a problem you want to work on — not because I'm asking you to believe a pitch, but because you read the code above and it held up — this is where you start.

## Build it real, build it fast, build it strong

Every one of you reading this is building something. There are millions of repos, millions of ideas, millions of half-finished side projects. What separates infrastructure that lasts from the rest isn't the size of the vision — it's whether it's real, whether it's tested, and whether it's secure enough that someone can build their own work on top of it without fear.

That's the standard for every contribution here. Not the fastest hack that makes a demo look impressive — the version that's actually correct, actually signed, actually verified, actually hard to break. If you find a weak spot, harden it. If you see a gap, close it with a real implementation and a real test, not a comment promising it later. Move fast on the work that's genuinely done, and be honest the moment something isn't.

This is how we make this strong enough for the world it's built for — a world full of autonomous systems acting at machine speed, where the only thing standing between order and chaos is whether the trust underneath is real.

## Getting started

git clone https://github.com/abisheakp197/Universal-Trust-Layer.git
cd Universal-Trust-Layer/ube-foundation
cargo build
cargo test

Look at the "structurally present but incomplete" section above for real, scoped first contributions — or bring your own, per the section above. Open an issue before a large PR so we can align on approach — this project would rather have five focused, honest PRs than one sprawling one.

## Contributing

- Read the code before the pitch. If something in this README doesn't match what you find in src/, file an issue — that's a documentation bug, and it matters more here than in most projects, because honesty about current state is the product's credibility.
- Small, provable, tested changes over large speculative ones.
- If you're adding a claim (a new capability, a new guarantee), add the test that proves it in the same PR.

## License

Licensed under the Apache License, Version 2.0. See the LICENSE file for full terms.

This means: you're free to use, modify, and distribute this code — including in commercial products — as long as you include the original copyright notice and state any changes you made. It includes an explicit patent grant, which matters for a cryptography project: contributors and users are protected from patent claims tied to contributions made here.

Contributions require agreeing to the Contributor License Agreement (CLA) in CONTRIBUTING.md — this keeps the core layer genuinely open while giving the project room to build a sustainable business on top of it later, without ever taking back what's built here in the open.
