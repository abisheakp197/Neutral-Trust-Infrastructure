# Phase 11 — Real Test Status (as of this session)

Method used throughout: actual TypeScript files compiled with esbuild (real
toolchain, not a lint pass), then for the deeply-tested file, actual production
classes executed in-process with real ed25519 keys, real message passing, and
real adversarial input. No mocks, no stubbed logic.

## Status by file

| File | Compiles | Functionally tested | Notes |
|---|---|---|---|
| meshConsensus.ts | Yes | **Yes — deep** | 7 real bugs found & fixed (see below). Verified via live BFT simulation: n=4/f=1 and n=7/f=2 (the actual 3f+1 boundary), genuine double-signed equivocation every round, sync recovery exercised. All heights matched across honest nodes. |
| meshNode.ts | Yes (fixed) | No | Had a duplicate-export bug (`createMessage`/`verifyMessage` exported twice) that broke the build entirely. Fixed. Not yet logic-tested. |
| nodeDiscovery.ts | Yes (fixed) | No | Same duplicate-export bug pattern (`deriveKey`/`deriveContentKey`). Fixed. Not yet logic-tested. |
| opticalMesh.ts | Yes (fixed) | No | Had invalid call syntax (`startTracking(updateRateHz: 10)` — Python-style kwarg, invalid in TS/JS). Fixed. Not yet logic-tested. |
| jammingDefense.ts | Yes | In progress | Test harness built (synthetic RSSI time-series through the real CUSUM pipeline); not yet run/reported. |
| airGapBridge.ts | Yes | No | Compile-clean only. |
| cognitiveRadio.ts | Yes | No | Compile-clean only. |
| loraMesh.ts | Yes | No | Compile-clean only. |
| meshIntegrityVerifier.ts | Yes | No | Compile-clean only. |
| meshTimeSync.ts | Yes | No | Compile-clean only. |
| physicalResilience.ts | Yes | No | Compile-clean only. |
| powerSovereignty.ts | Yes | No | Compile-clean only. |
| rfFingerprinting.ts | Yes | No | Compile-clean only. |
| satelliteFallback.ts | Yes | No | Compile-clean only. |
| storeForward.ts | Yes | No | Compile-clean only. |

**"Compile-clean only" means**: the file is syntactically valid TypeScript and
will build. It does NOT mean the algorithm inside has been verified to behave
correctly. meshConsensus.ts is the only file where the actual logic has been
exercised under real conditions and proven to work — the other 14 still need
the same treatment before any of them should be trusted as "done."

## meshConsensus.ts — what was actually wrong and what was fixed

1. **State-machine deadlock.** `enterPropose`/`enterPrevote`/`enterPrecommit`
   each checked "are we already at the step we're about to transition into"
   before transitioning into it — impossible by construction. The engine could
   never produce a single block, with or without Byzantine actors.
2. **No idempotency guard on `enterCommit`.** Late-arriving votes could
   trigger a double-commit of the same block.
3. **`enterNewRound` preset the step marker to the wrong value**, which would
   have re-broken fix #1 once applied.
4. **BFT threshold formula was wrong.** `Math.ceil(2n/3) + 1` demands full
   unanimity at small validator-set sizes instead of the intended 2/3+1
   supermajority — defeats the purpose of fault tolerance. Fixed to the
   standard `Math.floor(2n/3) + 1`.
5. **Proposer selection silently desynced between nodes.** The original
   `ProposerSelector` mutated private state on every call; different code
   paths call `select()` a different number of times per node, so each node's
   local view of "who's the legitimate proposer" drifted apart, causing nodes
   to reject genuinely valid proposals. Replaced with a deterministic,
   stateless weighted round-robin — a pure function of (validators, height,
   round).
6. **Sync/catch-up was a dead end.** `SYNC_RESPONSE` was sent by one code path
   but never handled by any other — there wasn't even a public method to
   request a sync. A node that fell behind had no way to ever rejoin. Built
   `requestSync()` / `handleSyncResponse()` and wired both `sync:needed` sites
   to use them.
7. **Proposer's own prevote was always ~3s late.** The proposer never
   receives its own proposal over the network (self-delivery is skipped), so
   it waited out the full propose-timeout before prevoting — consistently
   missing the window other nodes used to reach quorum. Fixed: proposer now
   enters prevote immediately after broadcasting.

All seven were found and confirmed by actually running the code with
instrumented event logging, not by reading it.

## Next up
jammingDefense.ts test (CUSUM jamming detection on synthetic RF power data) is
queued, then airGapBridge.ts (Reed-Solomon FEC correctness), then the
remaining files in turn.
