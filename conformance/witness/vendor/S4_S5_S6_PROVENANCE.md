# S4 / S5 / S6 provenance — scripts could not be vendored

Decision on record: vendor the S4/S5/S6 scripts into NTI under Apache-2.0 so
there are frozen bytes to hash.

**This could not be carried out. No S4/S5/S6 script exists in any source
reachable from this environment, and the only repository that holds them is
private and not Apache-2.0 licensed.** The details are recorded here so the
gap is auditable rather than silently dropped.

## What S4, S5 and S6 are

They are named invariants of the **Agent Safety Layer (ASL)** project, not of
NTI. They appear in the ASL invariants table (public copy:
`Raja549h/asl-conformance-kit`, `docs/invariants.md`):

| ID | Invariant |
| :-- | :-------- |
| S4 | Thresholds are quiet on ordinary traffic, but the tripwire still fires. |
| S5 | Every kill path still fires the complete cascade. |
| S6 | Not defined in the public ASL conformance kit revision. |

The tests that implement S4 and S5 are named in that table, e.g.
`::test_tripwire_detects_scan`, `::test_budget_baseline_no_false_positives`,
`::test_kill_cascade_is_complete`.

## Why they could not be vendored

1. **They are not in this repository.** `conformance/` did not exist before
   this change; NTI contains no S4/S5/S6 scripts.
2. **They are not in the public ASL kit.** The kit ships protocol vectors and
   a verifier only. It contains no test scripts (verified: no `test_*` files).
   Its README states the test suite "belong[s] in the ASL source repository,
   not in this kit".
3. **The ASL source repository is private.** `Raja549h/helper` returns HTTP
   404 for an authenticated request. Its `SOURCE_COMMIT`
   (`8e8961b733e49cc0ce814132a89b399aa982b097`) is named but not fetchable.
4. **No public copy exists.** A GitHub code search for the S4 test name
   `test_tripwire_detects_scan` returns `total_count: 0`.
5. **The license forbids relicensing.** The ASL kit's `LICENSE` is
   "Copyright (c) 2026 The ASL Project. All rights reserved." — it is **not**
   Apache-2.0. Even if the scripts were reachable, they could not be copied
   into an Apache-2.0 repository without the copyright holder's permission.

## What would unblock this

- Written permission from the ASL copyright holder to relicense the S4/S5/S6
  test scripts under Apache-2.0, **and** read access to `Raja549h/helper`; or
- A public, permissively licensed ASL release that includes the test suite.

Once the scripts are obtainable, place them under `conformance/witness/vendor/`,
add their SHA-256 values to `MANIFEST.json`, and regenerate the signature.
