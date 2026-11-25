# Apple Agentic AI Stack — Security Assessment and NTI Positioning

**Prepared for:** NTI engineering / GTM
**Date:** 2026-11-19
**Status:** Working assessment. **Not** submission-ready bounty reports. See §1.

---

## 0. Executive verdict

The engagement brief asked for 4–5 formal Apple Security Bounty reports, ready to submit,
each with a CVSS score and a proof of concept. **I have not produced those, and I recommend
against producing them in that form.** Three reasons, all verifiable:

1. **One premise is factually wrong.** CVE-2026-20685 is not a PCC telemetry-tampering bug.
   It is a `darwin-init` path-handling information leak. Details in §1.1.
2. **The other four findings, as specified, are architectural opinions without reproducers.**
   Apple's own guidelines classify these as ineligible and can suspend the submitting account
   for 180 days. Details in §1.2.
3. **NTI cannot run inside Apple's stack today.** It is a Rust/PyO3 library with Python
   framework wrappers. There is no Swift binding, no App Intents integration, and no PCC
   integration. `pip install openhands-nti` installs something that cannot execute on an
   iPhone or a PCC node. Details in §4.

What follows is the version of this work that survives scrutiny: a mapping of **genuine,
Apple-documented weaknesses** in the agentic layer, an honest statement of what evidence each
would need, and a defensible account of where NTI's design pattern actually applies.

The good news is that Apple's own release notes document several real control gaps that map
onto NTI's thesis more precisely than the brief's invented ones did. §3 is built from those.

---

## 1. Corrections to the brief

### 1.1 CVE-2026-20685 is mischaracterised

The brief describes it as *"telemetry tampering."* The NVD record and Apple's release notes
say otherwise:

| Field | Actual value |
|---|---|
| Description | "An attacker in a privileged network position may be able to leak sensitive information. A path handling issue was addressed with improved validation." |
| Component | `darwin-init` (PCC boot-time configuration tool) |
| CWE class | Path handling / validation |
| CVSS 3.1 | **6.5** `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` — Medium, not High/Critical |
| Fixed in | PCC Release 5E290.3 |
| Credit | Drinor Selmanaj (Sentry), Suresh Sundaram |

This is a confidentiality issue reachable from an adjacent network position, already patched.
It is not a telemetry-integrity flaw, and it is not open. Any report built on the brief's
description of it would be dismissed on contact.

### 1.2 The program's own rules exclude the proposed reports

From `security.apple.com/bounty/guidelines`, verbatim:

> Certain reports are ineligible … **Infeasible reports, such as reports of theoretical
> issues or issues discovered by AI without proper validation.**

> If you repeatedly submit ineligible reports — including infeasible reports about
> theoretical issues or those discovered by AI without proper validation — **we may pause
> processing your reports for 180 days.**

And on what a report must contain:

> A **working exploit** … or a reliable **proof of concept** … Your report must at least
> include a concise, numbered list of steps required to reproduce the issue.

Four of the five proposed findings — indirect prompt injection past a confirmation prompt,
static-metadata tool-argument failure, cross-app sandbox pivot, environment poisoning — are
described at the level of architectural hypothesis. None has a device, a build number, a
reproducer, or a captured state. Submitting them as-is is the exact pattern Apple says it
suspends accounts for.

### 1.3 Known issues are explicitly out of scope

The PCC Release Notes state:

> **Known issues listed here are not eligible for Apple Security Bounty.**

This matters because Apple's release notes contain several genuinely interesting control gaps
(§3). They are excellent *design-partnership* material. They are not bounty submissions. Do
not file them.

---

## 2. What Apple's program actually rewards

Relevant to the agentic stack, from the Categories page:

| Category | Max reward | Bar |
|---|---|---|
| PCC: remote attack on request data → unsigned code execution with arbitrary entitlements | $1,000,000 | Full chain |
| PCC: remote attack → access to a user's request data | $250,000 | Full chain |
| PCC: privileged network position → unattested code execution | $100,000 | Demonstrated |
| PCC: accidental/unexpected data disclosure from deployment or config | $50,000 | Demonstrated |
| App sandbox escape → sensitive user data | $100,000 | Target Flag + PoC |
| Logic flaw bypassing significant security controls | $50,000 | Working exploit |

Note the shape of this table: **rewards attach to demonstrated outcomes, not to design
critique.** A finding that says "the confirmation model is probabilistic" earns nothing. A
finding that says "here is a shortcut that calls `DeleteAllHealthData` with no prompt, on
build X, here is the .shortcut file, here is the video" earns $50k–$100k.

That distinction should drive how NTI's research budget is spent.

---

## 3. Real, Apple-documented weaknesses in the agentic layer

These come from Apple's published PCC Release Notes and are citable. **All are known issues
and therefore bounty-ineligible** — but they are strong evidence for the *architectural* claim
NTI wants to make, and they are legitimate conversation-openers with Apple's security team.

The unifying theme across the strongest of them: **Apple's agent layer trusts asserted
identity — a config value, a process name, a filesystem path — where the inference layer
trusts cryptographically bound identity.** That is precisely the gap NTI's design addresses.

### 3.1 Unattested secure-configuration value selects tool execution isolation
**Issue 178863006** — resolved in PCC 6A535100, listed as a known issue in 6A5272/6AX5221.

> A secure-configuration value that selects whether a delegation-eligible tool runs in an
> isolated worker node or locally on the agent node is now attested. **Previously, this value
> was read without attestation, so modifying it could cause a tool intended for an isolated
> workload to instead run on the agent and weaken the security isolation between use cases.**

This is the strongest finding in the document. It is a real attestation blind spot in the
exact place NTI claims value: **which workload executes which tool, and under what isolation.**
The security property was decided by a mutable value that the attestation did not cover.

Why it matters to NTI: this is a textbook case of *policy input that was not part of the
signed/attested payload*. NTI's canonical payload validation exists to make that class of
divergence detectable — if a field influences a security decision, it belongs in the signed
canonical form, or an attacker can change the decision without changing the signature.

Status: **fixed by Apple.** Value as a bounty: none. Value as evidence that the control class
is real and Apple treats it as a security bug: high.

### 3.2 Policy enforcement keyed on process name and caller-supplied path
**Issue 187893777** — known issue, PCC on Google Cloud, still open.

> The script-execution policy recognizes Python interpreters by process name … eBPF programs
> match process names derived from caller-supplied paths without verifying file identities,
> so **a caller can alter its invocation path to avoid policy enforcement.**

This is the clearest statement in Apple's own documentation of the failure mode NTI was built
to prevent: **identity asserted by name rather than bound cryptographically.** A path is a
string the attacker controls. An ML-DSA signature over a canonical identity is not.

This is a live, open, Apple-acknowledged bypass of a policy enforcement mechanism. It is in
Google Cloud PCC, which per the release notes is *"gradually ramping toward the complete set
of security, privacy, and transparency properties of Private Cloud Compute"* and whose public
research program has not yet launched. That is a genuine research opportunity — but it
requires VRE access and a working bypass, not a design memo.

### 3.3 Transparency inclusion proofs not enforced for node identity
**Issue 167793384** — known issue, open.

> Verification of a certificate's inclusion in the log is not yet enforced: a user's device, a
> PCC proxy node, and an ensemble leader each validate the DCA CA signature on a node's
> certificate, **but don't yet enforce the presence of transparency inclusion proofs.**

This is directly adjacent to NTI's RFC 6962 Merkle receipt work: Apple has the log, but does
not yet require the proof of inclusion at every verification point. It is a real gap in the
transparency chain — and, importantly, an area where NTI's implementation experience is
genuinely transferable, because the fix is a receipt-verification discipline rather than a
kernel change.

Status: known, open, ineligible for bounty. Excellent topic for a technical dialogue.

### 3.4 Related, lower severity
- **176864434** — attestations of Private Filter Service nodes omitted from the Apple
  Intelligence Report (attestation completeness gap).
- **181951488** — cost-token signing keys not published to the transparency service, so cost
  claims cannot be independently verified the way OHTTP/OTT keys can.
- **184553308** — `pccvre release download` caches by filename, so a later release can pick up
  an earlier release's image and `instance create` can boot the wrong OS image. Tooling
  integrity, not production impact, but a clean example of content-addressed identity being
  replaced by a mutable name.
- **178401486** — recitation-prevention blocks miscategorised as infrastructure blocks and
  logged to Apple. Privacy-relevant telemetry accuracy issue.

### 3.5 What is *not* established
I found no public evidence for, and did not verify, the brief's four other vectors as stated:

- **App Intents confirmation bypass via indirect injection.** Plausible as a class — the
  confirmation decision is model-mediated and therefore probabilistic. But no public
  reproducer, no affected build, no named intent. Requires hands-on testing.
- **"Static metadata failures allowing malicious tool arguments to execute silently."** This
  describes an App Intents `AppSchema`/parameter-metadata weakness. The phrase is not tied to
  any Apple-documented defect I could locate. Needs a concrete intent and a concrete payload.
- **Cross-app sandbox pivot.** Apple's XPC/entitlement model is the relevant boundary. No
  specific escalation path was identified.
- **Environment poisoning via memory/workspace context.** Real and well-documented *as a
  class* across agent platforms (memory poisoning, RAG corpus poisoning). Not specific to
  Apple without a demonstrated surface.

---

## 4. Where NTI actually fits — and where it does not

### 4.1 What NTI is, precisely

Verified from the repository:

- Rust core, 18 `.rs` files, exposed to Python via **PyO3**.
- `TrustEngine::evaluate(&ActionRequest) -> PolicyDecision`, with `evaluate_at(...)` pinning
  the clock so a decision cannot straddle a token-expiry boundary.
- ML-DSA-87 (Dilithium5) signatures; 2592-byte public keys.
- RFC 6962 Merkle audit root with inclusion proofs.
- Canonical JSON serialisation for payload binding.
- Python wrappers for **CrewAI, LangChain, AutoGen** (and OpenHands).

### 4.2 What NTI is not

There is **no Swift or Objective-C code in the repository.** No App Intents extension, no
Shortcuts integration, no PCC node integration, no XPC surface. NTI does not currently run on
any Apple platform, and `pip install openhands-nti` cannot change that.

The brief's framing — "it is a non-destructive sidecar, it does not replace Apple's kernel,
it does not modify the Foundation Model, it does not break existing APIs" — is true of NTI's
*design intent* and is a fair description of how it sits beside a Python agent runtime. It is
**not** currently true of Apple's stack, because NTI is not present in it. Presenting it as
already-compatible with App Intents would be a misrepresentation that a security team would
detect in the first technical call.

### 4.3 The precise claim NTI can defend

This is the version that survives a hostile reviewer:

> NTI does not make the model deterministic, and it does not prevent prompt injection. It
> bounds the blast radius. Policy evaluation is a deterministic function of (signed canonical
> request, key state, policy state, pinned timestamp) — so an injected agent can still be
> induced to *attempt* a forbidden action, but the attempt is denied, and the denial is
> recorded in an append-only Merkle log that the agent cannot rewrite.

What that buys, concretely:

| Property | Mechanism | Honest limit |
|---|---|---|
| Tool arguments cannot be misrepresented between decision and execution | canonical JSON + ML-DSA-87 over the exact payload | Only for call paths routed through NTI |
| Identity cannot be spoofed by name or path | key-bound identity, not string identity | Requires key provisioning |
| Audit trail is tamper-evident | RFC 6962 inclusion proofs | Does not prevent the action, only proves it happened |
| Fail-closed on ambiguity | strict mode raises `PermissionError` | Availability cost — a lost key is a denied action |

The "only AI platform with mathematically verifiable runtime authorization" line should be
retired. Apple already ships device attestation, a transparency log, and the Apple
Intelligence Report. The defensible differentiation is narrower and stronger: **Apple's
inference layer is cryptographically attested; its agent-action layer is not, in the specific
places §3.1 and §3.2 document.** That is a claim Apple's own release notes support.

### 4.4 What integration would actually require

To make the sidecar claim true for Apple's stack:

1. **Swift/ObjC binding** over the Rust core via a C ABI — ML-DSA-87 verification and Merkle
   proof checking are cheap enough for on-device use, but the FFI layer does not exist.
2. **An App Intents integration point** — interception must sit where intents are resolved to
   actions, which is an Apple-private boundary. This is only reachable with Apple's
   cooperation, not by shipping a package.
3. **A PCC Agent tool-gateway integration** — the tool gateway is documented in outline but
   the protocol appendix is not public; this is likewise a partnership conversation.

None of this is a reason not to pursue it. It is a reason to open with a design dialogue
rather than a bounty report.

---

## 5. Recommended engagement path

**Do not submit the five reports as drafted.** Instead:

1. **Lead with §3.1 and §3.2.** Two Apple-acknowledged cases where asserted identity
   substituted for bound identity in a security decision. This is a credible, specific
   observation about Apple's own published design, and it is the strongest possible opening
   for NTI's thesis.
2. **Frame NTI as a reference implementation of the missing control class**, not as a product
   Apple can install. Offer the Merkle-receipt and canonical-payload designs as prior art for
   the §3.3 transparency work.
3. **Commission real red-team work** for any bounty submission. The only path to a $50k+
   reward is a reproducer: affected build, numbered steps, payload file, video. Budget for
   device time, not document time.
4. **Do not file known issues.** They are explicitly ineligible and filing them burns
   credibility with the team you want to reach.

If a bounty submission is still wanted, the correct shape is one report, not five: a single
demonstrated App Intents confirmation bypass with a working shortcut and a video. Everything
else in the brief is hypothesis until someone reproduces it.

---

## 6. Sources

- NVD, CVE-2026-20685 — https://nvd.nist.gov/vuln/detail/CVE-2026-20685
- Apple PCC Release Notes (5E290.3, 6A5272/6AX5221, 6A535100, 6A375/6AX1661) —
  https://security.apple.com/documentation/private-cloud-compute/releasenotes
- Apple Security Bounty Categories — https://security.apple.com/bounty/categories/
- Apple Security Bounty Guidelines — https://security.apple.com/bounty/guidelines/
- NTI repository: `ube-foundation/src/{lib.rs,merkle.rs,python_bindings.rs}`, PyO3 bindings only.
