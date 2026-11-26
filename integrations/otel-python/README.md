# nti-otel

Tamper-evident records for AI agent tool calls, produced from the OpenTelemetry spans you already emit.

## What it answers

> Has this record of what my agent did been altered since it was written?

It does not answer *"was the agent authorized to do this?"*. That question needs a record bound to the engine's own verdict, which the reference engine does not implement yet — see [NTI-1 RFC 0001](https://github.com/abisheakp197/nti-spec/blob/main/rfcs/0001-authorization-receipts.md). These are records of observed decisions, and calling them NTI authorization receipts would be a claim the code cannot support.

## Why this shape

Most teams already emit spans for their tool calls. Asking them to add a new SDK, a new decorator and a new export path to get evidence is asking them to change their architecture to satisfy an auditor. Reading the spans they already produce costs one line.

Each recorded span becomes one entry in an append-only JSONL log. Every entry carries `sha256` over its canonical form and the hash of the entry before it, so:

- editing any field breaks that entry's hash;
- deleting or reordering an entry breaks every link after it;
- the file is self-contained evidence that can be shipped to a customer, with no server to trust and no network call.

## Use it

```python
from opentelemetry.sdk.trace import TracerProvider
from nti_otel import install

provider = TracerProvider()
install(provider, path="decisions.jsonl")
```

Verify it:

```console
$ nti-otel decisions.jsonl
OK: 2 entries, chain intact
  head sha256:41ab…
  tail sha256:8d0e…

$ nti-otel decisions.jsonl   # after an edit
FAIL: 1 problem(s) in 2 entries
  - entry 0: record_hash mismatch (claimed sha256:41ab…, computed sha256:7f31…)
```

## What gets recorded

Only spans that carry `nti.decision` or `nti.capability`, because tracing furniture outnumbers decisions by orders of magnitude. Per record: trace and span IDs, the parent span ID, span name, start and end time, status, and the decision attributes in `records.DECISION_ATTRIBUTES`.

Everything else on the span is dropped. A record has to stay small enough to retain for years, and evidence should not change when someone renames a telemetry attribute.

## Signing

Optional, and honestly scoped. `generate_signer()` returns an ML-DSA-87 signer and its public key. Two limits of `ube-foundation` 0.2.1 apply:

- a keypair cannot be persisted (`PqcKeyPair()` generates and nothing loads), so a key cannot survive a process restart;
- `verify()` is an instance method and there is no constructor from a public key, so a third party cannot verify a signature from the public key alone.

Until the engine supports key persistence and verification from a public key, signing is in-process and does not establish non-repudiation to anyone else. The chain does not depend on it.

## Scope

`nti_otel` treats the agent as the thing being observed. A deployment that needs the stronger claim has to wait for RFC 0001 work items, or produce its own evidence path.

Apache-2.0.
