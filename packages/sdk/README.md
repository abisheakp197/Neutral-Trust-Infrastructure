# UBE — Universal Backend Engine SDK

> **Civilization-grade sovereign backend automation with a self-learning AI intelligence layer.**

[![npm version](https://img.shields.io/npm/v/@ube/sdk)](https://www.npmjs.com/package/@ube/sdk)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-blue)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/license-UNLICENSED-red)](./LICENSE)
[![Deployed](https://img.shields.io/badge/deployed-Railway-blueviolet)](https://ube-production-2fd4.up.railway.app)

---

## What is UBE?

UBE is a sovereign backend automation platform — foundational infrastructure that any application, organization, or government can run on top of. It provides every critical backend primitive in a single, zero-dependency TypeScript SDK, each module backed by production-grade cryptographic algorithms and real mathematical implementations.

**No stubs. No `any`. No scaffolding. Every line does real work.**

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│               UBE Intelligence Layer                     │
│  Q-Learning · Isolation Forest · Holt-Winters · UCB1    │
│  Self-Healing · RCA · Predictive Scaling · Semantic Mem │
└────────────────────────┬────────────────────────────────┘
                         │ wraps & observes
┌────────────────────────▼────────────────────────────────┐
│                    UBE SDK Modules (22)                  │
│                                                          │
│  stream   batch    events   identity  federation         │
│  recovery validator pipeline sync     telemetry          │
│  encryption legal  workflow throttle  automation         │
│  auth     client  connector types     errors             │
└─────────────────────────────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│              UBE Gatekeeper Layer (13 files)             │
│  audit · sandbox · zkp · quantum · homomorphic           │
│  attestation · legalOracle · orchestration …             │
└─────────────────────────────────────────────────────────┘
```

---

## Installation

```bash
npm install @ube/sdk
# or
yarn add @ube/sdk
# or
pnpm add @ube/sdk
```

---

## Quick Start

```typescript
import { createUBE } from '@ube/sdk';

const ube = createUBE({
  tenantId: 'my-org',
  masterKey: process.env.UBE_MASTER_KEY!,
  environment: 'production',
  intelligence: {
    enabled: true,
    selfHealing: true,
    autoTuning: true,
    predictiveScaling: true,
  },
});

await ube.ready();

// Every operation is intelligence-wrapped automatically
const event = await ube.events.publish(
  'user.registered',
  { userId: '123', email: 'user@org.com' },
  makeAggregateId('user-123'),
  'User',
);

// Check AI intelligence summary
console.log(ube.summary());
```

---

## Module Reference

### `events` — Event Sourcing + CQRS + Pub/Sub

Full event-sourced system with cryptographic Merkle log, exactly-once delivery, dead letter queues, circuit breakers, saga choreography, and windowed stream processing.

```typescript
import { EventSystem, makeAggregateId } from '@ube/sdk/events';

const es = new EventSystem();

// Subscribe with consumer groups
es.bus.subscribe('user.*', async (event) => {
  console.log('Received:', event.type, event.payload);
}, { group: 'analytics', maxRetries: 3, backoffMs: 200 });

// Publish with idempotency
await es.publish('user.created', { name: 'Alice' }, makeAggregateId('u1'), 'User', {
  idempotencyKey: makeIdempotencyKey('create-alice'),
});

// CQRS command
es.commands.register('CreateUser', async (cmd) => {
  return { userId: crypto.randomUUID() };
});
await es.send('CreateUser', { name: 'Alice' });
```

**Key algorithms:** Merkle tree (SHA-256), counting Bloom filter (FNV-1a + Kirsch-Mitzenmacher), multi-level priority heap, Chandy-Lamport snapshot, vector clocks.

---

### `identity` — DIDs, Verifiable Credentials, MFA, RBAC

W3C DID + VC Data Model 2.0, FIDO2/WebAuthn, TOTP/HOTP (RFC 6238/4226), Schnorr ZK proof, Shamir threshold keys, UCAN capability tokens, OIDC federation.

```typescript
import { IdentitySystem } from '@ube/sdk/identity';

const id = new IdentitySystem();

// Create DID + enroll TOTP
const { did, totpUri, session } = await id.createIdentity({
  enrollTOTP: true,
  createSession: true,
  roles: ['user' as RoleId],
});

// Verify TOTP
const valid = await id.mfa.verifyTOTP(did, '123456');

// Issue Verifiable Credential
const vc = await id.credentials.issue(issuerDID, subjectDID, {
  degree: 'BSc Computer Science',
  institution: 'MIT',
}, { types: ['EducationCredential'], revocable: true });

// RBAC authorization
id.access.defineRole({ id: 'admin', name: 'Admin', permissions: [{ resource: '*', actions: ['*'] }] });
const decision = id.authorize(session, 'write', 'documents:123');
```

**Key algorithms:** P-256 ECDSA, HKDF, PBKDF2-310k, JWK SHA-256 thumbprint (RFC 7638), Schnorr Σ-protocol, Shamir over GF(p), BIP-32 HD keys, UCAN 1.0.

---

### `batch` — Parallel Batch Processing

Worker pools, adaptive AIMD concurrency, priority queues, job DAGs, exactly-once idempotency, checkpointing, fan-out/fan-in, pipeline stages, scheduled batches.

```typescript
import { BatchSystem } from '@ube/sdk/batch';

const bs = new BatchSystem();
const processor = bs.createProcessor(async (job, signal) => {
  return await processItem(job.input);
});

const summary = await bs.runSimple(
  largeDataset,
  'etl-job',
  async (job) => transform(job.input),
  { concurrency: 16, rateLimitPerSecond: 200, adaptiveConcurrency: true },
);

console.log(`${summary.completed}/${summary.total} jobs, p99=${summary.p99Ms}ms`);
```

**Key algorithms:** Kahn topological sort, token bucket, AIMD, EWMA throughput, t-digest latency histogram, circuit breaker, bulkhead isolation.

---

### `validator` — Schema Validation Engine

Full JSON Schema Draft-07, Zod-style fluent API, type coercion, XSS/SQL/path-traversal sanitization, custom async rules, discriminated unions, lazy recursive schemas, schema diffing.

```typescript
import { v, ValidationSystem } from '@ube/sdk/validator';

const UserSchema = v.object({
  id:    v.string().uuid(),
  email: v.string().email().max(255).sanitize(),
  age:   v.number().int().min(0).max(150).coerce(),
  role:  v.enum(['admin', 'user', 'viewer']),
  tags:  v.array(v.string()).max(10).optional(),
});

const result = UserSchema.safeParse(rawInput);
if (result.success) {
  console.log(result.data.email); // typed as string
} else {
  console.log(result.error.issues);
}
```

**Key algorithms:** JSON Schema Draft-07 reference resolution, FNV-1a sanitizer hashing, XSS/SQL/SSRF guard regexes, Zod-compatible brand inference.

---

### `recovery` — Disaster Recovery & Resilience

WAL with UNDO/REDO, PITR, Chandy-Lamport distributed snapshots, saga compensation, circuit breaker (RFC-conformant), health check engine (liveness/readiness/startup), chaos engineering, SLA error budgets, runbook executor.

```typescript
import { RecoverySystem, makeNodeId } from '@ube/sdk/recovery';

const rs = new RecoverySystem(makeNodeId(), {
  walConfig: { checkpointIntervalMs: 5_000, syncMode: 'fsync' },
});

// WAL transaction
const txId = makeTransactionId();
rs.wal.append(txId, 'INSERT', 'users', undefined, { id: '1', name: 'Alice' });
rs.wal.append(txId, 'COMMIT', 'users');

// PITR snapshot
const snap = rs.pitr.snapshot('pre-migration', currentState);

// Wrap any call with full resilience
const result = await rs.resilient('external-api', () => fetch(url), {
  retry: { maxAttempts: 3, backoffMs: 200, strategy: 'jitter' },
  circuitBreaker: { failureThreshold: 5, errorRateThreshold: 0.5 },
});
```

**Key algorithms:** FNV-1a CRC32, Chandy-Lamport consistent cuts, bully leader election, Shamir fencing tokens, CUSUM alarms, SLA burn rate (multi-window).

---

### `stream` — Reactive Stream Engine

Full operator algebra (map/filter/flatMap/scan/reduce/debounce/throttle/window/groupBy), credit-based backpressure, watermark engine, subjects, replay subjects, content-based routing, exactly-once processing, parallel execution lanes.

```typescript
import { UBEStream, Subject, merge } from '@ube/sdk/stream';

const stream = UBEStream.fromArray([1, 2, 3, 4, 5])
  .filter(item => item.value % 2 === 0)
  .map(item => item.value * 10)
  .rateLimit(100)
  .withBackpressure(16);

for await (const item of stream) {
  console.log(item.value); // 20, 40
}

// Hot subject
const events = new Subject<UserEvent>();
const unsubscribe = events.subscribe({ next: e => processEvent(e.value) });
events.next({ type: 'login', userId: '123' });
```

**Key algorithms:** Credit-based flow control, Holt-Winters watermark, token bucket rate limiting, Chandy-Lamport-style exactly-once, merge-sort parallel lanes.

---

### `federation` — Cross-Organization Identity Federation

SAML 2.0 model, OIDC Connect, WS-Fed protocol translation, Circle of Trust, attribute release policies, consent engine, SCIM 2.0 provisioning, federated SSO/SLO, cryptographic audit log.

```typescript
import { FederationSystem } from '@ube/sdk/federation';

const fed = new FederationSystem();

// Register entities
fed.entities.register({ id: makeEntityId('univ-idp'), protocol: 'saml2', role: 'idp', ... });
fed.entities.register({ id: makeEntityId('app-sp'),   protocol: 'oidc',  role: 'sp',  ... });

// Establish trust agreement
fed.trust.addAgreement({ idpId: 'univ-idp', spId: 'app-sp', trustLevel: 'high', ... });

// SSO flow
const result = await fed.sso('user@univ.edu', 'univ-idp', 'app-sp', authnContext, attrs, 'oidc');
console.log(result.token?.token); // JWT for the SP
```

---

### `intelligence` — Sovereign AI Brain (wraps all modules)

Multi-armed bandit config tuning, Q-learning adaptive routing, Holt-Winters forecasting, Isolation Forest anomaly detection, CUSUM change detection, Welford statistics, semantic memory with cosine retrieval, root cause analysis, self-healing state machine, autonomous policy engine, predictive auto-scaling, cross-module cascade detection.

```typescript
import { IntelligenceSystem } from '@ube/sdk/intelligence';

const intel = new IntelligenceSystem();

// Attach to any module
const batchIntel = intel.attach('batch', {
  enableSelfHealing: true,
  enableAutoTuning: true,
  enablePredictiveScaling: true,
});

// Observe a metric snapshot — AI does the rest
const report = batchIntel.observe({
  latencyMs: 450,
  errorRate: 0.02,
  concurrency: 8,
  queueDepth: 1200,
  throughputPerSec: 320,
});

console.log(report.anomalyDetected);      // false
console.log(report.insights);             // ['No anomalies detected']
console.log(report.forecast.latencyMs);   // predicted next latency
console.log(report.scalingDecision);      // { recommendedConcurrency: 12, reason: 'scale-out...' }

// Wrap any async function with full AI observation
const result = await intel.intelligentCall(
  'batch',
  () => processor.runSimple(items, 'job', executor),
  [],
);

// Cross-module cascade detection
const cascades = intel.hub.detectCascades(30_000);
console.log(cascades); // [...anomalies across modules]
```

**Key algorithms:**
- **UCB1 Bandit**: `score = mean + √(2 ln N / n_i)` — config auto-selection
- **Q-Learning**: `Q(s,a) ← Q(s,a) + α[r + γ max Q(s',a') − Q(s,a)]`
- **Isolation Forest**: random feature splits, path length anomaly score `2^(−E[h(x)]/c(n))`
- **Holt-Winters**: triple exponential smoothing (α, β, γ) with seasonal decomposition
- **CUSUM**: `S_high = max(0, S_high + x − μ − k)` — change-point detection
- **Welford**: `M₂ += δ(x − μ_new)` — online variance without numerical instability
- **Cosine memory**: `sim(a,b) = (a·b)/(‖a‖‖b‖)` — episodic retrieval

---

## Intelligence Layer — How It Works

Every UBE module exposes numeric metrics (latency, error rate, throughput, queue depth). The Intelligence Layer sits above, continuously:

1. **Observes** — collects metrics from every `wrap()` call
2. **Detects** — Isolation Forest + Z-score + CUSUM flag anomalies
3. **Forecasts** — Holt-Winters predicts next-window load
4. **Decides** — policy engine + Q-learning agent choose action
5. **Acts** — scale recommendation, config tuning, circuit breaker toggle
6. **Heals** — self-healing state machine runs remediation playbook
7. **Learns** — Q-table and bandit arms update from outcomes
8. **Remembers** — semantic memory stores episodes for future retrieval

You don't rebuild the modules. You call `intelligence.attach('module-id')` and every interaction with that module feeds the AI loop.

---

## SDK Statistics

| Metric | Value |
|--------|-------|
| Total modules | 22 |
| Total lines of code | ~28,000+ |
| Zero runtime dependencies | ✅ |
| TypeScript strict mode | ✅ |
| Real math (no stubs) | ✅ |
| Post-quantum crypto | ✅ (Kyber-768) |
| Zero-knowledge proofs | ✅ (Schnorr, Pedersen) |
| GDPR/HIPAA/CCPA native | ✅ |

---

## Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| 1 — SDK Complete | ✅ Done | All 22 modules + intelligence layer |
| 2 — Metadata Sovereignty | 🔜 Next | Traffic padding, timing jitter, onion routing, SGX/SEV/TDX enclaves |
| 3 — Decentralized Mesh | 🔜 | Kademlia DHT, Shamir data sharding, Raft consensus |
| 4 — One-Command Deploy | 🔜 | Docker, Helm, air-gapped bundles |
| 5 — Marketplace | 🔜 | Module registry, tiered pricing, revenue sharing |
| 6 — Verifiable Benchmarks | 🔜 | ZK-proofs of performance claims |
| 7 — Go CLI | 🔜 | Bubble Tea TUI, auto-updater |
| 8–10 | 🔜 | New engines, verticals, decentralized microservices |

---

## Deployment

```bash
# One-command sovereign deployment
curl ube.sh | bash

# Or Docker
docker run -e UBE_MASTER_KEY=your-key ube-production-2fd4.up.railway.app
```

Live: **https://ube-production-2fd4.up.railway.app**

---

## License

UNLICENSED — Proprietary. All rights reserved © 2026 Abisheak P.
