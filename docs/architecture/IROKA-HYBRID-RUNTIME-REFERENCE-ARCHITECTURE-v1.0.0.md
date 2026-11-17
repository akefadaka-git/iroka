# IROKA ZERO Hybrid Runtime Reference Architecture v1.0.0

**Status:** Reference architecture prepared; deployment target and Owner acceptance pending  
**Architecture posture:** Amharic-first, mobile/client-aware, hybrid execution, governed autonomy  
**Security baseline:** G01 identity, G02 Owner authority, G09 protected effects, G11 audit/checkpoints

## 1. Purpose and non-claims

This document defines a reference deployment architecture for IROKA's first hosted/private-infrastructure plus local-node profile. It separates deterministic authority and protected effects from probabilistic agents, external models and untrusted content.

It is not a claim that a deployable runtime exists. The current repository contains the Rust authorization/security kernel library and conformance tests, not a complete application server, local node, operating system, service container or installer. The deployment profile, hosting provider, target hardware, availability objectives and data jurisdiction remain Owner decisions.

## 2. Logical architecture

The reference system has six trust zones:

1. **Client and presentation zone:** Amharic-first web/mobile/PWA clients; no Owner or executor signing keys; no direct database or witness access.
2. **Edge/API zone:** TLS termination, request-size limits, authentication handoff, rate limiting, schema validation and correlation IDs. Edge services cannot grant capabilities.
3. **Identity and governance zone:** G01 credential verification, G02 Owner approval and trust-root lifecycle. Private keys remain in a separately controlled signing boundary; services receive only verified identities or signed approval artifacts.
4. **Deterministic kernel zone:** Rust IROKA kernel evaluates policy, validates exact operation grants, consumes nonces atomically, records admission, verifies executor results and creates receipts. Agents and models cannot bypass this boundary.
5. **Workload and executor zone:** Isolated workers handle ordinary bounded computation. Protected executors are separate least-privilege services with dedicated identities and signing keys. No general-purpose agent worker receives privileged credentials.
6. **Evidence and operations zone:** Append-only local audit, independently administered external witnesses, backup/restore, security monitoring, key lifecycle, incident response and release verification.

## 3. Hybrid deployment topology

### Hosted/private control plane
- API gateway and session service.
- Organization/tenant and policy service.
- Identity verification and Owner approval orchestration.
- Kernel service embedding the verified IROKA kernel library.
- Durable transactional database for operational state and nonce/receipt persistence.
- Queue for non-protected asynchronous workloads; messages are signed or integrity-bound and carry tenant, schema, expiry and correlation context.
- Audit exporter and checkpoint client.
- Monitoring, alerting, backup and recovery services.

### Local execution node
- Authenticated node identity and deployment-profile version.
- Minimal local kernel/agent runtime; no authority inferred from being local.
- Encrypted local data/cache with explicit retention and offline freshness rules.
- Sandboxed workload runner with CPU, memory, filesystem, network and effect budgets.
- Outbound authenticated connection to control plane and external witnesses.
- No inbound administrative exposure by default.
- Protected effects blocked whenever current policy, revocation state, trust or required audit cannot be established.

### External services
- Two or more separately administered checkpoint witnesses.
- Owner-approved HSM/KMS or equivalent signing boundary.
- Explicitly approved external model/tool providers, accessed only through a policy-controlled broker.
- Explicitly approved business executors (e.g. finance, records or messaging), each separately identified and scoped.

## 4. Request and protected-effect flow

1. Client submits a versioned request with tenant, locale/profile, request ID and correlation ID.
2. Edge validates transport, size and schema; it does not make authorization decisions.
3. Identity service verifies credentials and produces a typed verified principal.
4. Kernel loads a versioned policy, verified Genome baseline and current trust/revocation state.
5. Agent/model output is treated as untrusted proposed data. It cannot call an executor directly.
6. For a protected effect, kernel requires REQUIRE_APPROVAL, verifies an Owner-signed grant over the exact canonical operation, atomically consumes its nonce and commits admission audit before calling the executor.
7. Executor enforces durable nonce idempotency and returns a signed outcome bound to nonce and operation digest.
8. Kernel verifies the result, persists an opaque receipt, emits the outcome audit event and exposes only the permitted result projection to the client.
9. G11 batches and externally anchors audit checkpoints; evidence is independently retained and reconciled.

Any failure in identity, policy, approval, nonce consumption, admission audit, executor identity, result verification or receipt persistence blocks the protected path or records an indeterminate state. No retry with a new nonce is allowed to resolve an ambiguous external outcome.

## 5. Data and storage boundaries

| Data class | Storage boundary | Required control |
|---|---|---|
| Identity credentials | Identity vault/provider | Encryption, least privilege, expiry/revocation |
| Owner and root private keys | HSM/KMS or offline custody | Non-exportability where supported, dual control, ceremony logs |
| Trust bundles and public keys | Versioned trusted store | Signature verification, anti-rollback, immutable versions |
| Operational business data | Tenant-scoped database | Encryption, row/tenant isolation, retention and backup |
| Audit events/checkpoints | Append-only audit store plus external witnesses | Hash-chain integrity, signed receipts, independent retention |
| Executor idempotency/result ledger | Executor-owned durable store | Atomic nonce binding, exact retry, signed readback |
| Model prompts/outputs | Classified workload storage | Data minimization, provider controls, bounded retention |
| Build artifacts/SBOM | Immutable release storage | Digest, provenance and SBOM attestation |

Database access is mediated by services, not granted to agents. Tenant identifiers are authorization inputs, never trusted from a client without verification. Derived indexes, summaries and embeddings retain provenance to source records.

## 6. Network and service trust

- TLS 1.2+ minimum, TLS 1.3 preferred; mTLS for service-to-service and witness/executor links.
- Explicit CA trust, certificate identity mapping, bounded connect/read/write timeouts and response-size limits.
- No ambient proxy, redirect following or dynamic endpoint discovery for protected services.
- Egress allowlists by service identity, destination and protocol.
- Secrets are injected only to the smallest service boundary that requires them; no secrets in Git, build artifacts, prompts or logs.
- All inter-service contracts are versioned, authenticated, size-bounded and replay-aware.
- Local nodes initiate outbound connections; inbound administration is separately gated.

## 7. Availability, offline and recovery behavior

- Control plane is authoritative for policy, trust and revocation.
- Local offline work is limited to explicitly classified, non-protected tasks under a bounded freshness policy.
- Protected effects requiring current revocation or external quorum fail closed if freshness or quorum is unavailable.
- Queues use bounded retention, dead-letter handling and idempotency; they cannot silently retry protected side effects.
- RPO/RTO values are deployment-specific and must be approved before production.
- Restore requires independent validation of database integrity, trust versions, revocation state, audit head, anchored prefix, witness receipts and executor idempotency state before protected effects resume.

## 8. Runtime process boundaries

The production runtime should be split into separately deployable processes:
- iroka-api: client-facing API and session boundary.
- iroka-governance: identity, Owner approval and trust lifecycle orchestration.
- iroka-kernel-service: deterministic policy and G09 admission/receipt boundary.
- iroka-worker: untrusted task execution in sandboxed workloads.
- iroka-audit-bridge: local audit export and external checkpoint reconciliation.
- iroka-node-agent: local/hybrid node connectivity and local workload supervision.

These are logical component names, not existing binaries. The Rust kernel crate is linked into the kernel service; it is not itself a complete service.

## 9. Deployment environments

The first implementation target should be a non-production private-infrastructure staging environment, with a separate local-node profile for hybrid validation. Production must use a separately approved deployment profile and environment. No environment inherits production authority from staging.

Required environment separation:
- isolated development, test, staging and production accounts/projects;
- unique service identities and keys per environment;
- no production secrets in CI;
- immutable release artifact promotion by digest;
- policy and trust configuration promotion with independent approval;
- environment-specific witness endpoints and executor keys;
- network and data residency review.

## 10. Observability and incident response

Every protected operation must correlate identity, request, policy version, Genome digest, approval nonce, operation digest, executor identity, result signature, receipt digest and checkpoint evidence. Logs redact secrets and sensitive operation payloads by default.

Alerts cover trust-root changes, revocations, failed verification, repeated nonce use, executor signature failures, indeterminate outcomes, audit gaps, fork detection, witness quorum loss, checkpoint lag, privilege anomalies, emergency stop, dependency/advisory regressions, provenance failure, backup failure, restore drift and key-custody exceptions.

Runbooks must define containment, evidence preservation, key rotation/revocation, recovery, Owner notification and post-incident review.

## 11. Initial measurable deployment gates

- No protected effect executes without valid approval and admission audit.
- No agent/model receives root, Owner, witness or executor private keys.
- No cross-tenant access in the conformance suite.
- No unverified or stale trust state permits a protected effect.
- Every successful protected effect has a verifiable signed executor result and durable receipt.
- Every ambiguous effect remains discoverable by the same nonce.
- Every audit checkpoint is independently verifiable and externally retained.
- Restore preserves trust/revocation and audit continuity.
- All deployed artifacts map to a release tag, digest, SBOM and verified provenance.
- Critical user journeys pass Amharic/Ethiopic round-trip and Ethiopian-calendar profile tests.

## 12. Decisions required before A3 runtime implementation can be declared complete

Owner must select/approve:
1. Hosting provider and legal/data jurisdiction.
2. Initial private-infrastructure or hybrid pilot topology and named target hardware/OS.
3. Service framework/API protocol and production database.
4. Identity provider and credential proofing model.
5. HSM/KMS provider and custody ceremony.
6. External witness operators and endpoints.
7. First protected-effect domain and real executor system.
8. RPO/RTO, availability and support ownership.
9. Data classification, retention, residency and incident-response owners.

**Disposition:** The logical reference architecture is documented. Runtime implementation, production G09 integration and production deployment remain blocked by the unresolved deployment and executor selections and by absent external operational evidence.
