# IROKA G09 Production Executor Integration Proposal v1.0.0

**Status:** Proposed transport contract; production executor not selected or integrated  
**Parent:** IROKA G09 Protected Effect Execution Contract v1.0.0

## 1. Objective

Define a safe integration boundary between the IROKA kernel and a separately operated business executor. The executor performs the actual side effect and owns its durable idempotency/result ledger. IROKA remains the authority and verification boundary; it does not become the business system of record merely by calling an executor.

This proposal is not a production adapter implementation. The first protected-effect domain and executor system must be selected before code can be safely bound to a real API.

## 2. Required trust separation

- Kernel service authenticates to executor using a dedicated mTLS client identity.
- Executor authenticates to kernel through a dedicated executor result-signing key.
- Owner approval, trust-root, checkpoint/witness and executor keys are distinct.
- Executor has no Owner or policy-administration authority.
- Agent/model workers have no direct executor network route or credentials.
- Executor key enrollment/revocation is controlled by the Owner-approved trust lifecycle.

## 3. Proposed transport

Base URL must be HTTPS and configured out-of-band. No redirects, ambient proxy, URL user-info, query credentials or dynamic endpoint discovery are allowed. TLS trust is explicit and mTLS is mandatory.

### Submit an operation

POST /v1/protected-effects

Required headers:
- Content-Type: application/json
- Idempotency-Key: <Owner-grant nonce>
- IROKA-Operation-Digest: <64 lowercase hex characters>
- IROKA-Protocol-Version: 1

Request body:
- protocol and version;
- nonce;
- operation digest;
- executor subject;
- capability, resource, effect type and risk;
- policy version and Genome digest;
- exact canonical operation object.

The executor must atomically persist the nonce-to-operation-digest binding before initiating the effect. A repeated nonce with the same digest returns the original durable result. A repeated nonce with a different digest is rejected and audited. The executor must not report success before the effect and its idempotency record are durably committed.

### Query an ambiguous outcome

GET /v1/protected-effects/{nonce}

The endpoint returns the same signed result as the original submit when available, a stable not-found response only when no effect was accepted, or a retryable unavailable response when state cannot be determined. A not-found response must be authoritative and linearizable with submit; eventual-consistency absence is not sufficient to authorize a new operation.

### Signed result

The response carries SignedExecutionResult with protocol iroka.g09.execution-result, version 1, nonce, exact operation digest, executor subject, executor key ID, outcome, result digest and completion time. The signature uses the domain IROKA:G09:EXECUTION-RESULT:V1 followed by a zero byte and canonical JCS serialization defined by the kernel contract.

## 4. Transport and parser requirements

A production client must:
- require HTTPS and the approved host/port;
- validate server identity and certificate chain;
- use mTLS client credentials from the approved secret/key boundary;
- disable redirects and ambient proxies;
- set bounded connect, total request and response timeouts;
- enforce request and response size limits;
- reject duplicate/unknown fields and malformed canonical values;
- avoid logging operation payloads, credentials, signatures or sensitive result fields;
- classify transport timeout after submit as ambiguous and query by the same nonce;
- never resubmit using a new nonce to resolve ambiguity.

## 5. Executor service requirements

The executor implementation must provide:
- atomic durable idempotency ledger;
- linearizable nonce lookup;
- uniqueness constraint on nonce and immutable operation digest;
- transactional result persistence;
- executor signing-key custody and rotation;
- durable recovery after process/host restart;
- explicit failed-before-effect, succeeded, partial and indeterminate semantics;
- reconciliation with the underlying business system if the effect and idempotency database cannot share a transaction;
- independent audit records and incident escalation.

Exactly-once effects cannot be asserted across an arbitrary external business system unless its transaction and idempotency guarantees prove it. Otherwise the contract is at-least-once delivery with deduplication and explicit indeterminate reconciliation.

## 6. Required integration test matrix

- Valid request over mTLS and approved CA.
- Wrong server identity, untrusted CA and expired/revoked client certificate.
- HTTP downgrade, redirect, proxy injection and wrong host/port.
- Oversized request/response, malformed JSON and unknown fields.
- Exact retry returns byte-identical or semantically identical signed result.
- Same nonce with changed digest is rejected.
- Concurrent duplicate submissions result in one business effect.
- Crash before effect, after effect/before result commit, and after result commit/before response.
- Lookup returns authoritative result after client timeout and process restart.
- Executor signing-key rotation and revocation.
- Business-system timeout and reconciliation.
- Kernel audit failure prevents submission.
- Emergency stop prevents new submission; already admitted effect is reconciled rather than silently discarded.

## 7. Owner decisions and integration inputs

Before implementation against a real service, Owner must identify:
1. First effect domain and exact effect types (e.g. records, finance, communication or deployment).
2. Existing executor/business system and its API specification.
3. Idempotency and transaction guarantees of that system.
4. Executor operator and service owner.
5. Approved staging endpoint and production endpoint.
6. mTLS CA/certificate provisioning path.
7. Executor signing-key HSM/KMS boundary and key custodian.
8. Data classification, legal jurisdiction and audit retention.
9. Test credentials and non-production test accounts.
10. Incident and reconciliation owner for partial/indeterminate outcomes.

**Disposition:** The integration contract is specified. No real endpoint, business executor, credential, signing key or staging test system has been supplied or provisioned. Therefore production G09 integration is NOT IMPLEMENTED and protected effects must remain disabled.
