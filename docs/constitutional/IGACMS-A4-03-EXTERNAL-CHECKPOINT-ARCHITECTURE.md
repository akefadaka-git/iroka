# IGACMS A4-03-E — External Audit Checkpoint Architecture

**Document ID:** IGACMS-A4-03-E-ARCH-001  
**Version:** 0.1.0 (architecture proposal)  
**Status:** DESIGN COMPLETE — IMPLEMENTATION NOT AUTHORIZED BY THIS DOCUMENT  
**Design parent:** A2 Owner-approved baseline `a709fc473b23494839417449e34bebf4cb8be77a`  
**Design source HEAD:** `bb8b9f0ee81b59e793c30cc5c9a0357d3ed48e4a`  
**Work branch:** `architecture/a4-03-external-checkpoint`  
**Scope:** External cryptographic checkpoints for the existing local IGACMS audit chain  
**Merge, production activation and deployment:** NOT AUTHORIZED

## 1. Executive decision

The local SQLite audit chain remains the authoritative event-generation record for the current A3 implementation. Its hash chain detects in-database edits, reordering and deletion when the verifier has an independently trusted head. It does not, by itself, detect an administrator replacing the database and rebuilding a self-consistent chain from an earlier point.

This architecture adds an independently retained, signed checkpoint over a contiguous prefix of that local chain. A checkpoint is considered externally anchored only after:

1. the checkpoint signer has verified the complete local segment and continuity from the prior accepted checkpoint;
2. at least **two of three independently administered witnesses** have independently verified the checkpoint and segment, accepted the monotonic sequence, and issued signed receipts; and
3. at least **two independent immutable-retention domains** have durably retained the checkpoint, segment manifest, and witness receipts, with independently verifiable retention evidence.

A missing quorum, stale checkpoint, unavailable verifier, invalid receipt, or retention failure is never reported as externally anchored. Local audit availability and external-anchor availability are distinct states. No automatic fallback may relabel local-only evidence as externally anchored.

This is a technology-neutral architecture. It selects no cloud provider, witness operator, production key, HSM, account, region, or commercial service.

## 2. Scope, constraints and non-goals

### 2.1 In scope

- Canonical checkpoint and segment-manifest formats.
- Checkpoint signer and three independent witness roles.
- Witness quorum and independence requirements.
- Remote immutable retention and independent verification.
- Key creation, activation, rotation, revocation, compromise and recovery design.
- Failure, retry, fork, rollback, replay and disaster-recovery behavior.
- Privacy, operational controls, test requirements and implementation gates.

### 2.2 Explicitly out of scope

- Changes to the existing A2 constitutional catalogue, marker semantics, mutation classes, Owner authority or approval rules.
- Replacing the local SQLite audit store or its current hash-chain format.
- Selecting or onboarding a provider, witness operator or commercial service.
- Generating, importing, provisioning or activating production private keys.
- Executing a custody ceremony or appointing real-world key holders.
- Live network adapters, remote storage clients, witness services, production endpoints or infrastructure changes.
- Genesis activation, runtime promotion, merge, release or deployment.

The architecture does not change the approved rule that required local audit evidence must be durably recorded before a protected transition is accepted. Whether a future mutation class must wait for external quorum before finalization is a separate policy decision and is not silently introduced here.

## 3. Security objectives and adversary model

### 3.1 Objectives

- **History anchoring:** detect replacement, truncation or reconstruction of the local database behind an already witnessed checkpoint.
- **Authenticity:** bind each checkpoint to an authorized checkpoint-signing key and purpose.
- **Independent corroboration:** prevent the local service or a single administrator from manufacturing the only evidence of its own audit history.
- **Monotonicity:** reject stale, replayed, forked or regressing checkpoint sequences.
- **Durability:** preserve checkpoint and segment evidence outside the local database and outside one administrative failure domain.
- **Verifiability:** permit an offline verifier to validate signatures, continuity, witness quorum and retention evidence using pinned trust material.
- **Fail-closed assurance:** never convert unavailable or indeterminate external evidence into a PASS or anchored state.

### 3.2 Adversary capabilities

Assume an attacker may obtain root or administrator access to the application host, replace or restore its SQLite database, delete local WAL files, rewrite unanchored events, replay old checkpoint messages, compromise one witness, compromise one storage account, disrupt networks or clocks, submit malformed manifests, or attempt to exploit inconsistent canonicalization.

The design aims to remain tamper-evident if the application host and local database are compromised, provided the attacker has not also compromised the checkpoint signing authority, the required witness quorum, and the independent retention quorum.

The design does not claim protection if all independent trust domains collude or are simultaneously compromised. That is a residual governance and key-custody risk.

### 3.3 Trust-domain separation

The following roles MUST be separate security principals and administration domains:

| Role | Responsibility | Must not control |
|---|---|---|
| Audit producer | Appends events to the local chain | Checkpoint private key; witness quorum; remote retention administration |
| Checkpoint coordinator | Builds and submits checkpoint candidates | Witness signing keys; immutable-retention policy |
| Checkpoint signer | Signs a validated checkpoint payload | Local audit database administration; witness quorum |
| Witness W1/W2/W3 | Independently verifies and signs a receipt; retains its own evidence copy | Other witnesses' keys; checkpoint signer key |
| Retention domain R1/R2 | Immutable storage of checkpoint package and evidence | Checkpoint signer or witness private keys |
| Offline verifier | Validates exported evidence using pinned trust metadata | Any signing authority or mutation authority |

A witness MUST NOT be operated by the same principal that controls the checkpoint signer. At least two witnesses MUST be controlled by distinct legal/operational administrators and separate identity roots. The three witnesses MUST NOT share one cloud organization, root credential, deployment pipeline, or single revocation authority. The two retention domains MUST be independently administered and have separate credentials and recovery paths.

A provider can host more than one technical component only if the administrative and credential independence is demonstrated; physical service labels alone do not prove independence. The final operator topology requires a documented independence assessment.

## 4. Cryptographic profile and canonical encoding

### 4.1 Baseline profile

- Hash: SHA-256.
- Signature: Ed25519, consistent with the existing IGACMS A3 attestation profile.
- Encoding: deterministic canonical JSON using RFC 8785 JCS, UTF-8, with duplicate object keys rejected before canonicalization.
- Domain separation: every digest and signature payload uses a distinct, versioned context string.
- Identifiers: lowercase ASCII UUIDv4 or another explicitly versioned collision-resistant identifier format; no implicit Unicode normalization of identifiers.
- Time: UTC RFC 3339 timestamps for audit and expiry metadata. Time is informational and bounded by policy; sequence and hash continuity, not wall-clock time, determine ordering.

Suggested context labels:

- `IGACMS-AUDIT-SEGMENT-v1\0`
- `IGACMS-AUDIT-CHECKPOINT-v1\0`
- `IGACMS-AUDIT-WITNESS-RECEIPT-v1\0`
- `IGACMS-AUDIT-RETENTION-RECEIPT-v1\0`

The exact byte construction and test vectors MUST be frozen before implementation. The implementation MUST NOT sign a pretty-printed JSON string or an implementation-specific map serialization.

### 4.2 Segment manifest

Each checkpoint covers one contiguous sequence interval from the prior accepted checkpoint's next sequence through the candidate's last sequence. The segment manifest contains:

- schema and format version;
- audit-log identity and environment identity;
- first and last event sequence numbers;
- event count;
- first event hash and final event hash;
- previous accepted checkpoint digest;
- digest of the exact ordered event export or canonical segment package;
- digest of the local chain verification report;
- checkpoint policy identifier and version;
- creation time and declared clock-quality metadata.

The verifier MUST confirm that event count equals the inclusive sequence interval, that every event is present exactly once, that each event's previous-hash pointer is continuous, and that the last event hash equals the declared audit head. A digest of a manifest without the underlying segment is not sufficient to independently verify event-level continuity.

### 4.3 Checkpoint envelope

A checkpoint envelope contains:

- `schema = "igacms.audit-checkpoint"`;
- `version = 1`;
- `log_id` and `environment_id`;
- `checkpoint_sequence` (strictly increasing per log);
- `first_event_sequence` and `last_event_sequence`;
- `event_count`;
- `segment_manifest_digest`;
- `audit_head_hash`;
- `previous_checkpoint_digest` (null only for the first checkpoint);
- `checkpoint_policy_id` and `policy_version`;
- `signer_key_id` and `signer_key_epoch`;
- `issued_at`, `not_before`, and `expires_at`;
- `signature_algorithm`;
- `signature`.

The checkpoint digest is SHA-256 over the canonical envelope payload excluding the signature field and any transport metadata, prefixed by the checkpoint domain-separation context. The signature is Ed25519 over the same domain-separated canonical payload. The envelope MUST bind the signer key ID, purpose, policy version and log identity.

The first checkpoint establishes a genesis anchor for the audit log and MUST include an explicit genesis-anchor designation and an Owner-approved trust-policy reference. It MUST NOT be confused with or modify IGACMS constitutional Genesis.

### 4.4 Witness receipt

Each witness receipt contains:

- checkpoint digest and sequence;
- log identity and previous checkpoint digest;
- segment-manifest digest;
- witness identity and witness key ID/epoch;
- witness policy version;
- verification result and verifier build identity;
- witness receipt time and clock-quality metadata;
- immutable-retention object identifier or independently verifiable retention reference;
- receipt expiry/renewal policy;
- witness signature.

A receipt is valid only if the witness has independently verified the checkpoint signature, the complete segment, continuity with its own last accepted checkpoint, policy freshness, signer-key status and absence of a sequence fork. A witness MUST persist its own monotonic high-water mark before issuing a receipt.

A witness receipt is not a generic acknowledgement that a message was received. It is a signed statement that the witness completed the defined verification procedure and retained the evidence package under its policy.

### 4.5 Retention receipt

Each retention domain produces evidence binding:

- checkpoint digest;
- segment-manifest digest;
- witness-receipt bundle digest;
- immutable object identifiers and object version IDs;
- retention mode and retain-until timestamp;
- policy/lock configuration evidence;
- storage-domain identity;
- retrieval verification result and time.

A storage API's success response alone is not sufficient. The coordinator or independent verifier MUST read back the exact object version and verify its digest and retention state.

## 5. Components and protocol

### 5.1 Logical components

1. **Local audit store:** existing SQLite append-only chain.
2. **Segment exporter:** creates a deterministic, complete event segment and manifest.
3. **Checkpoint coordinator:** schedules checkpoints, enforces contiguous ranges, collects receipts and reports state.
4. **Checkpoint signer:** signs only candidates that pass local chain and policy checks.
5. **Witnesses W1–W3:** independent verification, monotonic state, receipt signing and witness-side retention.
6. **Immutable retention domains R1/R2:** independently controlled, retention-locked evidence copies.
7. **Offline verifier:** verifies a portable evidence bundle without trusting the coordinator or source host.
8. **Monitoring and alerting:** detects lag, missing quorum, forks, retention-policy drift, expiry and key-status changes.

### 5.2 Normal checkpoint sequence

1. The local audit store commits events under its existing transaction and hash-chain rules.
2. The coordinator selects the next contiguous unanchored range. It MUST NOT skip, reorder or silently overlap events.
3. The exporter creates the canonical segment package and manifest. It records exact event count, range, final head and prior checkpoint digest.
4. The checkpoint signer independently verifies the local chain over the entire proposed range and verifies continuity from the last accepted checkpoint. It rejects a changed, truncated, duplicated, missing or forked range.
5. The signer creates and signs the checkpoint envelope.
6. The coordinator sends the exact envelope and segment package to W1, W2 and W3.
7. Each witness independently fetches or receives the full segment, verifies every event and hash link, verifies the checkpoint signature and key status, checks its persisted sequence/high-water mark, and rejects replay or a competing checkpoint for the same sequence.
8. Each accepting witness persists its monotonic state and immutable evidence before signing its receipt. A witness that cannot durably retain the package MUST NOT issue a successful receipt.
9. The coordinator collects at least two valid receipts from the three independent witnesses.
10. The coordinator writes the checkpoint, segment, receipts and metadata to R1 and R2. Each domain MUST provide retention evidence; the coordinator reads back and verifies the exact object versions and digests.
11. Only after witness quorum and both retention confirmations does the coordinator mark the checkpoint **ANCHORED**.
12. The coordinator publishes a signed status statement containing the checkpoint digest, sequence, quorum and retention evidence references. The local audit database is updated only as a cache of this state; it is not the source of truth for external anchoring.

The package is idempotent by checkpoint digest. Retrying the same checkpoint MUST return the same logical result and MUST NOT create a second sequence or a conflicting receipt. A changed payload requires a new checkpoint sequence linked to the prior accepted checkpoint, never an overwrite.

### 5.3 State model

Allowed checkpoint states:

- **LOCAL_ONLY:** local chain exists; no valid external witness quorum.
- **PREPARING:** a candidate segment is being built and verified.
- **SIGNED:** signer produced a valid envelope; not externally anchored.
- **WITNESSED:** at least two valid independent witness receipts exist; remote retention is incomplete.
- **ANCHORED:** witness quorum and both independent immutable-retention confirmations are verified.
- **DEGRADED:** a previously anchored checkpoint remains verifiable, but a freshness, renewal, monitoring or availability SLO is breached.
- **FORKED:** conflicting valid candidates or sequence histories are detected; new anchoring halts pending resolution.
- **REVOKED:** the checkpoint's signing authority or policy is revoked under the governing revocation procedure; historic evidence remains preserved and is marked with the reason and effective time.
- **INDETERMINATE:** evidence or trust status cannot be established.

Only **ANCHORED** means externally anchored. DEGRADED does not erase a historical anchor, but MUST expose the specific breached condition. LOCAL_ONLY, SIGNED, WITNESSED and INDETERMINATE MUST NOT be represented as anchored.

### 5.4 Checkpoint cadence and freshness

The initial architecture target is a configurable checkpoint cadence, not a hard-coded operational promise:

- routine target: checkpoint at least every 15 minutes or every 1,000 events, whichever occurs first;
- high-risk transition target: checkpoint after the corresponding local audit transaction and before any policy-defined external-assurance boundary;
- maximum tolerated anchor lag: a value explicitly approved per environment and mutation class.

These are proposed design defaults only. They require load, cost, connectivity and risk validation before adoption. The system MUST expose event-count lag, time lag, oldest unanchored event, last anchored sequence and last successful witness/retention times.

No wall-clock-only freshness check may be used to infer sequence completeness. Clock uncertainty MUST be reported and bounded.

## 6. Witness quorum and independence

### 6.1 Quorum

The design uses three configured witnesses and requires two valid receipts (2-of-3). Each witness has a unique key and durable monotonic state. A quorum is counted by distinct configured witness identities, not by number of signatures or endpoints.

A witness MUST reject:

- a checkpoint sequence less than or equal to its last accepted sequence unless the exact digest is an idempotent retry;
- a previous-checkpoint digest that does not match its stored head;
- a second digest for an already accepted sequence;
- an invalid or revoked signer key;
- an invalid segment, manifest or chain;
- a policy version it does not recognize;
- an expired or not-yet-valid envelope;
- a checkpoint whose log or environment identity is outside its assigned scope.

### 6.2 Independence criteria

Before onboarding, each witness must have documented evidence for:

- distinct accountable operator and administrator;
- distinct identity and credential root;
- separate private-key custody and recovery;
- separate deployment/release authority;
- separate audit trail and alerting;
- independent ability to retrieve and verify the evidence package;
- no shared single administrator who can silently change all witness state;
- documented compromise notification and revocation path.

The independence assessment is a required approval artifact. Merely deploying three processes or three accounts under one administrator does not satisfy 2-of-3 independence.

### 6.3 Witness loss and replacement

Loss of one witness leaves a 2-of-3 quorum possible but triggers a degraded-capacity alert. Loss of two witnesses prevents new anchoring. Replacement requires a governance-approved witness-set epoch transition, signed by the required current authority and acknowledged by the remaining valid witnesses. The new witness MUST bootstrap from the latest independently anchored checkpoint and verify the complete continuity package before voting.

No automatic substitution or silent roster expansion is allowed. Witness roster changes are separately governed and audited.

## 7. Immutable retention and evidence portability

### 7.1 Retention requirements

R1 and R2 MUST be independent administrative domains. Each MUST support immutable retention equivalent to compliance-mode object lock or a separately validated write-once retention control. The policy MUST prevent ordinary administrators and application credentials from shortening or bypassing the retention period.

Minimum requirements:

- retention lock is enabled before evidence is considered stored;
- checkpoint, complete segment, manifest, witness receipts, signer trust metadata and policy snapshot are stored together as a versioned evidence package;
- object versions are immutable and independently addressable;
- credentials are scoped to append/read/verify and cannot change retention policy;
- read-back digest verification is mandatory;
- retention expiry is monitored and renewed under an approved policy;
- deletion, legal hold and expiry actions are dual-controlled and audited;
- a periodic restore drill proves evidence can be retrieved without the original application account.

No single storage administrator may control both retention domains. A backup in the same account and IAM root is not an independent retention domain.

### 7.2 Portable evidence bundle

The export bundle MUST contain all data needed for offline verification, except private keys:

- checkpoint envelope;
- canonical segment manifest;
- exact ordered audit events for the covered range;
- prior checkpoint envelope and required continuity chain (or a verifiable trusted checkpoint bundle);
- two or more witness receipts;
- two retention receipts and object-version metadata;
- signer and witness public-key certificates/metadata;
- key lifecycle and revocation snapshots applicable at checkpoint time;
- policy version and independence roster snapshot;
- verifier test-vector version and package digest.

The verifier MUST NOT depend on a live call to the coordinator to establish integrity. If revocation freshness cannot be established from the bundle or a separately trusted current source, the result is INDETERMINATE, not PASS.

## 8. Key lifecycle and custody boundaries

### 8.1 Separate key purposes

At minimum, distinct keys are required for:

- checkpoint signer;
- each of the three witnesses;
- retention-domain receipts, if those receipts are cryptographically signed by the storage operator;
- offline policy/roster authorization, if required by the final governance model.

The existing Owner Genesis key MUST NOT be reused as a routine checkpoint key. Routine checkpoint keys MUST NOT authorize constitutional Genesis, marker assertion truth, Owner approvals or mutation actions.

### 8.2 Creation and custody

Production keys MUST be generated inside an approved hardware-backed or offline custody boundary and MUST NOT be exportable to the application host. Key creation, custodian appointment, recovery material, backup, quorum, dual control, ceremony evidence and activation require a separate Owner-approved custody plan.

No production key material is created, imported, requested or provisioned by this architecture stage. Synthetic keys may be used only in tests and MUST be clearly marked non-production.

### 8.3 Rotation

Each role has a monotonically increasing key epoch. Rotation must:

1. create a new key under the approved custody boundary;
2. publish a transition statement binding old key ID, new key ID, role, scope, effective sequence and effective time;
3. obtain the required governance authorization and witness acknowledgement;
4. sign new checkpoints only with the new active key after the transition point;
5. preserve old public keys and historical validity metadata for offline verification.

A routine rotation MUST NOT invalidate checkpoints validly signed before the effective revocation point.

### 8.4 Revocation and compromise

Revocation records include key ID, role, reason code, effective sequence/time, authority, evidence reference and replacement status. Revocation state is distributed to all witnesses and retention verifiers.

If the checkpoint signer is suspected compromised, new checkpoints stop. A replacement signer is activated only through the recovery authority path. Witnesses preserve all received evidence and mark checkpoints whose signatures fall within the compromise interval as **INDETERMINATE** pending adjudication; they do not silently rewrite history.

If one witness is compromised, its key is revoked and its receipts are excluded from new quorum decisions from the effective sequence. Historical receipts remain preserved with compromise annotations. If two witnesses are compromised, new anchoring stops until a separately approved roster recovery is completed.

No compromised key may authorize its own replacement or erase previously published receipts.

## 9. Failure, recovery and fork handling

| Failure | Required behavior | State / recovery |
|---|---|---|
| Local audit append fails | Existing protected transition remains blocked under current A2/A3 rules | Fail closed; no event or approval is silently accepted |
| Segment export incomplete or inconsistent | Do not sign | LOCAL_ONLY / INDETERMINATE; repair source evidence, then rebuild same unanchored range |
| Signer unavailable | Preserve local chain; queue candidate | LOCAL_ONLY; retry with bounded backoff |
| Signer key status unknown/revoked | Reject candidate | INDETERMINATE; resolve trust status, no fallback key |
| One witness unavailable | Continue only if two valid independent witnesses remain | Degraded capacity; alert |
| Fewer than two witnesses available | Do not mark witnessed or anchored | LOCAL_ONLY / DEGRADED; retry |
| Witness detects sequence fork | Halt new anchoring for that log | FORKED; preserve both candidates and investigate |
| One retention domain unavailable | Do not mark ANCHORED | WITNESSED; retry retention |
| Retention read-back or lock verification fails | Treat retention as failed | WITNESSED / INDETERMINATE; no success status |
| Network partition | No quorum claim | LOCAL_ONLY; preserve bounded local queue and alert on lag |
| Coordinator database rollback | Reconstruct from witness and retention evidence | Reconcile by highest common valid checkpoint; never trust local cache alone |
| Local database restored behind an anchor | Detect head mismatch against latest external checkpoint | Reject rollback; restore events from retained segment or enter recovery |
| Witness loses local state | Rebootstrap from latest anchored evidence and full continuity chain | No receipts until complete verification |
| Clock skew or time source loss | Continue sequence checks; mark time confidence degraded | INDETERMINATE for time-dependent validity where policy requires trusted time |
| Signer compromise | Stop signing; preserve evidence; execute key-recovery governance | Revocation and new key epoch; no retroactive silent re-signing |
| Retention policy drift | Alert and suspend new ANCHORED status | Restore lock configuration and verify stored object versions |

### 9.1 Recovery invariants

- No recovery process may discard a previously witnessed checkpoint.
- No process may select the longest chain solely by local sequence count; it must verify signatures, witness quorum, continuity and policy epoch.
- Conflicting valid checkpoints are preserved as evidence and trigger FORKED state.
- Recovery never changes an old checkpoint payload or receipt.
- Reconstructed local databases must be checked against the latest external checkpoint before protected operations resume.
- A missing checkpoint interval cannot be silently synthesized; it must be explicitly adjudicated and recorded as a gap.
- Recovery actions require a correlated audit event and, where they affect trust policy or roster, the appropriate Owner authority.

## 10. Privacy, data minimization and access control

Audit segments may contain sensitive operational data. The checkpoint package MUST contain only the minimum fields needed to prove event order and integrity. Where event payloads contain secrets or personal data, the architecture should separate the immutable integrity record from encrypted restricted payload storage:

- checkpointed event envelope: stable event ID, sequence, event type, actor/pseudonymous principal, time metadata, payload digest, prior hash and event hash;
- restricted payload: encrypted content under separately governed access and retention controls.

Redaction after checkpointing MUST NOT rewrite the historical checkpointed bytes. If a lawful erasure or correction is required, preserve the integrity envelope and append a new redaction/correction event; protect the restricted payload according to the applicable retention policy. Hashes of low-entropy sensitive values can leak information and MUST NOT be used as a substitute for encryption or keyed commitments without a documented threat analysis.

Witnesses and storage domains receive only the minimum evidence package required by policy. Access to exported bundles is logged and restricted. Public repository artifacts MUST never contain production audit payloads, secrets, private keys or personal data.

## 11. Offline verifier contract

The offline verifier accepts a portable evidence bundle and an explicit trust-policy snapshot. It MUST:

1. parse strictly and reject duplicate JSON keys, unknown critical fields and unsupported major versions;
2. canonicalize each signed payload using the frozen JCS profile;
3. recompute segment and checkpoint digests;
4. verify the checkpoint signature, signer scope and key validity at the relevant sequence/time;
5. verify all events in order, including event count, sequence continuity and every previous-hash link;
6. verify previous-checkpoint linkage back to a configured trust anchor;
7. verify at least two distinct witness signatures and their authorized roster membership at that checkpoint;
8. verify witness monotonic sequence and no conflicting checkpoint digest;
9. verify both independent retention receipts and the evidence package's exact object digests;
10. evaluate key revocation, policy freshness and compromise annotations;
11. produce a machine-readable report with per-check status and an overall result.

Overall results are limited to:

- **PASS-ANCHORED:** all cryptographic, continuity, quorum, retention and trust-policy checks pass.
- **FAIL:** a cryptographic or structural invariant is violated.
- **INDETERMINATE:** required trust, revocation, independence or retention evidence is missing or cannot be established.
- **UNSUPPORTED:** the bundle uses a version or algorithm the verifier does not implement.

The verifier MUST NOT convert INDETERMINATE or UNSUPPORTED into PASS. The report records verifier version, build digest, trust snapshot digest, bundle digest and exact checks performed.

## 12. Conformance and adversarial test plan

Implementation is not complete until the following suites run on the exact final source SHA.

### 12.1 Format and cryptography

- canonicalization test vectors across at least two independent implementations;
- duplicate-key, reordered-key, Unicode, invalid UTF-8, unsupported numeric and unknown-critical-field rejection;
- valid signature, invalid signature, wrong key, wrong purpose, wrong log, wrong environment and altered payload;
- signer key epoch, activation window, expiry and revocation boundary tests;
- domain-separation collision tests;
- digest mismatch at every package layer.

### 12.2 Chain, checkpoint and quorum

- complete contiguous segment accepted;
- missing, duplicated, reordered or modified event rejected;
- truncated local database after a witnessed head detected;
- database replacement and self-consistent chain reconstruction behind a witnessed head detected;
- stale checkpoint, replay, same-sequence competing digest and wrong previous-checkpoint digest rejected;
- 0-of-3 and 1-of-3 witness responses never yield quorum;
- 2-of-3 distinct valid witnesses yield quorum;
- duplicate receipt from one witness counts once;
- two witnesses sharing one identity root fail independence admission;
- one compromised witness cannot produce a quorum;
- witness state rollback and restore-from-old-backup rejected.

### 12.3 Retention and recovery

- immutable retention lock absent, shortened or bypassable => reject;
- write success with wrong read-back digest => reject;
- one retention domain unavailable => not anchored;
- two domains with same administrative root => independence test fails;
- object version overwritten or deleted => detection and alert;
- evidence export and offline verification with coordinator unavailable;
- restore drill from each retention domain independently;
- coordinator rollback, local DB rollback, network partition and partial receipt collection;
- signer rotation, witness rotation, revocation and compromise interval;
- fork detection and preservation of both candidate packages.

### 12.4 Operational and privacy

- secrets and private keys absent from logs, repository, fixtures and exported public artifacts;
- payload minimization and pseudonymous identity handling;
- bounded retries, backpressure, storage exhaustion and queue growth;
- monitoring for anchor lag, stale receipts, key expiry and retention expiry;
- alert delivery and escalation when quorum or retention is lost.

Critical invariants have zero tolerance. NOT RUN, BLOCKED and INDETERMINATE are never counted as PASS. Test fixtures use synthetic keys and synthetic audit events only.

## 13. Proposed implementation stages and acceptance gates

| Stage | Work | Exit evidence |
|---|---|---|
| E1 — Architecture freeze | Freeze envelope, manifest, receipt schemas, canonical byte rules, sequence semantics and test vectors | Owner-approved architecture version and independent design review or explicit waiver |
| E2 — Local protocol core | Pure Rust types, canonicalization, digest/signature verification, checkpoint state machine; no network or production keys | Unit/property tests and deterministic vectors |
| E3 — Witness protocol | Three test witness adapters with independent state stores, monotonicity, receipt signing and fault injection | 2-of-3 tests, replay/fork tests, witness independence evidence |
| E4 — Retention adapters | Two test retention adapters with immutable semantics, read-back and retention receipts | retention lock tests, independent restore drills |
| E5 — Offline verifier | Standalone verifier and portable bundle format | cross-implementation verification and adversarial suite |
| E6 — Integrated A4 verification | End-to-end exact-HEAD CI, threat-model reconciliation, fault/recovery evidence and closure package update | all required gates PASS; residual risks and evidence references recorded |
| E7 — Production readiness proposal | Provider/operator selection, cost, data residency, custody and operational SLO design | separate Owner decision; no automatic production activation |

The architecture stage does not authorize E2–E7 implementation. Each implementation stage must be separately scoped and remain on a dedicated branch until review. Production readiness and deployment require separate authorization.

## 14. Acceptance criteria for A4-03-E

A4-03-E may be considered implementation-verified only when all are true:

1. Frozen schemas and byte-level test vectors exist.
2. The checkpoint signer rejects any non-contiguous or locally invalid segment.
3. Three independently administered witness identities are evidenced; 2-of-3 valid receipts are required.
4. Each witness verifies the complete segment and persists its monotonic state before signing.
5. Two independently administered immutable-retention domains store and read back the full evidence package.
6. The offline verifier independently validates checkpoint, event chain, prior checkpoint, witness quorum, key lifecycle and retention evidence.
7. Truncation/reconstruction, replay, fork, signer compromise, witness loss, storage loss and rollback tests all pass.
8. Failure states never report ANCHORED or PASS-ANCHORED.
9. Key rotation, revocation and recovery are tested using synthetic keys; production custody remains separately gated.
10. Exact final HEAD CI and A4 evidence records are complete.

Even after these criteria pass, external anchoring proves that a particular audit history existed no later than the witnessed checkpoint and has not been altered relative to that anchor. It does **not** prove that the underlying event claims are true, that the event producer recorded every real-world event, or that all witnesses are honest.

## 15. Owner decisions reserved

The following choices remain intentionally open and require explicit Owner approval before implementation or procurement:

- final checkpoint cadence and maximum tolerated anchor lag;
- witness operator selection and documented independence assessment;
- retention operator/provider selection, data residency and retention duration;
- signer and witness custody model, custodian roles and recovery quorum;
- whether any mutation class must wait for external quorum before finalization;
- incident authority and adjudication procedure for a valid-looking fork;
- operational availability, cost and service-level targets;
- final cryptographic envelope version and any algorithm agility policy.

No defaults in this document are production commitments.

## 16. Current disposition

- **Architecture content:** DESIGN COMPLETE — proposed for review.
- **Implementation:** NOT STARTED.
- **Production signer/witness keys:** NOT CREATED.
- **Witness operators/providers:** NOT SELECTED.
- **Remote retention services:** NOT SELECTED OR CONFIGURED.
- **Live external checkpoint:** NOT RUN.
- **A4-03 external assurance:** NOT VERIFIED.
- **Overall A4:** remains PARTIAL — NOT CLOSED.
- **Merge/deployment/Genesis activation:** NOT AUTHORIZED.

This document closes only the architecture drafting task. It does not close A4-03-E implementation or the broader A4 stage.
