# IROKA BRAIN — A2 Cognitive Contracts Proposal

**Document ID:** IROKA-BRAIN-A2-CONTRACTS-001  
**Version:** 1.0.0  
**Status:** OWNER-APPROVED — A2 DESIGN/CONTRACT GATE VERIFIED-CLOSED; integration readiness remains dependency-gated  
**Parent:** IROKA-BRAIN-A1-001 v1.0.0 (Owner-approved / frozen)  
**Scope:** G03 task, result, plan, critique, model capability and domain adapter contracts  
**Implementation:** None. Design-only.

## 1. Ownership invariants

- G01 authenticates principals and supplies trusted tenant context.
- G02 owns policy, approval and authorization decisions.
- G03 owns cognitive coordination, reasoning, planning and cognitive critique.
- G04 owns knowledge sources, retrieval and evidence provenance.
- G05 owns memory policy, storage, consent, retention, correction and deletion.
- G06 owns modality processing and normalized observations.
- G07 owns agent identity/delegation; G08 durable orchestration; G09 protected effects.
- G10 owns evaluation; G11 independent assurance/audit; G12 governed evolution.

No model response, plan, task state, citation or critic result grants authority. No G03-owned duplicate domain store is permitted.

## 2. Versioning rules

Contract family: iroka.brain. Proposed major version: 1. Boundary serialization: UTF-8 JSON; internal implementation may use strongly typed Rust structures. Every envelope has schema_id, contract_version and correlation_id; task-scoped envelopes also have task_id. Unknown major versions, enum values, malformed required fields and unsupported capability combinations are rejected. Additive optional fields require explicit receiver support. Breaking changes require G12-governed version migration. No signed canonical digest is specified until its encoding and trust authority are approved.

## 3. Cognitive task envelope

~~~json
{
  "schema_id": "iroka.brain.task.v1",
  "contract_version": "1.0",
  "task_id": "opaque-id",
  "correlation_id": "opaque-id",
  "created_at": "RFC3339 UTC",
  "principal_ref": "opaque G01 verified-principal reference",
  "tenant_context_ref": "opaque G01 membership-context reference",
  "policy_context_ref": "opaque G02 policy context reference",
  "objective": {
    "text": "bounded objective",
    "success_criteria": ["explicit criterion"]
  },
  "task_class": "answer | research | analysis | planning | engineering | translation",
  "requested_capabilities": ["reasoning", "evidence_synthesis"],
  "input_refs": [
    {
      "ref": "opaque source reference",
      "source_domain": "user | G04 | G05 | G06 | CIW",
      "classification": "public | internal | confidential | restricted",
      "purpose": "declared purpose"
    }
  ],
  "locale": {
    "requested": "am-ET",
    "fallbacks": ["en"],
    "calendar": "ET | GC | unspecified",
    "timezone": "IANA timezone or unspecified"
  },
  "constraints": {
    "max_input_bytes": 1,
    "max_output_tokens": 1,
    "max_iterations": 1,
    "deadline_at": "RFC3339 UTC",
    "allow_external_provider": false,
    "allow_persistence": false,
    "allow_agent_delegation": false,
    "allow_protected_effects": false
  },
  "required_evidence": {
    "citation_required": false,
    "minimum_source_count": 0
  },
  "output_schema_id": "iroka.brain.result.v1"
}
~~~

Normative constraints:
1. Principal, tenant and policy references are opaque references issued/resolved by authoritative domains; untrusted user/model content cannot establish them.
2. Tenant context is bound to the verified principal and revalidated against membership/revocation. Caller-supplied tenant_id never establishes authority.
3. Classification and purpose are policy inputs; caller assertions require validation.
4. Budgets must be finite and nonzero for executable tasks. The trusted composition root intersects requested limits with configured ceilings.
5. First-slice flags for external provider, persistence, delegation and protected effects are false.
6. No credentials, trust roots, approval secrets or unrestricted personal data enter model-editable content.
7. A task envelope is not an authorization request or grant.

## 4. Cognitive result envelope

~~~json
{
  "schema_id": "iroka.brain.result.v1",
  "contract_version": "1.0",
  "task_id": "opaque-id",
  "correlation_id": "opaque-id",
  "status": "completed | partial | abstained | denied | cancelled | timed_out | budget_exhausted | failed",
  "answer": {"content": "localized response", "locale": "am-ET"},
  "claims": [
    {
      "claim_id": "opaque-id",
      "text": "claim",
      "epistemic_status": "source_supported | deterministic_check | inference | hypothesis | assumption | unknown",
      "evidence_refs": [],
      "limitations": []
    }
  ],
  "assumptions": [],
  "unresolved_questions": [],
  "uncertainty": {"kind": "calibrated | qualitative | unavailable", "value": null},
  "model_attribution": {"adapter_id": "deterministic-fake", "model_id": "fixture", "model_version": "immutable-version"},
  "termination": {"reason": "success | abstention | policy_denial | cancellation | timeout | budget | provider_error | validation_error"},
  "resource_usage": {"input_units": 0, "output_units": 0, "elapsed_ms": 0},
  "verification": {"status": "not_verified | deterministic_checks_passed | requires_independent_review", "assurance_ref": null}
}
~~~

A completed result satisfies declared task criteria, not necessarily external truth. Partial results identify unmet criteria. Abstention is a valid terminal state. A source reference does not prove claim support. Deterministic verification names its verifier/version. Only G11 issues independent assurance; G03 cannot populate an independent assurance receipt. Model attribution is mandatory for generated content. Hidden chain-of-thought, private prompts and secrets are excluded.

## 5. Plan and critic contracts

A plan proposal contains plan_id, task_id, schema/version, objective, success criteria, ordered stable step IDs, dependency edges, preconditions, expected outcomes, required capabilities, risk/reversibility, budget/deadline, approval points, stop/rollback conditions, evidence references and assumptions. Reject duplicate IDs, missing dependencies, cycles where DAG semantics apply, unmet prerequisites, out-of-scope capabilities and budget violations. A plan is not a G08 workflow or G09 execution grant.

A critic result contains critique_id, task_id, subject digest, model attribution, findings (severity/category/affected claim or step/evidence), coverage, limitations and recommendation (revise, abstain, escalate, or accept with limitations). A critic cannot authorize, change policy, certify itself or replace G11 assurance.

## 6. Model capability manifest

Proposed fields: adapter ID/version; model ID/exact revision; supported task classes, modalities and locales with evidence level; structured-output/streaming/cancellation support; context and size limits; privacy, retention and residency attributes; timeout/retry/rate-limit behavior; measured quality/latency/resource/cost metadata with benchmark reference; provider identity and license/provenance. Routing uses a trusted versioned allowlist. Provider metadata is not self-attested authority. The first implementation candidate uses only a deterministic fake adapter and synthetic fixtures; no provider is selected or activated.

## 7. Domain adapter boundaries and current evidence

| Adapter | G03 consumes | Authoritative owner | Current finding |
|---|---|---|---|
| Identity/tenant | Opaque principal and tenant-context refs | G01 | Kernel VerifiedPrincipal has no tenant resolver; OPEN |
| Policy | Versioned policy/decision ref | G02 | Kernel foundation contract excludes signed/persisted policy lifecycle; OPEN |
| Knowledge | Evidence refs, source metadata, freshness/conflict | G04 | CIW A2 says executable G04 API not reconciled; OPEN |
| Memory | Permitted context refs and lifecycle metadata | G05 | No executable G05 API verified; OPEN |
| Perception | Normalized observation refs | G06 | No executable G06 API verified; OPEN |
| Orchestration | Workflow/task refs and state snapshots | G08 | G08 A2 draft has tenant and branch-lineage blockers; OPEN |
| Assurance | Trace/evidence refs | G11 | Reuse; no duplicate assurance store |
| Evaluation | Minimized evaluation record refs | G10 | Runtime contract not reconciled; OPEN |

No direct cross-domain database access or invented production endpoint is allowed.

## 8. Error taxonomy

Distinguish invalid schema/version; unauthenticated/revoked principal; invalid/expired tenant context; policy denied/unavailable; unsupported task/capability/locale; evidence unavailable/stale/conflicting; memory denied/expired/deleted; invalid observation; model unavailable/timeout/refusal/malformed output; budget exhaustion; cancellation; orchestration conflict/storage failure; and assurance escalation. Errors are stable machine-readable codes with safe localized explanations and no cross-tenant existence disclosure.

## 9. A2-to-A3 acceptance tests

1. Exact-version task/result round trip; reject unknown major versions and enums.
2. Reject forged principal, tenant and policy references.
3. Bind tenant context to authenticated principal; test membership revocation.
4. Enforce classification/purpose before model adapter invocation.
5. Bound input/output, iterations, time, concurrency and resources.
6. Normalize fake-adapter timeout, refusal, malformed output and cancellation.
7. Reject invalid plans, cycles and out-of-scope capabilities.
8. Ensure critic output never becomes G11 assurance.
9. Preserve evidence provenance; reject fabricated source references.
10. Create no G05/G06/G08/G09/G11-owned state in G03.
11. Preserve Amharic/English UTF-8 and Ethiopic script.
12. Prove no external provider, production data or protected side effect in the first increment.

## 10. Open A2 dependencies and decisions

| ID | Finding | Required disposition |
|---|---|---|
| A2-C01 | G01 tenant resolver absent from current Kernel contract | Approve authoritative resolver or block multi-tenant runtime |
| A2-C02 | G02 signed/persisted policy lifecycle absent from Kernel foundation | Define trusted policy composition and fail-closed adapter |
| A2-C03 | G04 executable API not reconciled | Identify exact version or defer adapter |
| A2-C04 | G05 executable API not verified | Identify exact version or defer adapter |
| A2-C05 | G06 executable API not verified | Identify exact version or defer adapter |
| A2-C06 | G08 PR #18 has missing tenant resolver and stale Kernel lineage | Resolve before multi-tenant workflow integration |
| A2-C07 | CIW PR #23 is based on earlier Kernel branch | Reconcile ancestry and exact-head tests before composition |
| A2-C08 | No Brain Amharic corpus/license/owner verified | Approve corpus provenance and qualified reviewers |
| A2-C09 | No workload/hardware benchmark thresholds | Approve representative workload and threshold methodology |
| A2-C10 | First A3 increment not yet approved | Separate explicit Owner authorization required |

## 11. A2 closure checklist

- [x] A1 architecture v1.0.0 frozen by Owner D2.
- [x] Repository/workstream inventory and relevant CIW/G08/Kernel contract review completed.
- [x] Task/result/plan/critic/gateway contracts drafted.
- [x] Owner approves this A2 contract proposal (2026-11-09).
- [x] G01/G02 contract boundaries accepted; executable integration remains blocked until exact authoritative APIs and trust/policy lifecycle are reconciled.
- [x] G04/G05/G06 executable interfaces explicitly deferred; G03 may consume only verified versioned ports, never duplicate their authority.
- [x] G08 and CIW integration explicitly gated on exact-base/ancestry reconciliation before any dependent composition.
- [x] Synthetic-only fixtures approved for initial development; real corpus ingestion and numerical quality/performance thresholds deferred pending provenance, reviewer and representative workload approval.
- [x] Broader A3 scope direction recorded; separate explicit A3 implementation authorization remains required.
- [x] A2 design/contract closure recorded by Owner approval (2026-11-09).

**Disposition:** A2 DESIGN/CONTRACT GATE — VERIFIED-CLOSED by Owner approval on 2026-11-09. This closure is limited to architecture and interface contracts. Integration readiness is **PARTIAL**: A2-C01 through A2-C07 remain implementation-entry blockers for the affected adapters; A2-C08/C09 remain deferred to licensed-corpus and benchmark approval; no unresolved interface may be replaced by a guessed API.

### 12. Owner approval and dependency disposition — 2026-11-09

The Owner approved this proposal as the binding G03 cognitive contract v1.0.0 and selected a broader, cross-domain A3 direction. The approval accepts the ownership invariants, envelope semantics, plan/critic boundaries, model-gateway contract, error taxonomy and A2 acceptance suite.

The following are explicit A3 integration gates, not permission to bypass missing domain authorities:

- **G01/G02:** no Brain-owned identity, tenant resolver, policy engine, trust root, approval registry or audit store. Pin and reconcile the authoritative Kernel API and trusted composition root before enabling authenticated or tenant-scoped execution.
- **G04/G05/G06:** define adapters against their owners' exact versioned contracts only. Until then, evidence, memory and perception adapters remain unavailable and tasks must abstain or return a typed unavailable result.
- **G08/CIW:** no branch stacking or code adoption until exact commit ancestry, base compatibility and complete diff review are established. Existing candidate PRs are not implicitly approved or merged by this decision.
- **Amharic data:** synthetic fixtures only. Any real corpus requires source-by-source provenance, licence/permission, integrity and qualified language review.
- **Benchmarks:** establish a reproducible harness and measurement definitions first. Numeric release thresholds require representative workloads, hardware and Owner disposition; no target may be invented.
- **G07/G09:** no agent delegation or protected effects in this A3 scope. G03 may emit proposals only; execution remains separately authorized through the existing governance boundary.
- **A3 authorization:** this document records the broader proposed scope, not implementation authorization. A separate explicit Owner authorization is required after the A3 work packages and exact baseline are presented.

No merge, deployment, production activation, signing, external provider activation or paid-service dependency is authorized.
