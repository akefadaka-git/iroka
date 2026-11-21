# TALORA–IROKA A3 Implementation Status

- **Record:** TALORA-IROKA-A3-STATUS-001
- **Version:** 0.1.0
- **Date:** 19 November 2026
- **Phase:** A3 implementation in progress
- **Outcome:** PARTIAL — first private task-service slice implemented and verified
- **Authority:** Owner authorization received 19 November 2026
- **No merge or deployment authority:** This record does not authorize PR merge, main-branch changes, production data, live providers, or A5 deployment.

## 1. Immutable implementation baseline

- IROKA repository: `akefadaka-git/iroka`
- Implementation branch: `integration/talora-a3-private-api`
- Base IROKA main SHA: `1aea1447eadf1d827d702fd6c4034fa058aac21e`
- Verified code head: `8056cea136f42436d896078046796eba2129092b`
- Draft PR: [#129](https://github.com/akefadaka-git/iroka/pull/129)
- TALORA repository: `akefadaka-git/talora`
- TALORA main SHA remains: `2562962fc44636cdebfa49c7bf3c3cdcb618751c`
- IROKA main remains: `1aea1447eadf1d827d702fd6c4034fa058aac21e`

The implementation branch is based directly on the stated IROKA main SHA. Documentation-only status records were added after the verified code head; they do not alter the verified source baseline. No merge, rebase, force-push, or deletion of candidate branches was performed.

## 2. Implemented files

1. `Cargo.toml` — added `crates/iroka-talora-api` to the IROKA workspace.
2. `Cargo.lock` — added the workspace package and its existing locked dependencies.
3. `crates/iroka-brain/Cargo.toml`, `src/lib.rs`, `src/neurogenetic.rs` — salvaged the independent BRAIN cognitive core from candidate SHA `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d`; the feed-forward test fixture now uses structurally verified cells, and equivalent `Default` implementations are derived to satisfy Clippy.
4. `crates/iroka-talora-api/Cargo.toml` — added the private API crate with serde, serde_json, sha2, and local IROKA kernel/BRAIN dependencies.
5. `crates/iroka-talora-api/src/lib.rs` — added the development-only service core, typed task/capability contracts, route handler, kernel-policy enforcement, BRAIN-backed fake adapter and tests.

No IROKA source was copied into TALORA. The TALORA repository was not modified.

## 3. Verified implementation in this slice

- Private route-handler contract for health, capabilities, task submission, task status, terminal SSE event and cancellation response.
- Injected workload-authenticator boundary, service audience check, and tenant/workspace/project/scope enforcement.
- Existing IROKA kernel policy evaluator is invoked before accepting the supported capability.
- TALORA fake/local execution is routed through the salvaged BRAIN CognitiveRuntime and its deterministic fake adapter; no remote inference is performed.
- Deterministic fake/local adapter is the only enabled adapter class; remote adapter classes are rejected.
- Idempotency replay and conflicting-payload rejection.
- Hard development caps for request text, objective, output, task count, input-reference count and task lifetime.
- Consent, authorization, policy, output-schema, expiry and document-revision references are bound to each task request/result.
- Development profile accepts synthetic-classified input references only.
- Remote-provider and persistent-memory permissions must be false.
- Paid-provider calls and ETB cost attribution are explicitly zero.
- Amharic locale identifier `am-ET` and English are accepted. This is not a claim of validated Amharic model quality or full-workflow support.
- Request text is processed in memory and is not included in retained task results. Task metadata is process-local and bounded.

## 4. Exact-head CI evidence

The following GitHub Actions run verified the exact code head `8056cea136f42436d896078046796eba2129092b`:

- Run **44457815902**: [Rust kernel verification](https://github.com/akefadaka-git/iroka/actions/runs/44457815902)
- Formatting: PASS
- Workspace compilation: PASS
- No-default-features compilation: PASS
- Unit and contract tests: PASS — 45 BRAIN/neurogenetic, 71 kernel, 2 integration, and 13 TALORA API tests
- Clippy: PASS
- Overall run: SUCCESS

Earlier failures were corrected before the verified head. The initial service slice, kernel-policy integration, request-envelope implementation and HTTP lifecycle tests each passed their subsequent exact-head runs. The first BRAIN integration run (44457497090) exposed ten neurogenetic test-fixture failures because feed-forward tests used proposed rather than structurally verified cells. After correcting the fixture, the full test suite passed; Clippy then identified three derivable Default implementations. Those were corrected without changing runtime policy, and Run 44457815902 passed all checks.

## 5. Explicitly not implemented or not verified

- No network listener or runnable HTTP host is attached to the route handler. TLS termination, loopback binding, trusted reverse-proxy configuration, connection limits and request deadlines remain host responsibilities.
- No production workload-token verifier, issuer trust store, revocation source, credential rotation or mutual-TLS deployment is configured. The authenticator is an injected trust boundary; tests use a test-only authenticator.
- The service executes the fake adapter synchronously. There is no asynchronous worker queue, durable event replay, durable task storage or effective cancellation of an in-flight task.
- G05 governed memory, persistent project-memory opt-in, retention, correction and deletion are not implemented. This slice does not persist project memory.
- G03/G08 inference and workflow components are not integrated into this branch.
- G05/G02/G11 PostgreSQL, authority, multiworker and checkpoint components are not integrated into this branch.
- CIW conversation routes, BRAIN cognitive core and the separate localization candidate are not integrated.
- No live model provider, provider key, paid inference, production creative data, production SLO, production topology or deployment is enabled.
- TALORA backend client integration has not been implemented in the TALORA repository.
- No end-to-end TALORA-to-IROKA network test, database migration test, SBOM or integrated independent security/architecture review has been completed.

## 6. Component disposition for A3

The implementation uses the current IROKA main kernel as the stable policy primitive and adds the TALORA service boundary as a new workspace crate. This is a bounded initial slice, not proof that the divergent G03/G08 and G05/G02/G11 candidates have been reconciled into one compatible graph.

The initial capability remains `talora.dev.fake.v1`. BRAIN is now included as an isolated cognitive core and is called only through its deterministic fake adapter. The separate G03/G08 workflow/inference candidate, G05/G02/G11 memory/authority/checkpoint candidates, CIW and localization remain excluded from this slice rather than silently assumed present. G05 memory is not bypassed or duplicated; no persistent memory endpoint is exposed.

## 7. Governance and next gate

- A3 implementation: **IN PROGRESS / PARTIAL**
- First service slice: **IMPLEMENTED**
- Exact code-head CI: **PASS**
- Full TALORA–IROKA integration: **NOT VERIFIED**
- A4: **NOT STARTED**
- Independent security/architecture review: remains after implementation and A4 reconciliation, before A5, per `OD-2026-11-17-IR-01`.
- PR #129: **OPEN / DRAFT / UNMERGED**
- IROKA main changes: **NONE**
- TALORA main changes: **NONE**
- A5 deployment: **NOT AUTHORIZED**

Next A3 work: complete the trusted HTTP host and workload-authentication adapter, reconcile the G03/G08 and G05/G02/G11 component interfaces without destructive branch composition, add the approved memory/API lifecycle boundaries, and then implement the TALORA backend client and integrated end-to-end tests on separate reviewable branches.
