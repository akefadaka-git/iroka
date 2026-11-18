# G08 Workflow Graph — A3 Implementation Note

- Gene: `g08.workflow-graph`
- Contract: IROKA A2 Character Gene Contracts v1.0.0
- Semantic review: `A2-G08-WORKFLOW-GRAPH-SEMANTIC-REVIEW-001` (VERIFIED_CLOSED; bounded A3 amendment)
- Base: `implementation/a3-g07-ci-matrix` at `bbd971f35cf6b19be53921cfbb75c1a54912250c`
- Scope: workflow graph validation only; no scheduler, coordinator persistence, worker execution, or protected side effect.

## Implemented controls

1. Workflow identity, strict semantic graph version and exact revision reference resolve against a trusted immutable workflow-revision registry.
2. Node IDs and operation references resolve through the operation registry. Operation implementation digests, registry-owned effect classes and immutable configuration values are bound to each node. Configuration JSON is canonicalized and its SHA-256 digest recomputed; a matching registry key alone is insufficient.
3. Edge IDs, endpoints, self-edges, duplicate IDs/pairs and dependency semantics resolve through a versioned dependency-kind registry. This v1 contract supports only mandatory, unconditional `required` (success/block) and `ordering` (completion/continue) edges. Unknown, optional or conditional kinds fail closed; all edges remain in the topological constraints.
4. Canonical graph digest binds the immutable graph revision, normalized node/edge ordering, operation/configuration references, workflow/operation/dependency/checkpoint registry digests, validator version and SHA-256 configuration digest semantics.
5. Deterministic Kahn topological traversal uses lexicographic tie-breaking. A valid order contains every node exactly once and respects every edge. Cycles and invalid references emit no topological order.
6. Structured provenance covers graph source/revision, each node operation and configuration, each dependency edge, registry sources and validation inputs. Incomplete, duplicate or mismatched provenance fails closed.
7. Checkpoint references resolve to immutable registry entries bound to workflow revision, node and configuration. A safe-stop node requires a valid checkpoint and an explicit recovery-node reference; recovery references must resolve within the graph.
8. Strict A3 Draft 2020-12 input/output schemas and positive/negative schema vectors are added.

## Registry trust boundary

`WorkflowGraphRegistry` is an injected trusted interface. Its implementation must resolve only authenticated, immutable, versioned snapshots and registered effect classes. This module verifies returned bindings and recomputes canonical configuration digests; it does not itself implement registry signature verification, key custody or registry enrollment. Caller-supplied graph data cannot replace registry state.

## A2 semantic gaps

The implementation addresses G08-WG-SEM-01 through G08-WG-SEM-08. It does not support optional or conditional dependencies in this contract version; unsupported dependency semantics fail closed. No optimization may remove or bypass a mandatory dependency.

## Verification

- Rust unit tests cover deterministic ordering and digest reproducibility; revision/version and registry substitution; canonical configuration digest recomputation; effect-class and dependency semantics; missing/duplicate node and edge identities; invalid endpoints, self-edges and cycles; complete provenance; checkpoint immutability/binding; and safe-stop/recovery paths.
- Python schema validator checks Draft 2020-12 meta-schema validity and positive/negative input/output vectors.
- The three-workflow exact-SHA matrix is required on the final candidate. Do not claim verification until Rust, GENESIS and supply-chain runs all identify the same source SHA and succeed. The G08-specific workflow must also pass on that SHA.

## Not implemented in this slice

- `g08.scheduler-policy`
- `g08.coordination-state`
- Durable workflow/task orchestration contract in PR #18 (separate draft A2 proposal with unresolved G01 tenant-context prerequisite)
- Worker scheduling, execution, G09 adapters, side effects, production persistence or runtime activation.
