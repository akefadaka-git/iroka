# G08 Workflow Graph — A3 Implementation Note

- Gene: `g08.workflow-graph`
- Contract: IROKA A2 Character Gene Contracts v1.0.0
- Semantic review: `A2-G08-WORKFLOW-GRAPH-SEMANTIC-REVIEW-001` (VERIFIED_CLOSED; bounded A3 amendment)
- Base: `implementation/a3-g07-ci-matrix` at `bbd971f35cf6b19be53921cfbb75c1a54912250c`
- Scope: workflow graph validation only; no scheduler, coordinator persistence, worker execution, or protected side effect.

## Implemented controls

1. Workflow identity, strict semantic graph version and exact revision reference resolve against a trusted immutable workflow-revision registry.
2. Node IDs, node types, operation references, implementation/configuration digests and registered effect classes are validated against an operation registry.
3. Edge IDs, endpoints, self-edges, duplicate endpoint pairs and exact required-success/block versus ordering-completion/continue semantics are validated against a dependency registry.
4. Canonical graph digest binds graph revision, normalized node/edge ordering, operation registry, dependency registry, workflow registry, validator version and SHA-256 configuration digest semantics.
5. Deterministic Kahn topological traversal uses lexicographic tie-breaking. Every node appears exactly once on valid graphs; cycles and invalid references emit no topological order.
6. Provenance and version-bound evidence are required and checked against the registry snapshot digests.
7. Strict A3 Draft 2020-12 input/output schemas and positive/negative schema vectors are added.

## Registry trust boundary

`WorkflowGraphRegistry` is an injected trusted interface. Its implementation must resolve only authenticated, immutable, versioned snapshots. This module verifies the returned bindings and digest references; it does not itself implement signature verification, key custody or registry enrollment. Caller-supplied graph data cannot replace registry state.

## A2 semantic gaps

The implementation addresses G08-WG-SEM-01 through G08-WG-SEM-08. Dependency types are deliberately bounded to registered `required` and `ordering` semantics. Unknown dependency kinds fail closed. No optimization may remove a dependency edge.

## Verification

- Rust unit tests cover positive ordering, order-independent digest, strict semantic versions, exact revision-reference binding, registry substitution, operation/configuration/effect-class substitution, dependency semantic substitution, invalid references, self-edges, duplicate nodes, unknown dependency kinds and cycles.
- Python schema validator checks Draft 2020-12 meta-schema validity and positive/negative input/output vectors.
- The three-workflow exact-SHA matrix is required on the final code-bearing candidate. Do not claim verification until Rust, GENESIS and supply-chain runs all identify the same source SHA and succeed.

## Not implemented in this slice

- `g08.scheduler-policy`
- `g08.coordination-state`
- Durable workflow/task orchestration contract in PR #18 (separate draft A2 proposal with unresolved tenant-context dependency)
- Worker scheduling, execution, G09 adapters, side effects, production persistence or runtime activation.
