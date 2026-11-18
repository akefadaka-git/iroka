# G01 lineage A3 bounded amendment v1.1.0

## Status and scope

This additive amendment closes the A2 lineage semantic gaps G01-LIN-SEM-01 through G01-LIN-SEM-06. The frozen A2 v1.0.0 schemas remain unchanged. The amendment changes only the G01 lineage v1.1.0 input/output schemas, evaluator and positive/negative conformance vectors. The 12-chromosome/36-gene genome and no-authority boundary are unchanged.

## Proof binding

The input now requires a proof reference, issuer identity, signature reference, proof-policy ID/version and canonical SHA-256 digest. A trusted resolver must retrieve the exact proof bytes, verify signature and issuer trust under the named policy, and bind the proof to the subject, predecessor, relationship, epoch and contract version.

## Relationship cardinality

The v1.1.0 contract permits only `derived` and `successor`. `merged` is rejected until a separate schema version defines and validates a multi-parent representation. This is the A2-approved fail-closed alternative; a single predecessor must not be misrepresented as a complete merge.

## Graph and epoch integrity

The resolver must establish complete parent resolution, acyclicity, conflict-free ancestry and authoritative epoch monotonicity. A positive output includes structured proof-verification, graph-integrity, parent-resolution and epoch-validation evidence. The output schema requires positive depth and all evidence flags for `lineage_valid=true`; invalid output cannot claim positive depth.

## Conformance

The v1.1.0 vector set covers derived/successor positive cases and negative proof absence, invalid proof/issuer, cycles, conflicting parents, incomplete graph, non-monotonic epoch, unsupported merge, contradictory output and unknown predecessor.

## Remaining production boundary

The resolver trait is an integration boundary. Production closure still requires an authoritative subject/predecessor registry, retrievable signed succession-proof store, proof issuer trust policy, complete graph traversal and authoritative epoch source. Test doubles do not satisfy those deployment requirements.
