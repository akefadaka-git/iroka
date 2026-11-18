# G01 compatibility A3 bounded amendment v1.1.0

## Status and scope

This additive amendment closes A2 compatibility semantic gaps G01-COMP-SEM-01 through G01-COMP-SEM-06. The frozen A2 v1.0.0 schemas remain unchanged. The amendment changes only G01 compatibility v1.1.0 schemas, evaluator and positive/negative conformance vectors. The 12-chromosome/36-gene genome and no-authority boundary are unchanged.

## Canonical contract and version resolution

The input now names a canonical contract registry and version grammar. The trusted resolver must apply the policy-selected grammar to the exact source and target strings, resolve each to an immutable contract identity, and reject unknown, ambiguous or guessed normalization.

## Authenticated policy

The input binds policy ID, version, issuer and SHA-256 digest. The resolver must authenticate issuer/signature, policy immutability, scope and validity interval before semantic comparison. The policy's independently derived result, not `declared_compatible`, determines the decision.

## Migration evidence

A non-null migration digest requires a retrievable migration reference. The resolver authenticates the artifact, digest, provenance and exact source/target binding. Null is accepted only when the authenticated policy proves no migration is required.

## Output and conflict semantics

The output evidence records canonical source/target contract identities and versions, grammar/registry identity, policy issuer/version/digest and scope/validity checks, semantic comparison digest/result, declaration conflict and migration verification. The output schema enforces `compatibility=true` only with `decision=compatible`; incompatible and migration-required decisions must be false. A caller declaration conflict is recorded and produces a fail-closed effective decision.

## Conformance

The v1.1.0 vectors cover compatible/no-migration and migration-required positive cases plus unknown/ambiguous versions, registry/grammar mismatch, unauthenticated policy, declaration conflict, missing/invalid migration, unsupported null migration and contradictory output.

## Remaining production boundary

The resolver trait is an integration boundary. Production closure requires an authenticated immutable contract registry, explicit version-grammar policy, policy issuer trust roots, migration artifact storage and verification. Test doubles do not satisfy these deployment requirements.
