# IROKA Native Cognition

This crate is the first native reasoning increment for IROKA. It uses deterministic
symbolic forward-chaining over explicit facts and rules; it does not invoke an
external model, network, filesystem, tool or protected side effect.

## Current capabilities

- Typed positive and explicit-negative literals.
- Deterministic rule ordering and multi-step forward inference.
- Query outcomes: entailed, refuted, unknown or contradicted.
- Provenance trace for every derived fact.
- Hard limits for elapsed time, inference steps, facts and rules.
- Explicit terminal reasons; budget exhaustion is never reported as completion.
- Unit tests for inference, contradiction, unknowns and resource bounds.

## Current limitations

This is a bounded symbolic substrate, not general intelligence. It does not yet
provide natural-language understanding, probabilistic inference, theorem proving,
constraint solving, temporal/causal reasoning, knowledge ingestion, durable memory,
planning/search, learning, multimodal perception, agent orchestration or a full
Kernel authorization composition. Those are separate implementation workstreams.

The default runtime budget is three seconds. The budget is a hard stop condition
checked between inference operations; OS scheduling and process termination are
outside the crate's ability to guarantee at an exact wall-clock instant.
