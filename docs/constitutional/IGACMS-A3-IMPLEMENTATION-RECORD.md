# IGACMS A3 implementation record

**Authorization:** Owner authorization received 2026-11-07 for A3.1–A3.8 in `akefadaka-git/iroka`.
**Baseline:** IGACMS v1.0 A2 at `a709fc473b23494839417449e34bebf4cb8be77a`.
**Branch:** `feat/igacms-a3-implementation`.
**Merge/deployment:** not authorized; not performed.

## Work packages
1. A3.1 — Machine-readable DNA/Genome/chromosome/gene/marker schemas and complete manifest.
2. A3.2 — Canonical validator including all eight historical domains, explicitly including `reasoning`, 12 chromosomes, 36 core genes, 14 principles, 14 invariants, 27 markers, uniqueness and acyclic dependencies.
3. A3.3 — SHA-256 fingerprint over deterministic canonical JSON. This initial implementation is restricted to the integer-only manifest profile; it is not claimed as a general RFC 8785 implementation for arbitrary floating-point JSON.
4. A3.4 — Ed25519 attestation and trust-root verification, epoch-zero genesis and anti-rollback. No production keys are created or provisioned.
5. A3.5 — M0–M5 evidence gates, Owner approval and independent review controls, M5 dual control.
6. A3.6 — Kernel integration gate before Owner-approved authorization decisions.
7. A3.7 — Historical digest-preserving migration evidence; DNA-045 remains extension-review and outside genesis.
8. A3.8 — Positive/negative conformance tests; full A4 exact-SHA execution and independent review require recorded evidence.

## Known limitations to close before A3 completion
- Raw JSON duplicate-key detection is not yet implemented at token parsing level.
- JCS numeric serialization is restricted to integer-only values; full RFC 8785 numeric support is required before claiming general JCS conformance.
- Trust-root provenance metadata is not a production custody ceremony.
- Source tests are not PASS evidence until run at the exact final SHA.
