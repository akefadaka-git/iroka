# IROKA A2 Owner Approval Record

- Record ID: IROKA-A2-OWNER-APPROVAL-001
- Version: 1.0.0
- Date: 2026-11-05
- Authority: Repository Owner
- Governing register: IROKA-A2-OWNER-DECISION-REGISTER.md
- Status: APPROVED — OD-01 THROUGH OD-09
- Scope: Approval of the nine recommended defaults exactly as documented in the governing register.

## Owner decision

The Owner explicitly approves all nine recommendations in the IROKA A2 Owner Decision Register as written. No amendments, deferrals or rejections were supplied. The recommendations are adopted as the approved architectural direction, subject to their stated evidence, security, conformance and A2 exit requirements.

## Approved dispositions

| ID | Approved recommendation |
|---|---|
| OD-01 | Small capability-based microkernel with a minimal privileged core and isolated user-space services. Existing Rust kernel work remains an implementation foundation subject to exact-SHA security and architecture review. |
| OD-02 | Versioned, typed, deterministic IROKA Intermediate Representation (IIR), initially executed in a capability-restricted VM; native backends only after semantic equivalence, reproducible-build and security conformance evidence. |
| OD-03 | x86_64 and AArch64 initial architecture families; hosted development/test first; qualify specific hardware and firmware profiles separately. |
| OD-04 | Statically typed INL; ownership/borrowing or equivalently enforceable affine resource model; safe by default; narrowly scoped unsafe/FFI; explicit effects and deterministic error handling. |
| OD-05 | Rust-hosted compiler/verifier bootstrap; INL specified independently; self-hosting only after pinned conformance and reproducible-build requirements pass. |
| OD-06 | VYRAQON remains an independent, separately governed and versioned writing-system project; IROKA consumes integrity-verified releases through a narrow adapter and does not redefine it or grant it execution authority. |
| OD-07 | Versioned canonical semantic model; deterministic CBOR signed interchange envelope; JSON diagnostic/debug view; preserve original source bytes/code points and distinguish source from normalized interpretation. Cryptographic algorithms and key custody remain subject to security review. |
| OD-08 | Amharic-first Ethiopia profile with English secondary; preserve Ethiopic Unicode and mixed scripts; explicit Ethiopian/Gregorian calendar semantics; Ethiopia defaults where applicable; independently versioned African regional profiles. |
| OD-09 | Zero tolerance for known critical security failures; exact-SHA, target-specific conformance evidence; no aggregate score masking critical failures; separately approved hardware performance budgets; reproducible builds and signed provenance as release gates. |

## Binding qualifications

1. The A1 Amharic-first Ethiopian and African requirements remain binding and are not reopened or weakened.
2. Approval of OD-01 does not certify the existing Rust kernel as a secure or complete native OS.
3. Approval of OD-02 does not authorize native code generation before the stated verification gates.
4. Approval of OD-03 does not imply support for every device in either architecture family.
5. Approval of OD-04 and OD-05 does not mean the INL grammar, compiler, verifier or runtime are implemented or conformant.
6. Approval of OD-06 does not assert that the VYRAQON repository, normative release or bilateral compatibility contract has been verified.
7. Approval of OD-07 does not select cryptographic algorithms, key custody or trust roots; those require security review.
8. Synthetic fixtures alone are not authoritative Amharic/Ethiopic language or Ethiopian calendar oracles.
9. Hosted test evidence cannot certify bare-metal readiness.

## Authorization boundary

This record approves architecture decisions only. It does not authorize A3 implementation, source-code changes, trust-root or key changes, repository creation/publication, cross-repository release, main-branch changes, merges, branch deletion, or production deployment.

A3 remains a separate Owner authorization gate. A2 closure remains conditional on the full technical evidence and exit criteria in the governing register. Resolving all nine Owner decisions does not mean their dependent evidence is complete.

## Required next actions

1. Link this approval record from the decision register without changing its original recommendations.
2. Complete exact-SHA review of existing Rust kernel and workflow artifacts against OD-01–OD-05 and A1.
3. Close the remaining A2 evidence gaps: threat model and privilege boundary; normative INL specifications; verified VYRAQON repository/release and bilateral contract; reviewed Amharic/Ethiopic corpus; Ethiopian calendar oracle; executable conformance harness; hardware profiles and performance budgets.
4. Present an evidence-labelled A2 closure report and separate A3 authorization request.

## Approval provenance

The Owner's explicit instruction in this conversation on 2026-11-05 approved all nine recommendations and requested that they be recorded as approved. This record preserves that disposition. Any later amendment must be made through a separately identified, superseding Owner decision record; do not silently rewrite this record.

---

**Disposition: OD-01–OD-09 APPROVED. A3 NOT AUTHORIZED. A2 CLOSURE NOT YET VERIFIED.**
