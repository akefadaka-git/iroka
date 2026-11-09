# VYRAQON ↔ IROKA — Interoperability Specification

**Contract ID:** IROKA-VYRAQON-INTEROP-001  
**Version:** 1.0.0-draft  
**Status:** IROKA-side normative integration contract; VYRAQON-side ratification pending  
**Project boundary:** VYRAQON remains independently governed  
**Parent:** IROKA-A2-NATIVE-001; IROKA-A1-REGIONAL-001  
**Implementation authorization:** None

## 1. Purpose and authority

This document specifies how IROKA consumes VYRAQON as a first-class core writing and computational representation capability while preserving VYRAQON's independent identity, governance, repository, versioning and release authority.

This is an IROKA integration contract. It does not define or amend VYRAQON's normative grammar, glyph inventory, phonology, orthography, semantics or canonical encoding. Those must be ratified by the authoritative VYRAQON project. Until the VYRAQON repository and versioned standard exist, fields marked VYRAQON-AUTHORITATIVE are unresolved external dependencies.

## 2. Normative principles

1. VYRAQON is a first-class IROKA capability, not a theme or optional font.
2. VYRAQON is not owned by or absorbed into IROKA.
3. VYRAQON's own repository is authoritative for normative standards and releases.
4. IROKA owns adapters, execution policy, INL lowering, runtime bindings and IROKA-specific assurance.
5. No private grammar fork or silent semantic divergence is permitted.
6. VYRAQON parsing, translation or compilation cannot grant authority.
7. Source text, script, language, provenance and review state must be preserved.
8. Amharic-first Ethiopia requirements remain binding at all user-facing and developer-facing boundaries.

## 3. Repository and release boundary

Target repositories:
- `akefadaka-git/vyraqon`: normative VYRAQON standard, grammar, reference corpus, reference implementation, conformance suite and signed releases.
- `akefadaka-git/iroka`: IROKA adapter, INL front end/backend, runtime, policy integration and cross-project tests.

The VYRAQON repository has not yet been verified as available in the connected account. No VYRAQON release, grammar or digest is currently pinned by this specification. This is an explicit A2 dependency blocker.

IROKA MUST consume a pinned immutable release or content-addressed artifact. The dependency lock MUST include:
- VYRAQON project identifier and canonical repository;
- standard semantic version;
- grammar version;
- schema/AST/IR version;
- artifact digest and digest algorithm;
- signature and signer identity;
- release provenance and build attestation reference;
- compatibility range;
- retrieval location and license/usage terms;
- date and policy of verification.

Floating branches, mutable tags and unverified downloads MUST NOT be used in a production dependency lock.

## 4. Version and compatibility model

VYRAQON standard versioning is authoritative to VYRAQON maintainers and must be ratified there. IROKA's adapter MUST support explicit compatibility negotiation.

Required behavior:
- same supported major and compatible minor/patch: accept only if declared compatibility and conformance vectors pass;
- unsupported major: fail closed for semantic processing and executable lowering;
- unknown mandatory feature: reject;
- unknown optional annotation: preserve as opaque data only if the VYRAQON standard permits;
- signature/digest failure: reject;
- incompatible AST/IR schema: reject or use an explicitly versioned migration tool;
- migration: preserve original artifact and record source/target versions, tool version, digest and loss report.

No silent downgrade is allowed. An old artifact MUST NOT be interpreted under a new grammar merely because parsing succeeds.

## 5. Canonical interchange envelope

The transport envelope below is an IROKA proposal, not a claim about VYRAQON's final native serialization. Its exact field names and encoding require bilateral ratification.

Required logical fields:

| Field | Meaning |
|---|---|
| envelope_schema | IROKA interchange envelope version |
| project_id | Stable VYRAQON project identifier |
| standard_version | Exact VYRAQON standard version |
| grammar_version | Exact grammar version |
| semantic_schema | Exact semantic/AST schema version |
| artifact_digest | Digest of exact source/serialized artifact |
| digest_algorithm | Approved digest algorithm identifier |
| signature_evidence | Signature, signer and verification metadata |
| source_representation | VYRAQON representation kind |
| source_language | Declared human language, if applicable |
| source_script | Declared writing script, if applicable |
| locale_profile | User/deployment locale context, not semantic authority |
| source_payload | Original source bytes or losslessly encoded content |
| source_spans | Mapping from semantic nodes to original source spans |
| provenance | Author, origin, toolchain and transformation lineage |
| semantic_payload | Canonical semantic representation |
| effects | Declared effect metadata |
| capability_requirements | Required capability descriptors; never grants |
| target_constraints | Intended runtime/target constraints |
| diagnostics | Stable diagnostic IDs and localized messages |
| review_state | Draft, parsed, validated, reviewed, approved or rejected |

The envelope MUST distinguish source bytes from decoded text, display rendering and semantic representation. Canonical serialization MUST be defined by the VYRAQON authority for VYRAQON-native payloads.

## 6. Parsing and semantic validation pipeline

IROKA's adapter MUST process an incoming artifact in this order:

1. Enforce transport size and resource limits.
2. Preserve exact source bytes and calculate digest.
3. Verify release provenance/signature policy where required.
4. Validate project, standard, grammar and schema versions.
5. Decode using the declared encoding; reject invalid sequences without destructive replacement.
6. Parse using the pinned authoritative grammar implementation.
7. Validate AST/semantic invariants and canonicalization rules.
8. Bind source spans, language/script metadata and provenance.
9. Map supported constructs into IROKA's canonical typed IR.
10. Run INL type, effect, resource and capability analysis.
11. Produce diagnostics and a deterministic lowering report.
12. Submit any proposed executable artifact to IROKA policy and authorization controls.

At any stage, unsupported or ambiguous semantics MUST fail closed for executable lowering. The system MAY retain an opaque source artifact for human review without interpreting it.

## 7. Canonical semantic mapping and round-trip guarantees

The integration MUST define a versioned mapping from VYRAQON semantic constructs to IROKA canonical IR. The mapping table must identify:
- VYRAQON construct and normative reference;
- IROKA IR node/type;
- type/effect interpretation;
- source-span mapping;
- supported/unsupported status;
- losslessness classification;
- diagnostics and migration behavior;
- conformance fixture IDs.

Three outcomes are allowed:
- **LOSSLESS:** semantic and source representation can be reconstructed exactly under the specified canonical rules.
- **SEMANTICALLY_EQUIVALENT:** source formatting may differ, but canonical semantics remain exactly equal.
- **UNSUPPORTED/LOSSY:** cannot be safely mapped; executable lowering is rejected unless a separately reviewed non-executable transformation is explicitly requested.

Round-trip tests MUST compare semantic identity, not merely rendered string equality. Source-byte preservation is a separate assertion. No implementation may claim a lossless round trip where only a best-effort translation exists.

## 8. Translation and multilingual lineage

Human-language input and output are separate from VYRAQON's semantic identity. Translation must retain:
- original source bytes and declared language;
- target language and script;
- source/target locale profile;
- translation tool/model and exact version;
- prompt/configuration digest where policy permits;
- timestamp and transformation ID;
- confidence/uncertainty metadata where applicable;
- human review status and reviewer identity;
- links/digests for source and derived artifacts.

For Ethiopia, Amharic is the default interaction language and English is secondary. Amharic source must not be silently translated into English as the authoritative value. Generated Amharic must not be represented as verified or as a faithful quotation without review against the source. African regional profiles may add languages through reviewed profile-specific support declarations.

## 9. VYRAQON program representation to INL/IR

VYRAQON computational constructs may describe programs, algorithms, constraints, workflows or pseudocode. Conversion to executable INL/IR requires:
- supported normative construct and version;
- unambiguous semantics;
- complete type resolution;
- complete effect declaration;
- explicit capability requirements;
- bounded resource model;
- source/provenance lineage;
- deterministic compiler/toolchain version;
- policy approval for the intended execution context.

A generated program is untrusted until all validation stages pass. Compilation is not authorization. A successful compile does not imply permission to execute. A capability declaration is not a capability grant. Every protected side effect must be authorized by IROKA's Kernel/governance plane.

## 10. Runtime and effect boundary

The VYRAQON adapter MUST be a non-authoritative front end. It cannot:
- create or elevate a principal;
- mint or expand a capability;
- change policy or approval requirements;
- access secrets without an explicit capability;
- directly execute external effects;
- alter the trusted computing base;
- suppress audit or provenance events.

All executable outputs run through INL runtime/IR verifier, sandbox, resource quotas, capability checks, policy decision, approval if required and audit pipeline.

## 11. Amharic-first and Ethiopic fidelity

The adapter, developer tools and user workflows MUST conform to A1:
- Amharic-first default in Ethiopia profile; English selectable.
- Preserve Ethiopic Unicode code points, combining marks, punctuation and mixed-script content.
- Preserve original VYRAQON source bytes and glyph identity as defined by the authoritative standard.
- Do not assume VYRAQON script and Ethiopic script share shaping, normalization or directionality rules.
- Keep language, script, locale, calendar and regional profile as separate typed dimensions.
- Ethiopian calendar is the default user-facing calendar; Gregorian interoperability must be explicit.
- Africa/Addis_Ababa and ETB defaults apply where relevant to the Ethiopia profile.
- Amharic diagnostics, consent, review and error messages must be available and reviewed.
- Transliteration and translation are derived views; never overwrite authoritative source.
- Cross-regional processing must not impose Ethiopian defaults on other African profiles.

If a VYRAQON release cannot represent or round-trip Ethiopic and Amharic source metadata required by IROKA, the adapter must preserve that data in a lossless extension agreed with VYRAQON or reject the unsupported operation. It must not discard it.

## 12. Security and privacy

Threats include malicious payloads, parser exploits, resource exhaustion, Unicode confusables, bidi controls, spoofed provenance, dependency substitution, semantic ambiguity, prompt injection embedded in source and compiler differential behavior.

Controls:
- bounded parser depth, payload size, execution time and memory;
- sandboxed parsing/compilation where practical;
- strict schema validation;
- signed and digest-pinned releases;
- source/output separation;
- Unicode security diagnostics that do not rewrite source;
- no execution during parse/compile;
- no ambient network access from compiler;
- deterministic transformation logs;
- tenant-aware storage and access;
- secret redaction;
- fail-closed major-version and semantic ambiguity handling.

Source text and embedded instructions are untrusted data. A VYRAQON artifact cannot instruct IROKA to ignore policy, expose secrets or modify trust roots.

## 13. Error and diagnostic contract

Stable error classes include:
- INTEROP_TRANSPORT_LIMIT;
- INTEROP_DIGEST_MISMATCH;
- INTEROP_SIGNATURE_INVALID;
- INTEROP_PROJECT_UNKNOWN;
- INTEROP_VERSION_UNSUPPORTED;
- INTEROP_SCHEMA_INCOMPATIBLE;
- INTEROP_ENCODING_INVALID;
- INTEROP_GRAMMAR_INVALID;
- INTEROP_SEMANTIC_AMBIGUOUS;
- INTEROP_MAPPING_UNSUPPORTED;
- INTEROP_SOURCE_MAP_INCOMPLETE;
- INTEROP_EFFECT_UNDECLARED;
- INTEROP_CAPABILITY_MISSING;
- INTEROP_PROVENANCE_INCOMPLETE;
- INTEROP_POLICY_DENIED;
- INTEROP_REVIEW_REQUIRED.

Each diagnostic carries stable code, stage, severity, source span where available, machine-readable parameters and localized message. Amharic is the Ethiopia-profile default diagnostic language.

## 14. Measurable interoperability acceptance gates

| ID | Measure | Threshold |
|---|---|---|
| VY-ART-01 | Accepted release artifacts match pinned digest/signature policy | 100% |
| VY-VER-01 | Version matrix expected outcomes | 100% |
| VY-GRAM-01 | Normative positive/negative grammar vectors | 100% |
| VY-SEM-01 | Canonical semantic round-trip vectors | 100% |
| VY-SRC-01 | Lossless source-preservation vectors | 100% |
| VY-MAP-01 | Supported construct mapping fixtures | 100% expected mappings |
| VY-AMB-01 | Ambiguous/unsupported executable constructs accepted | 0 |
| VY-EFF-01 | Executable construct without declared effect accepted | 0 |
| VY-CAP-01 | VYRAQON expression mints or amplifies runtime authority | 0 |
| VY-AUTH-01 | VYRAQON/INL output bypasses IROKA policy/approval | 0 |
| VY-LINEAGE-01 | Derived translations retain complete lineage | 100% |
| VY-UNI-01 | Ethiopic source corruption in lossless path | 0 |
| VY-LOCALE-01 | Amharic-first critical workflows pass reviewed corpus | 100% |
| VY-AUD-01 | Parse/lower/load/policy/execute transitions auditable | 100% |

## 15. Bilateral governance required

Before cross-repository implementation, the VYRAQON project must ratify:
1. Stable project identity and canonical repository.
2. Ownership and maintainership.
3. Visibility and proprietary access policy.
4. Normative standard and grammar versioning.
5. Canonical serialization and semantic/AST schema.
6. Release signing and artifact provenance.
7. Compatibility and deprecation policy.
8. Conformance corpus and reference implementation.
9. Extension and vendor-specific metadata policy.
10. License/usage and redistribution terms.
11. Security disclosure and vulnerability response.
12. Amharic/Ethiopic interoperability expectations.

IROKA cannot unilaterally declare these VYRAQON normative decisions complete.

## 16. A2 dependency status

| Dependency | Status |
|---|---|
| IROKA-side integration boundary | SPECIFIED |
| IROKA canonical typed IR requirements | SPECIFIED; schema decision pending |
| INL effect/capability enforcement requirements | SPECIFIED |
| VYRAQON repository under destination account | NOT VERIFIED / MISSING |
| VYRAQON authoritative grammar and standard | MISSING |
| VYRAQON signed release and digest | MISSING |
| Bilateral compatibility and conformance ratification | UNRESOLVED |
| Cross-repository tests | NOT RUN |
| Executable integration | NOT IMPLEMENTED |

## 17. Exit criteria

This contract is ready for bilateral review, not implementation closure. A2 cannot mark VYRAQON interoperability VERIFIED-CLOSED until the VYRAQON repository exists, its authoritative standard is versioned, maintainers ratify the interface, a signed reference release is pinned, mapping vectors are agreed and the cross-repository suite passes on exact SHAs.

A3 implementation remains separately gated by Owner authorization.
