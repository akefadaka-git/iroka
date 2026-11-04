# A2 — API, Data and Event Interface Contracts

**Contract ID:** IROKA-A2-IFACE-001  
**Version:** 0.1.0  
**Status:** Proposed normative interface baseline; implementation not authorized by this document alone  
**Parents:** IROKA-A1-REGIONAL-001, IROKA-A2-IMPL-001  
**Applies to:** L10N, LOC, REG, CAL, IDN, DOC, OCR, KNOW and ASSURE boundaries

## 1. Normative precedence

A1 requirements prevail over this contract. This document fixes externally observable semantics and logical schemas. Concrete serialization may be JSON/HTTP, protobuf, or internal typed Rust/Python/TypeScript structures, but adapters MUST preserve the field meanings, validation, authorization and failure semantics below. A wire-format change requires a versioned contract amendment and compatibility plan.

All identifiers are opaque stable IDs. Display strings MUST NOT be used as primary keys. Every tenant-scoped request MUST be authorized against the tenant before data access, indexing, rendering, export or retrieval.

## 2. Common request context

Every authenticated API request carries or resolves the following context:

| Field | Type | Required | Semantics |
|---|---|---:|---|
| `request_id` | UUID | yes | Unique request identifier; generated at ingress if absent |
| `trace_id` | W3C trace ID | yes | End-to-end trace correlation |
| `tenant_id` | opaque ID | yes, tenant-scoped | Authorized tenant boundary; never trusted solely from body |
| `actor` | verified principal reference | yes | Set by authentication middleware, never caller-asserted |
| `profile_id` | opaque ID | yes for regional operations | Resolved deployment profile |
| `profile_version` | immutable version | yes for regional operations | Exact profile interpretation context |
| `language` | BCP 47 tag | context-dependent | Explicit operation/document language or resolved preference |
| `calendar` | registered calendar ID | date operations | Calendar semantics, e.g. `ethiopic` or `gregorian` |
| `time_zone` | IANA TZ identifier | local date-time operations | Explicit zone; never inferred from language |
| `idempotency_key` | opaque string | mutations with retry risk | Unique within tenant and operation scope |

The server MUST derive `actor` and effective tenant authorization from verified credentials and policy. Client-supplied profile, locale, calendar and zone values are requests subject to profile policy; they are not authority claims.

## 3. Canonical response and error envelope

Successful responses include `request_id`, `contract_version`, and the resource/result. Mutations return the resulting resource version and audit correlation identifier.

Errors use this stable shape:

```json
{
  "error": {
    "code": "CAL_INVALID_DATE",
    "message_key": "calendar.invalid_date",
    "message": "Reviewed localized message",
    "field": "date",
    "details": {},
    "retryable": false,
    "correlation_id": "opaque-id"
  },
  "request_id": "uuid",
  "contract_version": "1"
}
```

Machine code and semantics are language-invariant. Localized `message` is presentation only. Never expose secrets, cross-tenant existence, cryptographic internals or personal data in error details.

Minimum error families:
- `AUTH_UNAUTHENTICATED`, `AUTH_FORBIDDEN`, `TENANT_SCOPE_DENIED`
- `PROFILE_NOT_FOUND`, `PROFILE_VERSION_EXPIRED`, `PROFILE_MANDATORY_FIELD_UNRESOLVED`, `PROFILE_CONFLICT`
- `L10N_RESOURCE_MISSING`, `L10N_TRANSLATION_NOT_APPROVED`
- `LOC_AMBIGUOUS_NUMBER`, `LOC_INVALID_NUMBER`, `LOC_UNSUPPORTED_FORMAT`
- `CAL_INVALID_DATE`, `CAL_UNSUPPORTED_RANGE`, `CAL_AMBIGUOUS_LOCAL_TIME`
- `IDN_NAME_INVALID`, `IDN_MERGE_REQUIRES_REVIEW`, `IDN_DUPLICATE_CANDIDATE`
- `DOC_HASH_MISMATCH`, `DOC_RETENTION_BLOCKED`, `DOC_RENDER_FAILED`
- `OCR_REVIEW_REQUIRED`, `OCR_UNSUPPORTED_SCRIPT`
- `KNOW_SOURCE_FORBIDDEN`, `KNOW_UNANSWERABLE`, `KNOW_PROVENANCE_INCOMPLETE`
- `VALIDATION_FAILED`, `IDEMPOTENCY_CONFLICT`, `INTERNAL_ERROR`

HTTP mapping: 400 malformed/invalid input; 401 unauthenticated; 403 forbidden without disclosing resource existence; 404 absent or intentionally concealed resource; 409 state/idempotency conflict; 410 expired immutable version where appropriate; 422 semantically invalid/unsupported input; 429 rate limit; 5xx transient/internal failure. A 5xx response MUST NOT imply a mutation did not commit; clients MUST use idempotency/status lookup.

## 4. Core logical data schemas

### 4.1 Language resource

```json
{
  "resource_key": "stable.key",
  "source_language": "en",
  "source_text": "Immutable source text",
  "source_version": 3,
  "criticality": "safety_critical",
  "context": {"surface": "approval", "placeholders": []},
  "translations": [{
    "language": "am-ET",
    "text": "የተገመገመ ጽሑፍ",
    "version": 2,
    "status": "HUMAN_APPROVED",
    "reviewer_id": "opaque-id",
    "reviewed_at": "UTC-instant",
    "source_version": 3
  }],
  "effective_from": "UTC-instant"
}
```

A translation is valid only for its exact source version. A source edit invalidates approval of translations tied to an older source version. Critical strings MUST reject machine-only approval states.

### 4.2 Regional profile

```json
{
  "profile_id": "et-ET",
  "version": "1.0.0",
  "status": "PUBLISHED",
  "effective_from": "2026-11-04",
  "jurisdiction": {"country": "ET", "subnational": []},
  "languages": {"primary": "am-ET", "supported": ["en"]},
  "scripts": ["Ethiopic", "Latn"],
  "calendar": {"default": "ethiopic", "supported": ["ethiopic", "gregorian"]},
  "time_zone": {"default": "Africa/Addis_Ababa"},
  "currencies": {"default": "ETB", "supported": ["ETB"]},
  "number_policy": {"digits": ["ethiopic", "latn"], "default": "user_preference"},
  "date_policy": {"display_calendar": "ethiopic"},
  "legal_references": [],
  "data_governance": {"status": "UNREVIEWED"},
  "provenance": {"source": "approved-profile-record", "reviewer_id": null}
}
```

This is a technical fixture. Empty/unreviewed legal or data-governance references MUST block any operation requiring those rules. A profile cannot grant authorization.

### 4.3 Temporal values

```json
{"kind":"Instant","value":"2026-11-04T14:00:00Z"}
{"kind":"LocalDate","calendar":"ethiopic","year":2019,"month":2,"day":24}
{"kind":"LocalDateTime","calendar":"ethiopic","year":2019,"month":2,"day":24,"hour":9,"minute":30,"time_zone":"Africa/Addis_Ababa","ambiguity":"REJECT"}
{"kind":"CalendarDate","calendar":"gregorian","year":2026,"month":11,"day":4,"implementation":"adapter-version"}
```

These are distinct tagged variants, not interchangeable strings. Date-only values MUST NOT be serialized as UTC instants. Conversion returns source value/context, target value/context, implementation version and status.

### 4.4 Person name

```json
{
  "person_id": "opaque-id",
  "tenant_id": "opaque-id",
  "original_name": {"text":"አበበ በቀለ","script":"Ethiopic","language":"am"},
  "components": [{"text":"አበበ","source_order":0},{"text":"በቀለ","source_order":1}],
  "preferred_display": {"text":"አበበ በቀለ","order":"source"},
  "transliterations": [],
  "aliases": [],
  "verification": {"state":"UNVERIFIED","evidence_refs":[]},
  "version": 1
}
```

Components are optional and source order is retained. No family-name field is mandatory. Original name correction is append-only/audited; transliteration never overwrites it. G01 credential subjects are separate entities.

### 4.5 Document and derivative

```json
{
  "document_id": "opaque-id",
  "tenant_id": "opaque-id",
  "document_class": "official_record",
  "source_language": "am-ET",
  "profile": {"id":"et-ET","version":"1.0.0"},
  "original": {"storage_ref":"opaque-ref","sha256":"hex"},
  "retention_class": "policy-ref",
  "access_classification": "policy-ref",
  "derivatives": [{
    "kind":"ocr_text",
    "source_sha256":"hex",
    "tool":"engine-name",
    "tool_version":"version",
    "output_sha256":"hex",
    "review_state":"PENDING_REVIEW"
  }]
}
```

The original hash is immutable. Derivative creation does not change the original. Display numbering is a separate versioned policy result and is not the document primary key.

### 4.6 Knowledge source and retrieval result

```json
{
  "source_id":"opaque-id",
  "tenant_id":"opaque-id",
  "content_sha256":"hex",
  "language":"am-ET",
  "script":"Ethiopic",
  "rights_basis":"documented-reference",
  "access_classification":"policy-ref",
  "retention_policy":"policy-ref",
  "derived_items":[{
    "kind":"chunk",
    "source_id":"opaque-id",
    "source_sha256":"hex",
    "transform_version":"version",
    "span":{"start":0,"end":100}
  }]
}
```

A retrieval result includes source ID/version, exact source span, original/translated/derived label, relevance score and authorization decision reference. Authorization MUST occur before ranking/generation can expose content.

## 5. Required logical operations

Concrete transport paths are implementation-specific; the following operations and semantics are mandatory.

| Domain | Operation | Input | Output / invariant |
|---|---|---|---|
| L10N | resolve_resource | resource key, target language, context | approved translation or explicit fallback state |
| L10N | submit_translation_review | resource/version/language/review decision | reviewer-attributed immutable state transition |
| LOC | parse_number | text, locale, numeral policy | typed decimal/integer or explicit ambiguity error |
| LOC | format_number | typed value, locale, numeral policy | display string; source value unchanged |
| REG | resolve_profile | deployment, org/user preference, effective date | immutable profile version, precedence trace, unresolved obligations |
| REG | publish_profile_version | candidate, evidence, approvals | new immutable version; never mutate published version |
| CAL | convert_date | tagged source date, target calendar | tagged target date and adapter provenance |
| CAL | resolve_local_datetime | tagged local time, IANA zone, ambiguity policy | instant or typed ambiguity/invalid error |
| IDN | create_or_correct_person | tenant, source name, evidence | versioned person record and audit event |
| IDN | find_candidates | query and search modes | ranked suggestions, never identity proof |
| IDN | merge_person_records | records, evidence, approval | audited reversible/compensatable merge only |
| DOC | register_original | bytes, metadata, retention/access policy | immutable source hash and document ID |
| DOC | create_derivative | document ID, transform descriptor | provenance-linked derivative |
| OCR | submit_ocr | document/page scope, language hints | job and candidate output; never authoritative by default |
| OCR | review_ocr | candidate ID, correction/decision | reviewer-attributed accepted/corrected/rejected state |
| KNOW | ingest_source | source, rights, tenant, classification | immutable source record and processing state |
| KNOW | retrieve | tenant, query, language, filters | authorized source spans with provenance/citation |
| ASSURE | record_evaluation | suite/dataset/commit/metrics | immutable evidence record tied to exact SHA |

Mutations MUST be authenticated, tenant-scoped, idempotent where retries are possible, audited, and protected by the Kernel's existing authorization decision. Profile publication, translation approval, identity merge, OCR acceptance for consequential fields and retention-policy changes require explicit role/authority checks.

## 6. Event envelope

Domain events use a versioned envelope:

```json
{
  "event_id":"uuid",
  "event_type":"profile.version_published",
  "event_version":1,
  "occurred_at":"UTC-instant",
  "tenant_id":"opaque-id",
  "actor_ref":"verified-principal-ref",
  "aggregate":{"type":"regional_profile","id":"et-ET","version":"1.0.0"},
  "profile_context":{"id":"et-ET","version":"1.0.0"},
  "correlation":{"request_id":"uuid","trace_id":"w3c-trace-id"},
  "payload":{}
}
```

Events are immutable. Consumers MUST be idempotent by event ID, reject unsupported major versions, preserve unknown additive fields where safe, and enforce tenant authorization before processing. Event payloads MUST NOT contain unnecessary personal data or secrets. Audit events record machine-stable codes and UTC instants; localized display is derived separately.

Minimum event families: `translation.reviewed`, `profile.version_published`, `profile.version_expired`, `person.created`, `person.name_corrected`, `person.merge_approved`, `document.registered`, `document.derivative_created`, `ocr.review_decided`, `knowledge.source_ingested`, `evaluation.completed`.

## 7. Persistence and integrity invariants

1. Tenant ID is part of every tenant-scoped uniqueness and access boundary.
2. Published profile and translation versions are immutable; changes create new versions.
3. Original document bytes, original names and source text are not overwritten by derived values.
4. Canonical numeric and temporal values are typed; display strings are never authoritative.
5. Every derivative stores input hash, output hash, transformation/version and actor/system provenance.
6. Every consequential mutation has an audit event and optimistic concurrency/version check.
7. Idempotency records bind tenant, actor, operation, key and request digest; reusing a key with a different digest returns conflict.
8. Retention/deletion applies to originals and derivatives consistently with approved policy and legal hold; audit records preserve only permitted minimal evidence.
9. Cross-tenant foreign references are rejected at the storage boundary, not merely filtered in UI code.

## 8. Migration and compatibility contract

Schema changes use expand → dual-read/write where needed → verified backfill → cutover → contract. Each migration declares:
- source/target schema versions and compatibility window;
- deterministic backfill and resumability;
- tenant isolation and data-integrity checks;
- dry-run counts and sampled reconciliation;
- rollback/compensation path;
- treatment of historical records lacking locale/profile context;
- observability and stop conditions.

No migration may invent missing historical language, calendar, currency, jurisdiction or identity data. Unknown context remains explicitly unknown and blocks only operations that require it. Destructive contract steps require separate approval.

## 9. Implementation exit criteria

Before A3 implementation begins, the Owner-approved implementation package must include:
- selected transport and machine-readable OpenAPI/JSON Schema (or equivalent) for public boundaries;
- concrete database schema/index/constraint proposal and tenant-isolation strategy;
- event schema registry and compatibility policy;
- authorization matrix and audit event catalogue;
- migration/backfill/rollback design;
- exact dependency shortlist with license/security/maintenance evidence;
- unresolved fields and error semantics tested against the A2 acceptance plan.

This document establishes logical contracts and proposed payload shapes. It does not claim machine schema validation, implementation, legal review or production readiness.
