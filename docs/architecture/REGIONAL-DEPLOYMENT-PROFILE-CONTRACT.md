# Regional Deployment Profile Contract

**Contract ID:** IROKA-A1-REG-002  
**Status:** Binding A1 supporting contract  
**Parent:** [A1 Amharic-First Ethiopian and African Architecture Contract](A1-AMHARIC-FIRST-REGIONAL-ARCHITECTURE-CONTRACT.md)

## 1. Purpose

This contract defines how IROKA represents regional deployment settings without embedding country assumptions in shared domain logic. A regional profile is a versioned configuration and policy-reference bundle. It is not a substitute for legal review, identity proofing, or organization-specific policy.

## 2. Required profile semantics

Every production deployment profile MUST define and validate:

| Field | Required meaning |
|---|---|
| `profile_id` | Stable machine identifier; never derived from display name |
| `profile_version` | Immutable version identifier |
| `jurisdiction` | Country/territory and optional subnational jurisdiction |
| `effective_from` / `effective_until` | Validity interval and transition semantics |
| `languages.primary` | Primary language tag |
| `languages.supported[]` | Supported languages and review status |
| `scripts[]` | Supported scripts and rendering requirements |
| `calendar.default` | Named calendar identifier |
| `calendar.supported[]` | Other supported calendars |
| `time_zone.default` | IANA time-zone identifier |
| `currencies.default` | ISO 4217 currency code |
| `currencies.supported[]` | Supported currency codes |
| `number_format` | Decimal, grouping, percent and numeral-display preferences |
| `date_format` | Display conventions, separate from typed date semantics |
| `address_schema` | Versioned extensible address structure |
| `phone_conventions` | Calling code and parsing/formatting metadata |
| `document_conventions` | Approved template, numbering and records metadata |
| `legal_references[]` | Jurisdiction-scoped sources, effective dates and review state |
| `data_governance` | Residency, transfer, retention and classification references |
| `provenance` | Source, maintainer, reviewer and review timestamp |

Implementations MAY use another serialization format, but MUST preserve these semantics and validation constraints.

## 3. Ethiopia baseline profile

The initial Ethiopia profile MUST use:

- Primary language: `am-ET` (Amharic).
- Supported secondary language: `en` (English).
- Primary script: Ethiopic; Latin script supported for interoperability.
- Default civil display calendar: Ethiopian calendar.
- Interoperability calendar: Gregorian.
- Default time zone: `Africa/Addis_Ababa`.
- Default currency: `ETB`.
- Numerals: Ethiopic and international digits, with user/deployment preference.
- Identity names: original script preserved; transliteration is additive.

These are Ethiopia-profile defaults, not universal IROKA core defaults.

## 4. Resolution and precedence

The runtime MUST resolve profile settings deterministically:

1. Non-overridable security, legal and records obligations applicable to the deployment.
2. Active deployment profile.
3. Organization-level preferences where permitted.
4. User-level presentation preferences where permitted.
5. Explicit request-level formatting where permitted.

A lower-precedence setting MUST NOT override a higher-precedence requirement. If a mandatory jurisdictional rule is missing, contradictory or expired, the affected operation MUST fail closed or be routed for qualified review; it MUST NOT guess.

## 5. Versioning and migration

1. Profile versions MUST be immutable after publication.
2. Every update MUST record author, reviewer, source evidence, effective date, changed fields and migration impact.
3. Runtime consumers MUST identify the profile version used to interpret a material record or transaction.
4. Historical records MUST retain the semantic context required to interpret original dates, currencies, languages and jurisdictions.
5. Profile upgrades MUST NOT silently rewrite historical values or legal records.
6. Breaking changes require migration plan, compatibility window where feasible, rollback strategy and explicit approval.
7. Cached profile data MUST have bounded freshness and invalidation/revocation controls.

## 6. Separation of concerns

- Language tags MUST NOT be used as country identifiers.
- Country identifiers MUST NOT determine a person's language or identity.
- Calendar choice MUST NOT be inferred from language alone.
- Currency display MUST NOT mutate ledger or transaction values.
- Legal references MUST be jurisdiction- and effective-date-scoped.
- Address and identity structures MUST NOT impose one cultural naming or administrative model.
- Core authorization, tenant isolation, audit and cryptographic trust semantics MUST remain invariant across profiles.

## 7. Illustrative Ethiopia profile

```yaml
profile_id: et-ET
profile_version: 1.0.0
jurisdiction:
  country: ET
  subnational: null
effective_from: "2026-11-04"
languages:
  primary: am-ET
  supported:
    - tag: en
      status: supported
scripts: [Ethiopic, Latin]
calendar:
  default: ethiopic
  supported: [ethiopic, gregorian]
time_zone:
  default: Africa/Addis_Ababa
currencies:
  default: ETB
  supported: [ETB]
number_format:
  numeral_systems: [ethiopic, latn]
  default_display: user_preference
date_format:
  default_calendar: ethiopic
address_schema: et-address-v1
phone_conventions: et-phone-v1
document_conventions: et-documents-v1
legal_references: []
data_governance:
  residency_policy_ref: unresolved
  cross_border_policy_ref: unresolved
provenance:
  source: IROKA A1 baseline
  reviewer: pending-qualified-local-review
```

This example is a schema illustration, not a claim that Ethiopian legal requirements have been researched or approved.

## 8. Conformance requirements

A profile implementation passes only when required fields validate, unsupported settings are rejected, precedence is deterministic, profile version/provenance are auditable, historical interpretation remains stable after upgrades, and Ethiopia plus at least one independently configured African profile pass the same conformance suite. Security, privacy, tenant isolation and audit behavior MUST remain invariant.

## 9. A1/A2 boundary

A1 establishes this logical contract. A2 MUST select concrete standards, libraries, schema encoding, profile storage, update/signature model, migration semantics and conformance fixtures. No specific library or legal policy is approved merely by this contract.
