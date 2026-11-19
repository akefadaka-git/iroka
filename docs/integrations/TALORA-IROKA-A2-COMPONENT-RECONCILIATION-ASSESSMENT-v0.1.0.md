# TALORA–IROKA A2 Component Reconciliation and Closure Assessment

- **Document ID:** TALORA-IROKA-A2-CRA-001
- **Version:** 0.1.0
- **Assessment date:** 19 November 2026
- **Repositories:** `akefadaka-git/iroka`, `akefadaka-git/talora`
- **IROKA comparison baseline:** `main` at `1aea1447eadf1d827d702fd6c4034fa058aac21e`
- **Documentation branch:** `docs/talora-iroka-a2-reconciliation-v0.1.1`
- **Authority:** Owner-governed; read-only technical reconciliation
- **Outcome:** **PARTIAL / NOT CLOSED**
- **A3:** NOT AUTHORIZED
- **Merge:** NOT AUTHORIZED
- **A5:** NOT AUTHORIZED

## 1. Executive determination

All nine Owner decisions are recorded. The integration contract has
been aligned to those decisions. The live IROKA repository does not,
however, contain one compatible immutable commit graph bringing
together the kernel/G03/G08 work, CIW/API surface, G05/G02/G11
persistence and checkpoint work, BRAIN and localization.

The strongest observed candidate subsets are:
- G03/G08 kernel: `implementation/a3-g08-workflow-graph` at
  `0680337b7dd0966374acd2649cd9197e56b8d92a`.
- G05/G02/G11: `feat/g11-provider-adapters-a3-rebased` at
  `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810`.

They are mutually divergent and both modify shared Kernel code. CIW,
BRAIN and localization are further separate lines. The G05 HTTP host is
not the TALORA task API. No deterministic fake model adapter was
verified on the exact inspected refs. No full release baseline can be
responsibly frozen from this evidence.

**Decision:** TALORA–IROKA A2 remains open. Recording D01–D09 does not
itself close the technical baseline requirement.

## 2. Owner dispositions applied

| ID | Exact disposition | Assessment treatment |
|---|---|---|
| D01 | `RECONCILE` | Reconcile candidates; freeze only after a compatible immutable graph is demonstrated. Not achieved. |
| D02 | `API` | Private authenticated service API only; no SDK. |
| D03 | `API_ONLY` | No IROKA source copying, vendoring, modification, redistribution or sublicensing. |
| D04 | `DEV_FIRST` | Development/test only; no production creative data or production topology claim. |
| D05 | `FAKE_LOCAL` | No live provider. Deterministic fake/local model adapter is required but not verified as implemented. |
| D06 | `HARD_CAPS` | Hard preflight and spend controls required. Numeric ETB/rate/quota values remain unapproved; paid inference stays disabled. |
| D07 | `OPTIN` | Ephemeral by default; persistent project memory requires explicit opt-in, scope and deletion controls. |
| D08 | `REVIEWED` | Amharic-first; full-workflow support requires rights-cleared corpora, competent reviewers and measurable tests. |
| D09 | `MEASURE_FIRST` | No production SLO or support commitment before measurement and operating ownership. |

Decision date for all nine: **19 November 2026**. Approval evidence
is preserved in the companion decision register.

## 3. Live component and immutable-ref inventory

All SHAs below were resolved against the named live branch ref on
19 November 2026. Ahead/behind figures are GitHub compare results
against the IROKA `main` SHA above, not claims of mergeability.

| Candidate | Branch and exact head | Observed contents / dependency facts | Reconciliation result |
|---|---|---|---|
| IROKA main | `main` — `1aea1447eadf1d827d702fd6c4034fa058aac21e` | Cargo workspace contains only `crates/iroka-kernel`; Rust 1.75; kernel pins base64 0.22.1, ed25519-dalek 2.1.1, rusqlite 0.32.1, serde_jcs 0.2.0, sha1 0.10.6 and sha2 0.10.9. | Reference only; not approved as integration baseline. |
| G03/G08 kernel | `implementation/a3-g08-workflow-graph` — `0680337b7dd0966374acd2649cd9197e56b8d92a` | 378 ahead / 3 behind main. Workspace Rust 1.75, kernel only; exports G03 inference rules, premise model, uncertainty calculus and G08 workflow graph. The G03 refs `37078b14927730d81ed756fdd9542698e4e2e490`, `cc6f8fb030e11d195376c35bc69c8b0d1a19e4ed` and `1792d3834fbbf51a298d59ce2dddea067e1802de` are ancestors (58, 73 and 41 commits respectively). | Best inspected single G03/G08 subset; not integrated with G05/G02/G11 or localization. No exact-head PR run returned. |
| G08 character workflow | `implementation/a3-g08-character-workflow-graph` — `0dbe0d58f312ef5ddf2be5d3f6b7dde6569d566b` | Workspace declares Rust 1.89.0; `rust-toolchain.toml` pins 1.100.0. | Separate divergent line and MSRV break against Rust 1.75 baseline. |
| G05/G02/G11 | `feat/g11-provider-adapters-a3-rebased` — `8f7ddb9e9dd2b796cd303ba645a1a3c843eb3810` | 391 ahead / 3 behind main. Workspace kernel + `iroka-g05-memory`, Rust 1.75. G05 pins PostgreSQL 0.19.12, postgres-native-tls 0.5.0, native-tls 0.2.12, rusqlite 0.32.1, serde_jcs 0.2.0 and ed25519-dalek 2.1.1. Lockfile contains 154 packages including tokio-postgres/TLS. | Best G05/G02/G11 subset. Descends from G05 HTTP by 13 commits and G05 Postgres/multiworker by 57 commits. No exact-head PR run returned. |
| G05 HTTP predecessor | `feat/g05-http-host-a3` — `c8991fc61170bc04d7aeaea390a76a85900c2232` | Exact-head workflow run 43280580981 succeeded. Loopback-only host behind TLS-terminating proxy; endpoint `/v1/g05/execute`. | Earlier predecessor only; not TALORA task API. |
| G05 Postgres predecessor | `feat/g05-postgres-g11-multiworker-a3` — `2bfac619b9601330b3343f86277bb5ba29ae22b2` | Exact-head workflow runs 43240878046 and 43240392654 succeeded. | Earlier predecessor only; does not verify later G11 provider head. |
| CIW conversation | `feat/ciw-amharic-answer-only-chat` — `69f3c181791a8dd3c5baf3d18d4556f8f316b1a1` | 172 ahead / 25 behind main. Adds `iroka-conversation`, SQLite conversation/generation flow and browser chat routes. Exact-head run 42562324737 succeeded. | Browser/conversation candidate, not verified private TALORA task API; diverges from G05/G11 (400 / 172 commits). |
| BRAIN/G04/G05 | `feat/brain-a3-b04-g05-memory-core` — `b27816c1c3b172c0a7503d6602cddeaa6008c6cb` | 163 ahead / 3 behind main. Workspace includes kernel, `iroka-g04-contract` and `iroka-g05-memory`; G05 manifest is SQLite-oriented. | Older G04/G05 line; modifies shared Kernel files. No exact-head PR run returned. |
| BRAIN cognitive core | `feat/inga-neurogenetic-a3-foundation` — `e2ad1dc6a7916028dbcdfbd2d2ec948e0a554f4d` | 27 ahead / 3 behind main. Adds `iroka-brain`, depending on serde and serde_json. | Separate model-independent cognitive-core candidate. |
| Localization | `feat/a3-4-localization-completion` — `d51a971d295e7b75e3d17fc51202d99c1db1abab` | 59 ahead / 3 behind main; adds `localization.rs` and tests. Diverges from G03/G08 (378 / 59 commits). | Separate kernel line; not automatically present in G03/G08. No exact-head PR run returned. |

## 4. Dependency and branch compatibility

1. G03/G08 and G05/G02/G11 are diverged histories: 378 commits on
   the G03/G08 side and 391 on the G05/G11 side. Both modify shared
   Kernel files, including `lib.rs`, identity/security, authority and
   policy modules. This is not a safe fast-forward or simple
   workspace-member addition.
2. CIW also changes Kernel identity/security code and is independently
   diverged from G05/G11. It cannot be combined by branch-name
   convention or cherry-picked without source-level reconciliation.
3. Localization and BRAIN are separate kernel/workspace lines; they
   are not automatically included by G03/G08 or G05/G11.
4. The G08 character-workflow branch declares Rust 1.89.0/toolchain
   1.100.0, while main and G05/G11 declare Rust 1.75.
5. G05/G11 adds PostgreSQL, tokio and TLS dependency families. They
   are pinned on that branch, but no merged lockfile or combined
   `cargo check/test` was run.
6. G11 HTTPS is checkpoint publication, not model inference.
   No `ModelAdapter`/`DeterministicFakeAdapter` implementation was
   verified on the exact inspected refs.
7. G05 exposes only `/v1/g05/execute`; CIW exposes conversation and
   generation/event routes. Neither establishes the full
   `GET /api/v1/capabilities`, `POST /api/v1/tasks`, task
   status/events/cancel and memory API as one private TALORA service.

**Compatibility conclusion:** no one immutable commit graph can
currently be frozen for the full TALORA-facing integration scope.

## 5. Exact-head workflow evidence

| Candidate exact head | Workflow evidence returned | Assessment |
|---|---|---|
| CIW `69f3c181...` | 42562324737 — completed, success | PASS for isolated CIW head only. |
| G05 HTTP `c8991fc6...` | 43280580981 — completed, success | PASS for older predecessor only. |
| G05 Postgres `2bfac619...` | 43240878046 and 43240392654 — completed, success | PASS for older predecessor only. |
| G08 coordinator `2cfcf8db...` | 43230367894 — completed, success; commit changes workflow branch triggers | Not evidence for G08 implementation head. |
| G11 provider `8f7ddb9e...` | No PR-triggered run returned | NOT VERIFIED at current exact head. |
| G03/G08 `0680337b...` | No PR-triggered run returned | NOT VERIFIED at current exact head. |
| BRAIN/G05 `b27816c1...` | No PR-triggered run returned | NOT VERIFIED at current exact head. |
| Localization `d51a971d...` | No PR-triggered run returned | NOT VERIFIED at current exact head. |

The workflow lookup returns PR-triggered runs and the first page only.
An empty result does not prove no historical or push-triggered run
exists. No combined graph build, test, migration, SBOM or end-to-end
API run was performed.

## 6. A2 closure decision

**Overall A2: PARTIAL / NOT CLOSED.**

The decision layer is complete: all nine Owner dispositions are
recorded. The contract is aligned and the actual component graph has
been reconciled. The D01 technical exit condition is not met because
no compatible immutable commit graph exists in the inspected refs.
The full TALORA task API and deterministic model adapter are also
not verified.

A2 must not be labelled VERIFIED-CLOSED. This does not invalidate
the Owner dispositions; it records that their approved reconciliation
process exposed unresolved integration work.

## 7. D02–D09 implementation consequences

- **D02 API:** private authenticated service API only; no SDK. No
  verified TALORA task API implementation was found.
- **D03 API_ONLY:** IROKA declares `LicenseRef-Proprietary`.
  Public visibility is not a license. No source reuse or redistribution
  is granted by this assessment.
- **D04 DEV_FIRST:** development/test only. No production creative data,
  topology, residency, key provisioning or deployment claim.
- **D05 FAKE_LOCAL:** live provider remains disabled. A deterministic
  fake/local model adapter remains unverified.
- **D06 HARD_CAPS:** hard limits are required, but numeric quotas,
  rates, ETB FX source and spend caps are not specified. Paid inference
  remains disabled.
- **D07 OPTIN:** persistent memory is opt-in by policy; implementation,
  retention windows, deletion propagation and deletion SLA remain
  unverified.
- **D08 REVIEWED:** no evidence here establishes a rights-cleared
  Amharic corpus, competent reviewer roster or passed workflow
  acceptance suite. Full-workflow claims remain prohibited.
- **D09 MEASURE_FIRST:** no production SLO, support, on-call or recovery
  commitment.

## 8. Required next action

Keep main and implementation branches unchanged. Before source
composition, obtain separate explicit Owner authorization for A3.
An A3 work plan should:
1. create a clean integration branch and preserve all source branches;
2. reconcile G03/G08 kernel work with G05/G02/G11 at file/API level;
3. decide whether CIW is adapted to the private service boundary or
   excluded from initial TALORA integration;
4. reconcile localization and BRAIN without source copying beyond the
   API_ONLY grant;
5. establish one Rust toolchain/MSRV and regenerate one lockfile;
6. implement the private TALORA task API and deterministic fake/local
   model adapter;
7. run combined build/tests, migrations, tenant/security tests, cost,
   memory and language acceptance, and exact-head CI;
8. preserve A4 and the integrated independent security/architecture
   assessment after implementation/A4 and before A5 under
   `OD-2026-11-17-IR-01`.

## 9. Change and authorization record

- Documentation-only updates on the reconciliation branch.
- IROKA `main` and TALORA `main` unchanged.
- No implementation branch rebased, merged, force-pushed or deleted.
- No source code copied between repositories.
- No live model provider, production key, production data, deployment
  or paid service activated.
- A3 implementation: NOT AUTHORIZED.
- PR merge: NOT AUTHORIZED.
- A5 deployment: NOT AUTHORIZED.
