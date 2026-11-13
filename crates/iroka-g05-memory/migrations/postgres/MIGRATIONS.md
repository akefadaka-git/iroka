# G05/G02 PostgreSQL migration manifest

This directory is an ordered, append-only migration sequence. Apply each file exactly once,
in ascending numeric prefix, using a dedicated migration role. Runtime roles must not
modify immutable authority history. A deployment migration ledger must record the full
filename, checksum, applied timestamp, and migration tool version; a filename prefix
alone is not a sufficient duplicate detector.

## Canonical order

| Version | File | Responsibility | Introduced by |
|---|---|---|---|
| 0001 | `0001_shared_g05_g11.sql` | Shared G05/G11 persistence and audit/outbox base schema | Existing baseline |
| 0002 | `0002_g02_authority.sql` | G02 commands, policy snapshots/heads, memberships, emergency stop, base authority outbox | Existing baseline |
| 0003 | `0003_g02_owner_key_registry.sql` | Root-signed Owner key registry versions, Owner key bindings and Owner-key revocations | G02 A3 reconciliation |
| 0004 | `0004_g02_revocation_projections.sql` | Credential, signing-key and approval revocation projections | G02 A3 reconciliation |

## Rules

1. Never reuse a numeric version for a different SQL file. The former
   `0003_g02_revocation_projections.sql` name is retired; its SQL is preserved byte-for-byte
   as version 0004.
2. Install and verify the root-signed Owner registry (0003) before accepting commands that
   depend on registry-backed Owner keys. Root public keys remain pinned out-of-band.
3. Apply 0004 after 0003. The revocation projections are separate from the Owner registry's
   own `g02_owner_key_revocations` table; consumers must fail closed if either authoritative
   revocation source is unavailable.
4. The G11 outbox delivery/acknowledgement extension proposed separately is deliberately not
   included in this Phase A sequence. It must receive the next unused version only after its
   dependency and deployment compatibility review.
5. Before production rollout, compare the migration ledger and checksums against every
   deployed database. Do not rename or replay a migration already recorded in a deployed
   ledger; use a forward-only compatibility migration where required.
6. Clean-install and upgrade-path tests must apply this manifest in order and verify rollback
   behavior. No production database was accessed by this reconciliation.

## Current limitation

The existing crate test helpers historically applied SQL files directly with `include_str!`;
they did not provide a production migration ledger. This manifest establishes source order,
but does not claim that a production migration runner or deployed-schema inventory has been
verified. Production rollout remains blocked pending that evidence.
