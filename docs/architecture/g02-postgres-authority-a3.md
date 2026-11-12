# G02 PostgreSQL authority integration — A3 implementation contract

**Status:** A3 implementation slice; not production approval  
**Parent:** PR #77 head `2bfac619b9601330b3343f86277bb5ba29ae22b2`  
**Branch:** `feat/g02-postgres-authority-a3`

## Purpose

Provide a shared, transactional persistence boundary for Owner-signed G02 policy lifecycle, emergency-stop state, tenant membership and G11 authority events. G09 must resolve current policy from this authority immediately before protected effects; it must not treat a cached ALLOW or an old execution grant as current authority.

## Required command transaction

1. Parse bounded canonical command bytes and verify the Owner signature against the independently pinned trust-root snapshot.
2. Begin a PostgreSQL transaction and acquire a transaction-scoped advisory lock for the affected authority key.
3. Re-check signer issuer/key revocation and command replay inside that transaction.
4. Enforce strictly increasing policy epoch / membership version / emergency-stop version. Reject stale, duplicate, conflicting or expired commands.
5. Insert immutable signed command evidence and immutable policy snapshot where applicable.
6. Update the current policy head, emergency-stop singleton, or tenant-membership projection using compare-and-swap predicates.
7. Insert the corresponding content-free G11 authority outbox event in the same transaction.
8. Commit. Only then return an accepted command receipt. Any failure rolls back all authority and outbox writes.

The migration creates immutable evidence tables and mutable current-state projections. The application adapter MUST implement the transaction above; the schema alone does not confer authority.

## G09 resolution contract

A resolver response must include policy ID, epoch, payload digest, signature-verification result, validity interval, current emergency-stop state/version, principal and tenant binding, and a monotonic authority revision. It must read from the primary/linearizable authority path, not a lagging replica or process cache. Missing, expired, revoked, stale, conflicting or unavailable state returns deny/defer. G09 must re-resolve immediately before each external effect and bind any short-lived grant to the returned epoch, digest, tenant and resource scope.

A database row is not proof of Owner authorization: the adapter verifies the stored canonical bytes and signature against pinned trust roots on read (or verifies a content-addressed immutable record with a separately protected verification cache whose invalidation is tied to revocation revisions). Trust-root rotation/revocation remains a separate G02 lifecycle concern.

## Schema boundary

- `g02_owner_commands` and `g02_policy_snapshots` are append-only signed evidence.
- `g02_policy_heads`, `g02_emergency_stop` and `g02_tenant_memberships` are current-state projections updated only by the transactional command processor.
- `g02_authority_outbox` is inserted atomically with accepted authority mutations and delivered at least once with idempotent event IDs.
- No private signing keys, production credentials or user content are stored here.

## Required A4 tests before claiming closure

- Signature tampering, unknown/revoked Owner key, expired command, replay, epoch rollback and conflicting same-epoch payload.
- Emergency-stop activation/deactivation races with policy resolution; fail-closed behavior on unavailable authority.
- Concurrent commands against the same policy and membership, proving monotonic CAS behavior.
- Transaction interruption at every write boundary proving no partial projection/outbox state.
- Multi-process PostgreSQL tests proving one accepted command and one outbox event.
- Replica-lag simulation proving G09 never resolves authority from a stale replica.
- Runtime role cannot mutate/delete signed history or directly alter projections.
- G09 scope, tenant, epoch and digest binding; immediate revalidation and revocation between grant issuance and effect.
- G11 outbox retry, lease expiry, duplicate delivery and audit-chain integrity.

## Explicit non-claims

This migration and contract do not yet implement the Rust PostgreSQL command processor, G09 production resolver, service host, witness quorum, immutable retention adapters, production trust-root provisioning, independent security review, deployment or production activation. Those remain separate implementation and verification gates.
