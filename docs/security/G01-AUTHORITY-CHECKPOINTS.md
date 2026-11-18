# G01 Authority Registry Checkpoint Operations

## Security invariant

The identity-root, identity-succession, and compatibility registries each have an independent monotonic checkpoint. A checkpoint binds the registry name to an exact revision and SHA-256 digest. Registry installation advances the checkpoint before writing the registry database. Registry reads require an exact revision-and-digest match. Missing, older, newer, or conflicting checkpoint state fails closed.

## Required storage separation

The checkpoint must not share the authority-registry database or its backup/restore domain.

A local single-node configuration may use two distinct files:

- Authority data: `SqliteG01AuthorityStore::open("authority-registry.sqlite")`
- Checkpoint data: `SqliteSecurityStore::open("authority-checkpoints.sqlite")`

The files must have separate access controls and independently managed backups. Do not put both files in one snapshot set that can be rolled back together. The code exposes `AuthorityCheckpointStore` so production deployments can replace the local SQLite checkpoint adapter with a remote append-only witness, hardware-backed monotonic counter, or separately administered security service.

**Important limitation:** two SQLite files on one host do not protect against an attacker who can modify or restore both files, compromise the host, or control both backup domains. The local SQLite adapter is a development/single-node protection and is not, by itself, evidence of production-grade anti-rollback security. Production approval requires an independently protected witness implementation and recovery testing against coordinated rollback.

## Installation and recovery behavior

1. Verify the root signature and envelope validity.
2. Atomically advance the independent checkpoint to the envelope revision and digest.
3. Persist the signed envelope in the authority database.
4. On every security-sensitive read, verify the root signature and compare the persisted envelope against the checkpoint.
5. If the checkpoint advanced but the authority write failed, retry only the exact same signed envelope. Do not decrement or reset the checkpoint.
6. If the authority database is restored from an older backup, reject the restored state and recover by reinstalling the exact checkpointed envelope or a newer Owner-authorized envelope.
7. If checkpoint state is missing, inaccessible, inconsistent, or rolled back, deny the operation. Never rebuild a checkpoint from the registry database being checked.

## Evidence and release gates

- The automated restore test covers restoration of an old authority database while the independent checkpoint remains current.
- A separate test and operational drill must cover checkpoint loss, checkpoint tampering, and coordinated rollback of both storage domains.
- A production checkpoint adapter must authenticate its witness, enforce monotonic compare-and-advance semantics, and fail closed on network/service errors.
- A4 remains blocked until the independent witness, signed identity evidence verification, dependency audit, SBOM artifact, and exact-head CI evidence are independently verified.
