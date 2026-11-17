# G12 Operational Provisioning and Recovery v1.0.0

**Stage:** A3 implementation contract  
**Scope:** G12 rollback guard and version-lineage operational security inputs  
**Status:** Provisioning/recovery APIs implemented; live Owner-signed documents and production root set are not provisioned by this repository change.

## Security boundary

The kernel accepts no self-issued trust root, model-generated Owner key, default issuer, or development bypass as production authority. The Owner-controlled root public-key set and its provenance are supplied out of band at process startup. Root private keys remain offline or in an Owner-controlled HSM/KMS and must never be committed to this repository.

All three operational documents below are independently root-signed, versioned, expiry-bounded and persisted only after signature and semantic validation. The same root set may sign all three document classes, but the subject-to-issuer policy remains a separate explicit authorization layer.

## 1. Trust snapshot provisioning

Create a `SignedTrustBundle` whose payload contains:
- strictly increasing non-zero bundle version;
- issued-at and expiry timestamps (maximum lifetime one year);
- lexicographically ordered unique trusted issuer IDs;
- keys sorted by (issuer, key ID), with valid Ed25519 public keys and bounded validity windows.

Sign `SignedTrustBundle::signing_bytes()` with the out-of-band root private key. Provision with `verify_and_install_trust_bundle_with_roots` or the single-root equivalent. The implementation verifies root validity, signature, ordering, key metadata and expiry, then atomically persists the anti-rollback high-water mark and complete signed JSON document.

The active trust snapshot is published only after durable installation. Key rotation must use a signed bundle with an intentional old/new key overlap. Removing a compromised key from a new bundle does not replace the live revocation check; revoked-key state remains authoritative.

## 2. Issuer-policy provisioning

Create a `SignedRollbackEvidencePolicy` with:
- strictly increasing non-zero policy version;
- issued-at and expiry timestamps (maximum lifetime one year);
- an explicit non-empty issuer set for each required subject class: `current_state`, `candidate_state`, `revocation_floor`, and `policy_version`;
- explicit wildcard subject mappings where needed, e.g. `lineage:artifact:*` and `lineage:mutation:*`; do not use a catch-all wildcard.

Sign the root-key-ID plus payload envelope. Provision with `verify_and_install_rollback_evidence_policy`. The policy is validated before its signed document and monotonic version are committed in one SQLite transaction. A generally trusted key is not sufficient: the runtime checks that the issuer is allowed for the exact evidence subject.

## 3. Version-lineage registry provisioning

Create a complete `SignedVersionLineageRegistrySnapshot` containing the full G12 lineage ancestry and approved mutation records, not a partial delta. The payload revision is strictly increasing and the document is bounded by issued-at/expiry.

The provisioning validator requires:
- exactly one canonical genesis root;
- unique SemVer versions and artifact digests;
- RFC 8785 JCS / SHA-256 artifact digest agreement;
- valid parent version/digest links and strictly increasing SemVer and epoch;
- a matching approved and gated mutation record for every non-root artifact;
- exact mutation source/target binding and a valid approval commitment.

Sign the root-key-ID plus payload envelope. Provision with `verify_and_install_version_lineage_snapshot`. Artifacts, mutation records, registry revision and signed snapshot history are installed in one immediate SQLite transaction. The read adapter resolves a candidate and its ancestry from one consistent deferred read transaction.

## 4. Startup and recovery

Use a private local SQLite database opened with `SqliteSecurityStore::open(path)`. On Unix, the store requires a non-symlink file with no group/other permissions and creates new files with mode 0600. SQLite is configured for WAL and FULL synchronous durability, with a five-second busy timeout. This adapter is single-node only.

At startup:
1. Load the current Owner-controlled `TrustRootSet` from the out-of-band root provisioning mechanism.
2. Open the persistent `SqliteSecurityStore`.
3. Call `G12SecurityRuntime::restore(&roots, Arc::new(store), now)`.
4. The runtime restores and re-verifies the signed trust bundle, issuer policy and lineage snapshot, then constructs the credential verifier and rollback evidence verifier against the same SQLite revocation store.
5. Use `runtime.evidence_verifier()` for G12 evidence checks and `runtime.lineage_registry()` for read-only lineage evaluation.

Recovery fails closed if any required signed document is missing, expired, malformed, signed by an unavailable/invalid root, has a rolled-back version/revision, or conflicts with its persisted digest. There is no fallback to test keys, empty trust, default issuers, or an unsigned registry.

After a policy or registry update, restart/reconstruct the runtime so the in-memory policy and verifier reflect the newly persisted signed document. A future hot-reload API must preserve the same serialize-verify-persist-publish ordering.

## 5. Storage and deployment constraints

- The SQLite adapter is for one authority node. Multi-node deployments require a shared transactional store with equivalent uniqueness, immediate write serialization, durability and fail-closed semantics.
- Back up the database using a SQLite-consistent backup procedure that includes WAL state; do not copy only the main database file while the service is active.
- After restoring a backup, run the application's recovery path and verify all three signed documents against the current Owner root set before accepting requests.
- The root set is intentionally not stored inside the database it authenticates. Root rotation/replacement remains a separate Owner ceremony.
- Production startup must not use test fixture keys or `NoRevocations`.

## 6. Evidence and remaining gates

Automated tests cover signed bundle recovery after file-store reopen, signed issuer-policy recovery, signed lineage registry recovery, signature tampering, rollback rejection, runtime assembly and fail-closed startup when required documents are absent.

These tests demonstrate the code paths using deterministic test signers. They do not constitute production provisioning. The repository does not contain the Owner's production root public keys, signed issuer policy, signed G12 registry snapshot, or corresponding provenance records. Those must be supplied and approved through the Owner's out-of-band signing ceremony.

One integrated independent security/architecture assessment, multi-node storage qualification, operational backup/restore drill and explicit deployment approval remain pre-deployment gates. The independent assessment is deferred until the integrated release candidate and A4 evidence are complete, under Owner Directive OD-2026-11-17-IR-01; it is not required for each implementation increment. No merge or deployment is authorized by this document.
