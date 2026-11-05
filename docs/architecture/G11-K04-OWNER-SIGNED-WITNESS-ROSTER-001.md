# K-04 Owner-Signed Witness Roster Activation

**Status:** Implemented as a code path; production trust provisioning remains blocked.

## Security authority

A witness roster is trusted only when a manifest signature verifies under the separately provisioned Owner root. The root is represented by `OwnerWitnessRosterRoot` and must be loaded by the deployment adapter from protected, out-of-band bootstrap configuration or hardware-backed trust. The manifest cannot introduce, replace, or authorize its own root.

No production Owner root is currently provisioned. Synthetic keys in unit tests are not production credentials. Until a genuine root is installed through the protected deployment boundary, callers must use `WitnessRosterState::unprovisioned()`; checkpoint quorum verification fails closed.

## Signed manifest contract

The versioned `SignedWitnessRosterManifest` envelope contains:

- `root_key_id`: exact identifier of the pinned Owner root;
- `payload.version`: positive, monotonically increasing roster version;
- `payload.owner_subject`: exact Owner identity bound to the pinned root;
- `payload.stream_id`: the one audit stream authorized by this roster;
- `payload.issued_at` and `payload.expires_at`: bounded validity window (maximum one year);
- `payload.witnesses`: exactly three entries, sorted by witness ID;
- `payload.revoked_key_ids`: sorted, unique key IDs explicitly retired by this version;
- `signature`: Ed25519 signature over the domain-separated, deterministic JSON envelope.

Each witness entry binds one witness ID to one signing-key ID and one Ed25519 public key, with its own validity interval. Duplicate witness IDs, key IDs, or public keys are rejected. A witness key cannot reuse the Owner root key. A key listed as revoked cannot remain active in the same roster.

## Activation procedure

Call `activate_signed_witness_roster(manifest, pinned_root, store, now)`.

Activation verifies the pinned root identity and validity, Owner subject, domain-separated signature, manifest time window, canonical ordering, exact roster cardinality, key uniqueness, key validity, stream scope, and explicit revocations. Only after all cryptographic and structural checks pass does it atomically persist the roster version and payload digest in the SQLite security store and return an active `WitnessRosterState`.

The active state carries its stream scope, roster version, and expiry. Both checkpoint quorum verification and receipt-chain verification require the caller's current time and reject expired or out-of-scope roster state. The approved two-of-three quorum remains a fixed kernel constant and is not supplied by the manifest.

## Rotation and revocation

A new Owner-signed manifest with a strictly higher version replaces the active roster. It should list retired signing-key IDs in `revoked_key_ids` and provide replacement public keys for the same three witness identities. Same-version identical manifests are idempotent; a lower version or different digest at the same version is rejected.

Historical receipt verification across a key-rotation boundary must retain and verify the applicable historical signed roster manifest for the receipt period. The current activation API returns the active roster only; a historical-roster resolver is a separate follow-up requirement before claiming full historical key-lifecycle assurance.

## Persistence and deployment limits

The SQLite high-water mark prevents rollback while its durable state is preserved. It is a single-node adapter, not a hardware monotonic counter: restoring an older database snapshot can roll back local state. Production deployment therefore requires protected backups and an independent external high-water/checkpoint anchor, or a shared transactional store with equivalent anti-rollback guarantees.

The code does not prove that three witnesses are independently administered. That requires operational evidence of separate administrators, custody, infrastructure, and recovery controls. No production key generation, key custody, or production activation is performed by this implementation.
