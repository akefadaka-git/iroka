-- G02 key and identity revocation projections. Commands and effects are
-- committed atomically with the immutable command record and G11 outbox.
BEGIN;
SELECT pg_advisory_xact_lock(77305112);

CREATE TABLE IF NOT EXISTS g02_signing_key_revocations (
    issuer TEXT NOT NULL,
    key_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_by_command_id TEXT NOT NULL REFERENCES g02_owner_commands(command_id),
    revoked_at BIGINT NOT NULL CHECK (revoked_at >= 0),
    PRIMARY KEY (issuer, key_id)
);

CREATE TABLE IF NOT EXISTS g02_credential_revocations (
    issuer TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    revoked_by_command_id TEXT NOT NULL REFERENCES g02_owner_commands(command_id),
    revoked_at BIGINT NOT NULL CHECK (revoked_at >= 0),
    PRIMARY KEY (issuer, credential_id)
);

CREATE TABLE IF NOT EXISTS g02_approval_revocations (
    approval_id TEXT PRIMARY KEY,
    reason TEXT NOT NULL,
    revoked_by_command_id TEXT NOT NULL REFERENCES g02_owner_commands(command_id),
    revoked_at BIGINT NOT NULL CHECK (revoked_at >= 0)
);

COMMIT;
