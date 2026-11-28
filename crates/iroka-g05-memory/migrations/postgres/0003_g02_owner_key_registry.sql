-- Root-verified G02 Owner-key registry and authoritative PostgreSQL revocations.
-- Trust roots are pinned out-of-band in service configuration; this migration
-- stores only root-signed public-key bindings and append-only revocation facts.
BEGIN;
SELECT pg_advisory_xact_lock(77305112);

CREATE TABLE IF NOT EXISTS g02_owner_key_registry_versions (
    version BIGINT PRIMARY KEY CHECK (version > 0),
    root_key_id TEXT NOT NULL,
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > issued_at),
    payload_sha256 CHAR(64) NOT NULL CHECK (length(payload_sha256) = 64),
    installed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS g02_owner_keys (
    registry_version BIGINT NOT NULL REFERENCES g02_owner_key_registry_versions(version),
    owner_subject TEXT NOT NULL,
    issuer TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    not_before BIGINT NOT NULL CHECK (not_before >= 0),
    not_after BIGINT NOT NULL CHECK (not_after > not_before),
    PRIMARY KEY (registry_version, issuer, key_id),
    UNIQUE (registry_version, owner_subject, key_id)
);

CREATE INDEX IF NOT EXISTS g02_owner_keys_lookup
    ON g02_owner_keys(issuer, key_id, registry_version DESC);

CREATE TABLE IF NOT EXISTS g02_owner_key_revocations (
    issuer TEXT NOT NULL,
    key_id TEXT NOT NULL,
    revoked_at BIGINT NOT NULL CHECK (revoked_at >= 0),
    reason_code TEXT NOT NULL,
    revoked_by_command_id TEXT NOT NULL REFERENCES g02_owner_commands(command_id),
    PRIMARY KEY (issuer, key_id)
);

CREATE OR REPLACE FUNCTION g02_reject_owner_registry_mutation()
RETURNS trigger LANGUAGE plpgsql AS $g02$
BEGIN
    RAISE EXCEPTION 'G02 Owner registry and revocation history is append-only';
END;
$g02$;

DROP TRIGGER IF EXISTS g02_owner_registry_versions_no_mutation ON g02_owner_key_registry_versions;
CREATE TRIGGER g02_owner_registry_versions_no_mutation
BEFORE UPDATE OR DELETE ON g02_owner_key_registry_versions
FOR EACH ROW EXECUTE FUNCTION g02_reject_owner_registry_mutation();

DROP TRIGGER IF EXISTS g02_owner_keys_no_mutation ON g02_owner_keys;
CREATE TRIGGER g02_owner_keys_no_mutation
BEFORE UPDATE OR DELETE ON g02_owner_keys
FOR EACH ROW EXECUTE FUNCTION g02_reject_owner_registry_mutation();

DROP TRIGGER IF EXISTS g02_owner_key_revocations_no_mutation ON g02_owner_key_revocations;
CREATE TRIGGER g02_owner_key_revocations_no_mutation
BEFORE UPDATE OR DELETE ON g02_owner_key_revocations
FOR EACH ROW EXECUTE FUNCTION g02_reject_owner_registry_mutation();

COMMIT;
