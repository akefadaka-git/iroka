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


CREATE OR REPLACE FUNCTION g02_reject_revocation_mutation()
RETURNS trigger LANGUAGE plpgsql AS $g02$
BEGIN
    RAISE EXCEPTION 'G02 revocation history is append-only';
END;
$g02$;

DROP TRIGGER IF EXISTS g02_signing_key_revocations_no_mutation ON g02_signing_key_revocations;
CREATE TRIGGER g02_signing_key_revocations_no_mutation
BEFORE UPDATE OR DELETE ON g02_signing_key_revocations
FOR EACH ROW EXECUTE FUNCTION g02_reject_revocation_mutation();

DROP TRIGGER IF EXISTS g02_credential_revocations_no_mutation ON g02_credential_revocations;
CREATE TRIGGER g02_credential_revocations_no_mutation
BEFORE UPDATE OR DELETE ON g02_credential_revocations
FOR EACH ROW EXECUTE FUNCTION g02_reject_revocation_mutation();

DROP TRIGGER IF EXISTS g02_approval_revocations_no_mutation ON g02_approval_revocations;
CREATE TRIGGER g02_approval_revocations_no_mutation
BEFORE UPDATE OR DELETE ON g02_approval_revocations
FOR EACH ROW EXECUTE FUNCTION g02_reject_revocation_mutation();

COMMIT;
