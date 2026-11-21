-- G02 shared PostgreSQL authority state for multi-instance G01/G09 resolution.
-- Owner signatures are verified by the application against pinned trust roots;
-- this schema stores the signed bytes and verified lifecycle state, never keys.
-- Apply with a dedicated migration role. Runtime roles must not UPDATE/DELETE
-- immutable command or policy history.
BEGIN;
SELECT pg_advisory_xact_lock(77305112);

CREATE TABLE IF NOT EXISTS g02_owner_commands (
    command_id TEXT PRIMARY KEY,
    owner_subject TEXT NOT NULL,
    signer_issuer TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > issued_at),
    payload_canonical BYTEA NOT NULL,
    payload_sha256 CHAR(64) NOT NULL CHECK (length(payload_sha256) = 64),
    signature BYTEA NOT NULL,
    command_kind TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS g02_policy_snapshots (
    policy_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    policy_version TEXT NOT NULL,
    owner_subject TEXT NOT NULL,
    signer_issuer TEXT NOT NULL,
    signer_key_id TEXT NOT NULL,
    issued_at BIGINT NOT NULL CHECK (issued_at >= 0),
    expires_at BIGINT NOT NULL CHECK (expires_at > issued_at),
    canonical_payload BYTEA NOT NULL,
    payload_sha256 CHAR(64) NOT NULL CHECK (length(payload_sha256) = 64),
    signature BYTEA NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (policy_id, epoch),
    UNIQUE (policy_id, policy_version)
);

CREATE TABLE IF NOT EXISTS g02_policy_heads (
    policy_id TEXT PRIMARY KEY,
    current_epoch BIGINT NOT NULL CHECK (current_epoch > 0),
    current_payload_sha256 CHAR(64) NOT NULL CHECK (length(current_payload_sha256) = 64),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (policy_id, current_epoch)
      REFERENCES g02_policy_snapshots(policy_id, epoch)
      DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS g02_policy_revocations (
    policy_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    reason_code TEXT NOT NULL,
    revoked_by_command_id TEXT NOT NULL REFERENCES g02_owner_commands(command_id),
    revoked_at BIGINT NOT NULL CHECK (revoked_at >= 0),
    PRIMARY KEY (policy_id, epoch)
);

CREATE TABLE IF NOT EXISTS g02_emergency_stop (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    active BOOLEAN NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    reason_code TEXT NOT NULL,
    changed_by_command_id TEXT NOT NULL REFERENCES g02_owner_commands(command_id),
    changed_at BIGINT NOT NULL CHECK (changed_at >= 0)
);

CREATE TABLE IF NOT EXISTS g02_tenant_memberships (
    subject_ref TEXT NOT NULL,
    tenant_ref TEXT NOT NULL,
    active BOOLEAN NOT NULL,
    version BIGINT NOT NULL CHECK (version > 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= 0),
    command_id TEXT NOT NULL REFERENCES g02_owner_commands(command_id),
    PRIMARY KEY (subject_ref, tenant_ref)
);

CREATE TABLE IF NOT EXISTS g02_authority_outbox (
    event_id TEXT PRIMARY KEY,
    command_id TEXT NOT NULL UNIQUE REFERENCES g02_owner_commands(command_id),
    event_kind TEXT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL CHECK (length(payload_sha256) = 64),
    payload_json JSONB NOT NULL,
    occurred_at BIGINT NOT NULL CHECK (occurred_at >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    delivered_at TIMESTAMPTZ,
    lease_owner TEXT,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CHECK ((lease_owner IS NULL) = (lease_token IS NULL)),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);

CREATE INDEX IF NOT EXISTS g02_authority_outbox_ready
    ON g02_authority_outbox(next_attempt_at, occurred_at, event_id)
    WHERE delivered_at IS NULL;

CREATE OR REPLACE FUNCTION g02_reject_history_mutation()
RETURNS trigger LANGUAGE plpgsql AS $g02$
BEGIN
    RAISE EXCEPTION 'G02 signed command and policy history is append-only';
END;
$g02$;

DROP TRIGGER IF EXISTS g02_owner_commands_no_mutation ON g02_owner_commands;
CREATE TRIGGER g02_owner_commands_no_mutation
BEFORE UPDATE OR DELETE ON g02_owner_commands
FOR EACH ROW EXECUTE FUNCTION g02_reject_history_mutation();

DROP TRIGGER IF EXISTS g02_policy_snapshots_no_mutation ON g02_policy_snapshots;
CREATE TRIGGER g02_policy_snapshots_no_mutation
BEFORE UPDATE OR DELETE ON g02_policy_snapshots
FOR EACH ROW EXECUTE FUNCTION g02_reject_history_mutation();

COMMIT;
