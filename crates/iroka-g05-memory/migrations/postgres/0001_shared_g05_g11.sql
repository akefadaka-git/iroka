-- IROKA G05/G11 shared PostgreSQL persistence schema.
-- Apply with a dedicated migration role; runtime workers receive only the
-- least-privilege grants required by their service role.
BEGIN;

CREATE TABLE IF NOT EXISTS g05_memory_records (
    memory_id TEXT PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    memory_class TEXT NOT NULL,
    content_sha256 CHAR(64) NOT NULL,
    purpose TEXT NOT NULL,
    classification TEXT NOT NULL,
    lifecycle_state TEXT NOT NULL,
    expires_at BIGINT,
    record_version BIGINT NOT NULL CHECK (record_version > 0),
    retention_policy_ref TEXT NOT NULL,
    metadata_json JSONB NOT NULL,
    record_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_ref, memory_id)
);

CREATE INDEX IF NOT EXISTS g05_memory_tenant_subject_state
    ON g05_memory_records (tenant_ref, subject_ref, lifecycle_state);

CREATE TABLE IF NOT EXISTS g05_memory_g11_outbox (
    event_id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL,
    tenant_ref TEXT NOT NULL,
    payload_sha256 CHAR(64) NOT NULL,
    payload_json JSONB NOT NULL,
    occurred_at BIGINT NOT NULL,
    delivered_at BIGINT,
    acknowledgment_sha256 CHAR(64),
    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    lease_owner TEXT,
    lease_token UUID,
    lease_expires_at TIMESTAMPTZ,
    last_error_code TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (memory_id) REFERENCES g05_memory_records(memory_id),
    CHECK ((delivered_at IS NULL) = (acknowledgment_sha256 IS NULL)),
    CHECK ((lease_owner IS NULL) = (lease_token IS NULL)),
    CHECK ((lease_owner IS NULL) = (lease_expires_at IS NULL))
);

CREATE INDEX IF NOT EXISTS g05_g11_outbox_ready
    ON g05_memory_g11_outbox (next_attempt_at, occurred_at, event_id)
    WHERE delivered_at IS NULL;

CREATE INDEX IF NOT EXISTS g05_g11_outbox_expired_lease
    ON g05_memory_g11_outbox (lease_expires_at)
    WHERE delivered_at IS NULL AND lease_token IS NOT NULL;

CREATE TABLE IF NOT EXISTS g11_memory_audit_events (
    sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
    event_id TEXT NOT NULL UNIQUE,
    payload_sha256 CHAR(64) NOT NULL CHECK (length(payload_sha256) = 64),
    previous_digest CHAR(64) NOT NULL CHECK (length(previous_digest) = 64),
    event_digest CHAR(64) NOT NULL CHECK (length(event_digest) = 64),
    occurred_at BIGINT NOT NULL,
    accepted_at BIGINT NOT NULL,
    event_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS g11_memory_audit_head (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    digest CHAR(64) NOT NULL CHECK (length(digest) = 64)
);

INSERT INTO g11_memory_audit_head (singleton, sequence, digest)
VALUES (TRUE, 0, repeat('0', 64))
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS g11_memory_receipts (
    event_id TEXT PRIMARY KEY REFERENCES g11_memory_audit_events(event_id),
    payload_sha256 CHAR(64) NOT NULL CHECK (length(payload_sha256) = 64),
    accepted_at BIGINT NOT NULL,
    receipt_json JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE OR REPLACE FUNCTION g11_reject_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $g11$
BEGIN
    RAISE EXCEPTION 'G11 audit records and receipts are append-only';
END;
$g11$;

DROP TRIGGER IF EXISTS g11_memory_audit_events_no_update ON g11_memory_audit_events;
CREATE TRIGGER g11_memory_audit_events_no_update
BEFORE UPDATE OR DELETE ON g11_memory_audit_events
FOR EACH ROW EXECUTE FUNCTION g11_reject_audit_mutation();

DROP TRIGGER IF EXISTS g11_memory_receipts_no_update ON g11_memory_receipts;
CREATE TRIGGER g11_memory_receipts_no_update
BEFORE UPDATE OR DELETE ON g11_memory_receipts
FOR EACH ROW EXECUTE FUNCTION g11_reject_audit_mutation();

CREATE TABLE IF NOT EXISTS g11_signed_checkpoints (
    checkpoint_id TEXT PRIMARY KEY,
    stream_id TEXT NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    previous_digest CHAR(64),
    checkpoint_digest CHAR(64) NOT NULL,
    signer_key_id TEXT NOT NULL,
    payload_json JSONB NOT NULL,
    signature BYTEA NOT NULL,
    published_at TIMESTAMPTZ,
    publication_receipt JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (stream_id, sequence),
    CHECK ((published_at IS NULL) = (publication_receipt IS NULL))
);

COMMIT;
