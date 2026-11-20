-- IROKA first-party task lifecycle persistence.
-- Operational task metadata only: no prompt text, model output, credentials or secrets.
BEGIN;
SELECT pg_advisory_xact_lock(77305112);

CREATE TABLE IF NOT EXISTS iroka_tasks (
    task_id TEXT PRIMARY KEY,
    tenant_ref TEXT NOT NULL,
    principal_ref TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    capability_version TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    request_sha256 CHAR(64) NOT NULL CHECK (length(request_sha256) = 64),
    correlation_id TEXT NOT NULL,
    client_request_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'accepted','queued','running','awaiting_authorization','succeeded',
        'failed','cancel_requested','cancelled','expired'
    )),
    task_version BIGINT NOT NULL CHECK (task_version > 0),
    created_at BIGINT NOT NULL CHECK (created_at >= 0),
    updated_at BIGINT NOT NULL CHECK (updated_at >= created_at),
    expires_at BIGINT NOT NULL CHECK (expires_at > created_at),
    result_ref TEXT,
    error_code TEXT,
    UNIQUE (tenant_ref, principal_ref, idempotency_key)
);

CREATE INDEX IF NOT EXISTS iroka_tasks_scope_created
    ON iroka_tasks (tenant_ref, principal_ref, created_at DESC, task_id);

CREATE INDEX IF NOT EXISTS iroka_tasks_dispatch
    ON iroka_tasks (state, created_at, task_id)
    WHERE state IN ('accepted','queued','awaiting_authorization');

CREATE TABLE IF NOT EXISTS iroka_task_events (
    task_id TEXT NOT NULL REFERENCES iroka_tasks(task_id),
    sequence BIGINT NOT NULL CHECK (sequence > 0),
    event_id TEXT NOT NULL UNIQUE,
    event_type TEXT NOT NULL,
    task_state TEXT NOT NULL,
    task_version BIGINT NOT NULL CHECK (task_version > 0),
    actor_ref TEXT NOT NULL,
    occurred_at BIGINT NOT NULL CHECK (occurred_at >= 0),
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb
        CHECK (jsonb_typeof(metadata_json) = 'object'),
    PRIMARY KEY (task_id, sequence)
);

CREATE INDEX IF NOT EXISTS iroka_task_events_stream
    ON iroka_task_events (task_id, sequence);

CREATE OR REPLACE FUNCTION iroka_reject_task_event_mutation()
RETURNS trigger LANGUAGE plpgsql AS $task_events$
BEGIN
    RAISE EXCEPTION 'IROKA task events are append-only';
END;
$task_events$;

DROP TRIGGER IF EXISTS iroka_task_events_no_update ON iroka_task_events;
CREATE TRIGGER iroka_task_events_no_update
BEFORE UPDATE OR DELETE ON iroka_task_events
FOR EACH ROW EXECUTE FUNCTION iroka_reject_task_event_mutation();

COMMIT;
