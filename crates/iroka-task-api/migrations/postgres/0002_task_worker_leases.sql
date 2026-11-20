-- Durable task worker ownership. No worker process or model execution is enabled here.
BEGIN;
ALTER TABLE iroka_tasks
    ADD COLUMN IF NOT EXISTS lease_owner TEXT,
    ADD COLUMN IF NOT EXISTS lease_token UUID,
    ADD COLUMN IF NOT EXISTS lease_expires_at BIGINT,
    ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS next_attempt_at BIGINT NOT NULL DEFAULT 0;

DO $lease$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='iroka_tasks_lease_binding_check'
          AND conrelid='iroka_tasks'::regclass
    ) THEN
        ALTER TABLE iroka_tasks ADD CONSTRAINT iroka_tasks_lease_binding_check
        CHECK (
            (lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL)
            OR
            (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL)
        );
    END IF;
END
$lease$;

CREATE INDEX IF NOT EXISTS iroka_tasks_worker_claim
    ON iroka_tasks (state, next_attempt_at, created_at, task_id)
    WHERE state IN ('queued','cancel_requested');

CREATE INDEX IF NOT EXISTS iroka_tasks_expired_leases
    ON iroka_tasks (lease_expires_at, task_id)
    WHERE lease_token IS NOT NULL;
COMMIT;
