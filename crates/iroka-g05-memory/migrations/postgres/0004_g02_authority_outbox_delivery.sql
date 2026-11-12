-- G02 authority outbox delivery acknowledgement and retry diagnostics.
BEGIN;
SELECT pg_advisory_xact_lock(77305114);

ALTER TABLE g02_authority_outbox
    ADD COLUMN IF NOT EXISTS acknowledgment_sha256 CHAR(64);
ALTER TABLE g02_authority_outbox
    ADD COLUMN IF NOT EXISTS last_error_code TEXT;

CREATE INDEX IF NOT EXISTS g02_authority_outbox_expired_lease
    ON g02_authority_outbox(lease_expires_at)
    WHERE delivered_at IS NULL AND lease_token IS NOT NULL;

COMMIT;
