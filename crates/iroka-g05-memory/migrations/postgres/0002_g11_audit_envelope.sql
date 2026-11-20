-- Add a domain discriminator for generic G11 audit envelopes.
BEGIN;
ALTER TABLE g11_memory_audit_events
    ADD COLUMN IF NOT EXISTS event_domain TEXT NOT NULL DEFAULT 'memory';
DO $domain$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname='g11_memory_audit_events_domain_check'
          AND conrelid='g11_memory_audit_events'::regclass
    ) THEN
        ALTER TABLE g11_memory_audit_events
            ADD CONSTRAINT g11_memory_audit_events_domain_check
            CHECK (event_domain IN ('memory','envelope'));
    END IF;
END
$domain$;
CREATE INDEX IF NOT EXISTS g11_memory_audit_events_domain_sequence
    ON g11_memory_audit_events(event_domain,sequence);
COMMIT;
