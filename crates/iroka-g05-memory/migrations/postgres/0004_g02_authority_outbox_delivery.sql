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


CREATE OR REPLACE FUNCTION g02_protect_authority_outbox_payload()
RETURNS trigger LANGUAGE plpgsql AS $g02$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION 'G02 authority outbox history is append-only';
    END IF;
    IF OLD.delivered_at IS NOT NULL THEN
        RAISE EXCEPTION 'delivered G02 authority outbox events are immutable';
    END IF;
    IF (NEW.delivered_at IS NULL) <> (NEW.acknowledgment_sha256 IS NULL)
        OR (NEW.acknowledgment_sha256 IS NOT NULL AND
            (length(trim(NEW.acknowledgment_sha256)) <> 64 OR
             trim(NEW.acknowledgment_sha256) !~* '^[0-9a-f]{64}
        OR NEW.command_id IS DISTINCT FROM OLD.command_id
        OR NEW.event_kind IS DISTINCT FROM OLD.event_kind
        OR NEW.payload_sha256 IS DISTINCT FROM OLD.payload_sha256
        OR NEW.payload_json IS DISTINCT FROM OLD.payload_json
        OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'G02 authority outbox payload is immutable';
    END IF;
    RETURN NEW;
END;
$g02$;

DROP TRIGGER IF EXISTS g02_authority_outbox_immutable_payload ON g02_authority_outbox;
CREATE TRIGGER g02_authority_outbox_immutable_payload
BEFORE UPDATE OR DELETE ON g02_authority_outbox
FOR EACH ROW EXECUTE FUNCTION g02_protect_authority_outbox_payload();

COMMIT;
))
    THEN
        RAISE EXCEPTION 'G02 outbox acknowledgement evidence is malformed';
    END IF;
    IF NEW.event_id IS DISTINCT FROM OLD.event_id
        OR NEW.command_id IS DISTINCT FROM OLD.command_id
        OR NEW.event_kind IS DISTINCT FROM OLD.event_kind
        OR NEW.payload_sha256 IS DISTINCT FROM OLD.payload_sha256
        OR NEW.payload_json IS DISTINCT FROM OLD.payload_json
        OR NEW.occurred_at IS DISTINCT FROM OLD.occurred_at
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
    THEN
        RAISE EXCEPTION 'G02 authority outbox payload is immutable';
    END IF;
    RETURN NEW;
END;
$g02$;

DROP TRIGGER IF EXISTS g02_authority_outbox_immutable_payload ON g02_authority_outbox;
CREATE TRIGGER g02_authority_outbox_immutable_payload
BEFORE UPDATE OR DELETE ON g02_authority_outbox
FOR EACH ROW EXECUTE FUNCTION g02_protect_authority_outbox_payload();

COMMIT;
