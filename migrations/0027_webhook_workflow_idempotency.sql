-- Durable webhook workflow idempotency.
--
-- A caller-provided key is scoped by the server-resolved community and the
-- workflow row. The payload hash prevents one key from silently naming two
-- different requests. Runs created by event, schedule, or manual triggers keep
-- both columns NULL and retain their existing behavior.

ALTER TABLE workflow_runs
    ADD COLUMN webhook_idempotency_key VARCHAR(256),
    ADD COLUMN webhook_payload_hash BYTEA,
    ADD COLUMN webhook_credential_salt BYTEA,
    ADD COLUMN webhook_credential_hash BYTEA,
    ADD COLUMN webhook_channel_id UUID,
    ADD COLUMN webhook_definition JSONB,
    ADD COLUMN webhook_definition_hash BYTEA,
    ADD COLUMN webhook_execution_lease_id UUID,
    ADD COLUMN webhook_execution_lease_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT chk_workflow_runs_webhook_identity_set CHECK (
        (webhook_idempotency_key IS NULL) = (webhook_payload_hash IS NULL)
        AND (webhook_idempotency_key IS NULL) = (webhook_credential_salt IS NULL)
        AND (webhook_idempotency_key IS NULL) = (webhook_credential_hash IS NULL)
        AND (webhook_idempotency_key IS NULL) = (webhook_channel_id IS NULL)
        AND (webhook_idempotency_key IS NULL) = (webhook_definition IS NULL)
        AND (webhook_idempotency_key IS NULL) = (webhook_definition_hash IS NULL)
    ),
    ADD CONSTRAINT chk_workflow_runs_webhook_idempotency_key CHECK (
        webhook_idempotency_key IS NULL
        OR webhook_idempotency_key ~ '^[A-Za-z0-9:_-]+$'
    ),
    ADD CONSTRAINT chk_workflow_runs_webhook_payload_hash CHECK (
        webhook_payload_hash IS NULL OR length(webhook_payload_hash) = 32
    ),
    ADD CONSTRAINT chk_workflow_runs_webhook_credential_salt CHECK (
        webhook_credential_salt IS NULL OR length(webhook_credential_salt) = 16
    ),
    ADD CONSTRAINT chk_workflow_runs_webhook_credential_hash CHECK (
        webhook_credential_hash IS NULL OR length(webhook_credential_hash) = 32
    ),
    ADD CONSTRAINT chk_workflow_runs_webhook_definition_hash CHECK (
        webhook_definition_hash IS NULL OR length(webhook_definition_hash) = 32
    ),
    ADD CONSTRAINT chk_workflow_runs_webhook_lease_pair CHECK (
        (webhook_execution_lease_id IS NULL)
            = (webhook_execution_lease_expires_at IS NULL)
    ),
    ADD CONSTRAINT chk_workflow_runs_webhook_lease_identity CHECK (
        webhook_execution_lease_id IS NULL OR webhook_idempotency_key IS NOT NULL
    );

ALTER TABLE workflow_runs
    ADD CONSTRAINT fk_workflow_runs_webhook_channel
        FOREIGN KEY (community_id, webhook_channel_id)
        REFERENCES channels (community_id, id);

CREATE UNIQUE INDEX idx_workflow_runs_webhook_idempotency
    ON workflow_runs (community_id, workflow_id, webhook_idempotency_key)
    WHERE webhook_idempotency_key IS NOT NULL;

-- A keyed run is the durable identity that makes an external retry safe. The
-- workflow FK historically cascades all runs, so protect keyed rows at the
-- child table itself: direct deletes and workflow-delete cascades both pass
-- through this trigger and fail. Non-keyed legacy runs retain their existing
-- lifecycle behavior.
CREATE FUNCTION prevent_keyed_workflow_run_delete()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.webhook_idempotency_key IS NOT NULL THEN
        RAISE EXCEPTION
            'cannot delete durable keyed webhook workflow run %/%',
            OLD.workflow_id,
            OLD.webhook_idempotency_key
            USING ERRCODE = '23503';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER trg_prevent_keyed_workflow_run_delete
    BEFORE DELETE ON workflow_runs
    FOR EACH ROW
    EXECUTE FUNCTION prevent_keyed_workflow_run_delete();

COMMENT ON COLUMN workflow_runs.webhook_idempotency_key IS
    'Caller key for a webhook run, unique within server-resolved community and workflow.';
COMMENT ON COLUMN workflow_runs.webhook_payload_hash IS
    'SHA-256 of the exact webhook request body bound to webhook_idempotency_key.';
COMMENT ON COLUMN workflow_runs.webhook_credential_salt IS
    'Per-run salt for the immutable one-way replay credential verifier.';
COMMENT ON COLUMN workflow_runs.webhook_credential_hash IS
    'SHA-256 replay credential verifier; the plaintext webhook secret is never copied into the run.';
COMMENT ON COLUMN workflow_runs.webhook_channel_id IS
    'Immutable channel authority snapshot captured when the keyed webhook run is created.';
COMMENT ON COLUMN workflow_runs.webhook_definition IS
    'Immutable workflow definition snapshot used by keyed-run crash recovery.';
COMMENT ON COLUMN workflow_runs.webhook_definition_hash IS
    'Workflow definition hash captured with webhook_definition.';
COMMENT ON COLUMN workflow_runs.webhook_execution_lease_id IS
    'Fencing token for the process allowed to transition a pending webhook run to running.';
COMMENT ON COLUMN workflow_runs.webhook_execution_lease_expires_at IS
    'Expiry for pending-run handoff recovery; an expired lease may be reclaimed by an exact replay.';
