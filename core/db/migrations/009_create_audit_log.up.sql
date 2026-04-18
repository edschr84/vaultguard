CREATE TABLE audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    event_time  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_type  TEXT        NOT NULL,   -- 'user' | 'client' | 'system'
    actor_id    TEXT        NOT NULL,
    action      TEXT        NOT NULL,   -- 'secret.read' | 'token.issue' | etc.
    resource    TEXT        NOT NULL,
    outcome     TEXT        NOT NULL CHECK (outcome IN ('success', 'failure')),
    remote_ip   INET,
    request_id  TEXT,
    detail      JSONB       NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_audit_log_time     ON audit_log (event_time DESC);
CREATE INDEX idx_audit_log_actor    ON audit_log (actor_id);
CREATE INDEX idx_audit_log_action   ON audit_log (action);
CREATE INDEX idx_audit_log_resource ON audit_log (resource);

-- Immutable enforcement: reject any UPDATE or DELETE on audit_log
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log rows are immutable';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_log_no_update
    BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

CREATE TRIGGER trg_audit_log_no_delete
    BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();
