CREATE TABLE policies (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT        NOT NULL UNIQUE,
    description TEXT        NOT NULL DEFAULT '',
    -- Rego policy source (OPA stub)
    rego_source TEXT        NOT NULL DEFAULT '',
    -- Simplified allow-list rules stored as JSONB for the built-in engine
    rules       JSONB       NOT NULL DEFAULT '[]',
    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE policy_bindings (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id   UUID        NOT NULL REFERENCES policies (id) ON DELETE CASCADE,
    subject_type TEXT       NOT NULL CHECK (subject_type IN ('user', 'client', 'group')),
    subject_id  TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (policy_id, subject_type, subject_id)
);

CREATE INDEX idx_policy_bindings_subject ON policy_bindings (subject_type, subject_id);

CREATE TRIGGER trg_policies_updated_at
    BEFORE UPDATE ON policies
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
