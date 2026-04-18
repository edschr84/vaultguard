CREATE TABLE leases (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    lease_id        TEXT        NOT NULL UNIQUE,
    secret_id       UUID        NOT NULL REFERENCES vault_secrets (id) ON DELETE CASCADE,
    issued_to       TEXT        NOT NULL,   -- client_id or user_id string
    expires_at      TIMESTAMPTZ NOT NULL,
    renewable       BOOLEAN     NOT NULL DEFAULT TRUE,
    revoked         BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    last_renewed_at TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_leases_lease_id  ON leases (lease_id);
CREATE INDEX idx_leases_expires   ON leases (expires_at);
CREATE INDEX idx_leases_secret_id ON leases (secret_id);
