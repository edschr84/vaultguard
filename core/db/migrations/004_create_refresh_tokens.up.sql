CREATE TABLE refresh_tokens (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash      TEXT        NOT NULL UNIQUE,   -- SHA-256 hex of the raw token
    client_id       TEXT        NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    user_id         UUID        REFERENCES users (id) ON DELETE CASCADE,
    scope           TEXT        NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked         BOOLEAN     NOT NULL DEFAULT FALSE,
    revoked_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_hash      ON refresh_tokens (token_hash);
CREATE INDEX idx_refresh_tokens_client_id ON refresh_tokens (client_id);
CREATE INDEX idx_refresh_tokens_user_id   ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_expires   ON refresh_tokens (expires_at);
