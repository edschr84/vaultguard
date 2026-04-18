CREATE TABLE authorization_codes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    code            TEXT        NOT NULL UNIQUE,
    client_id       TEXT        NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    user_id         UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    redirect_uri    TEXT        NOT NULL,
    scope           TEXT        NOT NULL,
    nonce           TEXT,
    code_challenge  TEXT,
    code_challenge_method TEXT CHECK (code_challenge_method IN ('S256', 'plain')),
    expires_at      TIMESTAMPTZ NOT NULL,
    used            BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_auth_codes_code      ON authorization_codes (code);
CREATE INDEX idx_auth_codes_client_id ON authorization_codes (client_id);
CREATE INDEX idx_auth_codes_expires   ON authorization_codes (expires_at);
