CREATE TABLE signing_keys (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    kid             TEXT        NOT NULL UNIQUE,
    algorithm       TEXT        NOT NULL DEFAULT 'RS256',
    -- PEM-encoded private key, encrypted at rest using envelope encryption
    private_key_enc BYTEA       NOT NULL,
    public_key_pem  TEXT        NOT NULL,
    active          BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rotated_at      TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_signing_keys_kid    ON signing_keys (kid);
CREATE INDEX idx_signing_keys_active ON signing_keys (active);
