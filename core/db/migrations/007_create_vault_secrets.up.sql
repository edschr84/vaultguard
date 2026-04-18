CREATE TABLE vault_secrets (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace       TEXT        NOT NULL,
    mount           TEXT        NOT NULL,
    path            TEXT        NOT NULL,
    version         INT         NOT NULL DEFAULT 1,
    -- AES-256-GCM ciphertext (nonce prepended)
    ciphertext      BYTEA       NOT NULL,
    -- Encrypted data key (wrapped by root key)
    data_key_enc    BYTEA       NOT NULL,
    metadata        JSONB       NOT NULL DEFAULT '{}',
    created_by      UUID        REFERENCES users (id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted         BOOLEAN     NOT NULL DEFAULT FALSE,
    deleted_at      TIMESTAMPTZ,
    UNIQUE (namespace, mount, path, version)
);

CREATE INDEX idx_vault_secrets_path    ON vault_secrets (namespace, mount, path);
CREATE INDEX idx_vault_secrets_version ON vault_secrets (namespace, mount, path, version DESC);

-- Latest-version helper view
CREATE VIEW vault_secret_latest AS
SELECT DISTINCT ON (namespace, mount, path)
    *
FROM vault_secrets
WHERE deleted = FALSE
ORDER BY namespace, mount, path, version DESC;
