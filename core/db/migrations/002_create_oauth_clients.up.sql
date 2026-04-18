CREATE TYPE client_type AS ENUM ('confidential', 'public');
CREATE TYPE grant_type  AS ENUM (
    'authorization_code',
    'client_credentials',
    'refresh_token',
    'urn:ietf:params:oauth:grant-type:device_code'
);

CREATE TABLE oauth_clients (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       TEXT        NOT NULL UNIQUE,
    client_secret_hash TEXT,                       -- NULL for public clients
    name            TEXT        NOT NULL,
    client_type     client_type NOT NULL DEFAULT 'confidential',
    redirect_uris   TEXT[]      NOT NULL DEFAULT '{}',
    allowed_scopes  TEXT[]      NOT NULL DEFAULT '{"openid","profile","email"}',
    allowed_grants  grant_type[] NOT NULL DEFAULT '{"authorization_code","refresh_token"}',
    access_token_ttl  INT       NOT NULL DEFAULT 900,   -- seconds
    refresh_token_ttl INT       NOT NULL DEFAULT 86400,
    metadata        JSONB       NOT NULL DEFAULT '{}',
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_oauth_clients_client_id ON oauth_clients (client_id);

CREATE TRIGGER trg_oauth_clients_updated_at
    BEFORE UPDATE ON oauth_clients
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
