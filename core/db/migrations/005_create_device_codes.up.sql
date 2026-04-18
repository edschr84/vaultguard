CREATE TABLE device_codes (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    device_code     TEXT        NOT NULL UNIQUE,
    user_code       TEXT        NOT NULL UNIQUE,
    client_id       TEXT        NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    scope           TEXT        NOT NULL,
    verification_uri TEXT       NOT NULL,
    expires_at      TIMESTAMPTZ NOT NULL,
    interval_secs   INT         NOT NULL DEFAULT 5,
    -- NULL = pending, UUID = approved user, empty string = denied
    user_id         UUID        REFERENCES users (id) ON DELETE SET NULL,
    denied          BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_device_codes_device_code ON device_codes (device_code);
CREATE INDEX idx_device_codes_user_code   ON device_codes (user_code);
CREATE INDEX idx_device_codes_expires     ON device_codes (expires_at);
