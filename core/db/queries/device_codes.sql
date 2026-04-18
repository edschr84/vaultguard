-- name: CreateDeviceCode :one
INSERT INTO device_codes (
    device_code, user_code, client_id, scope,
    verification_uri, expires_at, interval_secs
) VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetDeviceCodeByDeviceCode :one
SELECT * FROM device_codes WHERE device_code = $1;

-- name: GetDeviceCodeByUserCode :one
SELECT * FROM device_codes WHERE user_code = $1;

-- name: ApproveDeviceCode :exec
UPDATE device_codes SET user_id = $2 WHERE user_code = $1;

-- name: DenyDeviceCode :exec
UPDATE device_codes SET denied = TRUE WHERE user_code = $1;

-- name: DeleteExpiredDeviceCodes :exec
DELETE FROM device_codes WHERE expires_at < NOW();
