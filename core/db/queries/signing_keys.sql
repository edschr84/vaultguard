-- name: CreateSigningKey :one
INSERT INTO signing_keys (kid, algorithm, private_key_enc, public_key_pem, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetActiveSigningKey :one
SELECT * FROM signing_keys
WHERE active = TRUE
ORDER BY created_at DESC
LIMIT 1;

-- name: ListActiveSigningKeys :many
SELECT * FROM signing_keys
WHERE active = TRUE
ORDER BY created_at DESC;

-- name: GetSigningKeyByKID :one
SELECT * FROM signing_keys WHERE kid = $1;

-- name: DeactivateSigningKey :exec
UPDATE signing_keys
SET active = FALSE, rotated_at = NOW()
WHERE kid = $1;

-- name: ListVerifiableSigningKeys :many
-- Returns active keys plus recently rotated ones still within token TTL window
SELECT * FROM signing_keys
WHERE active = TRUE
   OR (rotated_at IS NOT NULL AND rotated_at > NOW() - INTERVAL '2 hours')
ORDER BY created_at DESC;
