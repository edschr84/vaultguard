-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, expires_at)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = $1;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked = TRUE, revoked_at = NOW()
WHERE token_hash = $1;

-- name: RevokeRefreshTokensByUser :exec
UPDATE refresh_tokens
SET revoked = TRUE, revoked_at = NOW()
WHERE user_id = $1 AND revoked = FALSE;

-- name: RevokeRefreshTokensByClient :exec
UPDATE refresh_tokens
SET revoked = TRUE, revoked_at = NOW()
WHERE client_id = $1 AND revoked = FALSE;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at < NOW();
