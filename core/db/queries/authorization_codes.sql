-- name: CreateAuthorizationCode :one
INSERT INTO authorization_codes (
    code, client_id, user_id, redirect_uri, scope,
    nonce, code_challenge, code_challenge_method, expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: GetAuthorizationCode :one
SELECT * FROM authorization_codes WHERE code = $1;

-- name: MarkAuthorizationCodeUsed :exec
UPDATE authorization_codes SET used = TRUE WHERE code = $1;

-- name: DeleteExpiredAuthorizationCodes :exec
DELETE FROM authorization_codes WHERE expires_at < NOW();
