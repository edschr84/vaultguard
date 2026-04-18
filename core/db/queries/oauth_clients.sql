-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (
    client_id, client_secret_hash, name, client_type,
    redirect_uris, allowed_scopes, allowed_grants,
    access_token_ttl, refresh_token_ttl, metadata
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetOAuthClientByClientID :one
SELECT * FROM oauth_clients WHERE client_id = $1;

-- name: GetOAuthClientByID :one
SELECT * FROM oauth_clients WHERE id = $1;

-- name: ListOAuthClients :many
SELECT * FROM oauth_clients
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateOAuthClient :one
UPDATE oauth_clients
SET name              = COALESCE(sqlc.narg('name'), name),
    redirect_uris     = COALESCE(sqlc.narg('redirect_uris'), redirect_uris),
    allowed_scopes    = COALESCE(sqlc.narg('allowed_scopes'), allowed_scopes),
    allowed_grants    = COALESCE(sqlc.narg('allowed_grants'), allowed_grants),
    access_token_ttl  = COALESCE(sqlc.narg('access_token_ttl'), access_token_ttl),
    refresh_token_ttl = COALESCE(sqlc.narg('refresh_token_ttl'), refresh_token_ttl),
    enabled           = COALESCE(sqlc.narg('enabled'), enabled),
    metadata          = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: DeleteOAuthClient :exec
DELETE FROM oauth_clients WHERE id = $1;

-- name: CountOAuthClients :one
SELECT COUNT(*) FROM oauth_clients;
