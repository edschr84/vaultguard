-- name: CreateVaultSecret :one
INSERT INTO vault_secrets (namespace, mount, path, version, ciphertext, data_key_enc, metadata, created_by)
VALUES ($1, $2, $3,
    COALESCE(
        (SELECT MAX(version) + 1
         FROM vault_secrets
         WHERE namespace = $1 AND mount = $2 AND path = $3),
        1
    ),
    $4, $5, $6, $7)
RETURNING *;

-- name: GetVaultSecretLatest :one
SELECT * FROM vault_secrets
WHERE namespace = $1 AND mount = $2 AND path = $3 AND deleted = FALSE
ORDER BY version DESC
LIMIT 1;

-- name: GetVaultSecretByVersion :one
SELECT * FROM vault_secrets
WHERE namespace = $1 AND mount = $2 AND path = $3 AND version = $4 AND deleted = FALSE;

-- name: ListVaultSecretVersions :many
SELECT id, version, metadata, created_by, created_at, deleted, deleted_at
FROM vault_secrets
WHERE namespace = $1 AND mount = $2 AND path = $3
ORDER BY version DESC;

-- name: ListVaultSecretPaths :many
SELECT DISTINCT path
FROM vault_secrets
WHERE namespace = $1 AND mount = $2 AND deleted = FALSE
ORDER BY path;

-- name: SoftDeleteVaultSecret :exec
UPDATE vault_secrets
SET deleted = TRUE, deleted_at = NOW()
WHERE namespace = $1 AND mount = $2 AND path = $3 AND deleted = FALSE;

-- name: GetVaultSecretByID :one
SELECT * FROM vault_secrets WHERE id = $1;
