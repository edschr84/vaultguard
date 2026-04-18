-- name: CreateUser :one
INSERT INTO users (username, email, password_hash, display_name)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY created_at DESC
LIMIT $1 OFFSET $2;

-- name: UpdateUser :one
UPDATE users
SET username     = COALESCE(sqlc.narg('username'), username),
    email        = COALESCE(sqlc.narg('email'), email),
    display_name = COALESCE(sqlc.narg('display_name'), display_name),
    enabled      = COALESCE(sqlc.narg('enabled'), enabled),
    email_verified = COALESCE(sqlc.narg('email_verified'), email_verified),
    metadata     = COALESCE(sqlc.narg('metadata'), metadata)
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = $2 WHERE id = $1;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;
