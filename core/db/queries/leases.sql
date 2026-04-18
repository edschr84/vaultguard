-- name: CreateLease :one
INSERT INTO leases (lease_id, secret_id, issued_to, expires_at, renewable)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetLeaseByLeaseID :one
SELECT * FROM leases WHERE lease_id = $1;

-- name: RenewLease :one
UPDATE leases
SET expires_at = $2, last_renewed_at = NOW()
WHERE lease_id = $1 AND revoked = FALSE
RETURNING *;

-- name: RevokeLease :exec
UPDATE leases
SET revoked = TRUE, revoked_at = NOW()
WHERE lease_id = $1;

-- name: RevokeLeasesBySecret :exec
UPDATE leases
SET revoked = TRUE, revoked_at = NOW()
WHERE secret_id = $1 AND revoked = FALSE;

-- name: ListExpiredLeases :many
SELECT * FROM leases
WHERE expires_at < NOW() AND revoked = FALSE;

-- name: DeleteExpiredLeases :exec
DELETE FROM leases WHERE expires_at < NOW() - INTERVAL '7 days';
