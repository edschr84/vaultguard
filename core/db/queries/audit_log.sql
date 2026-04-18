-- name: AppendAuditLog :one
INSERT INTO audit_log (
    actor_type, actor_id, action, resource,
    outcome, remote_ip, request_id, detail
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: ListAuditLog :many
SELECT * FROM audit_log
ORDER BY event_time DESC
LIMIT $1 OFFSET $2;

-- name: ListAuditLogByActor :many
SELECT * FROM audit_log
WHERE actor_id = $1
ORDER BY event_time DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogByAction :many
SELECT * FROM audit_log
WHERE action = $1
ORDER BY event_time DESC
LIMIT $2 OFFSET $3;

-- name: ListAuditLogSince :many
SELECT * FROM audit_log
WHERE event_time >= $1
ORDER BY event_time DESC
LIMIT $2;
