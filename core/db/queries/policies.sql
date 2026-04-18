-- name: CreatePolicy :one
INSERT INTO policies (name, description, rego_source, rules)
VALUES ($1, $2, $3, $4)
RETURNING *;

-- name: GetPolicyByName :one
SELECT * FROM policies WHERE name = $1;

-- name: GetPolicyByID :one
SELECT * FROM policies WHERE id = $1;

-- name: ListPolicies :many
SELECT * FROM policies
ORDER BY name
LIMIT $1 OFFSET $2;

-- name: UpdatePolicy :one
UPDATE policies
SET description  = COALESCE(sqlc.narg('description'), description),
    rego_source  = COALESCE(sqlc.narg('rego_source'), rego_source),
    rules        = COALESCE(sqlc.narg('rules'), rules),
    enabled      = COALESCE(sqlc.narg('enabled'), enabled)
WHERE id = sqlc.arg('id')
RETURNING *;

-- name: DeletePolicy :exec
DELETE FROM policies WHERE id = $1;

-- name: CreatePolicyBinding :one
INSERT INTO policy_bindings (policy_id, subject_type, subject_id)
VALUES ($1, $2, $3)
RETURNING *;

-- name: ListPolicyBindingsForSubject :many
SELECT pb.*, p.name AS policy_name, p.rules, p.rego_source
FROM policy_bindings pb
JOIN policies p ON p.id = pb.policy_id
WHERE pb.subject_type = $1 AND pb.subject_id = $2 AND p.enabled = TRUE;

-- name: DeletePolicyBinding :exec
DELETE FROM policy_bindings
WHERE policy_id = $1 AND subject_type = $2 AND subject_id = $3;
