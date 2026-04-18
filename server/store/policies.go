package store

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vaultguard/core/identity"
)

const sqlCreatePolicy = `
	INSERT INTO policies (name, description, rego_source, rules)
	VALUES ($1, $2, $3, $4::jsonb)
	RETURNING id, name, description, rego_source, rules, enabled, created_at, updated_at`

const sqlGetPolicyByName = `
	SELECT id, name, description, rego_source, rules, enabled, created_at, updated_at
	FROM policies WHERE name = $1`

const sqlGetPolicyByID = `
	SELECT id, name, description, rego_source, rules, enabled, created_at, updated_at
	FROM policies WHERE id = $1`

const sqlListPolicies = `
	SELECT id, name, description, rego_source, rules, enabled, created_at, updated_at
	FROM policies ORDER BY name LIMIT $1 OFFSET $2`

const sqlUpdatePolicy = `
	UPDATE policies
	SET description = COALESCE($2, description),
	    rego_source = COALESCE($3, rego_source),
	    rules       = COALESCE($4::jsonb, rules),
	    enabled     = COALESCE($5, enabled)
	WHERE id = $1
	RETURNING id, name, description, rego_source, rules, enabled, created_at, updated_at`

const sqlDeletePolicy = `DELETE FROM policies WHERE id = $1`

const sqlCreatePolicyBinding = `
	INSERT INTO policy_bindings (policy_id, subject_type, subject_id)
	VALUES ($1, $2, $3)
	RETURNING id, policy_id, subject_type, subject_id, created_at`

const sqlListPolicyBindingsForSubject = `
	SELECT pb.id, pb.policy_id, pb.subject_type, pb.subject_id,
	       p.name, p.rules, p.rego_source, pb.created_at
	FROM policy_bindings pb
	JOIN policies p ON p.id = pb.policy_id
	WHERE pb.subject_type = $1 AND pb.subject_id = $2 AND p.enabled = TRUE`

const sqlDeletePolicyBinding = `
	DELETE FROM policy_bindings
	WHERE policy_id = $1 AND subject_type = $2 AND subject_id = $3`

func (db *DB) CreatePolicy(ctx context.Context, p identity.CreatePolicyParams) (identity.PolicyRow, error) {
	rulesJSON, _ := json.Marshal(p.Rules)
	return db.scanPolicy(db.pool.QueryRow(ctx, sqlCreatePolicy,
		p.Name, p.Description, p.RegoSource, string(rulesJSON),
	))
}

func (db *DB) GetPolicyByName(ctx context.Context, name string) (identity.PolicyRow, error) {
	return db.scanPolicy(db.pool.QueryRow(ctx, sqlGetPolicyByName, name))
}

func (db *DB) GetPolicyByID(ctx context.Context, id uuid.UUID) (identity.PolicyRow, error) {
	return db.scanPolicy(db.pool.QueryRow(ctx, sqlGetPolicyByID, id))
}

func (db *DB) ListPolicies(ctx context.Context, limit, offset int32) ([]identity.PolicyRow, error) {
	rows, err := db.pool.Query(ctx, sqlListPolicies, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []identity.PolicyRow
	for rows.Next() {
		r, err := db.scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) UpdatePolicy(ctx context.Context, p identity.UpdatePolicyParams) (identity.PolicyRow, error) {
	var rulesJSON *string
	if p.Rules != nil {
		b, _ := json.Marshal(*p.Rules)
		s := string(b)
		rulesJSON = &s
	}
	return db.scanPolicy(db.pool.QueryRow(ctx, sqlUpdatePolicy,
		p.ID,
		nullText(p.Description),
		nullText(p.RegoSource),
		nullText(rulesJSON),
		p.Enabled,
	))
}

func (db *DB) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, sqlDeletePolicy, id)
	return err
}

func (db *DB) CreatePolicyBinding(ctx context.Context, p identity.PolicyBindingParams) (identity.PolicyBindingRow, error) {
	var row identity.PolicyBindingRow
	var id, policyID pgtype.UUID
	err := db.pool.QueryRow(ctx, sqlCreatePolicyBinding,
		p.PolicyID, p.SubjectType, p.SubjectID,
	).Scan(&id, &policyID, &row.SubjectType, &row.SubjectID, &row.CreatedAt)
	if err != nil {
		return row, fmt.Errorf("scan policy binding: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	row.PolicyID = uuidFromPgtype(policyID)
	return row, nil
}

func (db *DB) ListPolicyBindingsForSubject(ctx context.Context, subjectType, subjectID string) ([]identity.PolicyBindingRow, error) {
	rows, err := db.pool.Query(ctx, sqlListPolicyBindingsForSubject, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []identity.PolicyBindingRow
	for rows.Next() {
		var row identity.PolicyBindingRow
		var id, policyID pgtype.UUID
		err := rows.Scan(
			&id, &policyID, &row.SubjectType, &row.SubjectID,
			&row.PolicyName, &row.Rules, &row.RegoSource, &row.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan policy binding row: %w", err)
		}
		row.ID = uuidFromPgtype(id)
		row.PolicyID = uuidFromPgtype(policyID)
		out = append(out, row)
	}
	return out, rows.Err()
}

func (db *DB) DeletePolicyBinding(ctx context.Context, policyID uuid.UUID, subjectType, subjectID string) error {
	_, err := db.pool.Exec(ctx, sqlDeletePolicyBinding, policyID, subjectType, subjectID)
	return err
}

func (db *DB) scanPolicy(r pgxScanner) (identity.PolicyRow, error) {
	var row identity.PolicyRow
	var id pgtype.UUID
	err := r.Scan(&id, &row.Name, &row.Description, &row.RegoSource, &row.Rules,
		&row.Enabled, &row.CreatedAt, &row.UpdatedAt)
	if err != nil {
		return row, fmt.Errorf("scan policy: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	return row, nil
}
