package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/google/uuid"
	"github.com/vaultguard/core/identity"
)

const (
	sqlCreateUser = `
		INSERT INTO users (username, email, password_hash, display_name)
		VALUES ($1, $2, $3, $4)
		RETURNING id, username, email, password_hash, display_name,
		          enabled, email_verified, metadata, created_at, updated_at`

	sqlGetUserByID = `
		SELECT id, username, email, password_hash, display_name,
		       enabled, email_verified, metadata, created_at, updated_at
		FROM users WHERE id = $1`

	sqlGetUserByEmail = `
		SELECT id, username, email, password_hash, display_name,
		       enabled, email_verified, metadata, created_at, updated_at
		FROM users WHERE email = $1`

	sqlGetUserByUsername = `
		SELECT id, username, email, password_hash, display_name,
		       enabled, email_verified, metadata, created_at, updated_at
		FROM users WHERE username = $1`

	sqlListUsers = `
		SELECT id, username, email, password_hash, display_name,
		       enabled, email_verified, metadata, created_at, updated_at
		FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	sqlUpdateUser = `
		UPDATE users
		SET username       = COALESCE($2, username),
		    email          = COALESCE($3, email),
		    display_name   = COALESCE($4, display_name),
		    enabled        = COALESCE($5, enabled),
		    email_verified = COALESCE($6, email_verified)
		WHERE id = $1
		RETURNING id, username, email, password_hash, display_name,
		          enabled, email_verified, metadata, created_at, updated_at`

	sqlUpdateUserPassword = `UPDATE users SET password_hash = $2 WHERE id = $1`
	sqlDeleteUser         = `DELETE FROM users WHERE id = $1`
)

func (db *DB) CreateUser(ctx context.Context, p identity.CreateUserParams) (identity.UserRow, error) {
	return db.scanUser(db.pool.QueryRow(ctx, sqlCreateUser, p.Username, p.Email, p.Password, p.DisplayName))
}

func (db *DB) GetUserByID(ctx context.Context, id uuid.UUID) (identity.UserRow, error) {
	return db.scanUser(db.pool.QueryRow(ctx, sqlGetUserByID, id))
}

func (db *DB) GetUserByEmail(ctx context.Context, email string) (identity.UserRow, error) {
	return db.scanUser(db.pool.QueryRow(ctx, sqlGetUserByEmail, email))
}

func (db *DB) GetUserByUsername(ctx context.Context, username string) (identity.UserRow, error) {
	return db.scanUser(db.pool.QueryRow(ctx, sqlGetUserByUsername, username))
}

func (db *DB) ListUsers(ctx context.Context, limit, offset int32) ([]identity.UserRow, error) {
	rows, err := db.pool.Query(ctx, sqlListUsers, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []identity.UserRow
	for rows.Next() {
		r, err := db.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) UpdateUser(ctx context.Context, p identity.UpdateUserParams) (identity.UserRow, error) {
	return db.scanUser(db.pool.QueryRow(ctx, sqlUpdateUser,
		p.ID,
		nullText(p.Username),
		nullText(p.Email),
		nullText(p.DisplayName),
		(*bool)(nil), // enabled handled separately if needed
		(*bool)(nil),
	))
}

func (db *DB) UpdateUserPassword(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := db.pool.Exec(ctx, sqlUpdateUserPassword, id, hash)
	return err
}

func (db *DB) DeleteUser(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, sqlDeleteUser, id)
	return err
}

// scanUser scans a single user row from any pgx Row or Rows.
type pgxScanner interface {
	Scan(dest ...any) error
}

func (db *DB) scanUser(r pgxScanner) (identity.UserRow, error) {
	var row identity.UserRow
	var id pgtype.UUID
	var metadata []byte
	err := r.Scan(
		&id, &row.Username, &row.Email, &row.PasswordHash, &row.DisplayName,
		&row.Enabled, &row.EmailVerified, &metadata, &row.CreatedAt, &row.UpdatedAt,
	)
	if err != nil {
		return row, fmt.Errorf("scan user: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	row.Metadata = metadata
	return row, nil
}
