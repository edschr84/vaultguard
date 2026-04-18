package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vaultguard/core/vault"
)

// ─── Vault secrets ───────────────────────────────────────────────────────────

const sqlCreateVaultSecret = `
	INSERT INTO vault_secrets
	    (namespace, mount, path, version, ciphertext, data_key_enc, metadata, created_by)
	VALUES ($1, $2, $3,
	    COALESCE(
	        (SELECT MAX(version) + 1 FROM vault_secrets
	         WHERE namespace=$1 AND mount=$2 AND path=$3),
	        1),
	    $4, $5, $6, $7)
	RETURNING id, namespace, mount, path, version, ciphertext, data_key_enc,
	          metadata, created_by, created_at, deleted, deleted_at`

const sqlGetVaultSecretLatest = `
	SELECT id, namespace, mount, path, version, ciphertext, data_key_enc,
	       metadata, created_by, created_at, deleted, deleted_at
	FROM vault_secrets
	WHERE namespace=$1 AND mount=$2 AND path=$3 AND deleted=FALSE
	ORDER BY version DESC LIMIT 1`

const sqlGetVaultSecretByVersion = `
	SELECT id, namespace, mount, path, version, ciphertext, data_key_enc,
	       metadata, created_by, created_at, deleted, deleted_at
	FROM vault_secrets
	WHERE namespace=$1 AND mount=$2 AND path=$3 AND version=$4 AND deleted=FALSE`

const sqlListVaultSecretVersions = `
	SELECT id, version, metadata, created_at
	FROM vault_secrets
	WHERE namespace=$1 AND mount=$2 AND path=$3
	ORDER BY version DESC`

const sqlListVaultSecretPaths = `
	SELECT DISTINCT path FROM vault_secrets
	WHERE namespace=$1 AND mount=$2 AND deleted=FALSE
	ORDER BY path`

const sqlSoftDeleteVaultSecret = `
	UPDATE vault_secrets
	SET deleted=TRUE, deleted_at=NOW()
	WHERE namespace=$1 AND mount=$2 AND path=$3 AND deleted=FALSE`

const sqlGetVaultSecretByID = `
	SELECT id, namespace, mount, path, version, ciphertext, data_key_enc,
	       metadata, created_by, created_at, deleted, deleted_at
	FROM vault_secrets WHERE id=$1`

func (db *DB) CreateVaultSecret(ctx context.Context, p vault.CreateSecretParams) (vault.RawSecret, error) {
	return db.scanVaultSecret(db.pool.QueryRow(ctx, sqlCreateVaultSecret,
		p.Namespace, p.Mount, p.Path,
		p.Ciphertext, p.DataKeyEnc,
		p.Metadata,
		nullUUID(p.CreatedBy),
	))
}

func (db *DB) GetVaultSecretLatest(ctx context.Context, ns, mount, path string) (vault.RawSecret, error) {
	return db.scanVaultSecret(db.pool.QueryRow(ctx, sqlGetVaultSecretLatest, ns, mount, path))
}

func (db *DB) GetVaultSecretByVersion(ctx context.Context, ns, mount, path string, ver int32) (vault.RawSecret, error) {
	return db.scanVaultSecret(db.pool.QueryRow(ctx, sqlGetVaultSecretByVersion, ns, mount, path, ver))
}

func (db *DB) ListVaultSecretVersions(ctx context.Context, ns, mount, path string) ([]vault.SecretVersionInfo, error) {
	rows, err := db.pool.Query(ctx, sqlListVaultSecretVersions, ns, mount, path)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []vault.SecretVersionInfo
	for rows.Next() {
		var v vault.SecretVersionInfo
		var id pgtype.UUID
		err := rows.Scan(&id, &v.Version, &v.Metadata, &v.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("scan secret version: %w", err)
		}
		v.ID = uuidFromPgtype(id)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (db *DB) ListVaultSecretPaths(ctx context.Context, ns, mount string) ([]string, error) {
	rows, err := db.pool.Query(ctx, sqlListVaultSecretPaths, ns, mount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (db *DB) SoftDeleteVaultSecret(ctx context.Context, ns, mount, path string) error {
	_, err := db.pool.Exec(ctx, sqlSoftDeleteVaultSecret, ns, mount, path)
	return err
}

func (db *DB) GetVaultSecretByID(ctx context.Context, id uuid.UUID) (vault.RawSecret, error) {
	return db.scanVaultSecret(db.pool.QueryRow(ctx, sqlGetVaultSecretByID, id))
}

func (db *DB) scanVaultSecret(r pgxScanner) (vault.RawSecret, error) {
	var s vault.RawSecret
	var id, createdBy pgtype.UUID
	var deletedAt pgtype.Timestamptz
	err := r.Scan(
		&id, &s.Namespace, &s.Mount, &s.Path, &s.Version,
		&s.Ciphertext, &s.DataKeyEnc, &s.Metadata,
		&createdBy, &s.CreatedAt, &s.Deleted, &deletedAt,
	)
	if err != nil {
		return s, fmt.Errorf("scan vault secret: %w", err)
	}
	s.ID = uuidFromPgtype(id)
	s.CreatedBy = uuidPtrFromPgtype(createdBy)
	if deletedAt.Valid {
		s.DeletedAt = &deletedAt.Time
	}
	return s, nil
}

// ─── Leases ───────────────────────────────────────────────────────────────────

const sqlCreateLease = `
	INSERT INTO leases (lease_id, secret_id, issued_to, expires_at, renewable)
	VALUES ($1, $2, $3, $4, $5)
	RETURNING lease_id, secret_id, issued_to, expires_at, renewable,
	          revoked, revoked_at, last_renewed_at, created_at`

const sqlGetLeaseByLeaseID = `
	SELECT lease_id, secret_id, issued_to, expires_at, renewable,
	       revoked, revoked_at, last_renewed_at, created_at
	FROM leases WHERE lease_id = $1`

const sqlRenewLease = `
	UPDATE leases SET expires_at=$2, last_renewed_at=NOW()
	WHERE lease_id=$1 AND revoked=FALSE
	RETURNING lease_id, secret_id, issued_to, expires_at, renewable,
	          revoked, revoked_at, last_renewed_at, created_at`

const sqlRevokeLease = `
	UPDATE leases SET revoked=TRUE, revoked_at=NOW() WHERE lease_id=$1`

func (db *DB) CreateLease(ctx context.Context, p vault.CreateLeaseParams) (vault.Lease, error) {
	return db.scanLease(db.pool.QueryRow(ctx, sqlCreateLease,
		p.LeaseID, p.SecretID, p.IssuedTo, p.ExpiresAt, p.Renewable,
	))
}

func (db *DB) GetLeaseByLeaseID(ctx context.Context, leaseID string) (vault.Lease, error) {
	return db.scanLease(db.pool.QueryRow(ctx, sqlGetLeaseByLeaseID, leaseID))
}

func (db *DB) RenewLease(ctx context.Context, leaseID string, newExpiry time.Time) (vault.Lease, error) {
	return db.scanLease(db.pool.QueryRow(ctx, sqlRenewLease, leaseID, newExpiry))
}

func (db *DB) RevokeLease(ctx context.Context, leaseID string) error {
	_, err := db.pool.Exec(ctx, sqlRevokeLease, leaseID)
	return err
}

func (db *DB) scanLease(r pgxScanner) (vault.Lease, error) {
	var l vault.Lease
	var secretID pgtype.UUID
	var revokedAt, lastRenewedAt pgtype.Timestamptz
	err := r.Scan(
		&l.LeaseID, &secretID, &l.IssuedTo, &l.ExpiresAt, &l.Renewable,
		&l.Revoked, &revokedAt, &lastRenewedAt, &l.CreatedAt,
	)
	if err != nil {
		return l, fmt.Errorf("scan lease: %w", err)
	}
	l.SecretID = uuidFromPgtype(secretID)
	if revokedAt.Valid {
		l.RevokedAt = &revokedAt.Time
	}
	return l, nil
}
