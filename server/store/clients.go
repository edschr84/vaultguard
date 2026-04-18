package store

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vaultguard/core/identity"
)

const (
	sqlCreateClient = `
		INSERT INTO oauth_clients
		    (client_id, client_secret_hash, name, client_type,
		     redirect_uris, allowed_scopes, allowed_grants,
		     access_token_ttl, refresh_token_ttl, metadata)
		VALUES ($1, $2, $3, $4::client_type,
		        $5, $6, $7::text[]::grant_type[],
		        $8, $9, '{}'::jsonb)
		RETURNING
		    id, client_id, client_secret_hash, name, client_type::text,
		    array_to_json(redirect_uris)::text,
		    array_to_json(allowed_scopes)::text,
		    array_to_json(allowed_grants::text[])::text,
		    access_token_ttl, refresh_token_ttl, enabled, metadata, created_at, updated_at`

	sqlGetClientByClientID = `
		SELECT id, client_id, client_secret_hash, name, client_type::text,
		       array_to_json(redirect_uris)::text,
		       array_to_json(allowed_scopes)::text,
		       array_to_json(allowed_grants::text[])::text,
		       access_token_ttl, refresh_token_ttl, enabled, metadata, created_at, updated_at
		FROM oauth_clients WHERE client_id = $1`

	sqlGetClientByID = `
		SELECT id, client_id, client_secret_hash, name, client_type::text,
		       array_to_json(redirect_uris)::text,
		       array_to_json(allowed_scopes)::text,
		       array_to_json(allowed_grants::text[])::text,
		       access_token_ttl, refresh_token_ttl, enabled, metadata, created_at, updated_at
		FROM oauth_clients WHERE id = $1`

	sqlListClients = `
		SELECT id, client_id, client_secret_hash, name, client_type::text,
		       array_to_json(redirect_uris)::text,
		       array_to_json(allowed_scopes)::text,
		       array_to_json(allowed_grants::text[])::text,
		       access_token_ttl, refresh_token_ttl, enabled, metadata, created_at, updated_at
		FROM oauth_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2`

	sqlDeleteClient = `DELETE FROM oauth_clients WHERE id = $1`
)

func (db *DB) CreateOAuthClient(ctx context.Context, p identity.CreateClientParams) (identity.ClientRow, error) {
	grants := make([]string, len(p.AllowedGrants))
	for i, g := range p.AllowedGrants {
		grants[i] = string(g)
	}
	return db.scanClient(db.pool.QueryRow(ctx, sqlCreateClient,
		p.ClientID,
		nullText(p.ClientSecretHash),
		p.Name,
		string(p.Type),
		toTextArray(p.RedirectURIs),
		toTextArray(p.AllowedScopes),
		toTextArray(grants),
		p.AccessTokenTTL,
		p.RefreshTokenTTL,
	))
}

func (db *DB) GetOAuthClientByClientID(ctx context.Context, clientID string) (identity.ClientRow, error) {
	return db.scanClient(db.pool.QueryRow(ctx, sqlGetClientByClientID, clientID))
}

func (db *DB) GetOAuthClientByID(ctx context.Context, id uuid.UUID) (identity.ClientRow, error) {
	return db.scanClient(db.pool.QueryRow(ctx, sqlGetClientByID, id))
}

func (db *DB) ListOAuthClients(ctx context.Context, limit, offset int32) ([]identity.ClientRow, error) {
	rows, err := db.pool.Query(ctx, sqlListClients, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []identity.ClientRow
	for rows.Next() {
		r, err := db.scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) UpdateOAuthClient(ctx context.Context, p identity.UpdateClientParams) (identity.ClientRow, error) {
	// Build dynamic update — for simplicity, do a full replace of provided fields.
	row, err := db.GetOAuthClientByID(ctx, p.ID)
	if err != nil {
		return row, err
	}
	if p.Name != nil {
		row.Name = *p.Name
	}
	if p.RedirectURIs != nil {
		row.RedirectURIs = *p.RedirectURIs
	}
	if p.AllowedScopes != nil {
		row.AllowedScopes = *p.AllowedScopes
	}
	if p.AccessTokenTTL != nil {
		row.AccessTokenTTL = *p.AccessTokenTTL
	}
	if p.RefreshTokenTTL != nil {
		row.RefreshTokenTTL = *p.RefreshTokenTTL
	}
	if p.Enabled != nil {
		row.Enabled = *p.Enabled
	}

	grants := row.AllowedGrants
	if p.AllowedGrants != nil {
		grants = make([]string, len(*p.AllowedGrants))
		for i, g := range *p.AllowedGrants {
			grants[i] = string(g)
		}
	}

	const q = `UPDATE oauth_clients
		SET name=$2, redirect_uris=$3, allowed_scopes=$4, allowed_grants=$5::text[]::grant_type[],
		    access_token_ttl=$6, refresh_token_ttl=$7, enabled=$8
		WHERE id=$1
		RETURNING id, client_id, client_secret_hash, name, client_type::text,
		          array_to_json(redirect_uris)::text,
		          array_to_json(allowed_scopes)::text,
		          array_to_json(allowed_grants::text[])::text,
		          access_token_ttl, refresh_token_ttl, enabled, metadata, created_at, updated_at`
	return db.scanClient(db.pool.QueryRow(ctx, q,
		p.ID, row.Name,
		toTextArray(row.RedirectURIs), toTextArray(row.AllowedScopes), toTextArray(grants),
		row.AccessTokenTTL, row.RefreshTokenTTL, row.Enabled,
	))
}

func (db *DB) DeleteOAuthClient(ctx context.Context, id uuid.UUID) error {
	_, err := db.pool.Exec(ctx, sqlDeleteClient, id)
	return err
}

func (db *DB) scanClient(r pgxScanner) (identity.ClientRow, error) {
	var row identity.ClientRow
	var id pgtype.UUID
	var secretHash pgtype.Text
	var metadata []byte
	var redirectURIsJSON, scopesJSON, grantsJSON string

	err := r.Scan(
		&id, &row.ClientID, &secretHash, &row.Name, &row.ClientType,
		&redirectURIsJSON, &scopesJSON, &grantsJSON,
		&row.AccessTokenTTL, &row.RefreshTokenTTL, &row.Enabled,
		&metadata, &row.CreatedAt, &row.UpdatedAt,
	)
	if err != nil {
		return row, fmt.Errorf("scan client: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	if secretHash.Valid {
		row.ClientSecretHash = &secretHash.String
	}
	row.RedirectURIs = unmarshalStringSlice(redirectURIsJSON)
	row.AllowedScopes = unmarshalStringSlice(scopesJSON)
	row.AllowedGrants = unmarshalStringSlice(grantsJSON)
	row.Metadata = metadata
	return row, nil
}
