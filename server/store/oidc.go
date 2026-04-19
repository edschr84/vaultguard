package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vaultguard/core/oidc"
)

// ─── Authorization codes ────────────────────────────────────────────────────

const sqlCreateAuthCode = `
	INSERT INTO authorization_codes
	    (code, client_id, user_id, redirect_uri, scope,
	     nonce, code_challenge, code_challenge_method, expires_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	RETURNING id, code, client_id, user_id, redirect_uri, scope,
	          nonce, code_challenge, code_challenge_method,
	          expires_at, used, created_at`

const sqlGetAuthCode = `
	SELECT id, code, client_id, user_id, redirect_uri, scope,
	       nonce, code_challenge, code_challenge_method,
	       expires_at, used, created_at
	FROM authorization_codes WHERE code = $1`

const sqlMarkAuthCodeUsed = `UPDATE authorization_codes SET used = TRUE WHERE code = $1`

func (db *DB) CreateAuthorizationCode(ctx context.Context, p oidc.AuthCodeParams) (oidc.AuthCodeRow, error) {
	return db.scanAuthCode(db.pool.QueryRow(ctx, sqlCreateAuthCode,
		p.Code, p.ClientID, p.UserID, p.RedirectURI, p.Scope,
		nullText(strPtr(p.Nonce)), nullText(strPtr(p.CodeChallenge)), nullText(strPtr(p.CodeChallengeMethod)),
		p.ExpiresAt,
	))
}

func (db *DB) GetAuthorizationCode(ctx context.Context, code string) (oidc.AuthCodeRow, error) {
	return db.scanAuthCode(db.pool.QueryRow(ctx, sqlGetAuthCode, code))
}

func (db *DB) MarkAuthorizationCodeUsed(ctx context.Context, code string) error {
	_, err := db.pool.Exec(ctx, sqlMarkAuthCodeUsed, code)
	return err
}

func (db *DB) scanAuthCode(r pgxScanner) (oidc.AuthCodeRow, error) {
	var row oidc.AuthCodeRow
	var id, userID pgtype.UUID
	var nonce, challenge, challengeMethod pgtype.Text
	err := r.Scan(
		&id, &row.Code, &row.ClientID, &userID, &row.RedirectURI, &row.Scope,
		&nonce, &challenge, &challengeMethod,
		&row.ExpiresAt, &row.Used, &row.CreatedAt,
	)
	if err != nil {
		return row, fmt.Errorf("scan auth code: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	row.UserID = uuidFromPgtype(userID)
	if nonce.Valid {
		row.Nonce = &nonce.String
	}
	if challenge.Valid {
		row.CodeChallenge = &challenge.String
	}
	if challengeMethod.Valid {
		row.CodeChallengeMethod = &challengeMethod.String
	}
	return row, nil
}

// ─── Refresh tokens ─────────────────────────────────────────────────────────

const sqlCreateRefreshToken = `
	INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, expires_at)
	VALUES ($1, $2, $3, $4, $5)
	RETURNING id, token_hash, client_id, user_id, scope, expires_at, revoked, created_at`

const sqlGetRefreshTokenByHash = `
	SELECT id, token_hash, client_id, user_id, scope, expires_at, revoked, created_at
	FROM refresh_tokens WHERE token_hash = $1`

const sqlRevokeRefreshToken = `
	UPDATE refresh_tokens SET revoked = TRUE, revoked_at = NOW() WHERE token_hash = $1`

func (db *DB) CreateRefreshToken(ctx context.Context, p oidc.RefreshTokenParams) error {
	_, err := db.pool.Exec(ctx, sqlCreateRefreshToken,
		p.TokenHash, p.ClientID, nullUUID(p.UserID), p.Scope, p.ExpiresAt,
	)
	return err
}

func (db *DB) GetRefreshTokenByHash(ctx context.Context, hash string) (oidc.RefreshTokenRow, error) {
	var row oidc.RefreshTokenRow
	var id, userID pgtype.UUID
	var createdAt time.Time
	err := db.pool.QueryRow(ctx, sqlGetRefreshTokenByHash, hash).Scan(
		&id, &row.TokenHash, &row.ClientID, &userID, &row.Scope,
		&row.ExpiresAt, &row.Revoked, &createdAt,
	)
	if err != nil {
		return row, fmt.Errorf("scan refresh token: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	row.UserID = uuidPtrFromPgtype(userID)
	return row, nil
}

func (db *DB) RevokeRefreshToken(ctx context.Context, hash string) error {
	_, err := db.pool.Exec(ctx, sqlRevokeRefreshToken, hash)
	return err
}

// ─── Device codes ────────────────────────────────────────────────────────────

const sqlCreateDeviceCode = `
	INSERT INTO device_codes
	    (device_code, user_code, client_id, scope,
	     verification_uri, expires_at, interval_secs)
	VALUES ($1, $2, $3, $4, $5, $6, $7)
	RETURNING id, device_code, user_code, client_id, scope,
	          verification_uri, expires_at, interval_secs,
	          user_id, denied, created_at`

const sqlGetDeviceCodeByDC = `
	SELECT id, device_code, user_code, client_id, scope,
	       verification_uri, expires_at, interval_secs,
	       user_id, denied, created_at
	FROM device_codes WHERE device_code = $1`

const sqlGetDeviceCodeByUC = `
	SELECT id, device_code, user_code, client_id, scope,
	       verification_uri, expires_at, interval_secs,
	       user_id, denied, created_at
	FROM device_codes WHERE user_code = $1`

const sqlApproveDeviceCode = `UPDATE device_codes SET user_id = $2 WHERE user_code = $1`
const sqlDenyDeviceCode = `UPDATE device_codes SET denied = TRUE WHERE user_code = $1`

func (db *DB) CreateDeviceCode(ctx context.Context, p oidc.DeviceCodeParams) (oidc.DeviceCodeRow, error) {
	return db.scanDeviceCode(db.pool.QueryRow(ctx, sqlCreateDeviceCode,
		p.DeviceCode, p.UserCode, p.ClientID, p.Scope,
		p.VerificationURI, p.ExpiresAt, p.IntervalSecs,
	))
}

func (db *DB) GetDeviceCodeByDeviceCode(ctx context.Context, dc string) (oidc.DeviceCodeRow, error) {
	return db.scanDeviceCode(db.pool.QueryRow(ctx, sqlGetDeviceCodeByDC, dc))
}

func (db *DB) GetDeviceCodeByUserCode(ctx context.Context, uc string) (oidc.DeviceCodeRow, error) {
	return db.scanDeviceCode(db.pool.QueryRow(ctx, sqlGetDeviceCodeByUC, uc))
}

func (db *DB) ApproveDeviceCode(ctx context.Context, userCode string, userID uuid.UUID) error {
	_, err := db.pool.Exec(ctx, sqlApproveDeviceCode, userCode, userID)
	return err
}

func (db *DB) DenyDeviceCode(ctx context.Context, userCode string) error {
	_, err := db.pool.Exec(ctx, sqlDenyDeviceCode, userCode)
	return err
}

func (db *DB) scanDeviceCode(r pgxScanner) (oidc.DeviceCodeRow, error) {
	var row oidc.DeviceCodeRow
	var id, userID pgtype.UUID
	err := r.Scan(
		&id, &row.DeviceCode, &row.UserCode, &row.ClientID, &row.Scope,
		&row.VerificationURI, &row.ExpiresAt, &row.IntervalSecs,
		&userID, &row.Denied, &row.CreatedAt,
	)
	if err != nil {
		return row, fmt.Errorf("scan device code: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	row.UserID = uuidPtrFromPgtype(userID)
	return row, nil
}

// ─── Signing keys ────────────────────────────────────────────────────────────

const sqlCreateSigningKey = `
	INSERT INTO signing_keys (kid, algorithm, private_key_enc, public_key_pem, expires_at)
	VALUES ($1, 'RS256', $2, $3, $4)`

const sqlGetActiveSigningKey = `
	SELECT id, kid, private_key_enc, public_key_pem, active, created_at, expires_at
	FROM signing_keys WHERE active = TRUE ORDER BY created_at DESC LIMIT 1`

const sqlListVerifiableSigningKeys = `
	SELECT id, kid, private_key_enc, public_key_pem, active, created_at, expires_at
	FROM signing_keys
	WHERE active = TRUE
	   OR (rotated_at IS NOT NULL AND rotated_at > NOW() - INTERVAL '2 hours')
	ORDER BY created_at DESC`

const sqlDeactivateSigningKey = `
	UPDATE signing_keys SET active = FALSE, rotated_at = NOW() WHERE kid = $1`

const sqlPruneSigningKeys = `
	DELETE FROM signing_keys
	WHERE active = FALSE AND rotated_at < NOW() - INTERVAL '2 hours'`

func (db *DB) CreateSigningKey(ctx context.Context, p oidc.SigningKeyParams) error {
	_, err := db.pool.Exec(ctx, sqlCreateSigningKey,
		p.KID, p.PrivateKeyEnc, p.PublicKeyPEM, p.ExpiresAt,
	)
	return err
}

func (db *DB) GetActiveSigningKey(ctx context.Context) (oidc.SigningKeyRow, error) {
	return db.scanSigningKey(db.pool.QueryRow(ctx, sqlGetActiveSigningKey))
}

func (db *DB) ListVerifiableSigningKeys(ctx context.Context) ([]oidc.SigningKeyRow, error) {
	rows, err := db.pool.Query(ctx, sqlListVerifiableSigningKeys)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []oidc.SigningKeyRow
	for rows.Next() {
		r, err := db.scanSigningKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (db *DB) DeactivateSigningKey(ctx context.Context, kid string) error {
	_, err := db.pool.Exec(ctx, sqlDeactivateSigningKey, kid)
	return err
}

// PruneSigningKeys deletes deactivated signing keys whose 2-hour overlap window has elapsed.
func (db *DB) PruneSigningKeys(ctx context.Context) error {
	_, err := db.pool.Exec(ctx, sqlPruneSigningKeys)
	return err
}

func (db *DB) scanSigningKey(r pgxScanner) (oidc.SigningKeyRow, error) {
	var row oidc.SigningKeyRow
	var id pgtype.UUID
	err := r.Scan(&id, &row.KID, &row.PrivateKeyEnc, &row.PublicKeyPEM, &row.Active, &row.CreatedAt, &row.ExpiresAt)
	if err != nil {
		return row, fmt.Errorf("scan signing key: %w", err)
	}
	row.ID = uuidFromPgtype(id)
	return row, nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
