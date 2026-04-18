package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Claims contains the additional custom claims beyond standard JWT fields.
type Claims map[string]any

// TokenIssuer handles JWT creation, validation, and refresh token bookkeeping.
type TokenIssuer struct {
	issuer  string
	keyRepo KeyRepository
	rtStore RefreshTokenStore
}

// KeyRepository provides the active signing key and public keyset.
type KeyRepository interface {
	ActiveKey(ctx context.Context) (*SigningKey, error)
	PublicKeySet(ctx context.Context) (jwk.Set, error)
}

// SigningKey is an in-memory representation of an RS256 key pair.
type SigningKey struct {
	KID        string
	PrivateKey *rsa.PrivateKey
	ExpiresAt  time.Time
}

// RefreshTokenStore persists hashed refresh tokens.
type RefreshTokenStore interface {
	CreateRefreshToken(ctx context.Context, p RefreshTokenParams) error
	GetRefreshTokenByHash(ctx context.Context, hash string) (RefreshTokenRow, error)
	RevokeRefreshToken(ctx context.Context, hash string) error
}

type RefreshTokenParams struct {
	TokenHash string
	ClientID  string
	UserID    *uuid.UUID
	Scope     string
	ExpiresAt time.Time
}

type RefreshTokenRow struct {
	ID        uuid.UUID
	TokenHash string
	ClientID  string
	UserID    *uuid.UUID
	Scope     string
	ExpiresAt time.Time
	Revoked   bool
}

// NewTokenIssuer creates a TokenIssuer.
func NewTokenIssuer(issuer string, keys KeyRepository, rt RefreshTokenStore) *TokenIssuer {
	return &TokenIssuer{issuer: issuer, keyRepo: keys, rtStore: rt}
}

// IssueAccessToken mints a signed RS256 JWT access token.
func (ti *TokenIssuer) IssueAccessToken(ctx context.Context, sub, clientID string, audience []string, scope string, ttl time.Duration, extra Claims) (string, error) {
	sk, err := ti.keyRepo.ActiveKey(ctx)
	if err != nil {
		return "", fmt.Errorf("get signing key: %w", err)
	}

	now := time.Now()
	jtiRaw := make([]byte, 16)
	_, _ = rand.Read(jtiRaw)

	tok, err := jwt.NewBuilder().
		Issuer(ti.issuer).
		Subject(sub).
		Audience(audience).
		IssuedAt(now).
		NotBefore(now).
		Expiration(now.Add(ttl)).
		JwtID(base64.RawURLEncoding.EncodeToString(jtiRaw)).
		Claim("client_id", clientID).
		Claim("scope", scope).
		Build()
	if err != nil {
		return "", fmt.Errorf("build token: %w", err)
	}

	for k, v := range extra {
		if err := tok.Set(k, v); err != nil {
			return "", fmt.Errorf("set claim %q: %w", k, err)
		}
	}

	privKey, err := jwk.FromRaw(sk.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("jwk from raw: %w", err)
	}
	if err := privKey.Set(jwk.KeyIDKey, sk.KID); err != nil {
		return "", err
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privKey))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return string(signed), nil
}

// IssueRefreshToken generates a random opaque refresh token and stores its hash.
func (ti *TokenIssuer) IssueRefreshToken(ctx context.Context, clientID string, userID *uuid.UUID, scope string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := hashToken(token)

	if err := ti.rtStore.CreateRefreshToken(ctx, RefreshTokenParams{
		TokenHash: hash,
		ClientID:  clientID,
		UserID:    userID,
		Scope:     scope,
		ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}
	return token, nil
}

// VerifyRefreshToken looks up and validates a refresh token by hash.
func (ti *TokenIssuer) VerifyRefreshToken(ctx context.Context, token string) (*RefreshTokenRow, error) {
	hash := hashToken(token)
	row, err := ti.rtStore.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found")
	}
	if row.Revoked {
		return nil, fmt.Errorf("refresh token has been revoked")
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, fmt.Errorf("refresh token has expired")
	}
	return &row, nil
}

// RevokeRefreshToken marks a refresh token as revoked.
func (ti *TokenIssuer) RevokeRefreshToken(ctx context.Context, token string) error {
	hash := hashToken(token)
	return ti.rtStore.RevokeRefreshToken(ctx, hash)
}

// ParseAndVerify validates a JWT against the provider's public JWKS.
func (ti *TokenIssuer) ParseAndVerify(ctx context.Context, tokenStr string) (jwt.Token, error) {
	keyset, err := ti.keyRepo.PublicKeySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("get keyset: %w", err)
	}
	tok, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(keyset),
		jwt.WithValidate(true),
		jwt.WithIssuer(ti.issuer),
	)
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return tok, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
