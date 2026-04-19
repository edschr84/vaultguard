package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// AuthorizationRequest holds parsed parameters from the /authorize endpoint.
type AuthorizationRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// AuthorizationCodeStore persists authorization codes.
type AuthorizationCodeStore interface {
	CreateAuthorizationCode(ctx context.Context, p AuthCodeParams) (AuthCodeRow, error)
	GetAuthorizationCode(ctx context.Context, code string) (AuthCodeRow, error)
	MarkAuthorizationCodeUsed(ctx context.Context, code string) error
}

type AuthCodeParams struct {
	Code                string
	ClientID            string
	UserID              uuid.UUID
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type AuthCodeRow struct {
	ID                  uuid.UUID
	Code                string
	ClientID            string
	UserID              uuid.UUID
	RedirectURI         string
	Scope               string
	Nonce               *string
	CodeChallenge       *string
	CodeChallengeMethod *string
	ExpiresAt           time.Time
	Used                bool
	CreatedAt           time.Time
}

// DeviceCodeStore persists device authorization codes.
type DeviceCodeStore interface {
	CreateDeviceCode(ctx context.Context, p DeviceCodeParams) (DeviceCodeRow, error)
	GetDeviceCodeByDeviceCode(ctx context.Context, dc string) (DeviceCodeRow, error)
	GetDeviceCodeByUserCode(ctx context.Context, uc string) (DeviceCodeRow, error)
	ApproveDeviceCode(ctx context.Context, userCode string, userID uuid.UUID) error
	DenyDeviceCode(ctx context.Context, userCode string) error
}

type DeviceCodeParams struct {
	DeviceCode      string
	UserCode        string
	ClientID        string
	Scope           string
	VerificationURI string
	ExpiresAt       time.Time
	IntervalSecs    int32
}

type DeviceCodeRow struct {
	ID              uuid.UUID
	DeviceCode      string
	UserCode        string
	ClientID        string
	Scope           string
	VerificationURI string
	ExpiresAt       time.Time
	IntervalSecs    int32
	UserID          *uuid.UUID
	Denied          bool
	CreatedAt       time.Time
}

// SigningKeyStore persists RS256 signing keys.
type SigningKeyStore interface {
	CreateSigningKey(ctx context.Context, p SigningKeyParams) error
	GetActiveSigningKey(ctx context.Context) (SigningKeyRow, error)
	ListVerifiableSigningKeys(ctx context.Context) ([]SigningKeyRow, error)
	DeactivateSigningKey(ctx context.Context, kid string) error
}

type SigningKeyParams struct {
	KID           string
	PrivateKeyEnc []byte
	PublicKeyPEM  string
	ExpiresAt     time.Time
}

type SigningKeyRow struct {
	ID            uuid.UUID
	KID           string
	PrivateKeyEnc []byte
	PublicKeyPEM  string
	Active        bool
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// KeyManager manages signing key lifecycle including rotation.
type KeyManager struct {
	mu         sync.RWMutex
	store      SigningKeyStore
	enc        KeyEncryptor
	activeKey  *SigningKey
	rotateEvery time.Duration
}

// KeyEncryptor encrypts/decrypts private key bytes for storage.
type KeyEncryptor interface {
	Encrypt(plaintext []byte) (ct, encDEK []byte, err error)
	Decrypt(ct, encDEK []byte) ([]byte, error)
}

// NewKeyManager creates and initialises a KeyManager.
func NewKeyManager(store SigningKeyStore, enc KeyEncryptor, rotateEvery time.Duration) (*KeyManager, error) {
	if rotateEvery == 0 {
		rotateEvery = 24 * time.Hour
	}
	km := &KeyManager{store: store, enc: enc, rotateEvery: rotateEvery}
	return km, nil
}

// Bootstrap ensures at least one active signing key exists, rotating if needed.
func (km *KeyManager) Bootstrap(ctx context.Context) error {
	row, err := km.store.GetActiveSigningKey(ctx)
	if err != nil || time.Now().After(row.ExpiresAt) {
		return km.Rotate(ctx)
	}
	sk, err := km.decryptKey(row)
	if err != nil {
		return fmt.Errorf("decrypt active key: %w", err)
	}
	km.mu.Lock()
	km.activeKey = sk
	km.mu.Unlock()
	slog.Info("signing key loaded", "kid", sk.KID)
	return nil
}

// Rotate generates a new RS256 key pair and deactivates the old one.
func (km *KeyManager) Rotate(ctx context.Context) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate rsa key: %w", err)
	}

	kid := uuid.New().String()
	expiresAt := time.Now().Add(km.rotateEvery + 2*time.Hour) // overlap window

	// Encode private key as PKCS#8 DER via jwk
	jwkKey, err := jwk.FromRaw(privKey)
	if err != nil {
		return fmt.Errorf("jwk from raw: %w", err)
	}
	privPEM, err := jwk.EncodePEM(jwkKey)
	if err != nil {
		return fmt.Errorf("encode pem: %w", err)
	}

	ct, encDEK, err := km.enc.Encrypt(privPEM)
	if err != nil {
		return fmt.Errorf("encrypt key: %w", err)
	}
	// Store as base64(ct) + "." + base64(encDEK); base64 chars never include "."
	encBlob := []byte(base64.RawURLEncoding.EncodeToString(ct) + "." + base64.RawURLEncoding.EncodeToString(encDEK))

	pubKey := privKey.Public()
	pubJWK, err := jwk.FromRaw(pubKey)
	if err != nil {
		return fmt.Errorf("pub jwk: %w", err)
	}
	pubPEM, err := jwk.EncodePEM(pubJWK)
	if err != nil {
		return fmt.Errorf("encode pub pem: %w", err)
	}

	// Deactivate old key
	old, err := km.store.GetActiveSigningKey(ctx)
	if err == nil {
		_ = km.store.DeactivateSigningKey(ctx, old.KID)
	}

	if err := km.store.CreateSigningKey(ctx, SigningKeyParams{
		KID:           kid,
		PrivateKeyEnc: encBlob,
		PublicKeyPEM:  string(pubPEM),
		ExpiresAt:     expiresAt,
	}); err != nil {
		return fmt.Errorf("store signing key: %w", err)
	}

	km.mu.Lock()
	km.activeKey = &SigningKey{KID: kid, PrivateKey: privKey, ExpiresAt: expiresAt}
	km.mu.Unlock()
	slog.Info("signing key rotated", "kid", kid)
	return nil
}

// ActiveKey returns the current signing key.
func (km *KeyManager) ActiveKey(_ context.Context) (*SigningKey, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	if km.activeKey == nil {
		return nil, fmt.Errorf("no active signing key")
	}
	return km.activeKey, nil
}

// PublicKeySet builds the JWKS from all verifiable keys in the store.
func (km *KeyManager) PublicKeySet(ctx context.Context) (jwk.Set, error) {
	rows, err := km.store.ListVerifiableSigningKeys(ctx)
	if err != nil {
		return nil, err
	}

	set := jwk.NewSet()
	for _, row := range rows {
		pubJWK, err := jwk.ParseKey([]byte(row.PublicKeyPEM), jwk.WithPEM(true))
		if err != nil {
			continue
		}
		_ = pubJWK.Set(jwk.KeyIDKey, row.KID)
		_ = pubJWK.Set(jwk.AlgorithmKey, "RS256")
		_ = pubJWK.Set(jwk.KeyUsageKey, jwk.ForSignature)
		_ = set.AddKey(pubJWK)
	}
	return set, nil
}

// decryptKey reconstructs a SigningKey from a SigningKeyRow.
func (km *KeyManager) decryptKey(row SigningKeyRow) (*SigningKey, error) {
	parts := strings.SplitN(string(row.PrivateKeyEnc), ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid encrypted key blob")
	}
	ct, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode ct: %w", err)
	}
	encDEK, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode dek: %w", err)
	}

	privPEM, err := km.enc.Decrypt(ct, encDEK)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	privJWK, err := jwk.ParseKey(privPEM, jwk.WithPEM(true))
	if err != nil {
		return nil, fmt.Errorf("parse pem: %w", err)
	}
	var privKey rsa.PrivateKey
	if err := privJWK.Raw(&privKey); err != nil {
		return nil, fmt.Errorf("extract rsa key: %w", err)
	}
	return &SigningKey{KID: row.KID, PrivateKey: &privKey, ExpiresAt: row.ExpiresAt}, nil
}

// Provider is the top-level OIDC authorization server.
type Provider struct {
	issuerURL  string
	keys       *KeyManager
	issuer     *TokenIssuer
	codes      AuthorizationCodeStore
	devices    DeviceCodeStore
	verifyURI  string
}

// NewProvider creates an OIDC Provider.
func NewProvider(
	issuerURL string,
	keys *KeyManager,
	rt RefreshTokenStore,
	codes AuthorizationCodeStore,
	devices DeviceCodeStore,
) *Provider {
	p := &Provider{
		issuerURL: issuerURL,
		keys:      keys,
		codes:     codes,
		devices:   devices,
		verifyURI: issuerURL + "/device",
	}
	p.issuer = NewTokenIssuer(issuerURL, keys, rt)
	return p
}

// Authorize validates an authorization request and issues a code.
func (p *Provider) Authorize(ctx context.Context, req AuthorizationRequest, userID uuid.UUID) (code, state string, err error) {
	if req.ResponseType != "code" {
		return "", "", fmt.Errorf("unsupported response_type: %q", req.ResponseType)
	}
	if req.ClientID == "" || req.RedirectURI == "" {
		return "", "", fmt.Errorf("client_id and redirect_uri are required")
	}

	rawCode := make([]byte, 32)
	if _, err := rand.Read(rawCode); err != nil {
		return "", "", err
	}
	codeStr := base64.RawURLEncoding.EncodeToString(rawCode)

	row, err := p.codes.CreateAuthorizationCode(ctx, AuthCodeParams{
		Code:                codeStr,
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		return "", "", fmt.Errorf("create auth code: %w", err)
	}
	return row.Code, req.State, nil
}

// ExchangeCode trades an authorization code for tokens.
func (p *Provider) ExchangeCode(ctx context.Context, code, redirectURI, verifier string, clientTTLs ClientTTLs) (*TokenResponse, error) {
	row, err := p.codes.GetAuthorizationCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("invalid code")
	}
	if row.Used {
		return nil, fmt.Errorf("code already used")
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, fmt.Errorf("code expired")
	}
	if row.RedirectURI != redirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch")
	}

	// PKCE check
	if row.CodeChallenge != nil && *row.CodeChallenge != "" {
		method := "S256"
		if row.CodeChallengeMethod != nil {
			method = *row.CodeChallengeMethod
		}
		if err := VerifyPKCE(*row.CodeChallenge, method, verifier); err != nil {
			return nil, err
		}
	}

	if err := p.codes.MarkAuthorizationCodeUsed(ctx, code); err != nil {
		return nil, fmt.Errorf("mark code used: %w", err)
	}

	sub := row.UserID.String()
	accessTTL := time.Duration(clientTTLs.AccessTokenTTL) * time.Second
	refreshTTL := time.Duration(clientTTLs.RefreshTokenTTL) * time.Second

	at, err := p.issuer.IssueAccessToken(ctx, sub, row.ClientID, []string{row.ClientID}, row.Scope, accessTTL, nil)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	uid := row.UserID
	rt, err := p.issuer.IssueRefreshToken(ctx, row.ClientID, &uid, row.Scope, refreshTTL)
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}

	idToken, err := p.issueIDToken(ctx, sub, row.ClientID, row.Scope, row.Nonce, accessTTL)
	if err != nil {
		return nil, fmt.Errorf("issue id token: %w", err)
	}

	return &TokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int(clientTTLs.AccessTokenTTL),
		RefreshToken: rt,
		IDToken:      idToken,
		Scope:        row.Scope,
	}, nil
}

// ClientTTLs carries per-client token lifetime configuration.
type ClientTTLs struct {
	AccessTokenTTL  int32
	RefreshTokenTTL int32
}

// TokenResponse is the standard /token endpoint response body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// InitiateDeviceFlow starts a device authorization request.
func (p *Provider) InitiateDeviceFlow(ctx context.Context, clientID, scope string) (*DeviceAuthResponse, error) {
	deviceRaw := make([]byte, 32)
	_, _ = rand.Read(deviceRaw)
	deviceCode := base64.RawURLEncoding.EncodeToString(deviceRaw)

	userCode := generateUserCode()

	row, err := p.devices.CreateDeviceCode(ctx, DeviceCodeParams{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		ClientID:        clientID,
		Scope:           scope,
		VerificationURI: p.verifyURI,
		ExpiresAt:       time.Now().Add(10 * time.Minute),
		IntervalSecs:    5,
	})
	if err != nil {
		return nil, fmt.Errorf("create device code: %w", err)
	}

	return &DeviceAuthResponse{
		DeviceCode:      row.DeviceCode,
		UserCode:        row.UserCode,
		VerificationURI: row.VerificationURI,
		ExpiresIn:       600,
		Interval:        int(row.IntervalSecs),
	}, nil
}

// DeviceAuthResponse is returned by /device/code.
type DeviceAuthResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// PollDeviceToken checks device code status and issues tokens when approved.
func (p *Provider) PollDeviceToken(ctx context.Context, deviceCode string, clientTTLs ClientTTLs) (*TokenResponse, error) {
	row, err := p.devices.GetDeviceCodeByDeviceCode(ctx, deviceCode)
	if err != nil {
		return nil, fmt.Errorf("invalid_client")
	}
	if time.Now().After(row.ExpiresAt) {
		return nil, fmt.Errorf("expired_token")
	}
	if row.Denied {
		return nil, fmt.Errorf("access_denied")
	}
	if row.UserID == nil {
		return nil, fmt.Errorf("authorization_pending")
	}

	uid := *row.UserID
	sub := uid.String()
	accessTTL := time.Duration(clientTTLs.AccessTokenTTL) * time.Second
	refreshTTL := time.Duration(clientTTLs.RefreshTokenTTL) * time.Second

	at, err := p.issuer.IssueAccessToken(ctx, sub, row.ClientID, []string{row.ClientID}, row.Scope, accessTTL, nil)
	if err != nil {
		return nil, err
	}
	rt, err := p.issuer.IssueRefreshToken(ctx, row.ClientID, &uid, row.Scope, refreshTTL)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  at,
		TokenType:    "Bearer",
		ExpiresIn:    int(clientTTLs.AccessTokenTTL),
		RefreshToken: rt,
		Scope:        row.Scope,
	}, nil
}

func (p *Provider) issueIDToken(ctx context.Context, sub, clientID, scope string, nonce *string, ttl time.Duration) (string, error) {
	extra := Claims{"nonce": ""}
	if nonce != nil {
		extra["nonce"] = *nonce
	}
	return p.issuer.IssueAccessToken(ctx, sub, clientID, []string{clientID}, scope, ttl, extra)
}

// generateUserCode produces a human-readable 8-character device user code.
func generateUserCode() string {
	const charset = "BCDFGHJKLMNPQRSTVWXZ"
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	result := make([]byte, 9)
	for i := 0; i < 4; i++ {
		result[i] = charset[int(b[i])%len(charset)]
	}
	result[4] = '-'
	for i := 0; i < 4; i++ {
		result[5+i] = charset[int(b[4+i])%len(charset)]
	}
	return string(result)
}
