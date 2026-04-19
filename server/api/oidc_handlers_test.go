package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/vaultguard/core/identity"
	"github.com/vaultguard/core/oidc"
	api "github.com/vaultguard/server/api"
)

// ── Fakes ──────────────────────────────────────────────────────────────────

type fakeKeyRepo struct {
	key *rsa.PrivateKey
	kid string
}

func newFakeKeyRepo(t *testing.T) *fakeKeyRepo {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeKeyRepo{key: k, kid: uuid.New().String()}
}

func (f *fakeKeyRepo) ActiveKey(_ context.Context) (*oidc.SigningKey, error) {
	return &oidc.SigningKey{KID: f.kid, PrivateKey: f.key, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (f *fakeKeyRepo) PublicKeySet(_ context.Context) (jwk.Set, error) {
	pub, _ := jwk.FromRaw(f.key.Public())
	_ = pub.Set(jwk.KeyIDKey, f.kid)
	_ = pub.Set(jwk.AlgorithmKey, "RS256")
	_ = pub.Set(jwk.KeyUsageKey, jwk.ForSignature)
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	return set, nil
}

type fakeRTStore struct{}

func (fakeRTStore) CreateRefreshToken(_ context.Context, _ oidc.RefreshTokenParams) error {
	return nil
}
func (fakeRTStore) GetRefreshTokenByHash(_ context.Context, _ string) (oidc.RefreshTokenRow, error) {
	return oidc.RefreshTokenRow{}, nil
}
func (fakeRTStore) RevokeRefreshToken(_ context.Context, _ string) error { return nil }

type fakeClientStore struct {
	byClientID map[string]identity.ClientRow
}

func (f *fakeClientStore) CreateOAuthClient(_ context.Context, p identity.CreateClientParams) (identity.ClientRow, error) {
	return identity.ClientRow{}, nil
}
func (f *fakeClientStore) GetOAuthClientByClientID(_ context.Context, clientID string) (identity.ClientRow, error) {
	row, ok := f.byClientID[clientID]
	if !ok {
		return identity.ClientRow{}, errors.New("not found")
	}
	return row, nil
}
func (f *fakeClientStore) GetOAuthClientByID(_ context.Context, _ uuid.UUID) (identity.ClientRow, error) {
	return identity.ClientRow{}, errors.New("not found")
}
func (f *fakeClientStore) UpdateOAuthClient(_ context.Context, _ identity.UpdateClientParams) (identity.ClientRow, error) {
	return identity.ClientRow{}, errors.New("not implemented")
}
func (f *fakeClientStore) DeleteOAuthClient(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeClientStore) ListOAuthClients(_ context.Context, _, _ int32) ([]identity.ClientRow, error) {
	return nil, nil
}

type fakeUserStore struct {
	byEmail map[string]identity.UserRow
}

func (f *fakeUserStore) CreateUser(_ context.Context, p identity.CreateUserParams) (identity.UserRow, error) {
	if f.byEmail == nil {
		f.byEmail = make(map[string]identity.UserRow)
	}
	row := identity.UserRow{
		ID:           uuid.New(),
		Username:     p.Username,
		Email:        p.Email,
		PasswordHash: p.Password,
		DisplayName:  p.DisplayName,
		Enabled:      true,
	}
	f.byEmail[p.Email] = row
	return row, nil
}
func (f *fakeUserStore) GetUserByID(_ context.Context, id uuid.UUID) (identity.UserRow, error) {
	for _, row := range f.byEmail {
		if row.ID == id {
			return row, nil
		}
	}
	return identity.UserRow{}, errors.New("not found")
}
func (f *fakeUserStore) GetUserByEmail(_ context.Context, email string) (identity.UserRow, error) {
	row, ok := f.byEmail[email]
	if !ok {
		return identity.UserRow{}, errors.New("not found")
	}
	return row, nil
}
func (f *fakeUserStore) GetUserByUsername(_ context.Context, username string) (identity.UserRow, error) {
	for _, row := range f.byEmail {
		if row.Username == username {
			return row, nil
		}
	}
	return identity.UserRow{}, errors.New("not found")
}
func (f *fakeUserStore) UpdateUser(_ context.Context, _ identity.UpdateUserParams) (identity.UserRow, error) {
	return identity.UserRow{}, errors.New("not implemented")
}
func (f *fakeUserStore) UpdateUserPassword(_ context.Context, _ uuid.UUID, _ string) error {
	return nil
}
func (f *fakeUserStore) DeleteUser(_ context.Context, _ uuid.UUID) error { return nil }
func (f *fakeUserStore) ListUsers(_ context.Context, _, _ int32) ([]identity.UserRow, error) {
	return nil, nil
}

type fakeCodeStore struct{}

func (fakeCodeStore) CreateAuthorizationCode(_ context.Context, p oidc.AuthCodeParams) (oidc.AuthCodeRow, error) {
	return oidc.AuthCodeRow{Code: p.Code}, nil
}
func (fakeCodeStore) GetAuthorizationCode(_ context.Context, _ string) (oidc.AuthCodeRow, error) {
	return oidc.AuthCodeRow{}, errors.New("not found")
}
func (fakeCodeStore) MarkAuthorizationCodeUsed(_ context.Context, _ string) error { return nil }

type fakeDeviceStore struct {
	approveCalled bool
	denyCalled    bool
}

func (f *fakeDeviceStore) CreateDeviceCode(_ context.Context, _ oidc.DeviceCodeParams) (oidc.DeviceCodeRow, error) {
	return oidc.DeviceCodeRow{}, nil
}
func (f *fakeDeviceStore) GetDeviceCodeByDeviceCode(_ context.Context, _ string) (oidc.DeviceCodeRow, error) {
	return oidc.DeviceCodeRow{}, errors.New("not found")
}
func (f *fakeDeviceStore) GetDeviceCodeByUserCode(_ context.Context, _ string) (oidc.DeviceCodeRow, error) {
	return oidc.DeviceCodeRow{}, errors.New("not found")
}
func (f *fakeDeviceStore) ApproveDeviceCode(_ context.Context, _ string, _ uuid.UUID) error {
	f.approveCalled = true
	return nil
}
func (f *fakeDeviceStore) DenyDeviceCode(_ context.Context, _ string) error {
	f.denyCalled = true
	return nil
}

func newTestOIDCHandler(t *testing.T, clientRows map[string]identity.ClientRow, userRows map[string]identity.UserRow, devices oidc.DeviceCodeStore) *api.OIDCHandler {
	t.Helper()
	keys := newFakeKeyRepo(t)
	rt := fakeRTStore{}
	issuer := oidc.NewTokenIssuer("https://test.example.com", keys, rt)
	return api.NewOIDCHandler(
		nil,
		nil,
		issuer,
		identity.NewUserService(&fakeUserStore{byEmail: userRows}),
		identity.NewClientService(&fakeClientStore{byClientID: clientRows}),
		devices,
		nil,
		"https://test.example.com",
	)
}

// ── Tests ──────────────────────────────────────────────────────────────────

func TestDiscoveryDocument(t *testing.T) {
	issuerURL := "https://test.example.com"

	r := chi.NewRouter()
	r.Get("/.well-known/openid-configuration", func(w http.ResponseWriter, req *http.Request) {
		doc := oidc.BuildDiscovery(issuerURL)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	})

	srv := httptest.NewServer(r)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var doc oidc.DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery doc: %v", err)
	}

	if doc.Issuer != issuerURL {
		t.Errorf("issuer: got %q, want %q", doc.Issuer, issuerURL)
	}
	if !strings.HasSuffix(doc.TokenEndpoint, "/token") {
		t.Errorf("token endpoint: got %q", doc.TokenEndpoint)
	}
	if !strings.HasSuffix(doc.JwksURI, "/jwks.json") {
		t.Errorf("jwks uri: got %q", doc.JwksURI)
	}
}

func TestTokenIssueAndVerify(t *testing.T) {
	keys := newFakeKeyRepo(t)
	rt := fakeRTStore{}
	issuer := oidc.NewTokenIssuer("https://test.example.com", keys, rt)

	at, err := issuer.IssueAccessToken(context.Background(),
		"user-123", "client-abc", []string{"client-abc"},
		"openid profile", 15*time.Minute, nil)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if at == "" {
		t.Fatal("expected non-empty access token")
	}

	// Parse manually to verify structure
	privJWK, _ := jwk.FromRaw(keys.key)
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.RS256)
	set := jwk.NewSet()
	pub, _ := jwk.FromRaw(keys.key.Public())
	_ = pub.Set(jwk.KeyIDKey, keys.kid)
	_ = pub.Set(jwk.AlgorithmKey, "RS256")
	_ = set.AddKey(pub)

	tok, err := jwt.Parse([]byte(at), jwt.WithKeySet(set), jwt.WithValidate(true))
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	if tok.Subject() != "user-123" {
		t.Errorf("sub: got %q, want %q", tok.Subject(), "user-123")
	}
	if tok.Issuer() != "https://test.example.com" {
		t.Errorf("iss: got %q", tok.Issuer())
	}

	scope, _ := tok.Get("scope")
	if fmt.Sprint(scope) != "openid profile" {
		t.Errorf("scope: got %q", scope)
	}
}

func TestPKCERoundTrip(t *testing.T) {
	verifier := strings.Repeat("a", 43)
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if err := oidc.VerifyPKCE(challenge, "S256", verifier); err != nil {
		t.Fatalf("S256 PKCE: %v", err)
	}
}

func TestConfidentialClientRequiresSecret(t *testing.T) {
	handler := newTestOIDCHandler(t, map[string]identity.ClientRow{
		"confidential-client": {
			ID:              uuid.New(),
			ClientID:        "confidential-client",
			Name:            "confidential-client",
			ClientType:      string(identity.ClientTypeConfidential),
			AllowedScopes:   []string{"openid"},
			AccessTokenTTL:  900,
			RefreshTokenTTL: 3600,
		},
	}, nil, &fakeDeviceStore{})

	r := chi.NewRouter()
	r.Post("/token", handler.Token)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", "confidential-client")
	form.Set("code", "abc")
	form.Set("redirect_uri", "https://client.example/callback")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadRequest)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "invalid_client" {
		t.Fatalf("error: got %q want %q", body["error"], "invalid_client")
	}
}

func TestRedirectURINotRegistered(t *testing.T) {
	handler := newTestOIDCHandler(t, map[string]identity.ClientRow{
		"client-1": {
			ID:           uuid.New(),
			ClientID:     "client-1",
			Name:         "client-1",
			ClientType:   string(identity.ClientTypePublic),
			RedirectURIs: []string{"https://client.example/callback"},
		},
	}, nil, &fakeDeviceStore{})

	r := chi.NewRouter()
	r.Get("/authorize", handler.Authorize)

	req := httptest.NewRequest(http.MethodGet,
		"/authorize?client_id=client-1&redirect_uri=https://evil.example/callback&response_type=code",
		nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadRequest)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "invalid_request" {
		t.Fatalf("error: got %q want %q", body["error"], "invalid_request")
	}
}

func TestDeviceCSRFRejected(t *testing.T) {
	pwHash, err := identityHashForTest("secret-password")
	if err != nil {
		t.Fatal(err)
	}
	devices := &fakeDeviceStore{}
	handler := newTestOIDCHandler(t, nil, map[string]identity.UserRow{
		"user@example.com": {
			ID:           uuid.New(),
			Username:     "user",
			Email:        "user@example.com",
			PasswordHash: pwHash,
			Enabled:      true,
		},
	}, devices)

	r := chi.NewRouter()
	r.Post("/device", handler.DeviceVerifySubmit)

	form := url.Values{}
	form.Set("csrf_token", "form-token")
	form.Set("user_code", "ABC-123")
	form.Set("action", "approve")
	form.Set("email", "user@example.com")
	form.Set("password", "secret-password")

	req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadRequest)
	}
	if devices.approveCalled || devices.denyCalled {
		t.Fatal("device action should not be reached on CSRF failure")
	}
}

func TestScopeEscalationClientCredentials(t *testing.T) {
	clientSecret := "top-secret"
	secretHash, err := identityHashForTest(clientSecret)
	if err != nil {
		t.Fatal(err)
	}
	handler := newTestOIDCHandler(t, map[string]identity.ClientRow{
		"client-cc": {
			ID:               uuid.New(),
			ClientID:         "client-cc",
			ClientSecretHash: &secretHash,
			Name:             "client-cc",
			ClientType:       string(identity.ClientTypeConfidential),
			AllowedScopes:    []string{"vault:read"},
			AllowedGrants:    []string{string(identity.GrantClientCredentials)},
			AccessTokenTTL:   900,
			RefreshTokenTTL:  3600,
		},
	}, nil, &fakeDeviceStore{})

	r := chi.NewRouter()
	r.Post("/token", handler.Token)

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", "client-cc")
	form.Set("client_secret", clientSecret)
	form.Set("scope", "vault:read vault:write")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusBadRequest)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["error"] != "invalid_scope" {
		t.Fatalf("error: got %q want %q", body["error"], "invalid_scope")
	}
}

func identityHashForTest(password string) (string, error) {
	userStore := &fakeUserStore{}
	userSvc := identity.NewUserService(userStore)
	row, err := userSvc.Create(context.Background(), identity.CreateUserParams{
		Username: "seed",
		Email:    "seed@example.com",
		Password: password,
	})
	if err != nil {
		return "", err
	}
	seedRow, err := userStore.GetUserByID(context.Background(), row.ID)
	if err != nil {
		return "", err
	}
	return seedRow.PasswordHash, nil
}
