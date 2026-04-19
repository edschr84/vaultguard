package api

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/vaultguard/core/identity"
	"github.com/vaultguard/core/oidc"
	"github.com/vaultguard/core/vault"
	"github.com/vaultguard/server/middleware"
)

type vaultTestKeyRepo struct {
	key *rsa.PrivateKey
	kid string
}

func newVaultTestKeyRepo(t *testing.T) *vaultTestKeyRepo {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &vaultTestKeyRepo{key: key, kid: uuid.NewString()}
}

func (r *vaultTestKeyRepo) ActiveKey(_ context.Context) (*oidc.SigningKey, error) {
	return &oidc.SigningKey{KID: r.kid, PrivateKey: r.key, ExpiresAt: time.Now().Add(time.Hour)}, nil
}

func (r *vaultTestKeyRepo) PublicKeySet(_ context.Context) (jwk.Set, error) {
	pub, err := jwk.FromRaw(r.key.Public())
	if err != nil {
		return nil, err
	}
	_ = pub.Set(jwk.KeyIDKey, r.kid)
	_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
	_ = pub.Set(jwk.KeyUsageKey, jwk.ForSignature)
	set := jwk.NewSet()
	_ = set.AddKey(pub)
	return set, nil
}

type vaultTestRTStore struct{}

func (vaultTestRTStore) CreateRefreshToken(context.Context, oidc.RefreshTokenParams) error {
	return nil
}
func (vaultTestRTStore) GetRefreshTokenByHash(context.Context, string) (oidc.RefreshTokenRow, error) {
	return oidc.RefreshTokenRow{}, errors.New("not found")
}
func (vaultTestRTStore) RevokeRefreshToken(context.Context, string) error { return nil }

type vaultTestSecretStore struct {
	raw       vault.RawSecret
	getCalled bool
}

func (s *vaultTestSecretStore) CreateVaultSecret(context.Context, vault.CreateSecretParams) (vault.RawSecret, error) {
	return vault.RawSecret{}, errors.New("not implemented")
}
func (s *vaultTestSecretStore) GetVaultSecretLatest(context.Context, string, string, string) (vault.RawSecret, error) {
	s.getCalled = true
	return s.raw, nil
}
func (s *vaultTestSecretStore) GetVaultSecretByVersion(context.Context, string, string, string, int32) (vault.RawSecret, error) {
	s.getCalled = true
	return s.raw, nil
}
func (s *vaultTestSecretStore) ListVaultSecretVersions(context.Context, string, string, string) ([]vault.SecretVersionInfo, error) {
	return nil, nil
}
func (s *vaultTestSecretStore) ListVaultSecretPaths(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func (s *vaultTestSecretStore) SoftDeleteVaultSecret(context.Context, string, string, string) error {
	return nil
}
func (s *vaultTestSecretStore) GetVaultSecretByID(context.Context, uuid.UUID) (vault.RawSecret, error) {
	return vault.RawSecret{}, errors.New("not found")
}

type vaultTestPolicyStore struct {
	bindings map[string][]identity.PolicyBindingRow
}

func (s *vaultTestPolicyStore) CreatePolicy(context.Context, identity.CreatePolicyParams) (identity.PolicyRow, error) {
	return identity.PolicyRow{}, errors.New("not implemented")
}
func (s *vaultTestPolicyStore) GetPolicyByName(context.Context, string) (identity.PolicyRow, error) {
	return identity.PolicyRow{}, errors.New("not implemented")
}
func (s *vaultTestPolicyStore) GetPolicyByID(context.Context, uuid.UUID) (identity.PolicyRow, error) {
	return identity.PolicyRow{}, errors.New("not implemented")
}
func (s *vaultTestPolicyStore) UpdatePolicy(context.Context, identity.UpdatePolicyParams) (identity.PolicyRow, error) {
	return identity.PolicyRow{}, errors.New("not implemented")
}
func (s *vaultTestPolicyStore) DeletePolicy(context.Context, uuid.UUID) error { return nil }
func (s *vaultTestPolicyStore) ListPolicies(context.Context, int32, int32) ([]identity.PolicyRow, error) {
	return nil, nil
}
func (s *vaultTestPolicyStore) CreatePolicyBinding(context.Context, identity.PolicyBindingParams) (identity.PolicyBindingRow, error) {
	return identity.PolicyBindingRow{}, errors.New("not implemented")
}
func (s *vaultTestPolicyStore) ListPolicyBindingsForSubject(_ context.Context, subjectType, subjectID string) ([]identity.PolicyBindingRow, error) {
	return s.bindings[subjectType+":"+subjectID], nil
}
func (s *vaultTestPolicyStore) DeletePolicyBinding(context.Context, uuid.UUID, string, string) error {
	return nil
}

func TestVaultReadDeniedWithoutMatchingPolicy(t *testing.T) {
	store := &vaultTestSecretStore{}
	handler, issuer := newVaultHandlerForTest(t, store, map[string][]identity.PolicyBindingRow{}, nil)
	token := issueVaultTestToken(t, issuer, uuid.NewString(), "vaultguard-cli")

	req := httptest.NewRequest(http.MethodGet, "/v1/local/app/db", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want %d", rec.Code, http.StatusForbidden)
	}
	if store.getCalled {
		t.Fatal("secret store should not be called when policy denies access")
	}
}

func TestVaultReadAllowedWithMatchingUserPolicy(t *testing.T) {
	enc, err := vault.NewEncryptor(base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := json.Marshal(vault.SecretData{"username": "robot"})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, encDEK, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	userID := uuid.NewString()
	store := &vaultTestSecretStore{
		raw: vault.RawSecret{
			ID:         uuid.New(),
			Namespace:  "local",
			Mount:      "app",
			Path:       "db",
			Version:    1,
			Ciphertext: ciphertext,
			DataKeyEnc: encDEK,
			CreatedAt:  time.Now(),
		},
	}
	rules, err := json.Marshal([]identity.Rule{{
		Effect:    "allow",
		Actions:   []string{"secret.read"},
		Resources: []string{"local/app/*"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	handler, issuer := newVaultHandlerForTest(t, store, map[string][]identity.PolicyBindingRow{
		"user:" + userID: {{Rules: rules}},
	}, enc)
	token := issueVaultTestToken(t, issuer, userID, "vaultguard-cli")

	req := httptest.NewRequest(http.MethodGet, "/v1/local/app/db", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status: got %d want %d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !store.getCalled {
		t.Fatal("secret store should be called when policy allows access")
	}
}

func newVaultHandlerForTest(t *testing.T, secretStore *vaultTestSecretStore, bindings map[string][]identity.PolicyBindingRow, encryptor *vault.Encryptor) (http.Handler, *oidc.TokenIssuer) {
	t.Helper()
	keyRepo := newVaultTestKeyRepo(t)
	issuer := oidc.NewTokenIssuer("https://vaultguard.test", keyRepo, vaultTestRTStore{})
	policySvc := identity.NewPolicyService(&vaultTestPolicyStore{bindings: bindings})
	enc := encryptor
	if enc == nil {
		var err error
		enc, err = vault.NewEncryptor(base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")))
		if err != nil {
			t.Fatal(err)
		}
	}
	vaultStore := vault.NewStore(secretStore, enc, nil, nil)

	r := chi.NewRouter()
	r.Use(middleware.BearerAuth(issuer))
	NewVaultHandler(vaultStore, nil, policySvc).Routes(r)
	return r, issuer
}

func issueVaultTestToken(t *testing.T, issuer *oidc.TokenIssuer, subject, clientID string) string {
	t.Helper()
	token, err := issuer.IssueAccessToken(context.Background(), subject, clientID, []string{clientID}, "vault:read vault:write", 15*time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
