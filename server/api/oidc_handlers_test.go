package api_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/vaultguard/core/oidc"
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
	verifier := strings.Repeat("a", 43) // min-length verifier for plain
	challenge := verifier

	if err := oidc.VerifyPKCE(challenge, "plain", verifier); err != nil {
		t.Fatalf("plain PKCE: %v", err)
	}
}

