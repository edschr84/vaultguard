package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyPKCES256(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if err := VerifyPKCE(challenge, "S256", verifier); err != nil {
		t.Errorf("valid S256: %v", err)
	}
}

func TestVerifyPKCEPlainRejected(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if err := VerifyPKCE(verifier, "plain", verifier); err == nil {
		t.Error("expected plain PKCE to be rejected")
	}
}

func TestVerifyPKCEWrongVerifier(t *testing.T) {
	h := sha256.Sum256([]byte("correct"))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])

	if err := VerifyPKCE(challenge, "S256", "wrong"); err == nil {
		t.Error("expected failure for wrong verifier")
	}
}

func TestVerifyPKCEUnknownMethod(t *testing.T) {
	if err := VerifyPKCE("challenge", "rs256", "verifier"); err == nil {
		t.Error("expected failure for unknown method")
	}
}

func TestValidateCodeChallenge(t *testing.T) {
	validChallenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // 43 chars

	if err := ValidateCodeChallenge(validChallenge, "S256"); err != nil {
		t.Errorf("valid S256 challenge: %v", err)
	}
	if err := ValidateCodeChallenge("", "S256"); err == nil {
		t.Error("expected error for empty challenge")
	}
	if err := ValidateCodeChallenge("short", "S256"); err == nil {
		t.Error("expected error for short challenge")
	}
	if err := ValidateCodeChallenge(validChallenge, "plain"); err == nil {
		t.Error("expected error for plain method")
	}
}
