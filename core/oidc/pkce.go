package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// VerifyPKCE validates the code_verifier against the stored code_challenge.
// Only S256 is accepted; plain is rejected as insecure.
func VerifyPKCE(challenge, method, verifier string) error {
	switch method {
	case "S256":
		h := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])
		if subtle.ConstantTimeCompare([]byte(expected), []byte(challenge)) != 1 {
			return fmt.Errorf("pkce: code_verifier does not match challenge")
		}
	case "plain":
		return fmt.Errorf("pkce: method \"plain\" is not accepted; use S256")
	default:
		return fmt.Errorf("pkce: unsupported method %q", method)
	}
	return nil
}

// ValidateCodeChallenge ensures the challenge and method are well-formed.
// Only S256 is permitted.
func ValidateCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return fmt.Errorf("pkce: code_challenge is required")
	}
	if method == "" {
		method = "S256"
	}
	if method != "S256" {
		return fmt.Errorf("pkce: code_challenge_method must be S256, got %q", method)
	}
	if len(challenge) < 43 || len(challenge) > 128 {
		return fmt.Errorf("pkce: code_challenge length must be 43–128 chars")
	}
	return nil
}
