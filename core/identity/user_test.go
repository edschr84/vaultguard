package identity

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	pw := "correct-horse-battery-staple"

	hash, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	if !verifyPassword(pw, hash) {
		t.Error("verifyPassword should return true for correct password")
	}
	if verifyPassword("wrong-password", hash) {
		t.Error("verifyPassword should return false for wrong password")
	}
}

func TestHashPasswordUniqueness(t *testing.T) {
	pw := "same-password"
	h1, _ := hashPassword(pw)
	h2, _ := hashPassword(pw)
	if h1 == h2 {
		t.Error("two hashes of the same password should differ (random salt)")
	}
	// Both should verify correctly
	if !verifyPassword(pw, h1) || !verifyPassword(pw, h2) {
		t.Error("both hashes should verify against original password")
	}
}
