package vault

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func newTestEncryptor(t *testing.T) *Encryptor {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc, err := NewEncryptor(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatalf("NewEncryptor: %v", err)
	}
	return enc
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc := newTestEncryptor(t)
	plaintext := []byte("super secret value 🔐")

	ct, encDEK, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) == 0 || len(encDEK) == 0 {
		t.Fatal("expected non-empty ciphertext and encDEK")
	}

	got, err := enc.Decrypt(ct, encDEK)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	enc := newTestEncryptor(t)
	pt := []byte("same plaintext")

	ct1, encDEK1, _ := enc.Encrypt(pt)
	ct2, encDEK2, _ := enc.Encrypt(pt)

	// Nonces must differ
	if string(ct1) == string(ct2) {
		t.Error("two encryptions of the same plaintext should differ (nonce randomness)")
	}
	if string(encDEK1) == string(encDEK2) {
		t.Error("two DEKs should differ")
	}

	// Both should still decrypt correctly
	got1, err := enc.Decrypt(ct1, encDEK1)
	if err != nil || string(got1) != string(pt) {
		t.Errorf("decrypt ct1 failed: %v, %q", err, got1)
	}
	got2, err := enc.Decrypt(ct2, encDEK2)
	if err != nil || string(got2) != string(pt) {
		t.Errorf("decrypt ct2 failed: %v, %q", err, got2)
	}
}

func TestDecryptWithWrongKey(t *testing.T) {
	enc1 := newTestEncryptor(t)
	enc2 := newTestEncryptor(t)

	ct, encDEK, err := enc1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = enc2.Decrypt(ct, encDEK)
	if err == nil {
		t.Error("expected decryption failure with wrong root key")
	}
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	enc := newTestEncryptor(t)
	ct, encDEK, _ := enc.Encrypt([]byte("value"))

	ct[len(ct)-1] ^= 0xFF // flip last byte

	_, err := enc.Decrypt(ct, encDEK)
	if err == nil {
		t.Error("expected decryption failure with tampered ciphertext")
	}
}

func TestNewEncryptorBadKey(t *testing.T) {
	_, err := NewEncryptor("not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid base64")
	}

	shortKey := base64.StdEncoding.EncodeToString([]byte("tooshort"))
	_, err = NewEncryptor(shortKey)
	if err == nil {
		t.Error("expected error for key shorter than 32 bytes")
	}
}
