package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Encryptor performs envelope encryption: a per-secret data key (DEK) is
// encrypted under the root key (KEK).  Only the encrypted DEK and ciphertext
// are stored; the plaintext DEK never touches disk.
type Encryptor struct {
	rootKey [32]byte
}

// NewEncryptor parses a base64-encoded 32-byte root key from the environment.
func NewEncryptor(rootKeyB64 string) (*Encryptor, error) {
	raw, err := base64.StdEncoding.DecodeString(rootKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode root key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("root key must be 32 bytes, got %d", len(raw))
	}
	e := &Encryptor{}
	copy(e.rootKey[:], raw)
	return e, nil
}

// Encrypt seals plaintext using a freshly generated DEK, then wraps the DEK
// under the root key.  Returns (ciphertext, encryptedDEK, error).
func (e *Encryptor) Encrypt(plaintext []byte) ([]byte, []byte, error) {
	dek, err := generateKey()
	if err != nil {
		return nil, nil, fmt.Errorf("generate dek: %w", err)
	}

	ct, err := sealAES(dek[:], plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("seal plaintext: %w", err)
	}

	encDEK, err := sealAES(e.rootKey[:], dek[:])
	if err != nil {
		return nil, nil, fmt.Errorf("wrap dek: %w", err)
	}

	return ct, encDEK, nil
}

// Decrypt unwraps the DEK under the root key, then opens the ciphertext.
func (e *Encryptor) Decrypt(ciphertext, encDEK []byte) ([]byte, error) {
	dek, err := openAES(e.rootKey[:], encDEK)
	if err != nil {
		return nil, fmt.Errorf("unwrap dek: %w", err)
	}

	pt, err := openAES(dek, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("open ciphertext: %w", err)
	}
	return pt, nil
}

// sealAES encrypts plaintext with AES-256-GCM.
// Output layout: [12-byte nonce][ciphertext+tag].
func sealAES(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return ct, nil
}

// openAES decrypts data produced by sealAES.
func openAES(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, data[:ns], data[ns:], nil)
}

func generateKey() ([32]byte, error) {
	var k [32]byte
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return k, err
	}
	return k, nil
}
