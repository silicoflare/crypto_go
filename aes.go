package crypto_go

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
)

// AES is the exported struct to handle AES operations.
type AES struct {
	key []byte
}

// NewAES creates a new AES.
// If password is empty, a random key of 32 bytes (AES-256) is generated.
func NewAES(password string) *AES {
	var key []byte
	if password == "" {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic("failed to generate random key")
		}
	} else {
		hash := sha256.Sum256([]byte(password))
		key = hash[:]
	}
	return &AES{key: key}
}

// Encrypt encrypts the given plaintext using AES-GCM and returns a base64 string.
func (a *AES) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, 12) // AES-GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	ciphertext := aesgcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts a base64-encoded ciphertext using AES-GCM.
func (a *AES) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	if len(data) < 12 {
		return "", errors.New("ciphertext too short")
	}

	nonce := data[:12]
	ciphertextData := data[12:]

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return "", err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// Key returns the AES key in hex format (for storage or inspection).
func (a *AES) Key() []byte {
	return a.key
}
