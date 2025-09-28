package crypto_go

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// RSA struct manages RSA operations.
type RSA struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewRSA creates a new RSA instance.
// If a PEM private key is provided, it loads it, otherwise generates a new 2048-bit key.
func NewRSA(privateKeyPEM string) (*RSA, error) {
	r := &RSA{}

	if privateKeyPEM != "" {
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, errors.New("invalid PEM block for RSA private key")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		r.privateKey = key
		r.publicKey = &key.PublicKey
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		r.privateKey = key
		r.publicKey = &key.PublicKey
	}

	return r, nil
}

// EncryptString encrypts a plaintext string and returns a Base64 ciphertext string.
func (r *RSA) EncryptString(plainText string) (string, error) {
	if r.publicKey == nil {
		return "", errors.New("public key is not set")
	}
	cipherBytes, err := rsa.EncryptPKCS1v15(rand.Reader, r.publicKey, []byte(plainText))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(cipherBytes), nil
}

// DecryptString decrypts a Base64 ciphertext string and returns the plaintext.
func (r *RSA) DecryptString(cipherText string) (string, error) {
	if r.privateKey == nil {
		return "", errors.New("private key is not set")
	}
	cipherBytes, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return "", err
	}
	plainBytes, err := rsa.DecryptPKCS1v15(rand.Reader, r.privateKey, cipherBytes)
	if err != nil {
		return "", err
	}
	return string(plainBytes), nil
}

// ExportPrivateKeyPEM returns the PEM-encoded private key as string.
func (r *RSA) ExportPrivateKeyPEM() string {
	privBytes := x509.MarshalPKCS1PrivateKey(r.privateKey)
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	})
	return string(privPEM)
}

// ExportPublicKeyPEM returns the PEM-encoded public key as string.
func (r *RSA) ExportPublicKeyPEM() (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(r.publicKey)
	if err != nil {
		return "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return string(pubPEM), nil
}
