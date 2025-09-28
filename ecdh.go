package crypto_go

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// ECDH handles ECDH operations with string inputs/outputs.
type ECDH struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
	curve      ecdh.Curve
}

// NewECDH creates a new ECDH instance.
// If privKeyBase64 is empty, a random key is generated.
func NewECDH(privKeyBase64 string) (*ECDH, error) {
	curve := ecdh.P256()

	var priv *ecdh.PrivateKey
	var pub *ecdh.PublicKey
	var err error

	if privKeyBase64 != "" {
		privBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
		if err != nil {
			return nil, err
		}
		priv, err = curve.NewPrivateKey(privBytes)
		if err != nil {
			return nil, err
		}
		pub = priv.PublicKey()
	} else {
		priv, err = curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		pub = priv.PublicKey()
	}

	return &ECDH{
		privateKey: priv,
		publicKey:  pub,
		curve:      curve,
	}, nil
}

// PublicKey returns the base64-encoded raw public key bytes.
func (e *ECDH) PublicKey() string {
	return base64.StdEncoding.EncodeToString(e.publicKey.Bytes())
}

// SharedSecret computes a base64-encoded shared secret given a remote public key.
func (e *ECDH) SharedSecret(remotePub string) (string, error) {
	remoteBytes, err := base64.StdEncoding.DecodeString(remotePub)
	if err != nil {
		return "", err
	}

	remoteKey, err := e.curve.NewPublicKey(remoteBytes)
	if err != nil {
		return "", errors.New("invalid remote public key")
	}

	secret, err := e.privateKey.ECDH(remoteKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(secret)
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// PrivateKey returns the base64-encoded private key.
func (e *ECDH) PrivateKey() string {
	return base64.StdEncoding.EncodeToString(e.privateKey.Bytes())
}

// Encrypt encrypts a message using an ephemeral keypair and the recipient's public key.
// Returns base64(ephemeralPub || ciphertext).
func (e *ECDH) Encrypt(remotePub string, message string) (string, error) {
	remoteBytes, err := base64.StdEncoding.DecodeString(remotePub)
	if err != nil {
		return "", err
	}

	remoteKey, err := e.curve.NewPublicKey(remoteBytes)
	if err != nil {
		return "", errors.New("invalid remote public key")
	}

	// Generate ephemeral key
	ephemeralPriv, err := e.curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	ephemeralPub := ephemeralPriv.PublicKey().Bytes()

	// Derive shared secret
	secret, err := ephemeralPriv.ECDH(remoteKey)
	if err != nil {
		return "", err
	}

	// Hash to AES key
	key := sha256.Sum256(secret)
	aes := NewAES(string(key[:])) // use your AES struct

	// Encrypt with AES
	ct, err := aes.Encrypt(message)
	if err != nil {
		return "", err
	}

	// Bundle ephemeral pubkey + AES ciphertext
	final := append(ephemeralPub, []byte(ct)...)
	return base64.StdEncoding.EncodeToString(final), nil
}

// Decrypt decrypts a message encrypted with Encrypt().
func (e *ECDH) Decrypt(ciphertextB64 string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}

	pubLen := len(e.publicKey.Bytes())
	if len(data) <= pubLen {
		return "", errors.New("invalid ciphertext length")
	}

	ephemeralPubBytes := data[:pubLen]
	ciphertextPart := string(data[pubLen:]) // stored as string (AES ciphertext b64)

	ephemeralKey, err := e.curve.NewPublicKey(ephemeralPubBytes)
	if err != nil {
		return "", errors.New("invalid ephemeral public key")
	}

	// Derive shared secret
	secret, err := e.privateKey.ECDH(ephemeralKey)
	if err != nil {
		return "", err
	}

	// Hash to AES key
	key := sha256.Sum256(secret)
	aes := NewAES(string(key[:]))

	// Decrypt using AES
	plaintext, err := aes.Decrypt(ciphertextPart)
	if err != nil {
		return "", err
	}

	return plaintext, nil
}
