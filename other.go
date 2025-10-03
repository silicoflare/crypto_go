package crypto_go

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"

	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
)

// Base64Decode decodes a base64 string
func Base64Decode(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}

// Base64Encode encodes bytes to a base64 string
func Base64Encode(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

// PBKDF2 with SHA-256
func PBKDF2Base64(passwordB64, saltB64 string, iter, keyLen int) (string, error) {
	password, err := Base64Decode(passwordB64)
	if err != nil {
		return "", err
	}
	salt, err := Base64Decode(saltB64)
	if err != nil {
		return "", err
	}
	key := pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
	return Base64Encode(key), nil
}

// Argon2id KDF
func Argon2idBase64(passwordB64, saltB64 string, memory, iterations, parallelism, keyLen uint32) (string, error) {
	password, err := Base64Decode(passwordB64)
	if err != nil {
		return "", err
	}
	salt, err := Base64Decode(saltB64)
	if err != nil {
		return "", err
	}
	key := argon2.IDKey(password, salt, iterations, memory, uint8(parallelism), keyLen)
	return Base64Encode(key), nil
}

// SHA256
func SHA256Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return Base64Encode(hash[:]), nil
}

// SHA512
func SHA512Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash := sha512.Sum512(data)
	return Base64Encode(hash[:]), nil
}

// SHA3-256
func SHA3_256Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash := sha3.Sum256(data)
	return Base64Encode(hash[:]), nil
}

// SHA3-512
func SHA3_512Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash := sha3.Sum512(data)
	return Base64Encode(hash[:]), nil
}

// HMAC-SHA256
func HMACSHA256Base64(keyB64, messageB64 string) (string, error) {
	return hmacBase64(keyB64, messageB64, sha256.New)
}

// HMAC-SHA512
func HMACSHA512Base64(keyB64, messageB64 string) (string, error) {
	return hmacBase64(keyB64, messageB64, sha512.New)
}

// Blake2b-256
func Blake2b256Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash, err := blake2b.New256(nil)
	if err != nil {
		return "", err
	}
	_, err = hash.Write(data)
	if err != nil {
		return "", err
	}
	return Base64Encode(hash.Sum(nil)), nil
}

// Blake2b-512
func Blake2b512Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash, err := blake2b.New512(nil)
	if err != nil {
		return "", err
	}
	_, err = hash.Write(data)
	if err != nil {
		return "", err
	}
	return Base64Encode(hash.Sum(nil)), nil
}

// HKDF (HMAC-based Key Derivation)
func HKDFBase64(hashFunc func() hash.Hash, secretB64, saltB64, infoB64 string, length int) (string, error) {
	secret, err := Base64Decode(secretB64)
	if err != nil {
		return "", err
	}
	salt, err := Base64Decode(saltB64)
	if err != nil {
		return "", err
	}
	info, err := Base64Decode(infoB64)
	if err != nil {
		return "", err
	}
	h := hkdf.New(hashFunc, secret, salt, info)
	okm := make([]byte, length)
	if _, err := io.ReadFull(h, okm); err != nil {
		return "", err
	}
	return Base64Encode(okm), nil
}

// Generic HMAC helper
func hmacBase64(keyB64, messageB64 string, fn func() hash.Hash) (string, error) {
	key, err := Base64Decode(keyB64)
	if err != nil {
		return "", err
	}
	message, err := Base64Decode(messageB64)
	if err != nil {
		return "", err
	}
	mac := hmac.New(fn, key)
	if _, err := mac.Write(message); err != nil {
		return "", err
	}
	return Base64Encode(mac.Sum(nil)), nil
}

// Generic wrapper
func ProcessBase64(inputB64 string, fn func([]byte) ([]byte, error)) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	result, err := fn(data)
	if err != nil {
		return "", err
	}
	return Base64Encode(result), nil
}

func RandomBase64String(length int) string {
	if length <= 0 {
		panic("length must be > 0")
	}
	// length*3/4 ensures enough bytes to encode into requested Base64 length
	raw := make([]byte, (length*3/4)+1)
	_, err := rand.Read(raw)
	if err != nil {
		panic(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw) // URL-safe Base64
	if len(encoded) > length {
		encoded = encoded[:length]
	}
	return encoded
}
