package crypto_go

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/pbkdf2"
)

// Base64Decode decodes a base64 string
func Base64Decode(input string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(input)
}

// Base64Encode encodes bytes to a base64 string
func Base64Encode(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}

// PBKDF2 generates a key from password using PBKDF2 with SHA-256
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

// SHA256 hashes input bytes
func SHA256Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(data)
	return Base64Encode(hash[:]), nil
}

// SHA512 hashes input bytes
func SHA512Base64(inputB64 string) (string, error) {
	data, err := Base64Decode(inputB64)
	if err != nil {
		return "", err
	}
	hash := sha512.Sum512(data)
	return Base64Encode(hash[:]), nil
}

// HMAC-SHA256 generates a keyed-hash
func HMACSHA256Base64(keyB64, messageB64 string) (string, error) {
	key, err := Base64Decode(keyB64)
	if err != nil {
		return "", err
	}
	message, err := Base64Decode(messageB64)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, err = mac.Write(message)
	if err != nil {
		return "", err
	}
	return Base64Encode(mac.Sum(nil)), nil
}

// Blake2b generates a Blake2b-256 hash
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

// Blake2b512 generates a Blake2b-512 hash
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

// Generic function wrapper: encode/decode in Base64
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
