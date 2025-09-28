package crypto_go

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

// ECDH handles ECDH operations with string inputs/outputs.
type ECDH struct {
	privateKey *big.Int
	publicX    *big.Int
	publicY    *big.Int
	curve      elliptic.Curve
}

// NewECDH creates a new ECDH instance.
// If privKeyBase64 is empty, a random key is generated.
func NewECDH(privKeyBase64 string) (*ECDH, error) {
	curve := elliptic.P256()
	var priv *big.Int
	var x, y *big.Int
	var err error

	if privKeyBase64 != "" {
		privBytes, err := base64.StdEncoding.DecodeString(privKeyBase64)
		if err != nil {
			return nil, err
		}
		priv = new(big.Int).SetBytes(privBytes)
		x, y = curve.ScalarBaseMult(priv.Bytes())
	} else {
		priv, x, y, err = generateKey(curve)
		if err != nil {
			return nil, err
		}
	}

	return &ECDH{
		privateKey: priv,
		publicX:    x,
		publicY:    y,
		curve:      curve,
	}, nil
}

func generateKey(curve elliptic.Curve) (*big.Int, *big.Int, *big.Int, error) {
	privBytes, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	priv := new(big.Int).SetBytes(privBytes)
	return priv, x, y, nil
}

// PublicKey returns the base64-encoded concatenated public key "X||Y".
func (e *ECDH) PublicKey() string {
	xBytes := e.publicX.Bytes()
	yBytes := e.publicY.Bytes()

	// pad to ensure fixed length for decoding
	keyLen := (e.curve.Params().BitSize + 7) / 8
	xPadded := leftPad(xBytes, keyLen)
	yPadded := leftPad(yBytes, keyLen)

	return base64.StdEncoding.EncodeToString(append(xPadded, yPadded...))
}

// SharedSecret computes a base64-encoded shared secret given a remote public key.
func (e *ECDH) SharedSecret(remotePub string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(remotePub)
	if err != nil {
		return "", err
	}

	keyLen := (e.curve.Params().BitSize + 7) / 8
	if len(data) != 2*keyLen {
		return "", errors.New("invalid public key length")
	}

	x := new(big.Int).SetBytes(data[:keyLen])
	y := new(big.Int).SetBytes(data[keyLen:])

	if !e.curve.IsOnCurve(x, y) {
		return "", errors.New("public key is not on curve")
	}

	secretX, _ := e.curve.ScalarMult(x, y, e.privateKey.Bytes())
	hash := sha256.Sum256(secretX.Bytes())
	return base64.StdEncoding.EncodeToString(hash[:]), nil
}

// PrivateKey returns the base64-encoded private key.
func (e *ECDH) PrivateKey() string {
	return base64.StdEncoding.EncodeToString(e.privateKey.Bytes())
}

// leftPad ensures byte slices are fixed length
func leftPad(b []byte, length int) []byte {
	if len(b) >= length {
		return b
	}
	padded := make([]byte, length)
	copy(padded[length-len(b):], b)
	return padded
}
