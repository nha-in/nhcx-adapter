package nhcx

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-jose/go-jose/v4"
)

// ErrNotCompactJWE is returned for a payload that is not a five-part token.
var ErrNotCompactJWE = errors.New("payload is not a compact JWE (expected five dot-separated parts)")

// Encrypt produces the compact JWE NHCX carries: RSA-OAEP-256 key wrap and
// A256GCM content encryption, with the x-hcx-* headers in the protected
// header. "alg", "enc" and "typ" are never taken from headers — the first
// two would misreport the algorithm, and NHCX validates the header against
// its schema, which admits only alg/enc and the x-hcx-* keys.
func Encrypt(payload []byte, pub *rsa.PublicKey, headers map[string]any) (string, error) {
	if pub == nil {
		return "", errors.New("no recipient public key")
	}
	if len(payload) == 0 {
		return "", errors.New("payload is empty")
	}
	opts := &jose.EncrypterOptions{}
	for k, v := range headers {
		switch k {
		case "alg", "enc", "typ":
			continue
		}
		opts.WithHeader(jose.HeaderKey(k), v)
	}
	enc, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: pub}, opts)
	if err != nil {
		return "", fmt.Errorf("create encrypter: %w", err)
	}
	obj, err := enc.Encrypt(payload)
	if err != nil {
		return "", fmt.Errorf("encrypt: %w", err)
	}
	return obj.CompactSerialize()
}

// Decrypt opens a compact JWE with this participant's private key. Only the
// RSA-OAEP family NHCX uses is accepted.
func Decrypt(compact string, priv *rsa.PrivateKey) ([]byte, error) {
	if priv == nil {
		return nil, errors.New("no private key")
	}
	if !IsCompactJWE(compact) {
		return nil, ErrNotCompactJWE
	}
	obj, err := jose.ParseEncrypted(compact,
		[]jose.KeyAlgorithm{jose.RSA_OAEP_256, jose.RSA_OAEP},
		[]jose.ContentEncryption{jose.A256GCM, jose.A128GCM, jose.A192GCM, jose.A256CBC_HS512, jose.A128CBC_HS256, jose.A192CBC_HS384})
	if err != nil {
		return nil, fmt.Errorf("parse JWE: %w", err)
	}
	plain, err := obj.Decrypt(priv)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plain, nil
}

// IsCompactJWE reports whether s has the five-part compact shape.
func IsCompactJWE(s string) bool {
	parts := strings.Split(strings.TrimSpace(s), ".")
	return len(parts) == 5 && parts[0] != ""
}

// ParseHeader decodes the protected header of a compact JWE without
// decrypting it, so the recipient code can be checked before any key is used.
func ParseHeader(compact string) (map[string]any, error) {
	if !IsCompactJWE(compact) {
		return nil, ErrNotCompactJWE
	}
	first := strings.Split(strings.TrimSpace(compact), ".")[0]
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(first, "="))
	if err != nil {
		return nil, fmt.Errorf("decode JWE header: %w", err)
	}
	var h map[string]any
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, fmt.Errorf("JWE header is not a JSON object: %w", err)
	}
	return h, nil
}
