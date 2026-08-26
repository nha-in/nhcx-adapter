// Package keys parses the RSA material the gateway works with: its own
// private key from the config, and the recipients' public certificates the
// participant registry hands out.
package keys

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Decode accepts key material either as plain PEM or base64-encoded PEM
// (the spelling the ABDM registry and hcxkit configs use) and returns PEM.
func Decode(material string) string {
	material = strings.TrimSpace(material)
	if strings.Contains(material, "-----BEGIN") {
		return material
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(material); err == nil && strings.Contains(string(b), "-----BEGIN") {
			return string(b)
		}
	}
	return material
}

// ParsePrivateKey reads an RSA private key in PKCS#8 or PKCS#1 PEM form.
func ParsePrivateKey(material string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(Decode(material)))
	if block == nil {
		return nil, errors.New("no PEM block found in private key material")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not an RSA key")
		}
		return rsaKey, nil
	}
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("private key is neither PKCS#8 nor PKCS#1: %w", err)
	}
	return rsaKey, nil
}

// ParsePublicKey reads an RSA public key out of an X.509 certificate, a
// PKIX "PUBLIC KEY" block, or a PKCS#1 "RSA PUBLIC KEY" block. Only the
// first PEM block is considered, so a certificate chain yields the leaf.
func ParsePublicKey(material string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(Decode(material)))
	if block == nil {
		return nil, errors.New("no PEM block found in certificate material")
	}
	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse public key: %w", err)
		}
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("public key is not an RSA key")
		}
		return rsaKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	rsaKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("certificate public key is not an RSA key")
	}
	return rsaKey, nil
}
