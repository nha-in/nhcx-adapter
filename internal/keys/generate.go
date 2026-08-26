package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Bounds on what Generate accepts: RSA generation cost grows steeply with
// key size, and NHCX registries expect 2048-bit keys.
const (
	MinKeyBits      = 2048
	MaxKeyBits      = 4096
	MaxValidityDays = 3650
)

// Subject describes the certificate to generate.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	State              string
	Locality           string
	Email              string
	ValidityDays       int // default 365
	KeyBits            int // default 2048
}

// Material is a freshly generated key pair with its self-signed
// certificate, all PEM-encoded.
type Material struct {
	PrivateKey  string // PKCS#8 "PRIVATE KEY"
	Certificate string // self-signed X.509 "CERTIFICATE" — what the registry takes as encryption_cert
	PublicKey   string // PKIX "PUBLIC KEY"
	CSR         string // "CERTIFICATE REQUEST", for a CA-signed certificate later
	NotAfter    time.Time
}

// Generate creates an RSA key and a self-signed X.509 encryption certificate
// for it, the pair a participant registers with the NHCX participant
// registry and keeps as participant.privateKey.
func Generate(s Subject) (*Material, error) {
	if s.CommonName == "" {
		return nil, errors.New("commonName is required")
	}
	bits := s.KeyBits
	if bits == 0 {
		bits = 2048
	}
	if bits < MinKeyBits || bits > MaxKeyBits {
		return nil, fmt.Errorf("keyBits must be between %d and %d", MinKeyBits, MaxKeyBits)
	}
	days := s.ValidityDays
	if days == 0 {
		days = 365
	}
	if days < 1 || days > MaxValidityDays {
		return nil, fmt.Errorf("validityDays must be between 1 and %d", MaxValidityDays)
	}

	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate RSA key: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("encode private key: %w", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("encode public key: %w", err)
	}

	name := pkix.Name{CommonName: s.CommonName}
	for dst, v := range map[*[]string]string{
		&name.Organization: s.Organization, &name.OrganizationalUnit: s.OrganizationalUnit,
		&name.Country: s.Country, &name.Province: s.State, &name.Locality: s.Locality,
	} {
		if v != "" {
			*dst = []string{v}
		}
	}
	var emails []string
	if s.Email != "" {
		emails = []string{s.Email}
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: name, EmailAddresses: emails, SignatureAlgorithm: x509.SHA256WithRSA,
	}, priv)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}
	notBefore := time.Now().Add(-5 * time.Minute) // tolerate clock skew at the registry
	notAfter := notBefore.AddDate(0, 0, days)
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               name,
		EmailAddresses:        emails,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &Material{
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})),
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})),
		PublicKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		CSR:         string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
		NotAfter:    notAfter,
	}, nil
}
