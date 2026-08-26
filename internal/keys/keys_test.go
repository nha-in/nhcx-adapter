package keys

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateRoundTrip(t *testing.T) {
	m, err := Generate(Subject{CommonName: "Kyro Max", Organization: "Kyro", Country: "IN", Email: "ops@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKey(m.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	pubFromCert, err := ParsePublicKey(m.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	pubFromKey, err := ParsePublicKey(m.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.PublicKey.Equal(pubFromCert) || !priv.PublicKey.Equal(pubFromKey) {
		t.Error("certificate / public key do not match the private key")
	}
	// The registry spelling: base64 of the PEM.
	if _, err := ParsePublicKey(base64.StdEncoding.EncodeToString([]byte(m.Certificate))); err != nil {
		t.Errorf("base64 PEM: %v", err)
	}
	if !strings.Contains(m.CSR, "CERTIFICATE REQUEST") {
		t.Error("no CSR")
	}
	for _, bad := range []Subject{{}, {CommonName: "x", KeyBits: 1024}, {CommonName: "x", ValidityDays: 99999}} {
		if _, err := Generate(bad); err == nil {
			t.Errorf("expected rejection for %+v", bad)
		}
	}
}
