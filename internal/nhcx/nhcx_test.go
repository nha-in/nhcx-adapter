package nhcx

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func TestBuildProtectedHeaders(t *testing.T) {
	h := BuildProtectedHeaders(map[string]any{
		HdrSender:        " 1000003463 ",
		HdrRecipient:     "1000004805@hcx",
		HdrCorrelationID: "not-a-uuid",
		HdrWorkflowID:    "",
	}, "v1/preauth/submit")
	if h[HdrSender] != "1000003463@hcx" || h[HdrRecipient] != "1000004805@hcx" {
		t.Errorf("codes: %v", h)
	}
	for _, k := range []string{HdrCorrelationID, HdrRequestID, HdrAPICallID} {
		if !IsID(GetString(h, k)) {
			t.Errorf("%s = %q is not a UUID", k, h[k])
		}
	}
	if h[HdrStatus] != "request.initiated" {
		t.Errorf("status %v", h[HdrStatus])
	}
	if _, ok := h[HdrWorkflowID]; ok {
		t.Error("blank workflow id must be dropped")
	}
	if _, err := time.Parse(TimestampLayout, GetString(h, HdrTimestamp)); err != nil {
		t.Errorf("timestamp %q: %v", h[HdrTimestamp], err)
	}

	keep := "0f4c2b2e-9c7a-4d55-8a1e-2b1b0c7d9e11"
	h = BuildProtectedHeaders(map[string]any{HdrCorrelationID: keep, HdrStatus: "response.partial"}, "v1/preauth/on_submit")
	if h[HdrCorrelationID] != keep || h[HdrStatus] != "response.partial" {
		t.Errorf("caller values must win: %v", h)
	}
	if DefaultStatus("v1/coverageeligibility/on_check") != "response.complete" {
		t.Error("on_ paths are responses")
	}
}

func TestEntityTypeAndTarget(t *testing.T) {
	for path, want := range map[string]string{
		"v1/preauth/on_submit":          "preauth",
		"/v1/coverageeligibility/check": "coverageeligibility",
		"v1/paymentnotice/request":      "payment",
		"v1/insuranceplan/on_request":   "insuranceplan",
		"v1/on_status":                  "status",
		"v1/error":                      "error",
		"claim/submit":                  "claim",
	} {
		if got := EntityType(path); got != want {
			t.Errorf("EntityType(%s) = %s, want %s", path, got, want)
		}
	}
	if got := TargetURL("https://apisbx.abdm.gov.in/hcx/v1", "/v1/preauth/submit"); got != "https://apisbx.abdm.gov.in/hcx/v1/preauth/submit" {
		t.Errorf("TargetURL = %s", got)
	}
	if got := TargetURL("https://x/hcx", "v1/claim/submit"); got != "https://x/hcx/v1/claim/submit" {
		t.Errorf("TargetURL = %s", got)
	}
	if AckTimestamp(time.Date(2026, 8, 25, 9, 5, 7, 42_000_000, time.UTC)) != "25/08/2026 09:05:07:042" {
		t.Error("ack timestamp format")
	}
}

func TestJWERoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	headers := map[string]any{HdrSender: "a@hcx", HdrRecipient: "b@hcx", HdrCorrelationID: NewID(), "alg": "none", "typ": "JWE"}
	compact, err := Encrypt([]byte(`{"resourceType":"Bundle"}`), &priv.PublicKey, headers)
	if err != nil {
		t.Fatal(err)
	}
	if !IsCompactJWE(compact) {
		t.Fatal("not compact")
	}
	h, err := ParseHeader(compact)
	if err != nil {
		t.Fatal(err)
	}
	if h["alg"] != "RSA-OAEP-256" || h["enc"] != "A256GCM" {
		t.Errorf("alg/enc must come from the encrypter: %v", h)
	}
	if _, ok := h["typ"]; ok {
		t.Error("typ must not be set — NHCX schema rejects it")
	}
	if h[HdrSender] != "a@hcx" || h[HdrRecipient] != "b@hcx" {
		t.Errorf("headers lost: %v", h)
	}
	plain, err := Decrypt(compact, priv)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != `{"resourceType":"Bundle"}` {
		t.Errorf("plaintext %s", plain)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := Decrypt(compact, other); err == nil {
		t.Error("wrong key must fail")
	}
	if _, err := Decrypt(strings.Join(strings.Split(compact, ".")[:4], "."), priv); err == nil {
		t.Error("truncated token must fail")
	}
}
