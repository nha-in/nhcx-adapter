// Package probe is the challenge/response the endpoint check uses to prove
// that a public URL leads to a gateway running with this configuration —
// not merely something that answers /healthz. The checker sends a random
// nonce; the gateway answers with an HMAC of it under a key derived from
// its own secrets. Nothing secret travels on the wire and a captured
// exchange cannot be replayed.
package probe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"

	"nhcx-gateway/internal/config"
)

// Request is the JSON body the checker POSTs to /healthz.
type Request struct {
	Probe string `json:"probe"`
}

// Response is the JSON body the gateway answers with (alongside the usual
// healthz fields).
type Response struct {
	ProbeAck string `json:"probe_ack"`
}

// Key derives the probe key from the configuration: two gateways share it
// exactly when they run as the same participant with the same credentials.
func Key(cfg *config.Config) []byte {
	h := sha256.New()
	h.Write([]byte("nhcx-gateway probe v1\x00"))
	h.Write([]byte(cfg.Participant.ParticipantID + "\x00"))
	h.Write([]byte(cfg.Participant.ClientSecret + "\x00"))
	h.Write([]byte(cfg.APIKey))
	return h.Sum(nil)
}

// Nonce returns a fresh random challenge.
func Nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// Ack is the expected answer to a nonce.
func Ack(key []byte, nonce string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(nonce))
	return hex.EncodeToString(m.Sum(nil))
}

// Verify reports whether ack answers nonce under key (constant time).
func Verify(key []byte, nonce, ack string) bool {
	return subtle.ConstantTimeCompare([]byte(Ack(key, nonce)), []byte(ack)) == 1
}
