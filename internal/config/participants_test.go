package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
)

func testRSAKey(t *testing.T) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// An adapter meant to replace hcxkit has to read a kit-shaped participants
// array: {participantId, name, callbackUrl} and nothing else. Everything the
// entry leaves out comes from the default profile.
func TestHostedParticipantInheritsAndAcceptsKitSpelling(t *testing.T) {
	cfg, err := Parse([]byte(`{
	  "participant": {
	    "participantId": "1000003463", "clientId": "cid", "clientSecret": "sec", "privateKey": "KEY"
	  },
	  "participants": [
	    {"participantId": "1000004805", "name": "Dummy IRDAI Payer",
	     "callbackUrl": "http://127.0.0.1:8082/nhcx/callback"},
	    {"participantId": "1000001518", "name": "PMJAY",
	     "callback": {"url": "http://127.0.0.1:8090/nhcx/callback", "appendPath": false, "apiKey": "pm-key"},
	     "clientId": "own-cid", "clientSecret": "own-sec"}
	  ],
	  "callback": {"url": "http://127.0.0.1:8765/nhcx/callback", "apiKey": "shared", "timeoutSeconds": 25}
	}`))
	if err != nil {
		t.Fatal(err)
	}

	all := cfg.AllParticipants()
	if len(all) != 3 {
		t.Fatalf("got %d profiles, want 3", len(all))
	}
	if all[0].ParticipantID != "1000003463@hcx" {
		t.Errorf("default code %q — @hcx should be appended", all[0].ParticipantID)
	}

	// The kit spelling folds into Callback, and the unset fields inherit.
	payer := all[1]
	if payer.ParticipantID != "1000004805@hcx" || payer.Name != "Dummy IRDAI Payer" {
		t.Errorf("payer identity: %+v", payer)
	}
	if payer.ClientID != "cid" || payer.ClientSecret != "sec" || payer.PrivateKey != "KEY" {
		t.Errorf("payer should inherit the default's credentials and key: %+v", payer)
	}
	cb := cfg.CallbackFor(payer)
	if cb.URL != "http://127.0.0.1:8082/nhcx/callback" {
		t.Errorf("callbackUrl was not honoured: %q", cb.URL)
	}
	if cb.APIKey != "shared" || cb.TimeoutSeconds != 25 || !cb.AppendsPath() {
		t.Errorf("payer callback should inherit apiKey/timeout/appendPath: %+v", cb)
	}

	// An entry that sets things of its own wins on exactly those.
	pmjay := all[2]
	if pmjay.ClientID != "own-cid" || pmjay.ClientSecret != "own-sec" {
		t.Errorf("pmjay should keep its own credentials: %+v", pmjay)
	}
	if pmjay.PrivateKey != "KEY" {
		t.Errorf("pmjay should still inherit the key: %q", pmjay.PrivateKey)
	}
	cb = cfg.CallbackFor(pmjay)
	if cb.URL != "http://127.0.0.1:8090/nhcx/callback" || cb.APIKey != "pm-key" || cb.AppendsPath() {
		t.Errorf("pmjay callback: %+v appendPath=%v", cb, cb.AppendsPath())
	}
	if cb.TimeoutSeconds != 25 {
		t.Errorf("pmjay should inherit the shared timeout, got %d", cb.TimeoutSeconds)
	}

	// The default profile itself is untouched by any of it.
	if def := cfg.CallbackFor(cfg.Participant); def.URL != "http://127.0.0.1:8765/nhcx/callback" || def.APIKey != "shared" {
		t.Errorf("default callback: %+v", def)
	}
}

func TestHostedParticipantsAreValidated(t *testing.T) {
	base := `"participant": {"participantId": "1@hcx", "clientId": "c", "clientSecret": "s", "privateKey": %q}`
	key := testRSAKey(t)

	for _, tc := range []struct{ name, participants, want string }{
		{"no code", `[{"name": "x"}]`, "participants[0].participantId is required"},
		{"duplicate of default", `[{"participantId": "1@hcx"}]`, "duplicates participant.participantId"},
		{"duplicate of each other", `[{"participantId": "2@hcx"}, {"participantId": "2"}]`, "duplicates participants[0]"},
		{"half credentials", `[{"participantId": "2@hcx", "clientId": "only"}]`, "must be set together"},
		{"bad key", `[{"participantId": "2@hcx", "privateKey": "not-a-key"}]`, "not a valid RSA private key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte("{" + fmt.Sprintf(base, key) + `, "participants": ` + tc.participants + "}"))
			if err != nil {
				t.Fatal(err)
			}
			err = cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("Validate() = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
