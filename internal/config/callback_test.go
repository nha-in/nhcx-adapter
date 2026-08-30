package config

import (
	"fmt"
	"testing"
)

// The shared callback block is a default, not a requirement: a gateway whose
// participants each name their own has nothing to fall back to and should not
// be made to invent one.
func TestCallbackBlockIsOptionalWhenEveryParticipantHasOne(t *testing.T) {
	key := testRSAKey(t)
	base := `"participant": {"participantId": "1@hcx", "clientId": "c", "clientSecret": "s", "privateKey": %q%s}`

	for _, tc := range []struct {
		name, participant, rest string
		ok                      bool
	}{
		{"shared callback serves the default", "", `, "callback": {"url": "http://127.0.0.1:1/cb"}`, true},
		{"default carries its own", `, "callback": {"url": "http://127.0.0.1:1/own"}`, "", true},
		{"nobody has one", "", "", false},
		{"hosted profile falls back to the shared one", "",
			`, "callback": {"url": "http://127.0.0.1:1/cb"}, "participants": [{"participantId": "2@hcx"}]`, true},
		{"hosted profile with neither", `, "callback": {"url": "http://127.0.0.1:1/own"}`,
			`, "participants": [{"participantId": "2@hcx"}]`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte("{" + fmt.Sprintf(base, key, tc.participant) + tc.rest + "}"))
			if err != nil {
				t.Fatal(err)
			}
			err = cfg.ValidateServe()
			if tc.ok && err != nil {
				t.Errorf("ValidateServe() = %v, want no callback complaint", err)
			}
			if !tc.ok && err == nil {
				t.Error("ValidateServe() accepted a participant with nowhere to deliver")
			}
		})
	}
}
