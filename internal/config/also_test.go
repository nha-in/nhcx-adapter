package config

import (
	"strings"
	"testing"
)

// The fan-out list: parsed, normalised, validated, and merged the same way
// routes are — an also belongs to the URL it was written for.
func TestCallbackAlso(t *testing.T) {
	t.Setenv("TEST_NHCX_SECRET", "x")
	body := strings.Replace(minimal, `"callback": {"url": "http://127.0.0.1:1/cb"}`,
		`"callback": {"url": "http://127.0.0.1:1/cb", "also": [{"url": "http://127.0.0.1:2/emr/", "routes": {"/v1/claim/on_submit/": "http://127.0.0.1:2/claims"}}]}`, 1)
	cfg, err := Load(writeCfg(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Callback.Also) != 1 || cfg.Callback.Also[0].URL != "http://127.0.0.1:2/emr/" {
		t.Fatalf("also not parsed: %+v", cfg.Callback.Also)
	}
	if cfg.Callback.Also[0].Routes["v1/claim/on_submit"] != "http://127.0.0.1:2/claims" {
		t.Errorf("also route key not cleaned: %v", cfg.Callback.Also[0].Routes)
	}
	if err := cfg.ValidateServe(); err != nil {
		t.Errorf("valid also refused: %v", err)
	}

	// A participant that redirects the base URL leaves the shared also
	// behind, exactly as it leaves the shared routes behind.
	cfg.Participants = []Participant{{ParticipantID: "1000004805@hcx", Callback: &Callback{URL: "http://127.0.0.1:3/payer"}}}
	if merged := cfg.CallbackFor(cfg.Participants[0]); len(merged.Also) != 0 {
		t.Errorf("participant URL override must reset also: %+v", merged.Also)
	}
	if merged := cfg.CallbackFor(cfg.AllParticipants()[0]); len(merged.Also) != 1 {
		t.Errorf("default participant must keep the shared also: %+v", merged.Also)
	}
}

func TestCallbackAlsoRejected(t *testing.T) {
	t.Setenv("TEST_NHCX_SECRET", "x")

	relative := strings.Replace(minimal, `"callback": {"url": "http://127.0.0.1:1/cb"}`,
		`"callback": {"url": "http://127.0.0.1:1/cb", "also": [{"url": "emr-svc"}]}`, 1)
	if cfg, err := Load(writeCfg(t, relative)); err != nil {
		t.Fatal(err)
	} else if err := cfg.ValidateServe(); err == nil || !strings.Contains(err.Error(), "callback.also[0].url") {
		t.Errorf("relative also URL must be rejected: %v", err)
	}

	nested := strings.Replace(minimal, `"callback": {"url": "http://127.0.0.1:1/cb"}`,
		`"callback": {"url": "http://127.0.0.1:1/cb", "also": [{"url": "http://127.0.0.1:2/emr", "also": [{"url": "http://127.0.0.1:3/x"}]}]}`, 1)
	if cfg, err := Load(writeCfg(t, nested)); err != nil {
		t.Fatal(err)
	} else if err := cfg.ValidateServe(); err == nil || !strings.Contains(err.Error(), "may not nest") {
		t.Errorf("nested also must be rejected: %v", err)
	}
}
