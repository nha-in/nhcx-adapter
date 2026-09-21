package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"nhcx-adapter/internal/adapter"
	"nhcx-adapter/internal/config"
	"nhcx-adapter/internal/keys"
	"nhcx-adapter/internal/probe"
)

type fake struct {
	srv       *httptest.Server
	tokenOK   bool
	cert      string // what /fetch/certs returns for our own code
	hasRecord bool
}

func newFake(t *testing.T) *fake {
	f := &fake{tokenOK: true, hasRecord: true}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		if !f.tokenOK {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid client"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "tok"})
	})
	mux.HandleFunc("POST /reg/participant/search", func(w http.ResponseWriter, r *http.Request) {
		if !f.hasRecord {
			_ = json.NewEncoder(w).Encode(map[string]any{"participants": []any{}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"participants": []any{map[string]any{
			"participant_code": "1000003463@hcx", "participant_name": "Kyro", "status": "Active",
			"endpoint_url": "https://example.invalid/in", "roles": []string{"10001"},
		}}})
	})
	mux.HandleFunc("POST /reg/fetch/certs", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"encryption_cert": f.cert})
	})
	mux.HandleFunc("POST /reg/participant/update", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["participant_code"] != "1000003463@hcx" || (body["encryption_cert"] == nil && body["endpoint_url"] == nil) {
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"participant_code": "1000003463@hcx", "status": "pending", "transactionid": "t1"})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func newAdapter(t *testing.T, f *fake, privPEM string) *adapter.Adapter {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`{
	  "participant": {"participantId": "1000003463", "clientId": "c", "clientSecret": "s", "privateKey": %q},
	  "urls": {"nhcx": %q, "participant": %q, "sessions": %q},
	  "ledger": {"enabled": false}
	}`, privPEM, f.srv.URL+"/hcx/v1", f.srv.URL+"/reg", f.srv.URL+"/sessions")))
	if err != nil {
		t.Fatal(err)
	}
	gw, err := adapter.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return gw
}

func TestRun(t *testing.T) {
	mine, _ := keys.Generate(keys.Subject{CommonName: "me"})
	other, _ := keys.Generate(keys.Subject{CommonName: "other"})
	f := newFake(t)

	f.cert = mine.Certificate
	rep := Run(context.Background(), newAdapter(t, f, mine.PrivateKey))
	if rep.Fatal() || !rep.Healthy() || rep.Cert != CertMatch || rep.Participant == nil || rep.Participant.EndpointURL != "https://example.invalid/in" || rep.Participant.Roles[0] != "10001" {
		t.Errorf("healthy setup: %+v", rep)
	}

	f.cert = other.Certificate
	rep = Run(context.Background(), newAdapter(t, f, mine.PrivateKey))
	if rep.Cert != CertMismatch || rep.Healthy() {
		t.Errorf("mismatch: %+v", rep.Checks)
	}

	f.cert = "Invalid Certificate Found"
	f.hasRecord = false
	rep = Run(context.Background(), newAdapter(t, f, mine.PrivateKey))
	if rep.Cert != CertMissing || rep.Participant != nil {
		t.Errorf("missing: %+v", rep.Checks)
	}

	f.tokenOK = false
	rep = Run(context.Background(), newAdapter(t, f, mine.PrivateKey))
	if !rep.Fatal() || len(rep.Checks) != 1 || rep.Checks[0].OK {
		t.Errorf("token failure must be fatal and stop early: %+v", rep.Checks)
	}

	// Upload path used by the interactive fix.
	f.tokenOK = true
	gw := newAdapter(t, f, mine.PrivateKey)
	if _, err := gw.ABDM().UpdateCertificate(context.Background(), mine.Certificate, []string{"10001"}); err != nil {
		t.Errorf("update: %v", err)
	}
	if _, err := gw.ABDM().UpdateEndpoint(context.Background(), "https://new.example/in", []string{"10001"}); err != nil {
		t.Errorf("update endpoint: %v", err)
	}
}

func TestEndpointCheck(t *testing.T) {
	cfg, _ := config.Parse([]byte(`{"participant":{"participantId":"1000003463","clientId":"c","clientSecret":"s","privateKey":"x"},"apiKey":"k"}`))
	key := probe.Key(cfg)
	other, _ := config.Parse([]byte(`{"participant":{"participantId":"1000003463","clientId":"c","clientSecret":"DIFFERENT","privateKey":"x"},"apiKey":"k"}`))
	otherKey := probe.Key(other)

	answerWith := func(k []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/in/healthz" || r.Method != http.MethodPost {
				w.WriteHeader(404) // a proxy's own 404: no acknowledgement
				return
			}
			if ae := r.Header.Get("Accept-Encoding"); ae != "identity" {
				t.Errorf("probe must not accept compression, got Accept-Encoding %q", ae)
			}
			var in probe.Request
			_ = json.NewDecoder(r.Body).Decode(&in)
			out := map[string]any{"status": "ok"}
			if in.Probe != "" && k != nil {
				out["probe_ack"] = probe.Ack(k, in.Probe)
			}
			_ = json.NewEncoder(w).Encode(out)
		}
	}
	good := httptest.NewServer(answerWith(key))
	defer good.Close()
	if c := TestEndpoint(context.Background(), good.URL+"/in/", key); !c.OK {
		t.Errorf("good endpoint: %s", c.Detail)
	}
	if c := TestEndpoint(context.Background(), good.URL, key); c.OK {
		t.Error("wrong path must fail")
	}
	stranger := httptest.NewServer(answerWith(otherKey))
	defer stranger.Close()
	if c := TestEndpoint(context.Background(), stranger.URL+"/in", key); c.OK || !strings.Contains(c.Detail, "not one running with this configuration") {
		t.Errorf("other configuration must fail: %s", c.Detail)
	}
	silent := httptest.NewServer(answerWith(nil))
	defer silent.Close()
	if c := TestEndpoint(context.Background(), silent.URL+"/in", key); c.OK {
		t.Error("no acknowledgement must fail")
	}
	if c := TestEndpoint(context.Background(), "", key); c.OK {
		t.Error("empty endpoint must fail")
	}
	if c := TestEndpoint(context.Background(), "http://127.0.0.1:1", key); c.OK {
		t.Error("unreachable must fail")
	}
	if probe.Ack(key, "n1") == probe.Ack(key, "n2") || probe.Verify(key, "n1", probe.Ack(otherKey, "n1")) {
		t.Error("ack must depend on nonce and key")
	}
}
