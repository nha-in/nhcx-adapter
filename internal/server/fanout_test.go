package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"nhcx-adapter/internal/config"
	"nhcx-adapter/internal/nhcx"
)

// recorder is a second integrator backend for fan-out tests.
type recorder struct {
	mu   sync.Mutex
	path string
	hdr  http.Header
	body []byte
	code int
	hits int
}

func newRecorder(t *testing.T) (*recorder, *httptest.Server) {
	rec := &recorder{code: http.StatusOK}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.mu.Lock()
		rec.path, rec.hdr, rec.body, rec.hits = r.URL.Path, r.Header.Clone(), body, rec.hits+1
		code := rec.code
		rec.mu.Unlock()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"received":"also"}`))
	}))
	t.Cleanup(srv.Close)
	return rec, srv
}

// TestInboundFanOut: with callback.also configured, one inbound message is
// posted to the primary callback and to every extra target, with the same
// dedupe id, and the delivery only counts when all of them accept.
func TestInboundFanOut(t *testing.T) {
	rec, second := newRecorder(t)
	f := newFixture(t, "", func(cfg *config.Config) {
		cfg.Callback.Also = []config.Callback{{URL: second.URL + "/emr", APIKey: "emr-secret"}}
	})

	corr := nhcx.NewID()
	status, out := f.post("/in/v1/preauth/on_submit", f.inboundJWE("v1/preauth/on_submit", map[string]any{
		nhcx.HdrSender: "1000004805@hcx", nhcx.HdrRecipient: "1000003463", nhcx.HdrCorrelationID: corr,
	}), nil)
	if status != http.StatusAccepted {
		t.Fatalf("status %d %v", status, out)
	}

	f.mu.Lock()
	primaryPath, primaryTxn := f.callbackPath, f.callbackHdr.Get("X-Hcxkit-Txn-Id")
	primaryBody := string(f.callbackBody)
	f.mu.Unlock()
	if primaryPath != "/hook/v1/preauth/on_submit" {
		t.Errorf("primary path %s", primaryPath)
	}

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if rec.hits != 1 || rec.path != "/emr/v1/preauth/on_submit" {
		t.Errorf("also target: hits=%d path=%s", rec.hits, rec.path)
	}
	if rec.hdr.Get("Authorization") != "Bearer emr-secret" {
		t.Errorf("also target auth %q — each target carries its own apiKey", rec.hdr.Get("Authorization"))
	}
	if got := rec.hdr.Get("X-Hcxkit-Txn-Id"); got == "" || got != primaryTxn {
		t.Errorf("dedupe id differs across targets: primary %q also %q", primaryTxn, got)
	}
	if rec.hdr.Get("X-Nhcx-Correlation-Id") != corr {
		t.Errorf("also correlation id %q", rec.hdr.Get("X-Nhcx-Correlation-Id"))
	}
	if string(rec.body) != primaryBody {
		t.Errorf("also target got a different envelope")
	}
}

// TestInboundFanOutFailures: a refusal anywhere refuses the whole delivery
// (so NHCX redelivers to everyone), and a dead primary does not starve the
// extra targets.
func TestInboundFanOutFailures(t *testing.T) {
	rec, second := newRecorder(t)
	f := newFixture(t, "", func(cfg *config.Config) {
		cfg.Callback.Also = []config.Callback{{URL: second.URL + "/emr"}}
	})

	// The extra target refuses: the primary already accepted, but NHCX must
	// still see a retryable failure.
	rec.mu.Lock()
	rec.code = 500
	rec.mu.Unlock()
	status, out := f.post("/in/v1/claim/on_submit", f.inboundJWE("v1/claim/on_submit", map[string]any{nhcx.HdrRecipient: "1000003463"}), nil)
	e, _ := out["error"].(map[string]any)
	if status != http.StatusBadGateway || e["code"] != "CALLBACK_HTTP_500" || e["retryable"] != true {
		t.Errorf("also 500: %d %v", status, out)
	}
	f.mu.Lock()
	if f.callbackPath != "/claims-only" {
		t.Errorf("primary was skipped: %s", f.callbackPath)
	}
	f.mu.Unlock()

	// The primary refuses: its failure wins, and the extra target is still
	// attempted.
	rec.mu.Lock()
	rec.code, rec.hits = http.StatusOK, 0
	rec.mu.Unlock()
	f.mu.Lock()
	f.callbackCode = 503
	f.mu.Unlock()
	status, out = f.post("/in/v1/claim/on_submit", f.inboundJWE("v1/claim/on_submit", map[string]any{nhcx.HdrRecipient: "1000003463"}), nil)
	e, _ = out["error"].(map[string]any)
	if status != http.StatusBadGateway || e["code"] != "CALLBACK_HTTP_503" {
		t.Errorf("primary 503: %d %v", status, out)
	}
	rec.mu.Lock()
	if rec.hits != 1 {
		t.Errorf("also target starved by the primary's failure: hits=%d", rec.hits)
	}
	rec.mu.Unlock()
}

// TestKitTypeHeader: a backend written for hcxkit dispatches on
// X-Hcxkit-Type, and the kit spells an insurance plan "insurance" and a
// coverage check "coverage" — not the protocol entity names.
func TestKitTypeHeader(t *testing.T) {
	f := newFixture(t, "")
	for _, tc := range []struct{ path, want string }{
		{"v1/insuranceplan/on_request", "insurance"},
		{"v1/coverageeligibility/on_check", "coverage"},
		{"v1/preauth/on_submit", "preauth"},
		{"v1/paymentnotice/request", "payment"},
	} {
		status, out := f.post("/in/"+tc.path, f.inboundJWE(tc.path, map[string]any{
			nhcx.HdrSender: "1000004805@hcx", nhcx.HdrRecipient: "1000003463", nhcx.HdrCorrelationID: nhcx.NewID(),
		}), nil)
		if status != http.StatusAccepted {
			t.Fatalf("%s: status %d %v", tc.path, status, out)
		}
		f.mu.Lock()
		got := f.callbackHdr.Get("X-Hcxkit-Type")
		f.mu.Unlock()
		if got != tc.want {
			t.Errorf("%s: X-Hcxkit-Type %q, want %q", tc.path, got, tc.want)
		}
	}
}
