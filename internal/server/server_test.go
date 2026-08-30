package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"nhcx-gateway/internal/config"
	"nhcx-gateway/internal/gateway"
	"nhcx-gateway/internal/nhcx"
	"nhcx-gateway/internal/probe"
)

// fixture stands up a fake ABDM (sessions + registry + exchange), a fake
// integrator callback, and the gateway under test wired to both.
type fixture struct {
	t         *testing.T
	self      *rsa.PrivateKey // the gateway's key
	payer     *rsa.PrivateKey // the counterparty's key
	abdm      *httptest.Server
	callback  *httptest.Server
	srv       *httptest.Server
	cfg       *config.Config
	apiKey    string
	sessions  atomic.Int32
	reject401 atomic.Bool // next gateway call answers 401 once

	mu           sync.Mutex
	gatewayBody  []byte
	callbackBody []byte
	callbackPath string
	callbackHdr  http.Header
	callbackCode int
}

func pemPublic(t *testing.T, k *rsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func pemPrivate(t *testing.T, k *rsa.PrivateKey) string {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func newFixture(t *testing.T, apiKey string) *fixture {
	t.Helper()
	f := &fixture{t: t, apiKey: apiKey, callbackCode: http.StatusOK}
	f.self, _ = rsa.GenerateKey(rand.Reader, 2048)
	f.payer, _ = rsa.GenerateKey(rand.Reader, 2048)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["clientId"] != "cid" || body["clientSecret"] != "sec" || r.Header.Get("X-CM-ID") != "sbx" {
			http.Error(w, "bad creds", 401)
			return
		}
		n := f.sessions.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": fmt.Sprintf("tok%d", n), "expiresIn": 1200})
	})
	mux.HandleFunc("POST /registry/fetch/certs", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("bearer_auth"), "Bearer tok") {
			http.Error(w, "no token", 401)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body["participantid"] {
		case "1000004805@hcx":
			_ = json.NewEncoder(w).Encode(map[string]any{"participant_code": "1000004805@hcx", "encryption_cert": pemPublic(t, &f.payer.PublicKey)})
		case "1000003463@hcx", "1000009999@hcx": // self, and a stranger the registry wrongly gave our cert
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption_cert": pemPublic(t, &f.self.PublicKey)})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption_cert": "Invalid Certificate Found"})
		}
	})
	mux.HandleFunc("POST /hcx/v1/{path...}", func(w http.ResponseWriter, r *http.Request) {
		if f.reject401.CompareAndSwap(true, false) {
			http.Error(w, "expired", 401)
			return
		}
		if !strings.HasPrefix(r.Header.Get("bearer_auth"), "Bearer tok") {
			http.Error(w, "no token", 401)
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.gatewayBody = body
		f.mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/bad") {
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "Request Validation Failed"})
			return
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"timestamp": "x", "result": map[string]any{"protocol_status": "request.queued"}})
	})
	f.abdm = httptest.NewServer(mux)
	t.Cleanup(f.abdm.Close)

	f.callback = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.callbackBody, f.callbackPath, f.callbackHdr = body, r.URL.Path, r.Header.Clone()
		code := f.callbackCode
		f.mu.Unlock()
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"received":true}`))
	}))
	t.Cleanup(f.callback.Close)

	// requireApiKey: the fixture is a sandbox gateway, where the key is
	// accepted but not demanded by default. The tests that check enforcement
	// need it demanded, so they ask for it explicitly.
	cfgJSON := fmt.Sprintf(`{
	  "apiKey": %q,
	  "requireApiKey": true,
	  "certs": {"refuseSelfKey": true},
	  "participant": {"participantId": "1000003463", "clientId": "cid", "clientSecret": "sec", "privateKey": %q},
	  "callback": {"url": %q, "apiKey": "cb-secret", "routes": {"v1/claim/on_submit": %q}},
	  "urls": {"nhcx": %q, "participant": %q, "sessions": %q},
	  "ledger": {"dir": %q},
	  "log": {"level": "error"}
	}`, apiKey, pemPrivate(t, f.self), f.callback.URL+"/hook", f.callback.URL+"/claims-only", f.abdm.URL+"/hcx/v1", f.abdm.URL+"/registry", f.abdm.URL+"/sessions", t.TempDir())
	cfg, err := config.Parse([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	f.cfg = cfg
	f.srv = httptest.NewServer(New(gw, slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Handler())
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fixture) post(path string, body string, hdr map[string]string) (int, map[string]any) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// sentJWE decrypts what reached the fake exchange with the payer's key.
func (f *fixture) sentJWE() (map[string]any, string, string) {
	f.t.Helper()
	f.mu.Lock()
	body := f.gatewayBody
	f.mu.Unlock()
	var envelope map[string]string
	if err := json.Unmarshal(body, &envelope); err != nil {
		f.t.Fatalf("gateway body: %v", err)
	}
	hdr, err := nhcx.ParseHeader(envelope["payload"])
	if err != nil {
		f.t.Fatal(err)
	}
	plain, err := nhcx.Decrypt(envelope["payload"], f.payer)
	if err != nil {
		f.t.Fatalf("payer cannot decrypt: %v", err)
	}
	return hdr, string(plain), envelope["type"]
}

const bundle = `{"resourceType":"Bundle","type":"collection","entry":[]}`

func TestOutboundEnvelope(t *testing.T) {
	f := newFixture(t, "k")
	status, out := f.post("/out/v1/preauth/submit", `{"recipient":"1000004805","workflow_id":"wf-1","fhir":`+bundle+`}`, nil)
	if status != http.StatusAccepted || out["ok"] != true {
		t.Fatalf("status %d body %v", status, out)
	}
	hdr, plain, typ := f.sentJWE()
	if plain != bundle {
		t.Errorf("payload %s", plain)
	}
	if typ != "" {
		t.Error("request APIs must not carry type=JWEPayload")
	}
	if hdr[nhcx.HdrSender] != "1000003463@hcx" || hdr[nhcx.HdrRecipient] != "1000004805@hcx" || hdr[nhcx.HdrStatus] != "request.initiated" || hdr[nhcx.HdrWorkflowID] != "wf-1" {
		t.Errorf("protected headers: %v", hdr)
	}
	if !nhcx.IsID(nhcx.GetString(hdr, nhcx.HdrCorrelationID)) || !nhcx.IsID(nhcx.GetString(hdr, nhcx.HdrAPICallID)) {
		t.Errorf("ids: %v", hdr)
	}
	respHdr, _ := out["headers"].(map[string]any)
	if respHdr[nhcx.HdrCorrelationID] != hdr[nhcx.HdrCorrelationID] {
		t.Error("response must report the headers that went on the wire")
	}
	if f.sessions.Load() != 1 {
		t.Errorf("one session fetch expected, got %d", f.sessions.Load())
	}

	// Second send reuses the cached certificate and token; a response API
	// threads the correlation id and declares its payload type.
	corr := nhcx.GetString(hdr, nhcx.HdrCorrelationID)
	status, _ = f.post("/out/v1/preauth/on_submit", `{"jwe_headers":{"x-hcx-recipient_code":"1000004805@hcx","x-hcx-correlation_id":"`+corr+`"},"fhir":`+bundle+`}`, nil)
	if status != http.StatusAccepted {
		t.Fatalf("on_submit status %d", status)
	}
	hdr, _, typ = f.sentJWE()
	if typ != "JWEPayload" || hdr[nhcx.HdrCorrelationID] != corr || hdr[nhcx.HdrStatus] != "response.complete" {
		t.Errorf("response headers: %v type=%s", hdr, typ)
	}
	if f.sessions.Load() != 1 {
		t.Errorf("token must be cached, got %d fetches", f.sessions.Load())
	}
}

func TestOutboundBareBundleWithHTTPHeaders(t *testing.T) {
	f := newFixture(t, "")
	status, _ := f.post("/out/v1/claim/submit", bundle, map[string]string{"x-hcx-recipient_code": "1000004805"})
	if status != http.StatusAccepted {
		t.Fatalf("status %d", status)
	}
	hdr, plain, _ := f.sentJWE()
	if plain != bundle || hdr[nhcx.HdrRecipient] != "1000004805@hcx" {
		t.Errorf("bare bundle: %v %s", hdr, plain)
	}
}

func TestOutboundFailures(t *testing.T) {
	f := newFixture(t, "k")

	// Wrong API key.
	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/out/v1/claim/submit", strings.NewReader(bundle))
	req.Header.Set("Authorization", "Bearer nope")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad key: %d", resp.StatusCode)
	}
	resp.Body.Close()

	cases := []struct {
		name, path, body string
		status           int
		code             string
	}{
		{"no recipient", "/out/v1/claim/submit", `{"fhir":` + bundle + `}`, 400, "NO_RECIPIENT"},
		{"not json", "/out/v1/claim/submit", `nope`, 400, "INVALID_ENVELOPE"},
		{"no bundle", "/out/v1/claim/submit", `{"recipient":"1000004805"}`, 400, "INVALID_ENVELOPE"},
		{"unknown participant", "/out/v1/claim/submit", `{"recipient":"1000000000","fhir":` + bundle + `}`, 422, "CERT_NOT_FOUND"},
		{"registry hands out our own key", "/out/v1/claim/submit", `{"recipient":"1000009999","fhir":` + bundle + `}`, 422, "SELF_ENCRYPTION_KEY"},
	}
	for _, c := range cases {
		status, out := f.post(c.path, c.body, nil)
		e, _ := out["error"].(map[string]any)
		if status != c.status || e["code"] != c.code {
			t.Errorf("%s: status %d code %v, want %d %s", c.name, status, e["code"], c.status, c.code)
		}
	}

	// NHCX's own verdict is passed through untouched.
	status, out := f.post("/out/v1/claim/bad", `{"recipient":"1000004805","fhir":`+bundle+`}`, nil)
	if status != 400 || out["ok"] != false || out["gateway_status"] != float64(400) {
		t.Errorf("gateway 400 must pass through: %d %v", status, out)
	}

	// Loopback to ourselves is legitimate.
	status, _ = f.post("/out/v1/claim/submit", `{"recipient":"1000003463","fhir":`+bundle+`}`, nil)
	if status != http.StatusAccepted {
		t.Errorf("self-addressed send: %d", status)
	}
}

func TestTokenRefreshOn401(t *testing.T) {
	f := newFixture(t, "")
	f.reject401.Store(true)
	status, _ := f.post("/out/v1/claim/submit", `{"recipient":"1000004805","fhir":`+bundle+`}`, nil)
	if status != http.StatusAccepted {
		t.Fatalf("status %d", status)
	}
	if f.sessions.Load() != 2 {
		t.Errorf("a 401 must trigger exactly one refresh, sessions=%d", f.sessions.Load())
	}
}

func (f *fixture) inboundJWE(path string, headers map[string]any) string {
	f.t.Helper()
	compact, err := nhcx.Encrypt([]byte(bundle), &f.self.PublicKey, nhcx.BuildProtectedHeaders(headers, path))
	if err != nil {
		f.t.Fatal(err)
	}
	return `{"payload":"` + compact + `"}`
}

func TestInboundDeliverAndAck(t *testing.T) {
	f := newFixture(t, "")
	corr := nhcx.NewID()
	status, out := f.post("/in/v1/preauth/on_submit", f.inboundJWE("v1/preauth/on_submit", map[string]any{
		nhcx.HdrSender: "1000004805@hcx", nhcx.HdrRecipient: "1000003463", nhcx.HdrCorrelationID: corr,
	}), nil)
	if status != http.StatusAccepted {
		t.Fatalf("status %d %v", status, out)
	}
	result, _ := out["result"].(map[string]any)
	if out["correlation_id"] != corr || !nhcx.IsID(out["api_call_id"].(string)) || result["entity_type"] != "preauth" ||
		result["sender_code"] != "1000004805@hcx" || result["recipient_code"] != "1000003463@hcx" || result["protocol_status"] != "request.queued" {
		t.Errorf("acceptance body: %v", out)
	}
	if ts, _ := out["timestamp"].(string); len(ts) != len("DD/MM/YYYY hh:mm:ss:sss") {
		t.Errorf("timestamp %q", ts)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.callbackPath != "/hook/v1/preauth/on_submit" {
		t.Errorf("callback path %s", f.callbackPath)
	}
	if f.callbackHdr.Get("Authorization") != "Bearer cb-secret" || f.callbackHdr.Get("X-Nhcx-Correlation-Id") != corr || f.callbackHdr.Get("X-Nhcx-Payload-Kind") != "fhir" {
		t.Errorf("callback headers %v", f.callbackHdr)
	}
	var env map[string]any
	if err := json.Unmarshal(f.callbackBody, &env); err != nil {
		t.Fatal(err)
	}
	var want any
	_ = json.Unmarshal([]byte(bundle), &want)
	if !reflect.DeepEqual(env["fhir"], want) {
		t.Errorf("delivered fhir %v", env["fhir"])
	}
	jh, _ := env["jwe_headers"].(map[string]any)
	meta, _ := env["meta"].(map[string]any)
	if jh[nhcx.HdrCorrelationID] != corr || jh["alg"] != "RSA-OAEP-256" || meta["payloadType"] != "fhir" || meta["path"] != "v1/preauth/on_submit" {
		t.Errorf("envelope %v", env)
	}
}

func TestInboundRootAliasAndProtocolMessage(t *testing.T) {
	f := newFixture(t, "")
	corr := nhcx.NewID()
	msg := `{"type":"ProtocolResponse","x-hcx-sender_code":"1000004805","x-hcx-correlation_id":"` + corr + `","x-hcx-status":"response.error","x-hcx-error_details":{"code":"ERR_X","message":"m"}}`
	status, out := f.post("/v1/error", msg, nil)
	if status != http.StatusAccepted || out["correlation_id"] != corr {
		t.Fatalf("status %d %v", status, out)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.callbackPath != "/hook/v1/error" || f.callbackHdr.Get("X-Nhcx-Payload-Kind") != "protocol" {
		t.Errorf("protocol delivery: %s %v", f.callbackPath, f.callbackHdr)
	}
	var env map[string]any
	_ = json.Unmarshal(f.callbackBody, &env)
	jh, _ := env["jwe_headers"].(map[string]any)
	if jh[nhcx.HdrSender] != "1000004805@hcx" || jh[nhcx.HdrStatus] != "response.error" {
		t.Errorf("protocol headers %v", jh)
	}
}

func TestInboundRoute(t *testing.T) {
	f := newFixture(t, "")
	status, _ := f.post("/in/v1/claim/on_submit", f.inboundJWE("v1/claim/on_submit", map[string]any{nhcx.HdrRecipient: "1000003463"}), nil)
	if status != http.StatusAccepted {
		t.Fatalf("status %d", status)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.callbackPath != "/claims-only" {
		t.Errorf("routed path %s, want /claims-only (route used verbatim)", f.callbackPath)
	}
}

func TestInboundFailures(t *testing.T) {
	f := newFixture(t, "")

	// Callback down → refuse the delivery so NHCX retries.
	f.mu.Lock()
	f.callbackCode = 500
	f.mu.Unlock()
	status, out := f.post("/in/v1/claim/on_submit", f.inboundJWE("v1/claim/on_submit", map[string]any{nhcx.HdrRecipient: "1000003463"}), nil)
	e, _ := out["error"].(map[string]any)
	if status != http.StatusBadGateway || e["code"] != "CALLBACK_HTTP_500" || e["retryable"] != true {
		t.Errorf("callback 500: %d %v", status, out)
	}
	f.mu.Lock()
	f.callbackCode = 200
	f.mu.Unlock()

	// Addressed to someone else.
	status, out = f.post("/in/v1/claim/on_submit", f.inboundJWE("v1/claim/on_submit", map[string]any{nhcx.HdrRecipient: "1000004805"}), nil)
	e, _ = out["error"].(map[string]any)
	if status != 400 || e["code"] != "WRONG_RECIPIENT" {
		t.Errorf("wrong recipient: %d %v", status, out)
	}

	// Encrypted for a different key.
	compact, _ := nhcx.Encrypt([]byte(bundle), &f.payer.PublicKey, map[string]any{nhcx.HdrRecipient: "1000003463@hcx"})
	status, out = f.post("/in/v1/claim/on_submit", `{"payload":"`+compact+`"}`, nil)
	e, _ = out["error"].(map[string]any)
	if status != 422 || e["code"] != "DECRYPT_FAILED" {
		t.Errorf("undecryptable: %d %v", status, out)
	}

	// Garbage.
	status, out = f.post("/in/v1/claim/on_submit", `{"payload":"abc"}`, nil)
	e, _ = out["error"].(map[string]any)
	if status != 400 || e["code"] != "INVALID_JWE" {
		t.Errorf("garbage: %d %v", status, out)
	}
	if status, _ := f.post("/in/v1/claim/on_submit", strings.Repeat("x", 9<<20), nil); status != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized body: %d", status)
	}
}

func TestTokenEndpoints(t *testing.T) {
	f := newFixture(t, "k")
	get := func(method, path, key string) (int, map[string]any) {
		req, _ := http.NewRequest(method, f.srv.URL+path, nil)
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	if status, _ := get("GET", "/token", ""); status != http.StatusUnauthorized {
		t.Errorf("token without API key: %d", status)
	}
	status, out := get("GET", "/token", "k")
	if status != 200 || out["token"] != "tok1" || out["token_type"] != "Bearer" || out["expires_in"].(float64) < 1100 {
		t.Errorf("token: %d %v", status, out)
	}
	if status, out := get("GET", "/token", "k"); status != 200 || out["token"] != "tok1" {
		t.Errorf("second read must reuse the cached token: %v", out)
	}
	status, out = get("POST", "/token/refresh", "k")
	if status != 200 || out["token"] != "tok2" || out["refreshed"] != true {
		t.Errorf("refresh: %d %v", status, out)
	}
	if f.sessions.Load() != 2 {
		t.Errorf("sessions fetched: %d", f.sessions.Load())
	}
}

func TestProbes(t *testing.T) {
	f := newFixture(t, "")
	resp, _ := http.Get(f.srv.URL + "/healthz")
	var plain map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&plain)
	resp.Body.Close()
	if resp.StatusCode != 200 || plain["probe_ack"] != nil {
		t.Errorf("healthz %d; no ack without a probe: %v", resp.StatusCode, plain)
	}
	resp, _ = http.Post(f.srv.URL+"/in/healthz", "application/json", strings.NewReader(`{"probe":"nonce-1"}`))
	var ans probe.Response
	_ = json.NewDecoder(resp.Body).Decode(&ans)
	resp.Body.Close()
	if resp.StatusCode != 200 || !probe.Verify(probe.Key(f.cfg), "nonce-1", ans.ProbeAck) {
		t.Errorf("/in/healthz probe ack: %d %q", resp.StatusCode, ans.ProbeAck)
	}
	resp, _ = http.Get(f.srv.URL + "/readyz")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("readyz before a token: %d", resp.StatusCode)
	}
	resp.Body.Close()
	f.post("/out/v1/claim/submit", `{"recipient":"1000004805","fhir":`+bundle+`}`, nil)
	resp, _ = http.Get(f.srv.URL + "/readyz")
	if resp.StatusCode != 200 {
		t.Errorf("readyz after a token: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func (f *fixture) get(path string) (int, map[string]any) {
	f.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+path, nil)
	if f.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+f.apiKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestLedger(t *testing.T) {
	f := newFixture(t, "k")

	// 1. An inbound request from the payer (we are the responder here).
	corr := nhcx.NewID()
	api := nhcx.NewID()
	body := f.inboundJWE("v1/preauth/submit", map[string]any{
		nhcx.HdrSender: "1000004805@hcx", nhcx.HdrRecipient: "1000003463", nhcx.HdrCorrelationID: corr, nhcx.HdrAPICallID: api, nhcx.HdrWorkflowID: "wf-9",
	})
	if status, _ := f.post("/in/v1/preauth/submit", body, nil); status != http.StatusAccepted {
		t.Fatalf("inbound status %d", status)
	}
	f.mu.Lock()
	if f.callbackHdr.Get("X-Nhcx-Redelivery") != "" {
		t.Error("first delivery is not a redelivery")
	}
	f.mu.Unlock()

	// The same api_call_id again: NHCX retrying → flagged for the backend.
	f.post("/in/v1/preauth/submit", body, nil)
	f.mu.Lock()
	if f.callbackHdr.Get("X-Nhcx-Redelivery") != "true" {
		t.Error("second delivery must be flagged as a redelivery")
	}
	f.mu.Unlock()

	// 2. Our response without a correlation id: the ledger threads it.
	status, out := f.post("/out/v1/preauth/on_submit", `{"recipient":"1000004805@hcx","fhir":`+bundle+`}`, nil)
	if status != http.StatusAccepted {
		t.Fatalf("on_submit status %d %v", status, out)
	}
	hdr, _, _ := f.sentJWE()
	if hdr[nhcx.HdrCorrelationID] != corr || hdr[nhcx.HdrWorkflowID] != "wf-9" {
		t.Errorf("response must reuse the inbound request's correlation and workflow ids: %v", hdr)
	}
	if id, _ := out["ledger_id"].(string); id == "" {
		t.Error("outbound answer carries the ledger id")
	}

	// 3. A failed send is recorded too.
	f.post("/out/v1/claim/submit", `{"recipient":"1000000000","fhir":`+bundle+`}`, nil)

	// Listing and filters.
	status, list := f.get("/ledger?limit=10")
	items, _ := list["items"].([]any)
	if status != 200 || len(items) != 4 {
		t.Fatalf("ledger list: %d %v", status, list)
	}
	_, failed := f.get("/ledger?status=failed")
	if n, _ := failed["count"].(float64); n != 1 {
		t.Errorf("status filter: %v", failed)
	}
	_, inbound := f.get("/ledger?direction=in&participant=1000004805")
	if n, _ := inbound["count"].(float64); n != 2 {
		t.Errorf("direction/participant filter: %v", inbound)
	}
	second, _ := inbound["items"].([]any)[0].(map[string]any)
	if second["redelivery"] != true || second["status"] != "delivered" || second["entity"] != "preauth" || second["kind"] != "request" {
		t.Errorf("inbound summary: %v", second)
	}
	if _, bad := f.get("/ledger?since=yesterday"); bad["error"] == nil {
		t.Error("bad since must be rejected")
	}

	// One entry in full.
	id, _ := second["id"].(string)
	status, entry := f.get("/ledger/" + id)
	if status != 200 || entry["fhir"] == nil || entry["headers"] == nil || entry["peer"] == nil {
		t.Errorf("entry: %d %v", status, entry)
	}
	if status, _ := f.get("/ledger/nope"); status != 404 {
		t.Errorf("unknown id: %d", status)
	}

	// The thread: request in, response out → completed, we were the responder.
	status, thread := f.get("/ledger/thread/" + corr)
	msgs, _ := thread["messages"].([]any)
	if status != 200 || thread["state"] != "completed" || thread["role"] != "responder" || thread["counterparty"] != "1000004805@hcx" || len(msgs) != 3 {
		t.Errorf("thread: %d %v", status, thread)
	}

	status, stats := f.get("/ledger/stats")
	if status != 200 || stats["total"] != float64(4) || stats["threads"] != float64(2) {
		t.Errorf("stats: %v", stats)
	}

	// Unauthenticated access is refused.
	req, _ := http.NewRequest(http.MethodGet, f.srv.URL+"/ledger", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ledger without key: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

// A sandbox gateway accepts the API key but does not demand it: the clients
// written for hcxkit authenticate none of these routes, and 401ing them all
// buys no security anybody asked for. Production is the opposite, and
// requireApiKey overrides either way.
func TestSandboxDoesNotDemandTheAPIKey(t *testing.T) {
	f := newFixture(t, "")

	// newFixture with no key leaves apiKey blank; build one that has a key
	// configured but is left at the sandbox default.
	cfgJSON := fmt.Sprintf(`{
	  "apiKey": "sekrit",
	  "participant": {"participantId": "1000003463", "clientId": "cid", "clientSecret": "sec", "privateKey": %q},
	  "callback": {"url": %q},
	  "urls": {"nhcx": %q, "participant": %q, "sessions": %q},
	  "ledger": {"dir": %q},
	  "log": {"level": "error"}
	}`, pemPrivate(t, f.self), f.callback.URL+"/hook",
		f.abdm.URL+"/hcx/v1", f.abdm.URL+"/registry", f.abdm.URL+"/sessions", t.TempDir())

	cfg, err := config.Parse([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKeyRequired() {
		t.Fatal("a sandbox gateway should not demand the API key by default")
	}
	gw, err := gateway.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(gw, slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Handler())
	defer srv.Close()

	// No Authorization header at all: the call is let through to be judged on
	// its merits, not turned away at the door.
	resp, err := http.Post(srv.URL+"/out/v1/preauth/submit", "application/json",
		strings.NewReader(`{"recipient":"1000004805@hcx","fhir":{"resourceType":"Bundle"}}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Errorf("sandbox refused an unauthenticated call: %d", resp.StatusCode)
	}

	// Production demands it, whatever else is configured.
	prod, err := config.Parse([]byte(strings.Replace(cfgJSON, `"apiKey": "sekrit",`,
		`"apiKey": "sekrit", "env": "production",`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	if !prod.APIKeyRequired() {
		t.Error("a production gateway must demand the API key")
	}
}

// A registry certificate that turns out to be one of ours stops the message
// in production — encrypting with it would put a payload on the wire that the
// far end cannot read. In the sandbox it does not: participants there are
// routinely onboarded under one credential and share a certificate, so the
// recipient really can decrypt, and refusing would wall off a working sandbox.
func TestSelfEncryptionKeyIsRefusedOnlyInProduction(t *testing.T) {
	base := `{
	  "participant": {"participantId": "1000003463", "clientId": "cid", "clientSecret": "sec", "privateKey": "KEY"},
	  "callback": {"url": "http://127.0.0.1:1/cb"}%s
	}`
	for _, tc := range []struct {
		name  string
		extra string
		want  bool
	}{
		{"sandbox allows it", "", false},
		{"production refuses it", `, "env": "production", "apiKey": "k"`, true},
		{"sandbox can opt in", `, "certs": {"refuseSelfKey": true}`, true},
		{"production can opt out", `, "env": "production", "apiKey": "k", "certs": {"refuseSelfKey": false}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.Parse([]byte(fmt.Sprintf(base, tc.extra)))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.RefusesSelfKey(); got != tc.want {
				t.Errorf("RefusesSelfKey() = %v, want %v", got, tc.want)
			}
		})
	}
}
