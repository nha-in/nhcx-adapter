package server

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"nhcx-adapter/internal/adapter"
	"nhcx-adapter/internal/config"
	"nhcx-adapter/internal/nhcx"
)

// An adapter hosting two identities has to get two things right that a
// single-participant one never faced: an inbound message must reach the
// callback of the participant it is addressed to, and an outbound one must go
// out as the participant that sent it. These tests pin both.

type hosted struct {
	t        *testing.T
	self     *rsa.PrivateKey // the default participant's key
	tenant   *rsa.PrivateKey // the hosted participant's own key
	payer    *rsa.PrivateKey // the counterparty
	abdm     *httptest.Server
	srv      *httptest.Server
	gw       *adapter.Adapter
	sessions map[string]int // clientId -> sessions issued

	mu       sync.Mutex
	hits     map[string][]string // callback name -> paths delivered
	lastHdr  http.Header
	lastBody []byte
	sent     []byte
}

const defaultCode = "1000003463@hcx"
const tenantCode = "1000004805@hcx"

func newHosted(t *testing.T, tenantKeyOfItsOwn bool, tenantCreds bool) *hosted {
	t.Helper()
	h := &hosted{t: t, hits: map[string][]string{}, sessions: map[string]int{}}
	h.self, _ = rsa.GenerateKey(rand.Reader, 2048)
	h.tenant, _ = rsa.GenerateKey(rand.Reader, 2048)
	h.payer, _ = rsa.GenerateKey(rand.Reader, 2048)

	tenantKey := h.self
	if tenantKeyOfItsOwn {
		tenantKey = h.tenant
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /sessions", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		h.mu.Lock()
		h.sessions[body["clientId"]]++
		n := h.sessions[body["clientId"]]
		h.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"accessToken": fmt.Sprintf("tok-%s-%d", body["clientId"], n), "expiresIn": 1200,
		})
	})
	mux.HandleFunc("POST /registry/fetch/certs", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch body["participantid"] {
		case "1000007777@hcx":
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption_cert": pemPublic(t, &h.payer.PublicKey)})
		case tenantCode:
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption_cert": pemPublic(t, &tenantKey.PublicKey)})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"encryption_cert": pemPublic(t, &h.self.PublicKey)})
		}
	})
	mux.HandleFunc("POST /hcx/v1/{path...}", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.sent = body
		h.lastHdr = r.Header.Clone()
		h.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]any{"timestamp": "x"})
	})
	h.abdm = httptest.NewServer(mux)
	t.Cleanup(h.abdm.Close)

	// One server, two mount points: whichever path is hit tells us which
	// participant's callback the adapter chose.
	cb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := "default"
		if strings.HasPrefix(r.URL.Path, "/tenant") {
			name = "tenant"
		}
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		h.hits[name] = append(h.hits[name], r.URL.Path)
		h.lastHdr, h.lastBody = r.Header.Clone(), body
		h.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(cb.Close)

	tenantFields := fmt.Sprintf(`"participantId": %q, "name": "Dummy IRDAI Payer",
	     "callback": {"url": %q, "apiKey": "tenant-secret"}`, tenantCode, cb.URL+"/tenant")
	if tenantKeyOfItsOwn {
		tenantFields += fmt.Sprintf(`, "privateKey": %q`, pemPrivate(t, h.tenant))
	}
	if tenantCreds {
		tenantFields += `, "clientId": "tenant-cid", "clientSecret": "tenant-sec"`
	}

	cfgJSON := fmt.Sprintf(`{
	  "participant": {"participantId": %q, "name": "Kyro Max", "clientId": "cid", "clientSecret": "sec", "privateKey": %q},
	  "participants": [{%s}],
	  "callback": {"url": %q, "apiKey": "default-secret"},
	  "urls": {"nhcx": %q, "participant": %q, "sessions": %q},
	  "ledger": {"dir": %q},
	  "log": {"level": "error"}
	}`, defaultCode, pemPrivate(t, h.self), tenantFields, cb.URL+"/hook",
		h.abdm.URL+"/hcx/v1", h.abdm.URL+"/registry", h.abdm.URL+"/sessions", t.TempDir())

	cfg, err := config.Parse([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateServe(); err != nil {
		t.Fatal(err)
	}
	gw, err := adapter.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h.gw = gw
	h.srv = httptest.NewServer(New(gw, slog.New(slog.NewTextHandler(io.Discard, nil)), "test").Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func (h *hosted) post(path, body string) (int, map[string]any) {
	h.t.Helper()
	resp, err := http.Post(h.srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// inbound builds a JWE addressed to code, encrypted with key.
func (h *hosted) inbound(path, code string, key *rsa.PrivateKey) string {
	h.t.Helper()
	compact, err := nhcx.Encrypt([]byte(`{"resourceType":"Bundle","id":"b1"}`), &key.PublicKey,
		nhcx.BuildProtectedHeaders(map[string]any{
			nhcx.HdrSender: "1000007777@hcx", nhcx.HdrRecipient: code, nhcx.HdrCorrelationID: nhcx.NewID(),
		}, path))
	if err != nil {
		h.t.Fatal(err)
	}
	return `{"payload":"` + compact + `"}`
}

func (h *hosted) delivered(name string) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.hits[name]...)
}

// A message for the hosted participant must reach the hosted participant's
// callback — the whole point of hosting it.
func TestInboundRoutesToTheAddressedParticipantsCallback(t *testing.T) {
	h := newHosted(t, false, false)

	status, out := h.post("/in/v1/preauth/on_submit", h.inbound("v1/preauth/on_submit", tenantCode, h.self))
	if status != http.StatusAccepted {
		t.Fatalf("tenant delivery: %d %v", status, out)
	}
	if got := h.delivered("tenant"); len(got) != 1 || got[0] != "/tenant/v1/preauth/on_submit" {
		t.Errorf("tenant callback got %v", got)
	}
	if got := h.delivered("default"); len(got) != 0 {
		t.Errorf("default callback should not have been called: %v", got)
	}

	// The per-participant API key travels with it, not the shared one.
	h.mu.Lock()
	auth := h.lastHdr.Get("Authorization")
	who := h.lastHdr.Get("X-Nhcx-Participant")
	body := append([]byte(nil), h.lastBody...)
	h.mu.Unlock()
	if auth != "Bearer tenant-secret" {
		t.Errorf("tenant callback authorization = %q", auth)
	}
	if who != tenantCode {
		t.Errorf("X-Nhcx-Participant = %q", who)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if meta, _ := env["meta"].(map[string]any); meta["participant"] != tenantCode {
		t.Errorf("envelope meta.participant = %v", env["meta"])
	}

	// …and one for the default participant still goes to the default callback.
	if status, out := h.post("/in/v1/claim/on_submit", h.inbound("v1/claim/on_submit", defaultCode, h.self)); status != http.StatusAccepted {
		t.Fatalf("default delivery: %d %v", status, out)
	}
	if got := h.delivered("default"); len(got) != 1 || got[0] != "/hook/v1/claim/on_submit" {
		t.Errorf("default callback got %v", got)
	}
}

// A hosted participant with a certificate of its own is decrypted with that
// key, not the default's.
func TestInboundDecryptsWithTheHostedParticipantsOwnKey(t *testing.T) {
	h := newHosted(t, true, false)

	status, out := h.post("/in/v1/preauth/on_submit", h.inbound("v1/preauth/on_submit", tenantCode, h.tenant))
	if status != http.StatusAccepted {
		t.Fatalf("status %d %v", status, out)
	}
	if got := h.delivered("tenant"); len(got) != 1 {
		t.Errorf("tenant callback got %v", got)
	}
	// The default participant's key must still work for its own traffic.
	if status, _ := h.post("/in/v1/claim/on_submit", h.inbound("v1/claim/on_submit", defaultCode, h.self)); status != http.StatusAccepted {
		t.Errorf("default participant status %d", status)
	}
}

// A code this adapter does not hold is still refused, and the error names
// every code it does hold rather than only the default.
func TestInboundRefusesACodeNoParticipantHolds(t *testing.T) {
	h := newHosted(t, false, false)
	status, out := h.post("/in/v1/claim/on_submit", h.inbound("v1/claim/on_submit", "1000001111@hcx", h.self))
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		t.Fatalf("status %d %v", status, out)
	}
	msg := fmt.Sprint(out["error"])
	if !strings.Contains(msg, "1000001111@hcx") || !strings.Contains(msg, defaultCode) || !strings.Contains(msg, tenantCode) {
		t.Errorf("error should name the addressed code and every hosted one: %v", out["error"])
	}
	if len(h.delivered("tenant"))+len(h.delivered("default")) != 0 {
		t.Error("a refused message must not be delivered anywhere")
	}
}

// Outbound goes out as the sender named in the envelope, and with that
// participant's session token when it has credentials of its own.
func TestOutboundSendsAsTheNamedParticipant(t *testing.T) {
	h := newHosted(t, false, true)

	body := fmt.Sprintf(`{"sender": %q, "recipient": "1000007777@hcx", "fhir": {"resourceType":"Bundle","id":"b1"}}`, tenantCode)
	status, out := h.post("/out/v1/preauth/submit", body)
	if status != http.StatusAccepted {
		t.Fatalf("status %d %v", status, out)
	}

	h.mu.Lock()
	sent, hdr := h.sent, h.lastHdr.Clone()
	h.mu.Unlock()

	var envelope map[string]string
	if err := json.Unmarshal(sent, &envelope); err != nil {
		t.Fatal(err)
	}
	protected, err := nhcx.ParseHeader(envelope["payload"])
	if err != nil {
		t.Fatal(err)
	}
	if got := nhcx.GetString(protected, nhcx.HdrSender); got != tenantCode {
		t.Errorf("x-hcx-sender_code = %q, want the hosted participant", got)
	}
	// Its own credentials mean its own session, not the default's.
	if auth := hdr.Get("Authorization"); auth != "Bearer tok-tenant-cid-1" {
		t.Errorf("dispatched with %q, want the hosted participant's token", auth)
	}

	// The default participant still sends as itself when no sender is named.
	if status, out := h.post("/out/v1/claim/submit", `{"recipient": "1000007777@hcx", "fhir": {"resourceType":"Bundle"}}`); status != http.StatusAccepted {
		t.Fatalf("default send: %d %v", status, out)
	}
	h.mu.Lock()
	sent, hdr = h.sent, h.lastHdr.Clone()
	h.mu.Unlock()
	_ = json.Unmarshal(sent, &envelope)
	protected, _ = nhcx.ParseHeader(envelope["payload"])
	if got := nhcx.GetString(protected, nhcx.HdrSender); got != defaultCode {
		t.Errorf("default sender = %q", got)
	}
	if auth := hdr.Get("Authorization"); auth != "Bearer tok-cid-1" {
		t.Errorf("default dispatched with %q", auth)
	}
}

// A hosted participant without credentials of its own shares the default's
// session rather than opening a second one for the same client.
func TestHostedParticipantWithoutCredentialsSharesTheDefaultSession(t *testing.T) {
	h := newHosted(t, false, false)

	for _, sender := range []string{defaultCode, tenantCode} {
		body := fmt.Sprintf(`{"sender": %q, "recipient": "1000007777@hcx", "fhir": {"resourceType":"Bundle"}}`, sender)
		if status, out := h.post("/out/v1/preauth/submit", body); status != http.StatusAccepted {
			t.Fatalf("send as %s: %d %v", sender, status, out)
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if n := h.sessions["cid"]; n != 1 {
		t.Errorf("sessions minted for the shared credential = %d, want 1", n)
	}
}

// One participant hosted here writing to another is legitimate: the local key
// really is the recipient's key, so the self-encryption guard must not fire.
func TestOneHostedParticipantMayWriteToAnother(t *testing.T) {
	h := newHosted(t, true, false)
	body := fmt.Sprintf(`{"sender": %q, "recipient": %q, "fhir": {"resourceType":"Bundle"}}`, defaultCode, tenantCode)
	if status, out := h.post("/out/v1/preauth/submit", body); status != http.StatusAccepted {
		t.Fatalf("loopback send refused: %d %v", status, out)
	}
}
