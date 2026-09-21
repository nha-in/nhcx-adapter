package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"nhcx-adapter/internal/adapter"
	"nhcx-adapter/internal/config"
	"nhcx-adapter/internal/nhcx"
)

// The password the fixture's panel is configured with.
const panelPassword = "panel-secret-xyz"

// panelClient is a browser: it keeps the session cookie and does not follow
// the redirect a login answers with, so the test can look at it.
func panelClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (f *fixture) signIn(t *testing.T, c *http.Client, password string) *http.Response {
	t.Helper()
	resp, err := c.PostForm(f.srv.URL+"/panel/login", url.Values{"password": {password}})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func TestPanelLoginGuardsEverything(t *testing.T) {
	f := newFixture(t, "k")
	c := panelClient(t)

	// The console itself: the login form until there is a session.
	resp, err := c.Get(f.srv.URL + "/panel")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Sign in") {
		t.Fatalf("signed out, /panel should show the login form; got %d %.80s", resp.StatusCode, body)
	}
	if strings.Contains(string(body), "id=\"tabs\"") {
		t.Error("the console was served to a caller with no session")
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("the panel must ship a content security policy, got %q", csp)
	}

	// The API: 401, and as JSON, so the page can tell it apart from a 404.
	resp, err = c.Get(f.srv.URL + "/panel/api/overview")
	if err != nil {
		t.Fatal(err)
	}
	var errBody map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&errBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API call: want 401, got %d", resp.StatusCode)
	}

	// A wrong password does not mint a session.
	if resp := f.signIn(t, c, "not-the-password"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: want 401, got %d", resp.StatusCode)
	}
	if len(c.Jar.Cookies(mustURL(t, f.srv.URL+"/panel"))) != 0 {
		t.Fatal("a failed login left a cookie behind")
	}

	// The right one does.
	if resp := f.signIn(t, c, panelPassword); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: want 303, got %d", resp.StatusCode)
	}
	cookies := c.Jar.Cookies(mustURL(t, f.srv.URL+"/panel"))
	if len(cookies) != 1 || cookies[0].Name != panelCookie {
		t.Fatalf("login should set exactly the session cookie, got %v", cookies)
	}

	resp, err = c.Get(f.srv.URL + "/panel/api/overview")
	if err != nil {
		t.Fatal(err)
	}
	var overview map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&overview)
	resp.Body.Close()
	if resp.StatusCode != 200 || overview["env"] != "sandbox" {
		t.Fatalf("overview after signing in: %d %v", resp.StatusCode, overview)
	}
	if _, ok := overview["stats"]; !ok {
		t.Error("the overview should carry the ledger stats")
	}

	// And the console is served now.
	resp, _ = c.Get(f.srv.URL + "/panel")
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `id="tabs"`) {
		t.Error("a signed-in caller should get the console")
	}

	// Signing out ends it.
	resp, err = c.Post(f.srv.URL+"/panel/logout", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, _ = c.Get(f.srv.URL + "/panel/api/overview")
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after signing out: want 401, got %d", resp.StatusCode)
	}
}

// A session cookie is not enough for anything that changes something: a
// cross-site form can carry the cookie but cannot set a header.
func TestPanelWritesNeedTheHeader(t *testing.T) {
	f := newFixture(t, "k")
	c := panelClient(t)
	f.signIn(t, c, panelPassword)

	body := `{"path":"v1/coverageeligibility/check","recipient":"1000004805@hcx","fhir":{"resourceType":"Bundle","type":"collection"}}`
	resp, err := c.Post(f.srv.URL+"/panel/api/send", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a POST without X-Panel-Request must be refused, got %d", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, f.srv.URL+"/panel/api/send", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Panel-Request", "1")
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&sent)
	resp.Body.Close()
	if resp.StatusCode != 200 || sent["ok"] != true {
		t.Fatalf("panel send: %d %v", resp.StatusCode, sent)
	}
	if sent["ledger_id"] == "" || sent["correlation_id"] == "" {
		t.Errorf("a send should answer with its ledger id and correlation id: %v", sent)
	}
	// It went through the same door as /out: the exchange got a JWE the
	// recipient can open, addressed by this adapter.
	hdr, plain, _ := f.sentJWE()
	if hdr[nhcx.HdrRecipient] != "1000004805@hcx" || !strings.Contains(plain, "Bundle") {
		t.Errorf("what reached the exchange: %v %s", hdr, plain)
	}
}

// Guessing is slowed down per address.
func TestPanelLoginRateLimited(t *testing.T) {
	f := newFixture(t, "k")
	c := panelClient(t)
	for i := 0; i < loginFreeTries; i++ {
		if resp := f.signIn(t, c, "wrong"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, resp.StatusCode)
		}
	}
	if resp := f.signIn(t, c, panelPassword); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after %d failures even the right password must wait; got %d", loginFreeTries, resp.StatusCode)
	}
}

// The live view: the stream carries what is already on record, then what
// happens next, as it happens.
func TestPanelStreamsLiveTraffic(t *testing.T) {
	f := newFixture(t, "k")
	c := panelClient(t)
	f.signIn(t, c, panelPassword)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, f.srv.URL+"/panel/api/stream?backfill=5", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("stream content type = %q", ct)
	}

	events := make(chan string, 16)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		var event string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				event = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: ") && event != "":
				events <- event + " " + strings.TrimPrefix(line, "data: ")
				event = ""
			}
		}
	}()

	// "ready" means the backlog is done and the stream is live.
	waitFor(t, events, "ready", 10*time.Second)

	// Now make some traffic and watch it arrive.
	status, out := f.post("/out/v1/coverageeligibility/check",
		`{"recipient":"1000004805@hcx","fhir":{"resourceType":"Bundle","type":"collection"}}`, nil)
	if status != http.StatusAccepted {
		t.Fatalf("the send the stream is supposed to show failed: %d %v", status, out)
	}
	line := waitFor(t, events, "message", 10*time.Second)
	var sm map[string]any
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "message ")), &sm); err != nil {
		t.Fatalf("streamed event is not JSON: %v", err)
	}
	if sm["path"] != "v1/coverageeligibility/check" || sm["direction"] != "out" || sm["status"] != "accepted" {
		t.Fatalf("streamed the wrong thing: %v", sm)
	}
	if sm["id"] != out["ledger_id"] {
		t.Errorf("the streamed entry should be the one the send recorded: %v vs %v", sm["id"], out["ledger_id"])
	}
}

func waitFor(t *testing.T, events <-chan string, want string, limit time.Duration) string {
	t.Helper()
	deadline := time.After(limit)
	for {
		select {
		case line := <-events:
			if strings.HasPrefix(line, want+" ") {
				return line
			}
		case <-deadline:
			t.Fatalf("no %q event within %s", want, limit)
		}
	}
}

// With no password there is no panel at all — not an open one.
func TestPanelOffWithoutAPassword(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cfgJSON := fmt.Sprintf(`{
	  "participant": {"participantId": "1000003463", "clientId": "cid", "clientSecret": "sec", "privateKey": %q},
	  "callback": {"url": "http://127.0.0.1:1/hook"},
	  "ledger": {"enabled": false},
	  "log": {"level": "error"}
	}`, pemPrivate(t, key))
	cfg, err := config.Parse([]byte(cfgJSON))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PanelEnabled() {
		t.Fatal("the panel must be off until a password is set")
	}
	gw, err := adapter.New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	srv := New(gw, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	if srv.panel != nil {
		t.Fatal("a server with no panel password should have no panel")
	}
	handler := srv.Handler()
	for _, path := range []string{"/panel", "/panel/api/overview", "/panel/api/stream"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s with the panel off: want 404, got %d", path, rec.Code)
		}
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
