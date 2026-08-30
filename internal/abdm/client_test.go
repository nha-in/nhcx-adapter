package abdm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"nhcx-gateway/internal/config"
)

func newClient(t *testing.T, mode, sessionsURL string) *Client {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`{
	  "participant": {"participantId": "1@hcx", "clientId": "cid", "clientSecret": "sec", "privateKey": "x"},
	  "auth": {"mode": %q, "tokenTtlSeconds": 300},
	  "urls": {"sessions": %q}
	}`, mode, sessionsURL)))
	if err != nil {
		t.Fatal(err)
	}
	// No participant set: the client falls back to the default profile's
	// credentials, which is all these tests exercise.
	return NewPool(cfg, nil, slog.New(slog.NewTextHandler(io.Discard, nil))).For(nil)
}

func TestGetSessionFormMode(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("content type %s", ct)
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "sec" || r.Form.Get("grant_type") != "client_credentials" {
			t.Errorf("form %v", r.Form)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "abc", "expires_in": 1200, "token_type": "Bearer"})
	}))
	defer srv.Close()

	c := newClient(t, "get-session", srv.URL)
	tok, err := c.Token(context.Background())
	if err != nil || tok != "abc" {
		t.Fatalf("token %q err %v", tok, err)
	}
	_, exp, _ := c.TokenInfo(context.Background())
	if ttl := time.Until(exp); ttl < 19*time.Minute || ttl > 20*time.Minute {
		t.Errorf("expires_in not honoured: %s", ttl)
	}
	if _, err := c.Token(context.Background()); err != nil || calls != 1 {
		t.Errorf("second call must hit the cache, calls=%d err=%v", calls, err)
	}
	if !c.TokenValid() {
		t.Error("token should be valid")
	}
}

func TestSessionsModeDefaultsTTLAndReportsRejection(t *testing.T) {
	reject := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"error":"invalid client"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "t"}) // no expiry field
	}))
	defer srv.Close()

	c := newClient(t, "sessions", srv.URL)
	_, err := c.Token(context.Background())
	e := AsError(err)
	if e == nil || e.Code != "TOKEN_HTTP_401" || e.Retryable || e.Body == "" {
		t.Fatalf("expected a typed 401 error, got %v", err)
	}
	reject = false
	if _, err := c.Token(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, exp, _ := c.TokenInfo(context.Background())
	if ttl := time.Until(exp); ttl < 4*time.Minute || ttl > 5*time.Minute {
		t.Errorf("configured tokenTtlSeconds must apply when the response has no expiry: %s", ttl)
	}
}
