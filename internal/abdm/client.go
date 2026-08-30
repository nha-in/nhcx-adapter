// Package abdm is the gateway's client for the ABDM side of NHCX: session
// tokens, the participant registry (recipient certificates) and the exchange
// gateway itself. Everything is synchronous and in-memory, with no
// persistence.
//
// A gateway that hosts several participants gets one Client per profile, all
// sharing a Pool. What they share is deliberate: certificates describe a
// counterparty, not us, so one cache serves every profile; session tokens are
// issued per credential, so they are keyed by clientId and profiles that
// inherit the default's credentials share its token rather than opening a
// second session for the same client.
package abdm

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"nhcx-gateway/internal/config"
	"nhcx-gateway/internal/keys"
	"nhcx-gateway/internal/nhcx"
	"nhcx-gateway/internal/participant"
)

// Error is a typed failure with a stable code the HTTP surface and the CLI
// can report. Retryable marks failures a caller may reasonably repeat.
type Error struct {
	Code      string
	Message   string
	Retryable bool
	Status    int    // upstream HTTP status, when there was one
	Body      string // upstream response body, when there was one (bounded)
	Err       error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error { return e.Err }

// AsError extracts an *Error from err, wrapping unknown errors as INTERNAL.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: "INTERNAL", Message: err.Error(), Err: err}
}

const maxErrBody = 4096

// Pool is what every participant's client shares: the configuration, the set
// of local identities, one certificate cache and one token cache.
type Pool struct {
	cfg    *config.Config
	locals *participant.Set
	log    *slog.Logger
	http   *http.Client

	tokenMu sync.Mutex
	tokens  map[string]*tokenEntry // credential key -> session

	certMu sync.RWMutex
	certs  map[string]certEntry
}

type tokenEntry struct {
	token   string
	expires time.Time
}

type certEntry struct {
	pem     string
	key     *rsa.PublicKey
	expires time.Time
}

// NewPool builds the shared state for a gateway's clients.
func NewPool(cfg *config.Config, locals *participant.Set, logger *slog.Logger) *Pool {
	if logger == nil {
		logger = slog.Default()
	}
	return &Pool{
		cfg:    cfg,
		locals: locals,
		log:    logger,
		http:   &http.Client{Timeout: time.Duration(cfg.OutboundTimeoutSeconds) * time.Second},
		tokens: make(map[string]*tokenEntry),
		certs:  make(map[string]certEntry),
	}
}

// For returns the client that acts as prof.
func (p *Pool) For(prof *participant.Profile) *Client { return &Client{pool: p, prof: prof} }

// SetHTTPClient swaps the transport every client in the pool uses (tests).
func (p *Pool) SetHTTPClient(h *http.Client) { p.http = h }

// Client talks to ABDM as one participant.
type Client struct {
	pool *Pool
	prof *participant.Profile
}

// Profile is the identity this client acts as.
func (c *Client) Profile() *participant.Profile { return c.prof }

// Code is the participant code this client acts as.
func (c *Client) Code() string {
	if c.prof == nil {
		return ""
	}
	return c.prof.Code()
}

// credentials returns the clientId/clientSecret this client authenticates
// with, and the cache key its session token is stored under. Profiles that
// inherit the default's credentials therefore share one session.
func (c *Client) credentials() (id, secret, key string) {
	if c.prof != nil {
		id, secret = c.prof.Participant.ClientID, c.prof.Participant.ClientSecret
	}
	if id == "" {
		id, secret = c.pool.cfg.Participant.ClientID, c.pool.cfg.Participant.ClientSecret
	}
	key = id
	if key == "" {
		// No credentials anywhere: keep the profiles apart rather than
		// letting them collide on the empty key.
		key = "\x00" + c.Code()
	}
	return id, secret, key
}

// SetHTTPClient swaps the underlying transport (tests). It affects every
// client in the pool.
func (c *Client) SetHTTPClient(h *http.Client) { c.pool.SetHTTPClient(h) }

// ---------------------------------------------------------------- token ----

// Token returns a valid session token, fetching or refreshing it when the
// cached one is missing or within a minute of expiry. Concurrent callers
// share one fetch.
func (c *Client) Token(ctx context.Context) (string, error) {
	c.pool.tokenMu.Lock()
	defer c.pool.tokenMu.Unlock()
	_, _, key := c.credentials()
	if e := c.pool.tokens[key]; e != nil && e.token != "" && time.Until(e.expires) > time.Minute {
		return e.token, nil
	}
	return c.fetchTokenLocked(ctx)
}

// TokenInfo returns the current token (fetching one if needed) together
// with its expiry, for callers that use the token themselves.
func (c *Client) TokenInfo(ctx context.Context) (token string, expiresAt time.Time, err error) {
	if _, err = c.Token(ctx); err != nil {
		return "", time.Time{}, err
	}
	c.pool.tokenMu.Lock()
	defer c.pool.tokenMu.Unlock()
	_, _, key := c.credentials()
	if e := c.pool.tokens[key]; e != nil {
		return e.token, e.expires, nil
	}
	return "", time.Time{}, nil
}

// RefreshToken discards the cached token and fetches a new one.
func (c *Client) RefreshToken(ctx context.Context) (string, error) {
	c.pool.tokenMu.Lock()
	defer c.pool.tokenMu.Unlock()
	return c.fetchTokenLocked(ctx)
}

// TokenValid reports whether a usable token is cached (readiness probe).
func (c *Client) TokenValid() bool {
	c.pool.tokenMu.Lock()
	defer c.pool.tokenMu.Unlock()
	_, _, key := c.credentials()
	e := c.pool.tokens[key]
	return e != nil && e.token != "" && time.Now().Before(e.expires)
}

func (c *Client) fetchTokenLocked(ctx context.Context) (string, error) {
	var (
		req *http.Request
		err error
	)
	clientID, clientSecret, cacheKey := c.credentials()
	switch c.cfg().Auth.Mode {
	case "get-session":
		form := url.Values{
			"client_id":     {clientID},
			"client_secret": {clientSecret},
			"grant_type":    {"client_credentials"},
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.cfg().URLs.Sessions, strings.NewReader(form.Encode()))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	default:
		body, _ := json.Marshal(map[string]string{
			"clientId":     clientID,
			"clientSecret": clientSecret,
			"grantType":    "client_credentials",
		})
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.cfg().URLs.Sessions, bytes.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("REQUEST-ID", uuid.New().String())
			req.Header.Set("TIMESTAMP", time.Now().UTC().Format(time.RFC3339))
			req.Header.Set("X-CM-ID", c.cfg().CMID)
		}
	}
	if err != nil {
		return "", &Error{Code: "TOKEN_REQUEST", Message: "build session request", Err: err}
	}
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return "", &Error{Code: "TOKEN_UNREACHABLE", Message: "session endpoint unreachable", Retryable: true, Err: err}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &Error{
			Code: fmt.Sprintf("TOKEN_HTTP_%d", resp.StatusCode), Message: "session endpoint rejected the credentials",
			Retryable: resp.StatusCode >= 500 || resp.StatusCode == 429, Status: resp.StatusCode, Body: clip(raw),
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", &Error{Code: "TOKEN_BAD_JSON", Message: "session response is not JSON", Retryable: true, Err: err, Body: clip(raw)}
	}
	token := firstString(out, "accessToken", "access_token")
	if token == "" {
		return "", &Error{Code: "TOKEN_MISSING", Message: "session response carried no access token", Body: clip(raw)}
	}
	ttl := time.Duration(c.cfg().Auth.TokenTTLSeconds) * time.Second
	if n := firstNumber(out, "expiresIn", "expires_in"); n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	c.pool.tokens[cacheKey] = &tokenEntry{token: token, expires: time.Now().Add(ttl)}
	c.log().Info("session token refreshed", "participant", c.Code(), "mode", c.cfg().Auth.Mode,
		"ttl", ttl.String(), "took", time.Since(start).Round(time.Millisecond).String())
	return token, nil
}

// ---------------------------------------------------------------- certs ----

// Certificate returns the RSA public key of a participant, from the cache
// when fresh, otherwise from the registry. The code may be given in either
// spelling.
func (c *Client) Certificate(ctx context.Context, code string) (*rsa.PublicKey, string, error) {
	code = nhcx.NormalizeCode(code)
	if code == "" {
		return nil, "", &Error{Code: "NO_RECIPIENT", Message: "participant code is empty"}
	}
	c.pool.certMu.RLock()
	entry, ok := c.pool.certs[strings.ToLower(code)]
	c.pool.certMu.RUnlock()
	if ok && time.Now().Before(entry.expires) {
		return entry.key, entry.pem, nil
	}
	return c.FetchCertificate(ctx, code)
}

// FetchCertificate always asks the registry and refreshes the cache.
func (c *Client) FetchCertificate(ctx context.Context, code string) (*rsa.PublicKey, string, error) {
	code = nhcx.NormalizeCode(code)
	if code == "" {
		return nil, "", &Error{Code: "NO_RECIPIENT", Message: "participant code is empty"}
	}
	endpoint := strings.TrimRight(c.cfg().URLs.Participant, "/") + "/fetch/certs"
	status, raw, err := c.postWithToken(ctx, endpoint, map[string]string{"participantid": code}, false)
	if err != nil {
		return nil, "", err
	}
	if status < 200 || status >= 300 {
		return nil, "", &Error{
			Code: fmt.Sprintf("CERT_FETCH_HTTP_%d", status), Message: "participant registry refused the certificate lookup for " + code,
			Retryable: status >= 500 || status == 429, Status: status, Body: clip(raw),
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, "", &Error{Code: "CERT_FETCH_BAD_JSON", Message: "registry response is not JSON", Retryable: true, Err: err, Body: clip(raw)}
	}
	pem := firstString(out, "encryption_cert", "encryptionCert", "cert")
	if pem == "" {
		return nil, "", &Error{Code: "CERT_NOT_FOUND", Message: "registry returned no encryption certificate for " + code, Body: clip(raw)}
	}
	// The registry answers "Invalid Certificate Found" as plain text for
	// participants without a certificate; that must never be cached.
	pub, err := keys.ParsePublicKey(pem)
	if err != nil {
		return nil, "", &Error{Code: "CERT_NOT_FOUND", Message: fmt.Sprintf("registry returned no usable certificate for %s: %q", code, clipStr(pem, 120)), Err: err}
	}
	// The registry has handed back one of our own keys for somebody else.
	// Whether that is fatal depends on where we are — see
	// config.RefusesSelfKey. It is never fatal for a participant this gateway
	// hosts itself (a loopback test, or one hosted participant writing to
	// another): there the local key is genuinely the recipient's key.
	if c.locals().OwnsKey(pub) && !c.locals().IsLocal(code) {
		if c.cfg().RefusesSelfKey() {
			return nil, "", &Error{Code: "SELF_ENCRYPTION_KEY", Message: "registry certificate for " + code + " is this gateway's own key; a payload encrypted with it would be unreadable at the far end"}
		}
		c.log().Warn("registry certificate is this gateway's own key",
			"participant", code,
			"note", "expected in a sandbox where participants share one certificate; "+
				"in production this would be unreadable at the far end")
	}
	c.pool.certMu.Lock()
	c.pool.certs[strings.ToLower(code)] = certEntry{pem: pem, key: pub, expires: time.Now().Add(time.Duration(c.cfg().Certs.CacheHours) * time.Hour)}
	c.pool.certMu.Unlock()
	c.log().Info("certificate fetched", "participant", code)
	return pub, pem, nil
}

// PostRegistry sends a JSON body to a path on the participant registry with
// this participant's session token, and hands back the status and raw body.
// It exists for the registry calls the gateway does not model itself — the
// policy search a kit client asks for — so they go out with the same token
// handling, refresh-on-401 and timeouts as everything else.
func (c *Client) PostRegistry(ctx context.Context, path string, body any) (int, []byte, error) {
	endpoint := strings.TrimRight(c.cfg().URLs.Participant, "/") + "/" + strings.TrimLeft(path, "/")
	return c.postWithToken(ctx, endpoint, body, false)
}

// Participant is a registry record, as far as the gateway cares.
type Participant struct {
	Code        string
	Name        string
	Status      string
	EndpointURL string
	Roles       []string
	Raw         map[string]any
}

// FetchParticipant reads a participant's registry record via
// /participant/search.
func (c *Client) FetchParticipant(ctx context.Context, code string) (*Participant, error) {
	code = nhcx.NormalizeCode(code)
	endpoint := strings.TrimRight(c.cfg().URLs.Participant, "/") + "/participant/search"
	status, raw, err := c.postWithToken(ctx, endpoint, map[string]string{"participant_code": code, "participantcode": code, "participantid": code}, false)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, &Error{Code: fmt.Sprintf("PARTICIPANT_HTTP_%d", status), Message: "participant registry refused the search for " + code,
			Retryable: status >= 500 || status == 429, Status: status, Body: clip(raw)}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, &Error{Code: "PARTICIPANT_BAD_JSON", Message: "registry response is not JSON", Err: err, Body: clip(raw)}
	}
	// The record may be the body itself or the first entry of "participants".
	rec := out
	if list, ok := out["participants"].([]any); ok {
		rec = nil
		for _, item := range list {
			if m, ok := item.(map[string]any); ok && nhcx.SameCode(firstString(m, "participant_code", "participantcode", "participantid"), code) {
				rec = m
				break
			}
		}
		if rec == nil && len(list) > 0 {
			rec, _ = list[0].(map[string]any)
		}
	}
	if rec == nil || firstString(rec, "participant_code", "participantcode", "participantid") == "" {
		return nil, &Error{Code: "PARTICIPANT_NOT_FOUND", Message: "registry has no record for " + code, Body: clip(raw)}
	}
	p := &Participant{
		Code:        nhcx.NormalizeCode(firstString(rec, "participant_code", "participantcode", "participantid")),
		Name:        firstString(rec, "participant_name", "participantname", "name"),
		Status:      firstString(rec, "status"),
		EndpointURL: firstString(rec, "endpoint_url", "endpointurl", "endpointUrl"),
		Raw:         rec,
	}
	for _, k := range []string{"roles", "role_code"} {
		if list, ok := rec[k].([]any); ok {
			for _, r := range list {
				if s, ok := r.(string); ok {
					p.Roles = append(p.Roles, s)
				}
			}
			if len(p.Roles) > 0 {
				break
			}
		}
	}
	return p, nil
}

// UpdateCertificate registers a new encryption certificate for this
// participant via /participant/update. roles is required by the registry on
// every update; pass what FetchParticipant returned.
func (c *Client) UpdateCertificate(ctx context.Context, certPEM string, roles []string) (json.RawMessage, error) {
	return c.updateParticipant(ctx, map[string]any{"encryption_cert": strings.TrimSpace(certPEM)}, roles)
}

// UpdateEndpoint registers where NHCX should deliver this participant's
// callbacks.
func (c *Client) UpdateEndpoint(ctx context.Context, endpointURL string, roles []string) (json.RawMessage, error) {
	return c.updateParticipant(ctx, map[string]any{"endpoint_url": strings.TrimSpace(endpointURL)}, roles)
}

func (c *Client) updateParticipant(ctx context.Context, fields map[string]any, roles []string) (json.RawMessage, error) {
	body := map[string]any{
		"participant_code": c.Code(),
		"scheme_code":      "PMJAY",
	}
	for k, v := range fields {
		body[k] = v
	}
	if len(roles) > 0 {
		body["roles"] = roles
	}
	endpoint := strings.TrimRight(c.cfg().URLs.Participant, "/") + "/participant/update"
	status, raw, err := c.postWithToken(ctx, endpoint, body, false)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, &Error{Code: fmt.Sprintf("PARTICIPANT_UPDATE_HTTP_%d", status), Message: "participant registry refused the certificate update",
			Retryable: status >= 500 || status == 429, Status: status, Body: clip(raw)}
	}
	c.ForgetCertificate(c.Code())
	if json.Valid(raw) {
		return json.RawMessage(raw), nil
	}
	out, _ := json.Marshal(string(raw))
	return out, nil
}

// OwnKey returns the public key this participant decrypts with.
func (c *Client) OwnKey() *rsa.PublicKey {
	if c.prof == nil {
		return nil
	}
	return c.prof.PublicKey()
}

// ForgetCertificate drops one cached certificate.
func (c *Client) ForgetCertificate(code string) {
	c.pool.certMu.Lock()
	delete(c.pool.certs, strings.ToLower(nhcx.NormalizeCode(code)))
	c.pool.certMu.Unlock()
}

// Shorthands for the pool's shared pieces.
func (c *Client) cfg() *config.Config      { return c.pool.cfg }
func (c *Client) log() *slog.Logger        { return c.pool.log }
func (c *Client) locals() *participant.Set { return c.pool.locals }
func (c *Client) httpClient() *http.Client { return c.pool.http }

// -------------------------------------------------------------- gateway ----

// GatewayResult is what the NHCX gateway answered to a dispatch.
type GatewayResult struct {
	URL        string
	StatusCode int
	Body       json.RawMessage
	Duration   time.Duration
}

// Dispatch posts a compact JWE to the NHCX API path. Response ("on_") APIs
// additionally declare the payload type in the body. A 401 from the gateway
// refreshes the token once and retries; any other status is returned to the
// caller as-is, with the body verbatim.
func (c *Client) Dispatch(ctx context.Context, path, compact string) (*GatewayResult, error) {
	target := nhcx.TargetURL(c.cfg().URLs.NHCX, path)
	body := map[string]string{"payload": compact}
	if nhcx.IsResponsePath(path) {
		body["type"] = "JWEPayload"
	}
	start := time.Now()
	status, raw, err := c.postWithToken(ctx, target, body, true)
	if err != nil {
		return nil, err
	}
	res := &GatewayResult{URL: target, StatusCode: status, Duration: time.Since(start)}
	if json.Valid(raw) {
		res.Body = json.RawMessage(raw)
	} else if len(raw) > 0 {
		res.Body, _ = json.Marshal(string(raw))
	} else {
		res.Body = json.RawMessage("null")
	}
	return res, nil
}

// postWithToken sends a JSON body with the session token, refreshing it once
// on a 401. gateway selects which error codes describe a transport failure.
func (c *Client) postWithToken(ctx context.Context, endpoint string, body any, gateway bool) (int, []byte, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return 0, nil, &Error{Code: "MARSHAL_ERROR", Message: "encode request body", Err: err}
	}
	label := "CERT_FETCH"
	if gateway {
		label = "GATEWAY"
	}
	for attempt := 0; attempt < 2; attempt++ {
		token, err := c.Token(ctx)
		if err != nil {
			return 0, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return 0, nil, &Error{Code: label + "_REQUEST", Message: "build request", Err: err}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		// NHCX documents its auth header as "bearer_auth"; Go would
		// canonicalise it to "Bearer_auth", so the map is written directly.
		// Authorization is sent as well for the services that read that one.
		req.Header["bearer_auth"] = []string{"Bearer " + token}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := c.httpClient().Do(req)
		if err != nil {
			return 0, nil, &Error{Code: label + "_UNREACHABLE", Message: endpoint + " unreachable", Retryable: true, Err: err}
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if readErr != nil {
			return 0, nil, &Error{Code: label + "_READ_ERROR", Message: "read response", Retryable: true, Err: readErr}
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			c.log().Warn("upstream answered 401, refreshing session token", "url", endpoint)
			if _, err := c.RefreshToken(ctx); err != nil {
				return 0, nil, err
			}
			continue
		}
		return resp.StatusCode, raw, nil
	}
	return 0, nil, &Error{Code: label + "_UNAUTHORIZED", Message: "upstream kept answering 401 after a token refresh", Status: http.StatusUnauthorized}
}

// ------------------------------------------------------------- helpers ----

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func firstNumber(m map[string]any, keys ...string) float64 {
	for _, k := range keys {
		switch v := m[k].(type) {
		case float64:
			return v
		case string:
			var f float64
			if _, err := fmt.Sscanf(v, "%g", &f); err == nil {
				return f
			}
		}
	}
	return 0
}

func clip(b []byte) string { return clipStr(string(b), maxErrBody) }

func clipStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
