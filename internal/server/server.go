// Package server is the HTTP surface of nhcx-gateway:
//
//	POST /out/{nhcx-path}   integrator → NHCX  (encrypt + dispatch, sync)
//	POST /in/{nhcx-path}    NHCX → integrator  (decrypt + deliver, sync)
//	POST /{nhcx-path}       alias of /in for a registry endpoint_url of "/"
//	GET  /ledger            recorded messages, newest first, with filters (API key)
//	GET  /ledger/stats      counts (API key)
//	GET  /ledger/thread/{correlation_id}   one exchange with its derived state (API key)
//	GET  /ledger/{id}       one message in full, bundle included (API key)
//	GET  /token             the ABDM session token this gateway holds (API key)
//	POST /token/refresh     discard it and mint a new one (API key)
//	GET  /healthz           process is up
//	GET  /readyz            a session token is held
package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"nhcx-gateway/internal/abdm"
	"nhcx-gateway/internal/gateway"
	"nhcx-gateway/internal/ledger"
	"nhcx-gateway/internal/probe"
)

// Server wraps the gateway in an http.Server.
type Server struct {
	gw       *gateway.Gateway
	log      *slog.Logger
	version  string
	http     *http.Server
	probeKey []byte
}

// New builds the server; Run starts it.
func New(gw *gateway.Gateway, logger *slog.Logger, version string) *Server {
	s := &Server{gw: gw, log: logger, version: version, probeKey: probe.Key(gw.Config())}
	s.http = &http.Server{
		Addr:              gw.Config().Listen,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	return s
}

// Handler returns the routed handler (also used by tests).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /in/healthz", s.healthz) // reachable under a registered endpoint_url of ".../in"
	mux.HandleFunc("POST /healthz", s.healthz)   // the endpoint check's probe (see package probe)
	mux.HandleFunc("POST /in/healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("POST /out/{path...}", s.requireAPIKey(s.outbound))
	mux.HandleFunc("GET /ledger", s.requireAPIKey(s.ledgerList))
	mux.HandleFunc("GET /ledger/stats", s.requireAPIKey(s.ledgerStats))
	mux.HandleFunc("GET /ledger/thread/{cid}", s.requireAPIKey(s.ledgerThread))
	mux.HandleFunc("GET /ledger/{id}", s.requireAPIKey(s.ledgerGet))
	mux.HandleFunc("GET /token", s.requireAPIKey(s.token(false)))
	mux.HandleFunc("POST /token/refresh", s.requireAPIKey(s.token(true)))
	mux.HandleFunc("POST /in/{path...}", func(w http.ResponseWriter, r *http.Request) { s.inbound(w, r, r.PathValue("path")) })
	mux.HandleFunc("POST /v1/{path...}", func(w http.ResponseWriter, r *http.Request) { s.inbound(w, r, "v1/"+r.PathValue("path")) })
	return s.recover(s.requestID(s.limitBody(mux)))
}

// Run serves until ctx is cancelled, then drains in-flight requests.
func (s *Server) Run(ctx context.Context) error {
	cfg := s.gw.Config()
	// Warm the session token so the first message does not pay for it, and
	// keep it fresh in the background; failures are logged and retried by
	// the next request anyway.
	go s.tokenLoop(ctx)
	if store := s.gw.Ledger(); store != nil {
		go s.sweepLoop(ctx, store)
	}

	errCh := make(chan error, 1)
	go func() {
		var err error
		if cfg.TLS.CertFile != "" {
			s.log.Info("listening", "addr", cfg.Listen, "tls", true, "participant", cfg.Participant.ParticipantID)
			err = s.http.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			s.log.Info("listening", "addr", cfg.Listen, "tls", false, "participant", cfg.Participant.ParticipantID)
			err = s.http.ListenAndServe()
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		s.log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.http.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-errCh
	}
}

func (s *Server) tokenLoop(ctx context.Context) {
	client := s.gw.ABDM()
	refresh := func() {
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if _, err := client.Token(tctx); err != nil {
			s.log.Error("session token refresh failed", "error", err.Error())
		}
	}
	refresh()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refresh()
		}
	}
}

func (s *Server) sweepLoop(ctx context.Context, store *ledger.Store) {
	sweep := func() {
		if n := store.Sweep(time.Now()); n > 0 {
			s.log.Info("ledger pruned", "entries", n)
		}
	}
	sweep()
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweep()
		}
	}
}

// ------------------------------------------------------------- ledger ----

func (s *Server) ledgerStore(w http.ResponseWriter, r *http.Request) *ledger.Store {
	store := s.gw.Ledger()
	if store == nil {
		s.fail(w, r, &abdm.Error{Code: "LEDGER_DISABLED", Message: "the ledger is disabled (ledger.enabled = false)"})
	}
	return store
}

// ledgerList: GET /ledger?direction=&entity=&kind=&status=&sender=&recipient=
// &participant=&correlation_id=&workflow_id=&since=&until=&before=&limit=
func (s *Server) ledgerList(w http.ResponseWriter, r *http.Request) {
	store := s.ledgerStore(w, r)
	if store == nil {
		return
	}
	q := r.URL.Query()
	query := ledger.Query{
		Direction: q.Get("direction"), Entity: q.Get("entity"), Kind: q.Get("kind"), Status: q.Get("status"),
		Sender: q.Get("sender"), Recipient: q.Get("recipient"), Participant: q.Get("participant"),
		CorrelationID: q.Get("correlation_id"), WorkflowID: q.Get("workflow_id"), Before: q.Get("before"),
	}
	var err error
	if query.Since, err = parseTime(q.Get("since")); err != nil {
		s.fail(w, r, &abdm.Error{Code: "BAD_QUERY", Message: "since: " + err.Error()})
		return
	}
	if query.Until, err = parseTime(q.Get("until")); err != nil {
		s.fail(w, r, &abdm.Error{Code: "BAD_QUERY", Message: "until: " + err.Error()})
		return
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 500 {
			s.fail(w, r, &abdm.Error{Code: "BAD_QUERY", Message: "limit must be 1–500"})
			return
		}
		query.Limit = n
	}
	items := store.List(query)
	out := map[string]any{"items": items, "count": len(items)}
	if len(items) > 0 && len(items) == max(query.Limit, 50) {
		out["next_before"] = items[len(items)-1].ID
	}
	writeJSON(w, http.StatusOK, out)
}

// parseTime accepts RFC 3339, a date, or a duration back from now ("24h").
func parseTime(v string) (time.Time, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, nil
	}
	if d, err := time.ParseDuration(v); err == nil {
		return time.Now().Add(-d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, v); err == nil {
			return t, nil
		}
	}
	return time.Time{}, errors.New("use RFC 3339, YYYY-MM-DD, or a duration such as 24h")
}

func (s *Server) ledgerGet(w http.ResponseWriter, r *http.Request) {
	store := s.ledgerStore(w, r)
	if store == nil {
		return
	}
	e, err := store.Get(r.PathValue("id"))
	if errors.Is(err, ledger.ErrNotFound) {
		s.fail(w, r, &abdm.Error{Code: "NOT_FOUND", Message: "no ledger entry " + r.PathValue("id")})
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

func (s *Server) ledgerThread(w http.ResponseWriter, r *http.Request) {
	store := s.ledgerStore(w, r)
	if store == nil {
		return
	}
	t := store.Thread(r.PathValue("cid"), s.gw.Config().Participant.ParticipantID)
	if t == nil {
		s.fail(w, r, &abdm.Error{Code: "NOT_FOUND", Message: "no messages with correlation id " + r.PathValue("cid")})
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func (s *Server) ledgerStats(w http.ResponseWriter, r *http.Request) {
	store := s.ledgerStore(w, r)
	if store == nil {
		return
	}
	writeJSON(w, http.StatusOK, store.Stats())
}

// ------------------------------------------------------------ handlers ----

// healthz is the liveness probe. A POST carrying {"probe": nonce} is the
// endpoint check: the answer adds "probe_ack", an HMAC of the nonce only a
// gateway with this configuration can produce (see package probe).
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"status": "ok", "service": "nhcx-gateway", "version": s.version,
		"env": s.gw.Config().Env, "participant": s.gw.Config().Participant.ParticipantID}
	if r.Method == http.MethodPost {
		var req probe.Request
		if body, err := io.ReadAll(io.LimitReader(r.Body, 4096)); err == nil {
			_ = json.Unmarshal(body, &req)
		}
		if req.Probe != "" && len(req.Probe) <= 128 {
			out["probe_ack"] = probe.Ack(s.probeKey, req.Probe)
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if !s.gw.ABDM().TokenValid() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "no session token"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

// token hands the ABDM session token to the integrator, for the ABDM calls
// this adapter does not make itself (registry searches, policy links, …).
// With refresh the cached token is discarded first.
func (s *Server) token(refresh bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		client := s.gw.ABDM()
		if refresh {
			if _, err := client.RefreshToken(r.Context()); err != nil {
				s.fail(w, r, err)
				return
			}
		}
		tok, exp, err := client.TokenInfo(r.Context())
		if err != nil {
			s.fail(w, r, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, http.StatusOK, map[string]any{
			"token":      tok,
			"token_type": "Bearer",
			"expires_at": exp.UTC().Format(time.RFC3339),
			"expires_in": int(time.Until(exp).Seconds()),
			"refreshed":  refresh,
			"request_id": requestIDFrom(r),
		})
	}
}

// outbound answers with the NHCX gateway's own status code, so the
// integrator sees the 202 (or the 4xx/5xx) exactly as NHCX produced it.
func (s *Server) outbound(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	req, err := gateway.ParseOutboundBody(r.PathValue("path"), body, r.Header)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.gw.Send(r.Context(), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, res.GatewayStatus, map[string]any{
		"ok":             res.Accepted(),
		"path":           res.Path,
		"url":            res.URL,
		"headers":        res.Headers,
		"gateway_status": res.GatewayStatus,
		"response":       res.Response,
		"duration_ms":    res.DurationMs,
		"ledger_id":      res.LedgerID,
		"request_id":     requestIDFrom(r),
	})
}

// inbound decrypts, delivers synchronously, and only then acknowledges with
// the 202 acceptance body. A delivery failure is answered with an error
// status so NHCX retries (it makes five attempts before dropping the
// correlation id); the integrator must therefore be idempotent on
// x-hcx-correlation_id.
func (s *Server) inbound(w http.ResponseWriter, r *http.Request, path string) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in, err := s.gw.Receive(path, body, clientIP(r))
	if err != nil {
		s.gw.RecordRefused(path, clientIP(r), gateway.PeekHeaders(body), err)
		s.fail(w, r, err)
		return
	}
	res, err := s.gw.Deliver(r.Context(), in)
	s.gw.RecordInbound(in, res, err)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ack := in.Acceptance()
	if in.LedgerID != "" {
		w.Header().Set("X-Nhcx-Ledger-Id", in.LedgerID)
	}
	writeJSON(w, http.StatusAccepted, ack)
}

// readBody drains the (size-limited) request body into a typed error on failure.
func readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return nil, &abdm.Error{Code: "BODY_TOO_LARGE", Message: fmt.Sprintf("request body exceeds %d bytes", tooBig.Limit), Err: err}
		}
		return nil, &abdm.Error{Code: "BODY_READ", Message: "read request body", Err: err}
	}
	return body, nil
}

// fail maps a typed error to an HTTP status and a JSON error body.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	e := abdm.AsError(err)
	status := statusFor(e)
	// Message failures on /out and /in are already logged as traffic lines
	// by the gateway; only log the rest here.
	if !strings.HasPrefix(r.URL.Path, "/out/") && !strings.HasPrefix(r.URL.Path, "/in/") && !strings.HasPrefix(r.URL.Path, "/v1/") || e.Code == "UNAUTHORIZED" {
		s.log.Warn("request failed", "method", r.Method, "path", r.URL.Path, "status", status,
			"code", e.Code, "error", e.Message, "cause", causeOf(e), "request_id", requestIDFrom(r))
	} else {
		s.log.Debug("request failed", "method", r.Method, "path", r.URL.Path, "status", status,
			"code", e.Code, "error", e.Message, "cause", causeOf(e), "request_id", requestIDFrom(r))
	}
	out := map[string]any{
		"ok":         false,
		"error":      map[string]any{"code": e.Code, "message": e.Message, "retryable": e.Retryable},
		"request_id": requestIDFrom(r),
	}
	if e.Status != 0 {
		out["upstream_status"] = e.Status
	}
	if e.Body != "" {
		var parsed any
		if json.Unmarshal([]byte(e.Body), &parsed) == nil {
			out["upstream_body"] = parsed
		} else {
			out["upstream_body"] = e.Body
		}
	}
	writeJSON(w, status, out)
}

func causeOf(e *abdm.Error) string {
	if e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func statusFor(e *abdm.Error) int {
	switch e.Code {
	case "INVALID_ENVELOPE", "INVALID_PAYLOAD", "INVALID_BODY", "INVALID_JWE", "NO_PATH", "NO_RECIPIENT", "WRONG_RECIPIENT", "BODY_READ":
		return http.StatusBadRequest
	case "DECRYPT_FAILED":
		return http.StatusUnprocessableEntity
	case "CERT_NOT_FOUND", "SELF_ENCRYPTION_KEY":
		return http.StatusUnprocessableEntity
	case "BODY_TOO_LARGE":
		return http.StatusRequestEntityTooLarge
	case "NOT_FOUND":
		return http.StatusNotFound
	case "BAD_QUERY":
		return http.StatusBadRequest
	case "LEDGER_DISABLED":
		return http.StatusNotImplemented
	}
	for _, prefix := range []string{"CALLBACK_", "GATEWAY_", "CERT_FETCH_", "TOKEN_"} {
		if strings.HasPrefix(e.Code, prefix) {
			return http.StatusBadGateway
		}
	}
	return http.StatusInternalServerError
}

// ---------------------------------------------------------- middleware ----

type ctxKey int

const requestIDKey ctxKey = 1

func requestIDFrom(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey).(string)
	return id
}

func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-Id"))
		if id == "" || len(id) > 128 {
			id = uuid.New().String()
		}
		w.Header().Set("X-Request-Id", id)
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
		s.log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rec.status,
			"ip", clientIP(r), "took", time.Since(start).Round(time.Millisecond).String(), "request_id", id)
	})
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	max := s.gw.Config().MaxBodyBytes
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if p := recover(); p != nil {
				s.log.Error("panic", "path", r.URL.Path, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": map[string]any{"code": "INTERNAL", "message": "internal error"}})
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// requireAPIKey guards /out with the configured bearer key. Without a key
// configured the surface is open — ValidateServe refuses that in production.
func (s *Server) requireAPIKey(next http.HandlerFunc) http.HandlerFunc {
	key := s.gw.Config().APIKey
	return func(w http.ResponseWriter, r *http.Request) {
		if key != "" {
			got := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer"))
			if got == "" {
				got = r.Header.Get("X-Api-Key")
			}
			if subtle.ConstantTimeCompare([]byte(got), []byte(key)) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="nhcx-gateway"`)
				writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": map[string]any{"code": "UNAUTHORIZED", "message": "missing or invalid API key"}})
				return
			}
		}
		next(w, r)
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// clientIP is the peer address; X-Forwarded-For is deliberately not trusted
// here — put the gateway behind a proxy that rewrites it if you need it.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
