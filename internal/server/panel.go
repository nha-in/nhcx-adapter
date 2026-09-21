// The operator console: one small web page on this same listener, behind a
// password, showing what the adapter is doing and letting the few things an
// operator actually does be done from a browser — watch the traffic, read a
// message, follow an exchange, send one, look a participant up, refresh the
// session.
//
// It is deliberately not an application. One embedded HTML file, no build
// step, no framework, no external asset — a page that works on a jump box
// with no internet, and a JSON API underneath that is the same API the CLI
// and the integrator already use.
//
// The security model is short enough to state: the page and its API live
// behind a password the operator sets, a login mints a cookie signed with a
// key minted at startup (so a restart logs everyone out and nothing about a
// session is ever written to disk), the cookie is HttpOnly and SameSite=
// Strict, every writing call must carry a header a cross-site form cannot
// send, and failed logins are rate limited per address. It is off until a
// password is set.
package server

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"nhcx-adapter/internal/abdm"
	"nhcx-adapter/internal/adapter"
	"nhcx-adapter/internal/config"
	"nhcx-adapter/internal/ledger"
	"nhcx-adapter/internal/nhcx"
)

//go:embed panel.html
var panelPage string

//go:embed panel_login.html
var panelLoginPage string

const panelCookie = "nhcx_panel"

// panel holds the console's session state. Everything in it is per-process
// and in memory: there is no session store to leak or to keep in sync.
type panel struct {
	base   string        // /panel
	pass   string        // the configured password
	ttl    time.Duration // how long a login lasts
	key    []byte        // cookie signing key, minted at startup
	secure bool          // set Secure on the cookie (TLS terminates here)

	page  string // the console, with its base path filled in
	login string // the login form, likewise

	limiter *loginLimiter
	log     *slog.Logger
}

// newPanel prepares the console, or returns nil when it is not configured.
func newPanel(cfg *config.Config, logger *slog.Logger) *panel {
	if !cfg.PanelEnabled() || cfg.Panel.Password == "" {
		return nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		// Without a signing key there is no session anyone can forge and
		// none anyone can hold either: refusing the panel is the safe half.
		logger.Error("panel disabled: no random source for its session key", "error", err.Error())
		return nil
	}
	base := cfg.Panel.Path
	p := &panel{
		base: base, pass: cfg.Panel.Password, key: key,
		ttl:     time.Duration(cfg.Panel.SessionHours) * time.Hour,
		secure:  cfg.TLS.CertFile != "",
		page:    strings.ReplaceAll(panelPage, "{{BASE}}", base),
		login:   strings.ReplaceAll(panelLoginPage, "{{BASE}}", base),
		limiter: newLoginLimiter(),
		log:     logger,
	}
	return p
}

// mount registers the console's routes. Everything under the panel's path
// belongs to it, including its own 404.
func (s *Server) mountPanel(mux *http.ServeMux) {
	p := s.panel
	if p == nil {
		return
	}
	b := p.base
	mux.HandleFunc("GET "+b, p.serveConsole)
	mux.HandleFunc("GET "+b+"/", p.serveConsole)
	mux.HandleFunc("POST "+b+"/login", p.handleLogin)
	mux.HandleFunc("POST "+b+"/logout", p.handleLogout)

	mux.HandleFunc("GET "+b+"/api/overview", p.guard(s.panelOverview))
	mux.HandleFunc("GET "+b+"/api/ledger", p.guard(s.ledgerList))
	mux.HandleFunc("GET "+b+"/api/ledger/{id}", p.guard(s.ledgerGet))
	mux.HandleFunc("GET "+b+"/api/thread/{cid}", p.guard(s.ledgerThread))
	mux.HandleFunc("GET "+b+"/api/stats", p.guard(s.ledgerStats))
	mux.HandleFunc("GET "+b+"/api/stream", p.guard(s.panelStream))
	mux.HandleFunc("GET "+b+"/api/participant", p.guard(s.panelParticipant))
	mux.HandleFunc("GET "+b+"/api/token", p.guard(s.token(false)))
	mux.HandleFunc("POST "+b+"/api/token/refresh", p.guard(s.token(true)))
	mux.HandleFunc("POST "+b+"/api/send", p.guard(s.panelSend))
	mux.HandleFunc("POST "+b+"/api/ledger/clear", p.guard(s.panelClearLedger))
}

// ---------------------------------------------------------------- auth ----

// sign returns the cookie value for a session expiring at exp.
func (p *panel) sign(exp int64) string {
	mac := hmac.New(sha256.New, p.key)
	fmt.Fprintf(mac, "%d", exp)
	return strconv.FormatInt(exp, 10) + "." + hex.EncodeToString(mac.Sum(nil))
}

// valid reports whether the request carries a live session cookie.
func (p *panel) valid(r *http.Request) bool {
	c, err := r.Cookie(panelCookie)
	if err != nil {
		return false
	}
	exp, _, ok := strings.Cut(c.Value, ".")
	if !ok {
		return false
	}
	at, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().Unix() >= at {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Value), []byte(p.sign(at))) == 1
}

func (p *panel) setCookie(w http.ResponseWriter, r *http.Request) {
	exp := time.Now().Add(p.ttl)
	http.SetCookie(w, &http.Cookie{
		Name: panelCookie, Value: p.sign(exp.Unix()), Path: p.base,
		Expires: exp, MaxAge: int(p.ttl.Seconds()),
		HttpOnly: true, Secure: p.secureFor(r), SameSite: http.SameSiteStrictMode,
	})
}

// secureFor decides whether the session cookie is marked Secure. TLS may
// terminate here or at a proxy in front, and a panel reached over HTTPS
// should keep its cookie off plain HTTP either way. The forwarded header is
// the caller's word for it, which is safe to take: the only session it can
// restrict is that caller's own.
func (p *panel) secureFor(r *http.Request) bool {
	return p.secure || r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func (p *panel) clearCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: panelCookie, Value: "", Path: p.base, MaxAge: -1,
		HttpOnly: true, Secure: p.secureFor(r), SameSite: http.SameSiteStrictMode,
	})
}

// guard is the panel's API door: a live session, and — for anything that
// changes something — a header no cross-site form or image can set, which is
// this page's whole CSRF story.
func (p *panel) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.valid(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false,
				"error": map[string]any{"code": "PANEL_UNAUTHORIZED", "message": "sign in to the panel first"}})
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Panel-Request") != "1" {
			writeJSON(w, http.StatusForbidden, map[string]any{"ok": false,
				"error": map[string]any{"code": "PANEL_CSRF", "message": "missing X-Panel-Request header"}})
			return
		}
		next(w, r)
	}
}

func (p *panel) serveConsole(w http.ResponseWriter, r *http.Request) {
	// The panel owns its subtree; an unknown path under it is a 404 rather
	// than the console served under the wrong URL.
	if r.URL.Path != p.base && r.URL.Path != p.base+"/" {
		http.NotFound(w, r)
		return
	}
	if !p.valid(r) {
		p.renderLogin(w, r, "", http.StatusOK)
		return
	}
	p.writeHTML(w, http.StatusOK, p.page)
}

func (p *panel) renderLogin(w http.ResponseWriter, r *http.Request, message string, status int) {
	body := strings.ReplaceAll(p.login, "{{MESSAGE}}", htmlEscape(message))
	p.writeHTML(w, status, body)
}

func (p *panel) writeHTML(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Everything the page needs is in the page. Nothing may be fetched from
	// anywhere else, and nothing may frame it.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func (p *panel) handleLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if wait, blocked := p.limiter.blocked(ip); blocked {
		p.log.Warn("panel login blocked", "ip", ip, "retry_in", wait.Round(time.Second).String())
		p.renderLogin(w, r, fmt.Sprintf("Too many attempts. Try again in %s.", wait.Round(time.Second)), http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil {
		p.renderLogin(w, r, "That form did not arrive intact.", http.StatusBadRequest)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.PostFormValue("password")), []byte(p.pass)) != 1 {
		left := p.limiter.failed(ip)
		p.log.Warn("panel login failed", "ip", ip, "attempts_left", left)
		p.renderLogin(w, r, "Wrong password.", http.StatusUnauthorized)
		return
	}
	p.limiter.succeeded(ip)
	p.setCookie(w, r)
	p.log.Info("panel login", "ip", ip)
	http.Redirect(w, r, p.base, http.StatusSeeOther)
}

func (p *panel) handleLogout(w http.ResponseWriter, r *http.Request) {
	p.clearCookie(w, r)
	http.Redirect(w, r, p.base, http.StatusSeeOther)
}

// loginLimiter slows password guessing: a handful of tries per address, then
// a lockout that doubles up to a quarter of an hour.
type loginLimiter struct {
	mu    sync.Mutex
	tries map[string]*loginState
}

type loginState struct {
	fails    int
	until    time.Time
	lockouts int
	seen     time.Time
}

const (
	loginFreeTries  = 5
	loginBaseLock   = time.Minute
	loginMaxLock    = 15 * time.Minute
	loginForgetting = time.Hour // an address quiet this long starts fresh
)

func newLoginLimiter() *loginLimiter { return &loginLimiter{tries: map[string]*loginState{}} }

// blocked reports whether this address must wait, and for how long.
func (l *loginLimiter) blocked(ip string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune()
	st := l.tries[ip]
	if st == nil {
		return 0, false
	}
	if wait := time.Until(st.until); wait > 0 {
		return wait, true
	}
	return 0, false
}

// failed records a wrong password and returns the tries left before a lockout.
func (l *loginLimiter) failed(ip string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.tries[ip]
	if st == nil {
		st = &loginState{}
		l.tries[ip] = st
	}
	st.seen = time.Now()
	st.fails++
	if st.fails < loginFreeTries {
		return loginFreeTries - st.fails
	}
	lock := loginBaseLock << min(st.lockouts, 8)
	if lock > loginMaxLock {
		lock = loginMaxLock
	}
	st.until, st.fails, st.lockouts = time.Now().Add(lock), 0, st.lockouts+1
	return 0
}

func (l *loginLimiter) succeeded(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.tries, ip)
}

// prune forgets addresses that have been quiet, so the map cannot grow
// without bound on an adapter facing the open internet. The caller holds l.mu.
func (l *loginLimiter) prune() {
	cut := time.Now().Add(-loginForgetting)
	for ip, st := range l.tries {
		if st.seen.Before(cut) && st.until.Before(time.Now()) {
			delete(l.tries, ip)
		}
	}
}

// ------------------------------------------------------------- the API ----

// panelOverview is what the console shows first: who this adapter is, where
// its traffic goes, whether it holds a session, and what the ledger holds.
func (s *Server) panelOverview(w http.ResponseWriter, r *http.Request) {
	cfg := s.gw.Config()
	profiles := make([]map[string]any, 0, s.gw.Profiles().Len())
	for _, prof := range s.gw.Profiles().All() {
		client := s.gw.ABDMFor(prof.Code())
		profiles = append(profiles, map[string]any{
			"code": prof.Code(), "name": prof.Label(), "default": prof.Default,
			"callback": s.gw.DeliveryURL("", prof.Code()), "token_valid": client.TokenValid(),
		})
	}
	out := map[string]any{
		"version": s.version, "env": cfg.Env, "listen": cfg.Listen, "public_url": cfg.PublicURL,
		"nhcx": cfg.URLs.NHCX, "registry": cfg.URLs.Participant, "auth_mode": cfg.Auth.Mode,
		"api_key_required": cfg.APIKeyRequired(), "tls": cfg.TLS.CertFile != "",
		"participants": profiles,
		"ledger": map[string]any{
			"enabled": cfg.LedgerEnabled(), "dir": cfg.Resolve(cfg.Ledger.Dir),
			"retention_days": cfg.Ledger.RetentionDays, "store_bodies": cfg.LedgerStoresBodies(),
		},
		"now": time.Now().Format(time.RFC3339),
	}
	if store := s.gw.Ledger(); store != nil {
		out["stats"] = store.Stats()
	}
	writeJSON(w, http.StatusOK, out)
}

// panelStream is the live view: the recent ledger, then every message as it
// is recorded, as server-sent events.
func (s *Server) panelStream(w http.ResponseWriter, r *http.Request) {
	store := s.ledgerStore(w, r)
	if store == nil {
		return
	}
	rc := http.NewResponseController(w)
	// The listener's write timeout is meant for requests that should be over
	// in seconds; a stream is not one of those.
	_ = rc.SetWriteDeadline(time.Time{})

	q := r.URL.Query()
	filter := ledger.Query{
		Direction: q.Get("direction"), Entity: q.Get("entity"), Kind: q.Get("kind"), Status: q.Get("status"),
		Participant: q.Get("participant"), CorrelationID: q.Get("correlation_id"),
	}
	backfill := 25
	if n, err := strconv.Atoi(q.Get("backfill")); err == nil && n >= 0 && n <= 200 {
		backfill = n
	}

	// Subscribe before reading the backlog, so a message recorded between
	// the two is delivered late rather than lost. The id filter on the way
	// out keeps it from being delivered twice.
	events, unsubscribe := store.Subscribe()
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx must not sit on the events
	w.WriteHeader(http.StatusOK)
	// Events are useless sitting in a buffer. If this connection cannot be
	// flushed there is nothing to serve, and the headers are already out.
	if err := rc.Flush(); err != nil {
		s.log.Warn("panel stream cannot flush", "error", err.Error())
		return
	}

	send := func(event string, v any) bool {
		body, err := json.Marshal(v)
		if err != nil {
			return true
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, body); err != nil {
			return false
		}
		return rc.Flush() == nil
	}

	var last string
	if backfill > 0 {
		history := filter
		history.Limit = backfill
		items := store.List(history)
		for i := len(items) - 1; i >= 0; i-- { // oldest first, as they happened
			if items[i].ID > last {
				last = items[i].ID
			}
			if !send("message", items[i]) {
				return
			}
		}
	}
	if !send("ready", map[string]any{"backfill": backfill}) {
		return
	}

	// A comment every twenty seconds keeps proxies from closing an idle
	// stream and tells us the client has gone when nothing is happening.
	ping := time.NewTicker(20 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case sm := <-events:
			if sm.ID <= last || !filter.Match(sm) {
				continue
			}
			last = sm.ID
			if !send("message", sm) {
				return
			}
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			if rc.Flush() != nil {
				return
			}
		}
	}
}

// panelSend is the console's send form. The body is the same envelope /out
// takes, plus the NHCX path, so what the panel sends and what an integrator
// sends go through one code path.
func (s *Server) panelSend(w http.ResponseWriter, r *http.Request) {
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var envelope struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		s.fail(w, r, &abdm.Error{Code: "INVALID_ENVELOPE", Message: "body must be a JSON object", Err: err})
		return
	}
	req, err := adapter.ParseOutboundBody(envelope.Path, body, nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.gw.Send(r.Context(), req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": res.Accepted(), "path": res.Path, "url": res.URL, "headers": res.Headers,
		"gateway_status": res.GatewayStatus, "response": res.Response, "duration_ms": res.DurationMs,
		"ledger_id": res.LedgerID, "correlation_id": nhcx.GetString(res.Headers, nhcx.HdrCorrelationID),
	})
}

// panelParticipant is the registry lookup: who a code belongs to and the
// certificate this adapter would encrypt to. ?refresh=1 asks the registry
// again instead of trusting the cache.
func (s *Server) panelParticipant(w http.ResponseWriter, r *http.Request) {
	code := strings.TrimSpace(r.URL.Query().Get("code"))
	if code == "" {
		s.fail(w, r, &abdm.Error{Code: "BAD_QUERY", Message: "code is required"})
		return
	}
	client := s.gw.ABDM()
	out := map[string]any{"code": nhcx.NormalizeCode(code)}
	if r.URL.Query().Get("refresh") == "1" {
		client.ForgetCertificate(code)
	}
	// The registry record is reshaped rather than passed through: the panel
	// reads named fields, and the raw record is handed over beside them for
	// the times the registry says something the adapter has no field for.
	if rec, err := client.FetchParticipant(r.Context(), code); err == nil && rec != nil {
		out["participant"] = map[string]any{
			"code": rec.Code, "name": rec.Name, "status": rec.Status,
			"endpoint_url": rec.EndpointURL, "roles": rec.Roles,
		}
		out["registry_record"] = rec.Raw
	} else if err != nil {
		out["participant_error"] = abdm.AsError(err).Message
	}
	_, pem, err := client.Certificate(r.Context(), code)
	if err != nil {
		out["certificate_error"] = abdm.AsError(err).Message
	} else {
		out["certificate"] = pem
	}
	writeJSON(w, http.StatusOK, out)
}

// panelClearLedger empties the ledger. It is the one irreversible thing the
// console can do, so it takes a body that says so in words.
func (s *Server) panelClearLedger(w http.ResponseWriter, r *http.Request) {
	store := s.ledgerStore(w, r)
	if store == nil {
		return
	}
	body, err := readBody(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Confirm string `json:"confirm"`
	}
	_ = json.Unmarshal(body, &req)
	if req.Confirm != "clear" {
		s.fail(w, r, &abdm.Error{Code: "NOT_CONFIRMED", Message: `send {"confirm":"clear"} to empty the ledger`})
		return
	}
	removed, err := store.Clear()
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.log.Warn("ledger cleared from the panel", "entries", removed, "ip", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cleared": removed})
}

// htmlEscape is enough for the one place the panel puts text into HTML: the
// login page's message, which is chosen from a handful of fixed strings.
func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(s)
}

// panelURL is where an operator points a browser: the listen address made
// dialable (a wildcard bind is not an address you can type), plus the path.
func (s *Server) panelURL() string {
	if s.panel == nil {
		return ""
	}
	cfg := s.gw.Config()
	scheme := "http"
	if cfg.TLS.CertFile != "" {
		scheme = "https"
	}
	host := cfg.Listen
	if strings.HasPrefix(host, ":") {
		host = "127.0.0.1" + host
	}
	host = strings.Replace(host, "0.0.0.0:", "127.0.0.1:", 1)
	host = strings.Replace(host, "[::]:", "127.0.0.1:", 1)
	return scheme + "://" + host + s.panel.base
}
