// Package config loads and validates the nhcx-adapter configuration.
//
// The file is JSON. Two conveniences keep secrets out of it: any string
// value may reference an environment variable as ${NAME}, and key material
// may point at a file as "@/path/to/key.pem". Everything environment-specific
// (gateway host, participant registry, session endpoint, consent-manager id)
// is derived from "env" and can be overridden field by field.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"nhcx-adapter/internal/keys"
)

// Environment names the NHCX deployment an adapter instance talks to.
type Environment string

const (
	Sandbox    Environment = "sandbox"
	Production Environment = "production"
)

// URLs are the three ABDM endpoints the adapter needs.
type URLs struct {
	// NHCX is the exchange gateway base, e.g. https://apisbx.abdm.gov.in/hcx/v1.
	NHCX string `json:"nhcx"`
	// Participant is the participant registry service base (fetch/certs, get/session).
	Participant string `json:"participant"`
	// Sessions is the ABDM session-token endpoint used by auth mode "sessions".
	Sessions string `json:"sessions"`
}

// EnvironmentDefaults returns the well-known endpoints and consent-manager id
// for an environment. The sandbox values are those the hcxkit reference
// implementation is verified against; the production values follow the
// documented host swap (apisbx→apis, sbxhcx→hcx, dev→live). Override any of
// them in the config when your onboarding letter says otherwise.
func EnvironmentDefaults(env Environment) (URLs, string) {
	switch env {
	case Production:
		return URLs{
			NHCX:        "https://apis.abdm.gov.in/hcx/v1",
			Participant: "https://apis.abdm.gov.in/pmjay/hcx/participanthcxservice",
			Sessions:    "https://live.abdm.gov.in/api/hiecm/gateway/v3/sessions",
		}, "abdm"
	default:
		return URLs{
			NHCX:        "https://apisbx.abdm.gov.in/hcx/v1",
			Participant: "https://apisbx.abdm.gov.in/pmjay/sbxhcx/participanthcxservice",
			Sessions:    "https://dev.abdm.gov.in/api/hiecm/gateway/v3/sessions",
		}, "sbx"
	}
}

// Participant is one identity this adapter holds on the exchange.
//
// The top-level "participant" is the default profile. Additional profiles in
// "participants" are hosted alongside it: each has its own registry code and
// its own callback, so one adapter can serve a provider and a payer at once
// and deliver each one's traffic to its own backend. Anything a hosted
// profile leaves unset is inherited from the default — credentials, key and
// callback — which is what makes a profile that is only
// {participantId, name, callback} work.
type Participant struct {
	// ParticipantID is the registry code, with or without the "@hcx" suffix.
	ParticipantID string `json:"participantId"`
	// Name is a label for logs and the startup banner. Cosmetic.
	Name string `json:"name,omitempty"`
	// ClientID / ClientSecret are the ABDM credentials issued at onboarding.
	// Blank on a hosted profile means "use the default profile's".
	ClientID     string `json:"clientId,omitempty"`
	ClientSecret string `json:"clientSecret,omitempty"`
	// PrivateKey is the RSA key matching the encryption certificate registered
	// for this participant: PEM, base64-encoded PEM, or "@file". Blank on a
	// hosted profile means the profile shares the default's certificate —
	// the usual arrangement, since one registered key can front several codes.
	PrivateKey string `json:"privateKey,omitempty"`
	// Callback overrides the top-level callback for messages addressed to
	// this participant. Unset fields fall back to it, so a profile normally
	// only names a URL.
	Callback *Callback `json:"callback,omitempty"`
	// CallbackURL is hcxkit's spelling of the same thing, accepted so a kit
	// config can be carried over unchanged. Callback wins when both are set.
	CallbackURL string `json:"callbackUrl,omitempty"`
}

// Callback is where decrypted inbound messages are delivered.
type Callback struct {
	// URL is the base endpoint of the integrator's backend.
	URL string `json:"url"`
	// AppendPath adds the NHCX API path the message arrived on to URL, so
	// ".../callback" receives an on_submit on ".../callback/v1/preauth/on_submit".
	AppendPath *bool `json:"appendPath,omitempty"`
	// TimeoutSeconds bounds one delivery; NHCX expects its 202 within 30s.
	TimeoutSeconds int `json:"timeoutSeconds"`
	// APIKey, when set, is sent to the callback as "Authorization: Bearer".
	APIKey string `json:"apiKey"`
	// Routes sends particular NHCX paths to their own URL instead of URL,
	// e.g. {"v1/preauth/on_submit": "http://preauth-svc/hook"}. A route is
	// used exactly as written — AppendPath does not apply to it.
	Routes map[string]string `json:"routes,omitempty"`
}

// Certificate drives "nhcx-adapter cert generate". The certificate's
// subject is always the participant id — the registry cares about the key,
// not the name — so only the lifetime and the file names are configurable
// (paths are relative to the config file).
type Certificate struct {
	ValidityDays    int    `json:"validityDays"` // default 365
	PrivateKeyFile  string `json:"privateKeyFile"`
	CertificateFile string `json:"certificateFile"`
}

// Auth selects how a session token is obtained.
type Auth struct {
	// Mode is "sessions" (ABDM HIECM gateway, JSON clientId/clientSecret —
	// the default) or "get-session" (participant service /get/session,
	// form-encoded client_id/client_secret, as the PMJAY handbook documents).
	Mode string `json:"mode"`
	// TokenTTLSeconds is assumed when the token response carries no expiry.
	TokenTTLSeconds int `json:"tokenTtlSeconds"`
}

// Certs controls the recipient certificate cache.
type Certs struct {
	CacheHours int `json:"cacheHours"`
	// RefuseSelfKey decides what happens when the registry hands back one of
	// this adapter's own certificates for another participant. Unset means
	// "in production, refuse; in sandbox, allow" — see RefusesSelfKey.
	RefuseSelfKey *bool `json:"refuseSelfKey,omitempty"`
}

// Ledger records every message that crosses the adapter (see package ledger).
type Ledger struct {
	Enabled *bool `json:"enabled,omitempty"`
	// Dir holds the records, relative to the config file. Default data/ledger.
	Dir string `json:"dir"`
	// RetentionDays prunes older day folders; 0 keeps everything.
	RetentionDays int `json:"retentionDays"`
	// StoreBodies keeps the FHIR bundles and peer responses, not just the
	// headers and outcomes.
	StoreBodies *bool `json:"storeBodies,omitempty"`
}

// TLS terminates HTTPS on the listener when both files are set.
type TLS struct {
	CertFile string `json:"certFile"`
	KeyFile  string `json:"keyFile"`
}

// Log configures the structured logger.
type Log struct {
	Level  string `json:"level"`  // debug, info, warn, error
	Format string `json:"format"` // json or text
}

// Config is the whole file.
type Config struct {
	Env    string `json:"env"`
	Listen string `json:"listen"`
	// PublicURL is how NHCX reaches this adapter from the outside, e.g.
	// https://hcx.example.com/in — what belongs in the registry's
	// endpoint_url. Optional; used to propose and verify the registration.
	PublicURL string `json:"publicUrl"`
	// APIKey is presented as "Authorization: Bearer" on /out and the kit
	// compatibility routes. Whether it is *demanded* is RequireAPIKey.
	APIKey string `json:"apiKey"`
	// RequireAPIKey forces the key to be checked, or forces it not to be.
	// Unset means "in production, yes; in sandbox, no" — see APIKeyRequired.
	RequireAPIKey *bool `json:"requireApiKey,omitempty"`
	// MaxBodyBytes caps request bodies on both surfaces.
	MaxBodyBytes int64 `json:"maxBodyBytes"`
	// OutboundTimeoutSeconds bounds one call to ABDM (token, certs, gateway).
	OutboundTimeoutSeconds int `json:"outboundTimeoutSeconds"`
	// CMID is the X-CM-ID sent to the ABDM session endpoint; blank = env default.
	CMID string `json:"cmId"`

	TLS         TLS         `json:"tls"`
	Participant Participant `json:"participant"`
	// Participants are additional identities hosted by this adapter; see
	// Participant. The default profile above is always first in AllParticipants.
	Participants []Participant `json:"participants,omitempty"`
	Callback     Callback      `json:"callback"`
	Certificate  Certificate   `json:"certificate"`
	Ledger       Ledger        `json:"ledger"`
	URLs         URLs          `json:"urls"`
	Auth         Auth          `json:"auth"`
	Certs        Certs         `json:"certs"`
	Log          Log           `json:"log"`

	// Path the config was loaded from; "@file" references resolve relative to it.
	path string
}

// Path returns where the config was loaded from ("" when parsed from memory).
func (c *Config) Path() string { return c.path }

// Resolve makes a file path from the config relative to the config file.
func (c *Config) Resolve(p string) string {
	if p == "" || filepath.IsAbs(p) || c.path == "" {
		return p
	}
	return filepath.Join(filepath.Dir(c.path), p)
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Read parses a config file with defaults applied but without resolving
// key files or validating — for commands that run before the key exists.
func Read(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	cfg.path = path
	return cfg, nil
}

// Load reads, expands and validates a config file.
func Load(path string) (*Config, error) {
	cfg, err := Read(path)
	if err != nil {
		return nil, err
	}
	if err := cfg.ResolveFiles(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// ParseAt is Parse for a document that lives (or will live) at path, so
// "@file" references can be resolved relative to it.
func ParseAt(raw []byte, path string) (*Config, error) {
	cfg, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	cfg.path = path
	return cfg, nil
}

// Parse decodes JSON, expands ${ENV} references and applies defaults. It does
// not validate or resolve @file references — Load does.
func Parse(raw []byte) (*Config, error) {
	var missing []string
	expanded := envRef.ReplaceAllStringFunc(string(raw), func(m string) string {
		name := m[2 : len(m)-1]
		v, ok := os.LookupEnv(name)
		if !ok {
			missing = append(missing, name)
			return ""
		}
		b, _ := json.Marshal(v)
		return string(b[1 : len(b)-1]) // JSON-escaped, without the quotes
	})
	if len(missing) > 0 {
		return nil, fmt.Errorf("environment variable(s) not set: %s", strings.Join(missing, ", "))
	}

	cfg := &Config{}
	dec := json.NewDecoder(strings.NewReader(expanded))
	dec.DisallowUnknownFields()
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	return cfg, nil
}

func (c *Config) applyDefaults() {
	c.Env = strings.ToLower(strings.TrimSpace(c.Env))
	if c.Env == "" {
		c.Env = string(Sandbox)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8090"
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 8 << 20
	}
	if c.OutboundTimeoutSeconds <= 0 {
		c.OutboundTimeoutSeconds = 30
	}
	if c.Callback.TimeoutSeconds <= 0 {
		c.Callback.TimeoutSeconds = 20
	}
	if c.Callback.AppendPath == nil {
		t := true
		c.Callback.AppendPath = &t
	}
	if c.Auth.Mode == "" {
		c.Auth.Mode = "sessions"
	}
	if c.Auth.TokenTTLSeconds <= 0 {
		c.Auth.TokenTTLSeconds = 1200
	}
	if c.Certs.CacheHours <= 0 {
		c.Certs.CacheHours = 24
	}
	if c.Certificate.ValidityDays == 0 {
		c.Certificate.ValidityDays = 365
	}
	if c.Ledger.Enabled == nil {
		t := true
		c.Ledger.Enabled = &t
	}
	if c.Ledger.StoreBodies == nil {
		t := true
		c.Ledger.StoreBodies = &t
	}
	if c.Ledger.Dir == "" {
		c.Ledger.Dir = "data/ledger"
	}
	if c.Ledger.RetentionDays < 0 {
		c.Ledger.RetentionDays = 0
	}
	if c.Certificate.PrivateKeyFile == "" {
		c.Certificate.PrivateKeyFile = "private_key.pem"
	}
	if c.Certificate.CertificateFile == "" {
		c.Certificate.CertificateFile = "certificate.pem"
	}
	for k, v := range c.Callback.Routes {
		if nk := strings.Trim(strings.TrimSpace(k), "/"); nk != k {
			delete(c.Callback.Routes, k)
			c.Callback.Routes[nk] = v
		}
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		if c.Env == string(Production) {
			c.Log.Format = "json"
		} else {
			c.Log.Format = "text"
		}
	}

	defaults, cmID := EnvironmentDefaults(Environment(c.Env))
	if c.URLs.NHCX == "" {
		c.URLs.NHCX = defaults.NHCX
	}
	if c.URLs.Participant == "" {
		c.URLs.Participant = defaults.Participant
	}
	if c.URLs.Sessions == "" {
		if c.Auth.Mode == "get-session" {
			c.URLs.Sessions = strings.TrimRight(c.URLs.Participant, "/") + "/get/session"
		} else {
			c.URLs.Sessions = defaults.Sessions
		}
	}
	if c.CMID == "" {
		c.CMID = cmID
	}
	normalizeParticipant(&c.Participant)
	for i := range c.Participants {
		normalizeParticipant(&c.Participants[i])
	}
}

// normalizeParticipant applies the "@hcx" suffix and folds hcxkit's
// "callbackUrl" spelling into the Callback struct, so everything downstream
// only has to look at one field.
func normalizeParticipant(p *Participant) {
	p.ParticipantID = strings.TrimSpace(p.ParticipantID)
	if p.ParticipantID != "" && !strings.HasSuffix(p.ParticipantID, "@hcx") {
		p.ParticipantID += "@hcx"
	}
	if url := strings.TrimSpace(p.CallbackURL); url != "" {
		if p.Callback == nil {
			p.Callback = &Callback{}
		}
		if p.Callback.URL == "" {
			p.Callback.URL = url
		}
	}
	if p.Callback == nil {
		return
	}
	for k, v := range p.Callback.Routes {
		if nk := strings.Trim(strings.TrimSpace(k), "/"); nk != k {
			delete(p.Callback.Routes, k)
			p.Callback.Routes[nk] = v
		}
	}
}

// ResolveFiles replaces "@path" key material with the file's contents.
func (c *Config) ResolveFiles() error {
	var err error
	c.Participant.PrivateKey, err = c.readRef(c.Participant.PrivateKey)
	if err != nil {
		return fmt.Errorf("participant.privateKey: %w", err)
	}
	for i := range c.Participants {
		c.Participants[i].PrivateKey, err = c.readRef(c.Participants[i].PrivateKey)
		if err != nil {
			return fmt.Errorf("participants[%d].privateKey: %w", i, err)
		}
	}
	return nil
}

// PrivateKeyFile returns the path participant.privateKey points at, or ""
// when the key is inline.
func (c *Config) PrivateKeyFile() string {
	v := strings.TrimSpace(c.Participant.PrivateKey)
	if !strings.HasPrefix(v, "@") {
		return ""
	}
	return c.Resolve(strings.TrimPrefix(v, "@"))
}

func (c *Config) readRef(v string) (string, error) {
	v = strings.TrimSpace(v)
	if !strings.HasPrefix(v, "@") {
		return v, nil
	}
	p := strings.TrimPrefix(v, "@")
	if !filepath.IsAbs(p) && c.path != "" {
		p = filepath.Join(filepath.Dir(c.path), p)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Validate checks everything every command needs. The listener-only fields
// (callback URL, TLS files) are checked by ValidateServe.
func (c *Config) Validate() error {
	var errs []error
	switch Environment(c.Env) {
	case Sandbox, Production:
	default:
		errs = append(errs, fmt.Errorf("env must be %q or %q, got %q", Sandbox, Production, c.Env))
	}
	if c.Participant.ParticipantID == "" {
		errs = append(errs, errors.New("participant.participantId is required"))
	}
	if c.Participant.ClientID == "" || c.Participant.ClientSecret == "" {
		errs = append(errs, errors.New("participant.clientId and participant.clientSecret are required"))
	}
	switch pk := strings.TrimSpace(c.Participant.PrivateKey); {
	case pk == "":
		errs = append(errs, errors.New("participant.privateKey is required (PEM, base64 PEM, or @file) — nhcx-adapter cert generate creates one"))
	case strings.HasPrefix(pk, "@"):
		errs = append(errs, fmt.Errorf("participant.privateKey: %s was not read (call ResolveFiles first)", pk))
	default:
		if _, err := keys.ParsePrivateKey(pk); err != nil {
			errs = append(errs, fmt.Errorf("participant.privateKey is not a valid RSA private key: %w", err))
		}
	}
	seen := map[string]int{}
	if c.Participant.ParticipantID != "" {
		seen[strings.ToLower(c.Participant.ParticipantID)] = -1
	}
	for i, p := range c.Participants {
		where := fmt.Sprintf("participants[%d]", i)
		if p.ParticipantID == "" {
			// A hosted profile is addressed by its code; without one it can
			// never be selected, and it would silently shadow the default.
			errs = append(errs, fmt.Errorf("%s.participantId is required", where))
		} else if prev, dup := seen[strings.ToLower(p.ParticipantID)]; dup {
			if prev == -1 {
				errs = append(errs, fmt.Errorf("%s.participantId %s duplicates participant.participantId", where, p.ParticipantID))
			} else {
				errs = append(errs, fmt.Errorf("%s.participantId %s duplicates participants[%d]", where, p.ParticipantID, prev))
			}
		} else {
			seen[strings.ToLower(p.ParticipantID)] = i
		}
		// Credentials and key are optional — blank inherits the default —
		// but a key that is present must be usable.
		switch pk := strings.TrimSpace(p.PrivateKey); {
		case pk == "":
		case strings.HasPrefix(pk, "@"):
			errs = append(errs, fmt.Errorf("%s.privateKey: %s was not read (call ResolveFiles first)", where, pk))
		default:
			if _, err := keys.ParsePrivateKey(pk); err != nil {
				errs = append(errs, fmt.Errorf("%s.privateKey is not a valid RSA private key: %w", where, err))
			}
		}
		if (p.ClientID == "") != (p.ClientSecret == "") {
			errs = append(errs, fmt.Errorf("%s: clientId and clientSecret must be set together (or both left blank to inherit)", where))
		}
	}
	if c.Certificate.ValidityDays < 1 || c.Certificate.ValidityDays > 3650 {
		errs = append(errs, errors.New("certificate.validityDays must be between 1 and 3650"))
	}
	switch c.Auth.Mode {
	case "sessions", "get-session":
	default:
		errs = append(errs, fmt.Errorf("auth.mode must be \"sessions\" or \"get-session\", got %q", c.Auth.Mode))
	}
	for name, u := range map[string]string{"urls.nhcx": c.URLs.NHCX, "urls.participant": c.URLs.Participant, "urls.sessions": c.URLs.Sessions} {
		if err := checkURL(u); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	switch c.Log.Format {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log.format must be \"json\" or \"text\", got %q", c.Log.Format))
	}
	switch strings.ToLower(c.Log.Level) {
	case "debug", "info", "warn", "warning", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level must be debug, info, warn or error, got %q", c.Log.Level))
	}
	return errors.Join(errs...)
}

// ValidateServe checks the fields only the HTTP server uses.
func (c *Config) ValidateServe() error {
	var errs []error
	// Every identity must end up with somewhere to deliver to — but not
	// necessarily this block. A participant carrying its own callback (the
	// default one included) needs nothing shared, so the top-level callback
	// is required only when something still falls back to it. Reporting the
	// participant that has no URL beats reporting a field that may not be
	// the one missing.
	for _, p := range c.AllParticipants() {
		if c.CallbackFor(p).URL == "" {
			who := p.ParticipantID
			if who == "" {
				who = "participant"
			}
			errs = append(errs, fmt.Errorf(
				"no callback url for %s: set callback.url, or a callback.url on that participant", who))
		}
	}
	if c.PublicURL != "" {
		if err := checkURL(c.PublicURL); err != nil {
			errs = append(errs, fmt.Errorf("publicUrl: %w", err))
		}
	}
	for path, u := range c.Callback.Routes {
		if err := checkURL(u); err != nil {
			errs = append(errs, fmt.Errorf("callback.routes[%q]: %w", path, err))
		}
	}
	for i, p := range c.Participants {
		if p.Callback == nil {
			continue
		}
		// A hosted profile with no URL of its own falls back to the default
		// callback, which is checked above; only an explicit one is checked here.
		if p.Callback.URL != "" {
			if err := checkURL(p.Callback.URL); err != nil {
				errs = append(errs, fmt.Errorf("participants[%d].callback.url: %w", i, err))
			}
		}
		for path, u := range p.Callback.Routes {
			if err := checkURL(u); err != nil {
				errs = append(errs, fmt.Errorf("participants[%d].callback.routes[%q]: %w", i, path, err))
			}
		}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		errs = append(errs, errors.New("tls.certFile and tls.keyFile must be set together"))
	}
	if c.Env == string(Production) && c.APIKey == "" {
		errs = append(errs, errors.New("apiKey is required in production: /out accepts any caller without it"))
	}
	return errors.Join(errs...)
}

func checkURL(u string) error {
	if strings.TrimSpace(u) == "" {
		return errors.New("is required")
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%q is not an absolute http(s) URL", u)
	}
	return nil
}

// Environment returns the typed environment.
func (c *Config) Environment() Environment { return Environment(c.Env) }

// IsProduction reports whether this instance talks to production NHCX.
func (c *Config) IsProduction() bool { return c.Environment() == Production }

// APIKeyRequired reports whether a caller must present the API key.
//
// Production: always, and ValidateServe refuses to start without a key set.
// Sandbox: no, even when a key is configured. A sandbox adapter is worked by
// hand and by clients written for hcxkit, which authenticates none of these
// routes — demanding a key there turns every call into a 401 for no security
// anyone asked for. The key is still honoured when presented, so a client
// that sends one is not punished for it.
//
// requireApiKey overrides both directions: set it true to close a sandbox
// adapter that is reachable from the network, false to open a production one
// (which ValidateServe will still complain about).
func (c *Config) APIKeyRequired() bool {
	if c.RequireAPIKey != nil {
		return *c.RequireAPIKey
	}
	return c.IsProduction()
}

// RefusesSelfKey reports whether a registry certificate that turns out to be
// one of ours, handed back for somebody else, should stop the message.
//
// In production it should: only the recipient can open a JWE, so encrypting
// with our own key puts a payload on the wire that the far end cannot read —
// and NHCX accepts it, so the failure surfaces over there, hours later, as
// somebody else's problem.
//
// In the sandbox it should not. Participants there are routinely onboarded
// under one credential and share a registered certificate, so the recipient
// really does hold the key and really can decrypt. Refusing turns a working
// sandbox into a wall of 422s. The condition is still logged, because it is
// worth knowing about before the same config reaches production.
func (c *Config) RefusesSelfKey() bool {
	if c.Certs.RefuseSelfKey != nil {
		return *c.Certs.RefuseSelfKey
	}
	return c.IsProduction()
}

// LedgerEnabled reports whether messages are recorded.
func (c *Config) LedgerEnabled() bool { return c.Ledger.Enabled == nil || *c.Ledger.Enabled }

// LedgerStoresBodies reports whether bundles are kept in the ledger.
func (c *Config) LedgerStoresBodies() bool {
	return c.Ledger.StoreBodies == nil || *c.Ledger.StoreBodies
}

// CallbackAppendsPath reports the resolved callback.appendPath.
func (c *Config) CallbackAppendsPath() bool {
	return c.Callback.AppendPath == nil || *c.Callback.AppendPath
}

// ------------------------------------------------------------- profiles ----

// AllParticipants returns every identity this adapter holds, the default
// profile first. Hosted profiles inherit the default's credentials and key
// where they set none of their own, so what comes back is always usable.
func (c *Config) AllParticipants() []Participant {
	out := make([]Participant, 0, 1+len(c.Participants))
	out = append(out, c.Participant)
	for _, p := range c.Participants {
		if p.ClientID == "" && p.ClientSecret == "" {
			p.ClientID, p.ClientSecret = c.Participant.ClientID, c.Participant.ClientSecret
		}
		if strings.TrimSpace(p.PrivateKey) == "" {
			p.PrivateKey = c.Participant.PrivateKey
		}
		out = append(out, p)
	}
	return out
}

// CallbackFor merges a participant's callback over the top-level one. A
// hosted profile that names only a URL keeps the shared timeout, API key,
// appendPath and routes; one that sets a field wins on that field alone.
func (c *Config) CallbackFor(p Participant) Callback {
	cb := c.Callback
	if p.Callback == nil {
		return cb
	}
	if p.Callback.URL != "" {
		cb.URL = p.Callback.URL
		// Routes belong to the URL they were written for. A profile that
		// redirects the base without restating them would otherwise scatter
		// its traffic across two backends.
		cb.Routes = p.Callback.Routes
	}
	if p.Callback.Routes != nil {
		cb.Routes = p.Callback.Routes
	}
	if p.Callback.AppendPath != nil {
		cb.AppendPath = p.Callback.AppendPath
	}
	if p.Callback.TimeoutSeconds > 0 {
		cb.TimeoutSeconds = p.Callback.TimeoutSeconds
	}
	if p.Callback.APIKey != "" {
		cb.APIKey = p.Callback.APIKey
	}
	return cb
}

// AppendsPath reports the resolved appendPath for a merged callback.
func (cb Callback) AppendsPath() bool { return cb.AppendPath == nil || *cb.AppendPath }

// Label names a participant for logs: its name when it has one, else its code.
func (p Participant) Label() string {
	if p.Name != "" {
		return p.Name
	}
	return p.ParticipantID
}
