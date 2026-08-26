// Package config loads and validates the nhcx-gateway configuration.
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

	"nhcx-gateway/internal/keys"
)

// Environment names the NHCX deployment a gateway instance talks to.
type Environment string

const (
	Sandbox    Environment = "sandbox"
	Production Environment = "production"
)

// URLs are the three ABDM endpoints the gateway needs.
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

// Participant is this gateway's own identity on the exchange.
type Participant struct {
	// ParticipantID is the registry code, with or without the "@hcx" suffix.
	ParticipantID string `json:"participantId"`
	// ClientID / ClientSecret are the ABDM credentials issued at onboarding.
	ClientID     string `json:"clientId"`
	ClientSecret string `json:"clientSecret"`
	// PrivateKey is the RSA key matching the encryption certificate registered
	// for this participant: PEM, base64-encoded PEM, or "@file".
	PrivateKey string `json:"privateKey"`
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

// Certificate drives "nhcx-gateway cert generate". The certificate's
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
}

// Ledger records every message that crosses the gateway (see package ledger).
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
	// PublicURL is how NHCX reaches this gateway from the outside, e.g.
	// https://hcx.example.com/in — what belongs in the registry's
	// endpoint_url. Optional; used to propose and verify the registration.
	PublicURL string `json:"publicUrl"`
	// APIKey, when set, must be presented as "Authorization: Bearer" on /out.
	APIKey string `json:"apiKey"`
	// MaxBodyBytes caps request bodies on both surfaces.
	MaxBodyBytes int64 `json:"maxBodyBytes"`
	// OutboundTimeoutSeconds bounds one call to ABDM (token, certs, gateway).
	OutboundTimeoutSeconds int `json:"outboundTimeoutSeconds"`
	// CMID is the X-CM-ID sent to the ABDM session endpoint; blank = env default.
	CMID string `json:"cmId"`

	TLS         TLS         `json:"tls"`
	Participant Participant `json:"participant"`
	Callback    Callback    `json:"callback"`
	Certificate Certificate `json:"certificate"`
	Ledger      Ledger      `json:"ledger"`
	URLs        URLs        `json:"urls"`
	Auth        Auth        `json:"auth"`
	Certs       Certs       `json:"certs"`
	Log         Log         `json:"log"`

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
	c.Participant.ParticipantID = strings.TrimSpace(c.Participant.ParticipantID)
	if c.Participant.ParticipantID != "" && !strings.HasSuffix(c.Participant.ParticipantID, "@hcx") {
		c.Participant.ParticipantID += "@hcx"
	}
}

// ResolveFiles replaces "@path" key material with the file's contents.
func (c *Config) ResolveFiles() error {
	var err error
	c.Participant.PrivateKey, err = c.readRef(c.Participant.PrivateKey)
	if err != nil {
		return fmt.Errorf("participant.privateKey: %w", err)
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
		errs = append(errs, errors.New("participant.privateKey is required (PEM, base64 PEM, or @file) — nhcx-gateway cert generate creates one"))
	case strings.HasPrefix(pk, "@"):
		errs = append(errs, fmt.Errorf("participant.privateKey: %s was not read (call ResolveFiles first)", pk))
	default:
		if _, err := keys.ParsePrivateKey(pk); err != nil {
			errs = append(errs, fmt.Errorf("participant.privateKey is not a valid RSA private key: %w", err))
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
	if err := checkURL(c.Callback.URL); err != nil {
		errs = append(errs, fmt.Errorf("callback.url: %w", err))
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
