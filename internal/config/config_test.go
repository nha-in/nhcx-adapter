package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nhcx-gateway/internal/keys"
)

var testKey = func() string {
	m, err := keys.Generate(keys.Subject{CommonName: "test"})
	if err != nil {
		panic(err)
	}
	return m.PrivateKey
}()

const minimal = `{
  "participant": {"participantId": "1000003463", "clientId": "cid", "clientSecret": "${TEST_NHCX_SECRET}", "privateKey": "@key.pem"},
  "callback": {"url": "http://127.0.0.1:1/cb"}
}`

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte(testKey), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSandboxDefaults(t *testing.T) {
	t.Setenv("TEST_NHCX_SECRET", `s3c"ret`)
	cfg, err := Load(writeCfg(t, minimal))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Env != "sandbox" || cfg.CMID != "sbx" {
		t.Errorf("env defaults: %q %q", cfg.Env, cfg.CMID)
	}
	if cfg.URLs.NHCX != "https://apisbx.abdm.gov.in/hcx/v1" || !strings.Contains(cfg.URLs.Participant, "sbxhcx") || !strings.Contains(cfg.URLs.Sessions, "dev.abdm") {
		t.Errorf("sandbox urls: %+v", cfg.URLs)
	}
	if cfg.Participant.ParticipantID != "1000003463@hcx" {
		t.Errorf("participant id not normalised: %q", cfg.Participant.ParticipantID)
	}
	if cfg.Participant.ClientSecret != `s3c"ret` {
		t.Errorf("env expansion (with JSON escaping) failed: %q", cfg.Participant.ClientSecret)
	}
	if !strings.HasPrefix(cfg.Participant.PrivateKey, "-----BEGIN") {
		t.Errorf("@file not resolved: %q", cfg.Participant.PrivateKey)
	}
	if cfg.Log.Format != "text" || cfg.Callback.TimeoutSeconds != 20 || !cfg.CallbackAppendsPath() {
		t.Errorf("defaults: %+v %+v", cfg.Log, cfg.Callback)
	}
	if err := cfg.ValidateServe(); err != nil {
		t.Errorf("sandbox serve without apiKey should be allowed: %v", err)
	}
}

func TestProductionDefaultsAndGuards(t *testing.T) {
	t.Setenv("TEST_NHCX_SECRET", "x")
	body := strings.Replace(minimal, `"participant"`, `"env": "production", "participant"`, 1)
	cfg, err := Load(writeCfg(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CMID != "abdm" || cfg.URLs.NHCX != "https://apis.abdm.gov.in/hcx/v1" ||
		cfg.URLs.Participant != "https://apis.abdm.gov.in/pmjay/hcx/participanthcxservice" ||
		!strings.Contains(cfg.URLs.Sessions, "live.abdm") || cfg.Log.Format != "json" {
		t.Errorf("production defaults: %+v cm=%s log=%+v", cfg.URLs, cfg.CMID, cfg.Log)
	}
	if err := cfg.ValidateServe(); err == nil || !strings.Contains(err.Error(), "apiKey") {
		t.Errorf("production must demand an apiKey, got %v", err)
	}
}

func TestRoutesAndCertificateDefaults(t *testing.T) {
	t.Setenv("TEST_NHCX_SECRET", "x")
	body := strings.Replace(minimal, `"callback": {"url": "http://127.0.0.1:1/cb"}`,
		`"callback": {"url": "http://127.0.0.1:1/cb", "routes": {"/v1/preauth/on_submit/": "http://127.0.0.1:1/preauth"}}, "certificate": {"certificateFile": "cert.pem"}`, 1)
	cfg, err := Load(writeCfg(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Callback.Routes["v1/preauth/on_submit"] != "http://127.0.0.1:1/preauth" {
		t.Errorf("route key not cleaned: %v", cfg.Callback.Routes)
	}
	if cfg.Certificate.ValidityDays != 365 || cfg.Certificate.PrivateKeyFile != "private_key.pem" || cfg.Certificate.CertificateFile != "cert.pem" || cfg.PrivateKeyFile() != "" {
		t.Errorf("certificate defaults: %+v", cfg.Certificate)
	}
	if got := cfg.Resolve("certificate.pem"); !strings.HasPrefix(got, filepath.Dir(cfg.Path())) {
		t.Errorf("Resolve: %s", got)
	}
	pub := strings.Replace(body, `"callback"`, `"publicUrl": "kyro.care/in", "callback"`, 1)
	if cfg, err := Load(writeCfg(t, pub)); err != nil {
		t.Fatal(err)
	} else if err := cfg.ValidateServe(); err == nil || !strings.Contains(err.Error(), "publicUrl") {
		t.Errorf("relative publicUrl must be rejected: %v", err)
	}
	bad := strings.Replace(body, `"http://127.0.0.1:1/preauth"`, `"preauth-svc"`, 1)
	if cfg, err := Load(writeCfg(t, bad)); err != nil {
		t.Fatal(err)
	} else if err := cfg.ValidateServe(); err == nil || !strings.Contains(err.Error(), "routes") {
		t.Errorf("relative route URL must be rejected: %v", err)
	}
	if unresolved, err := Read(writeCfg(t, strings.Replace(minimal, "@key.pem", "@missing.pem", 1))); err != nil {
		t.Errorf("Read must not need the key file: %v", err)
	} else if !strings.HasSuffix(unresolved.PrivateKeyFile(), "/missing.pem") {
		t.Errorf("PrivateKeyFile before resolution: %q", unresolved.PrivateKeyFile())
	}
}

func TestOverridesAndGetSession(t *testing.T) {
	t.Setenv("TEST_NHCX_SECRET", "x")
	body := strings.Replace(minimal, `"participant"`, `"auth": {"mode": "get-session"}, "urls": {"nhcx": "https://gw.example/hcx/v1"}, "participant"`, 1)
	cfg, err := Load(writeCfg(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.URLs.NHCX != "https://gw.example/hcx/v1" {
		t.Errorf("override lost: %s", cfg.URLs.NHCX)
	}
	if want := "https://apisbx.abdm.gov.in/pmjay/sbxhcx/participanthcxservice/get/session"; cfg.URLs.Sessions != want {
		t.Errorf("get-session url = %s, want %s", cfg.URLs.Sessions, want)
	}
}

func TestErrors(t *testing.T) {
	t.Setenv("TEST_NHCX_SECRET", "x")
	cases := map[string]string{
		"missing env var":  strings.Replace(minimal, "TEST_NHCX_SECRET", "TEST_NHCX_UNSET_VAR", 1),
		"unknown field":    strings.Replace(minimal, `"callback"`, `"bogus": 1, "callback"`, 1),
		"bad env":          strings.Replace(minimal, `"participant"`, `"env": "staging", "participant"`, 1),
		"missing key file": strings.Replace(minimal, "@key.pem", "@nope.pem", 1),
		"no client id":     strings.Replace(minimal, `"clientId": "cid", `, "", 1),
		"garbage key":      strings.Replace(minimal, `"@key.pem"`, `"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"`, 1),
	}
	for name, body := range cases {
		if _, err := Load(writeCfg(t, body)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	sample, err := os.ReadFile(filepath.Join("..", "..", "config.sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("NHCX_CLIENT_ID", "a")
	t.Setenv("NHCX_CLIENT_SECRET", "b")
	t.Setenv("NHCX_GATEWAY_API_KEY", "c")
	if _, err := Parse(sample); err != nil {
		t.Errorf("config.sample.json must parse: %v", err)
	}
}
