package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"nhcx-gateway/internal/config"
	"nhcx-gateway/internal/keys"
)

func key(k string) tea.KeyMsg {
	switch k {
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		return tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		return tea.KeyMsg{Type: tea.KeyRight}
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "ctrl+s":
		return tea.KeyMsg{Type: tea.KeyCtrlS}
	case "backspace":
		return tea.KeyMsg{Type: tea.KeyBackspace}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
}

func press(m *Model, keys ...string) {
	for _, k := range keys {
		m.Update(key(k))
	}
}

func typeText(m *Model, s string) {
	for _, r := range s {
		m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

func (m *Model) goTo(t *testing.T, path string) {
	t.Helper()
	m.cursor = 1
	for i := 0; i < len(m.rows)*2; i++ {
		if m.current().path == path {
			return
		}
		press(m, "down")
	}
	t.Fatalf("no field %s", path)
}

func TestEditAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	sample, err := os.ReadFile(filepath.Join("..", "..", "config.sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(path, sample, "why the editor opened")
	if err != nil {
		t.Fatal(err)
	}
	m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if v := m.View(); !strings.Contains(v, "why the editor opened") {
		t.Error("message banner missing")
	}

	// Enum: right arrow cycles env to production.
	m.goTo(t, "env")
	press(m, "right")
	if got := get(m.doc, "env"); got != "production" {
		t.Errorf("env = %v", got)
	}
	// Text: enter, retype, enter.
	m.goTo(t, "listen")
	press(m, "enter")
	if !m.editing {
		t.Fatal("enter should start editing")
	}
	m.input.SetValue("")
	typeText(m, "0.0.0.0:9000")
	press(m, "enter")
	if m.editing || get(m.doc, "listen") != "0.0.0.0:9000" {
		t.Errorf("listen = %v editing=%v", get(m.doc, "listen"), m.editing)
	}
	// Esc cancels an edit.
	press(m, "enter")
	typeText(m, "junk")
	press(m, "esc")
	if get(m.doc, "listen") != "0.0.0.0:9000" {
		t.Error("esc must discard the edit")
	}
	// Int: rejects garbage, accepts digits; arrows step.
	m.goTo(t, "callback.timeoutSeconds")
	press(m, "enter")
	m.input.SetValue("abc")
	press(m, "enter")
	if !m.editing || !m.statusIsErr {
		t.Error("non-numeric timeout must be refused")
	}
	m.input.SetValue("25")
	press(m, "enter")
	press(m, "right")
	if got := get(m.doc, "callback.timeoutSeconds"); got != 26 {
		t.Errorf("timeout = %v", got)
	}
	// Bool toggles.
	m.goTo(t, "callback.appendPath")
	press(m, "enter")
	if get(m.doc, "callback.appendPath") != false {
		t.Error("appendPath should toggle to false")
	}
	// Routes parse into a map; a bad pair is refused.
	m.goTo(t, "callback.routes")
	press(m, "enter")
	m.input.SetValue("/v1/preauth/on_submit/=http://a/x, v1/claim/on_submit=http://b/y")
	press(m, "enter")
	routes, _ := get(m.doc, "callback.routes").(map[string]any)
	if routes["v1/preauth/on_submit"] != "http://a/x" || routes["v1/claim/on_submit"] != "http://b/y" {
		t.Errorf("routes = %v", routes)
	}
	press(m, "enter")
	m.input.SetValue("nonsense")
	press(m, "enter")
	if !m.editing {
		t.Error("bad route must be refused")
	}
	press(m, "esc")
	// Backspace clears a text field so the default applies.
	m.goTo(t, "urls.nhcx")
	press(m, "backspace")
	if _, ok := m.doc["urls"].(map[string]any)["nhcx"]; ok {
		t.Error("cleared key should be removed")
	}

	// Validation reads the key for real: missing file, then a non-key file.
	if !hasProblem(m, "no such file") {
		t.Errorf("expected key-file problem, got %v", m.problems)
	}
	if err := os.WriteFile(filepath.Join(dir, "private_key.pem"), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	m.validate()
	if !hasProblem(m, "not a valid RSA private key") {
		t.Errorf("expected invalid-key problem, got %v", m.problems)
	}
	km, _ := keys.Generate(keys.Subject{CommonName: "t"})
	_ = os.WriteFile(filepath.Join(dir, "private_key.pem"), []byte(km.PrivateKey), 0o600)
	m.validate()
	if hasProblem(m, "privateKey") {
		t.Errorf("valid key must not be reported: %v", m.problems)
	}
	// q on a dirty model asks first; ctrl+s saves.
	_, cmd := m.Update(key("q"))
	if cmd != nil || !m.confirmQuit {
		t.Error("first q with unsaved changes must not quit")
	}
	press(m, "ctrl+s")
	if m.dirty || !m.saved {
		t.Errorf("save: dirty=%v saved=%v status=%s", m.dirty, m.saved, m.status)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.Contains(text, "${NHCX_CLIENT_SECRET}") {
		t.Error("env references must be written back verbatim")
	}
	if strings.Index(text, `"env"`) > strings.Index(text, `"participant"`) || strings.Index(text, `"participant"`) > strings.Index(text, `"certificate"`) {
		t.Error("keys should be written in form order")
	}
	t.Setenv("NHCX_CLIENT_ID", "a")
	t.Setenv("NHCX_CLIENT_SECRET", "b")
	t.Setenv("NHCX_GATEWAY_API_KEY", "c")
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("saved file must parse: %v", err)
	}
	if cfg.Env != "production" || cfg.Listen != "0.0.0.0:9000" || cfg.Callback.TimeoutSeconds != 26 || cfg.CallbackAppendsPath() || cfg.URLs.NHCX != "https://apis.abdm.gov.in/hcx/v1" {
		t.Errorf("saved config: %+v", cfg)
	}
	// Once saved, q quits.
	_, cmd = m.Update(key("q"))
	if cmd == nil {
		t.Error("q on a clean model must quit")
	}
	if v := m.View(); !strings.Contains(v, "nhcx-gateway") || !strings.Contains(v, "Environment") {
		t.Error("view renders")
	}
}

func TestSetValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(`{"participant":{"clientId":"${ID}"},"zzz":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetValues(path, map[string]any{"participant.privateKey": "@k.pem", "env": "production"}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	text := string(raw)
	for _, want := range []string{`"${ID}"`, `"@k.pem"`, `"production"`, `"zzz": 1`} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %s in %s", want, text)
		}
	}
}

func hasProblem(m *Model, s string) bool {
	for _, p := range m.problems {
		if strings.Contains(p, s) {
			return true
		}
	}
	return false
}

func TestSecretsMasked(t *testing.T) {
	m, err := New("x.json", []byte(`{"apiKey":"hunter2","participant":{"clientSecret":"${S}"}}`), "")
	if err != nil {
		t.Fatal(err)
	}
	m.goTo(t, "apiKey")
	if v := m.View(); strings.Contains(v, "hunter2") {
		t.Error("literal secret must be masked in the view")
	}
	m.goTo(t, "participant.clientSecret")
	if v := m.View(); !strings.Contains(v, "${S}") {
		t.Error("env references are shown as-is")
	}
}
