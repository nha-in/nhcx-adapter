// Package tui is the arrow-key configurator behind "nhcx-gateway config
// edit". It edits the JSON file itself — never the expanded config — so
// ${ENV} references and @file pointers are written back exactly as typed.
package tui

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"nhcx-gateway/internal/config"
)

type kind int

const (
	kText kind = iota
	kSecret
	kEnum
	kBool
	kInt
	kRoutes
)

// field is one editable value, addressed by its dotted JSON path.
type field struct {
	path    string
	label   string
	kind    kind
	options []string // enum choices; "" means "use the default"
	help    string
	hint    func(doc map[string]any) string // dynamic "(default: …)" text
}

type section struct {
	title  string
	fields []field
}

func envDefault(pick func(config.URLs, string) string) func(map[string]any) string {
	return func(doc map[string]any) string {
		env, _ := get(doc, "env").(string)
		urls, cm := config.EnvironmentDefaults(config.Environment(strings.ToLower(env)))
		return "default: " + pick(urls, cm)
	}
}

var sections = []section{
	{"General", []field{
		{path: "env", label: "Environment", kind: kEnum, options: []string{"sandbox", "production"},
			help: "Which NHCX deployment to talk to. Picks the gateway, registry, session endpoint and X-CM-ID."},
		{path: "listen", label: "Listen address", kind: kText, help: "host:port for the HTTP listener, e.g. 127.0.0.1:8090 or 0.0.0.0:8090."},
		{path: "publicUrl", label: "Public URL", kind: kText, help: "How NHCX reaches this gateway from outside, e.g. https://hcx.example.com/in — proposed as the registry endpoint_url."},
		{path: "apiKey", label: "API key (/out)", kind: kSecret,
			help: "Bearer key your system must send on /out. Required in production. ${VAR} reads it from the environment."},
		{path: "log.level", label: "Log level", kind: kEnum, options: []string{"info", "debug", "warn", "error"}},
		{path: "log.format", label: "Log format", kind: kEnum, options: []string{"", "json", "text"},
			help: "Blank = json in production, text in sandbox."},
	}},
	{"Participant", []field{
		{path: "participant.participantId", label: "Participant ID", kind: kText, help: "Your registry code, e.g. 1000003463@hcx (@hcx is added if missing)."},
		{path: "participant.clientId", label: "Client ID", kind: kText, help: "ABDM client id from onboarding. ${VAR} reads it from the environment."},
		{path: "participant.clientSecret", label: "Client secret", kind: kSecret, help: "ABDM client secret. Prefer ${NHCX_CLIENT_SECRET} over a literal."},
		{path: "participant.privateKey", label: "Private key", kind: kText,
			help: "PEM, base64 PEM, or @file relative to this config. Create one with: nhcx-gateway cert generate"},
	}},
	{"Callback (NHCX → your system)", []field{
		{path: "callback.url", label: "Callback URL", kind: kText, help: "Where decrypted messages are POSTed. The NHCX path is appended when 'Append path' is on."},
		{path: "callback.appendPath", label: "Append path", kind: kBool, help: "…/callback receives an on_submit on …/callback/v1/preauth/on_submit."},
		{path: "callback.timeoutSeconds", label: "Timeout (s)", kind: kInt, help: "How long your backend has to accept a delivery. NHCX wants its 202 within 30 s."},
		{path: "callback.apiKey", label: "Callback API key", kind: kSecret, help: "Sent to your backend as Authorization: Bearer."},
		{path: "callback.routes", label: "Routes", kind: kRoutes,
			help: "Per-path overrides as path=url, comma separated: v1/preauth/on_submit=http://preauth-svc/hook"},
	}},
	{"Endpoints (blank = environment default)", []field{
		{path: "urls.nhcx", label: "NHCX gateway", kind: kText, hint: envDefault(func(u config.URLs, _ string) string { return u.NHCX })},
		{path: "urls.participant", label: "Participant registry", kind: kText, hint: envDefault(func(u config.URLs, _ string) string { return u.Participant })},
		{path: "urls.sessions", label: "Session endpoint", kind: kText, hint: envDefault(func(u config.URLs, _ string) string { return u.Sessions }),
			help: "Only used by auth mode 'sessions'; 'get-session' derives it from the registry URL."},
		{path: "cmId", label: "X-CM-ID", kind: kText, hint: envDefault(func(_ config.URLs, cm string) string { return cm })},
		{path: "auth.mode", label: "Auth mode", kind: kEnum, options: []string{"sessions", "get-session"},
			help: "sessions = ABDM HIECM gateway (JSON). get-session = participant service /get/session (form). Ask your onboarding contact."},
		{path: "auth.tokenTtlSeconds", label: "Token TTL (s)", kind: kInt, help: "Assumed lifetime when the token response has no expiry. Default 1200."},
		{path: "certs.cacheHours", label: "Cert cache (h)", kind: kInt, help: "How long a counterparty certificate is cached. Default 24."},
	}},
	{"Certificate (nhcx-gateway cert generate)", []field{
		{path: "certificate.validityDays", label: "Validity (days)", kind: kInt, help: "Lifetime of a generated certificate. Default 365, at most 3650. The subject is always your participant id."},
		{path: "certificate.privateKeyFile", label: "Private key file", kind: kText, help: "Written relative to this config. Default private_key.pem."},
		{path: "certificate.certificateFile", label: "Certificate file", kind: kText, help: "The encryption_cert you register. Default certificate.pem."},
	}},
	{"Ledger (FHIR traffic record)", []field{
		{path: "ledger.enabled", label: "Enabled", kind: kBool, help: "Record every outbound and inbound message with headers, bundle and outcome; browse with /ledger or `nhcx-gateway ledger`."},
		{path: "ledger.dir", label: "Directory", kind: kText, help: "Relative to this config. Default data/ledger."},
		{path: "ledger.retentionDays", label: "Retention (days)", kind: kInt, help: "Older day folders are pruned hourly. 0 keeps everything."},
		{path: "ledger.storeBodies", label: "Store bundles", kind: kBool, help: "Off keeps only headers and outcomes — no PHI on disk."},
	}},
	{"TLS & limits", []field{
		{path: "tls.certFile", label: "TLS cert file", kind: kText, help: "Terminate HTTPS on the listener. Leave blank behind a reverse proxy."},
		{path: "tls.keyFile", label: "TLS key file", kind: kText},
		{path: "maxBodyBytes", label: "Max body (bytes)", kind: kInt, help: "Default 8388608 (8 MiB)."},
		{path: "outboundTimeoutSeconds", label: "ABDM timeout (s)", kind: kInt, help: "Per call to the token, registry and gateway endpoints. Default 30."},
	}},
}

// row is one line of the form: a section header or a field.
type row struct {
	header string
	field  *field
}

// Model is the Bubble Tea model.
type Model struct {
	path   string
	doc    map[string]any
	rows   []row
	cursor int
	offset int

	editing bool
	input   textinput.Model

	message string // banner shown above the form (why the editor was opened)

	dirty       bool
	confirmQuit bool
	saved       bool
	status      string
	statusIsErr bool
	problems    []string

	width, height int
}

// New builds a model over the JSON in raw, to be saved at path. message,
// when set, is shown above the form — the reason the editor was opened.
func New(path string, raw []byte, message string) (*Model, error) {
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s is not a JSON object: %w", path, err)
	}
	m := &Model{path: path, doc: doc, width: 100, height: 30, message: strings.TrimSpace(message)}
	for i := range sections {
		m.rows = append(m.rows, row{header: sections[i].title})
		for j := range sections[i].fields {
			m.rows = append(m.rows, row{field: &sections[i].fields[j]})
		}
	}
	m.cursor = 1
	m.input = textinput.New()
	m.input.Prompt = ""
	m.input.CharLimit = 4096
	m.validate()
	return m, nil
}

// Run opens the editor in the alternate screen and returns once the user
// quits. saved reports whether the file was written at least once. message
// is shown above the form when non-empty.
func Run(path string, raw []byte, message string) (saved bool, err error) {
	m, err := New(path, raw, message)
	if err != nil {
		return false, err
	}
	final, err := tea.NewProgram(m, tea.WithAltScreen()).Run()
	if err != nil {
		return false, err
	}
	if fm, ok := final.(*Model); ok {
		return fm.saved, nil
	}
	return m.saved, nil
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd { return nil }

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.input.Width = max(20, m.width-30)
		m.scroll()
		return m, nil
	case tea.KeyMsg:
		if m.editing {
			return m.updateEditing(msg)
		}
		return m.updateNav(msg)
	}
	return m, nil
}

func (m *Model) updateNav(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	if key != "q" && key != "ctrl+c" && key != "esc" {
		m.confirmQuit = false
	}
	switch key {
	case "ctrl+c":
		return m, tea.Quit
	case "q", "esc":
		if m.dirty && !m.confirmQuit {
			m.confirmQuit = true
			m.setStatus("unsaved changes — ctrl+s to save, q again to discard", true)
			return m, nil
		}
		return m, tea.Quit
	case "ctrl+s", "s":
		if err := m.save(); err != nil {
			m.setStatus("save failed: "+err.Error(), true)
		} else if len(m.problems) > 0 {
			m.setStatus(fmt.Sprintf("saved %s — %d problem(s) remain, see below", m.path, len(m.problems)), true)
		} else {
			m.setStatus("saved "+m.path, false)
		}
	case "up", "k", "shift+tab":
		m.move(-1)
	case "down", "j", "tab":
		m.move(1)
	case "pgup":
		for i := 0; i < 8; i++ {
			m.move(-1)
		}
	case "pgdown":
		for i := 0; i < 8; i++ {
			m.move(1)
		}
	case "home":
		m.cursor = 1
		m.scroll()
	case "end":
		m.cursor = len(m.rows) - 1
		m.scroll()
	case "left", "right", "h", "l", " ":
		f := m.current()
		switch f.kind {
		case kEnum:
			m.cycle(f, key == "left" || key == "h")
		case kBool:
			m.setValue(f, !m.boolValue(f))
		case kInt:
			delta := 1
			if key == "left" || key == "h" {
				delta = -1
			}
			if key == " " {
				return m, m.startEdit()
			}
			n, _ := strconv.Atoi(m.display(f, true))
			if n+delta >= 0 {
				m.setValue(f, n+delta)
			}
		default:
			return m, m.startEdit()
		}
	case "enter":
		f := m.current()
		switch f.kind {
		case kEnum:
			m.cycle(f, false)
		case kBool:
			m.setValue(f, !m.boolValue(f))
		default:
			return m, m.startEdit()
		}
	case "backspace", "delete", "ctrl+u":
		f := m.current()
		if f.kind != kBool {
			m.setValue(f, nil)
		}
	}
	return m, nil
}

func (m *Model) updateEditing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		return m, tea.Quit
	case "esc":
		m.editing = false
		m.input.Blur()
		return m, nil
	case "enter":
		f := m.current()
		text := strings.TrimSpace(m.input.Value())
		if err := m.commit(f, text); err != nil {
			m.setStatus(err.Error(), true)
			return m, nil
		}
		m.editing = false
		m.input.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m *Model) startEdit() tea.Cmd {
	f := m.current()
	m.editing = true
	m.input.SetValue(m.display(f, true))
	m.input.CursorEnd()
	return m.input.Focus()
}

// commit stores the edited text according to the field's kind.
func (m *Model) commit(f *field, text string) error {
	switch f.kind {
	case kInt:
		if text == "" {
			m.setValue(f, nil)
			return nil
		}
		n, err := strconv.Atoi(text)
		if err != nil || n < 0 {
			return errors.New("must be a whole number")
		}
		m.setValue(f, n)
	case kRoutes:
		routes, err := parseRoutes(text)
		if err != nil {
			return err
		}
		if len(routes) == 0 {
			m.setValue(f, nil)
		} else {
			m.setValue(f, routes)
		}
	default:
		if text == "" {
			m.setValue(f, nil)
		} else {
			m.setValue(f, text)
		}
	}
	return nil
}

func (m *Model) current() *field { return m.rows[m.cursor].field }

func (m *Model) move(delta int) {
	for i := m.cursor + delta; i >= 0 && i < len(m.rows); i += delta {
		if m.rows[i].field != nil {
			m.cursor = i
			break
		}
	}
	m.scroll()
}

func (m *Model) visibleRows() int { return max(5, m.height-7-m.bannerLines()) }

func (m *Model) bannerLines() int {
	if m.message == "" {
		return 0
	}
	return len(wrap(m.message, max(20, m.width-4))) + 1
}

func (m *Model) scroll() {
	v := m.visibleRows()
	// Keep the section header in view when the first field of a section is selected.
	top := m.cursor
	if top > 0 && m.rows[top-1].field == nil {
		top--
	}
	if top < m.offset {
		m.offset = top
	}
	if m.cursor >= m.offset+v {
		m.offset = m.cursor - v + 1
	}
	if m.offset < 0 {
		m.offset = 0
	}
}

func (m *Model) cycle(f *field, backwards bool) {
	cur := m.display(f, true)
	idx := 0
	for i, o := range f.options {
		if o == cur {
			idx = i
			break
		}
	}
	if backwards {
		idx = (idx - 1 + len(f.options)) % len(f.options)
	} else {
		idx = (idx + 1) % len(f.options)
	}
	if f.options[idx] == "" {
		m.setValue(f, nil)
	} else {
		m.setValue(f, f.options[idx])
	}
}

func (m *Model) boolValue(f *field) bool {
	v := get(m.doc, f.path)
	if b, ok := v.(bool); ok {
		return b
	}
	switch f.path { // absent means true for these
	case "callback.appendPath", "ledger.enabled", "ledger.storeBodies":
		return true
	}
	return false
}

func (m *Model) setValue(f *field, v any) {
	set(m.doc, f.path, v)
	m.dirty = true
	m.validate()
}

func (m *Model) setStatus(s string, isErr bool) {
	m.status, m.statusIsErr = s, isErr
}

// display renders a field's value; raw skips secret masking.
func (m *Model) display(f *field, raw bool) string {
	v := get(m.doc, f.path)
	switch f.kind {
	case kBool:
		return strconv.FormatBool(m.boolValue(f))
	case kRoutes:
		return formatRoutes(v)
	}
	var s string
	switch t := v.(type) {
	case nil:
		s = ""
	case string:
		s = t
	case json.Number:
		s = t.String()
	case float64:
		s = strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		s = strconv.FormatBool(t)
	default:
		b, _ := json.Marshal(t)
		s = string(b)
	}
	if f.kind == kSecret && !raw && s != "" && !strings.HasPrefix(s, "${") {
		return strings.Repeat("•", min(len(s), 12))
	}
	if f.path == "participant.privateKey" && !raw && strings.Contains(s, "-----BEGIN") {
		return "(inline PEM, " + strconv.Itoa(len(s)) + " bytes)"
	}
	return s
}

// ------------------------------------------------------------ validate ----

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// validate runs the real config loader over the document, treating unset
// ${ENV} references as present so the editor reports structural problems
// rather than the current shell's environment. The private key is read and
// parsed for real, so a wrong path or a non-key file shows up here.
func (m *Model) validate() {
	m.problems = nil
	raw, err := m.marshal()
	if err != nil {
		m.problems = []string{err.Error()}
		return
	}
	text := envRef.ReplaceAllStringFunc(string(raw), func(ref string) string {
		if _, ok := os.LookupEnv(ref[2 : len(ref)-1]); ok {
			return ref
		}
		return "placeholder"
	})
	cfg, err := config.ParseAt([]byte(text), m.path)
	if err != nil {
		m.problems = []string{strings.TrimPrefix(err.Error(), "parse config: ")}
		return
	}
	var errs []error
	if err := cfg.ResolveFiles(); err != nil {
		errs = append(errs, fmt.Errorf("%w — create one with: nhcx-gateway cert generate", err))
		cfg.Participant.PrivateKey = "" // report the missing file once, not twice
	}
	if err := cfg.Validate(); err != nil {
		errs = append(errs, err)
	}
	if err := cfg.ValidateServe(); err != nil {
		errs = append(errs, err)
	}
	for _, e := range errs {
		for _, line := range strings.Split(e.Error(), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, "privateKey is required") && cfg.Participant.PrivateKey == "" && len(errs) > 1 {
				continue
			}
			m.problems = append(m.problems, line)
		}
	}
}

// ---------------------------------------------------------------- save ----

func (m *Model) save() error {
	raw, err := m.marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.path, raw, 0o600); err != nil {
		return err
	}
	m.dirty, m.saved, m.confirmQuit = false, true, false
	return nil
}

// marshal writes the document with keys in form order, so a saved file
// reads like the sample rather than alphabetically.
func (m *Model) marshal() ([]byte, error) {
	var order []string
	for _, s := range sections {
		for _, f := range s.fields {
			order = append(order, f.path)
		}
	}
	return json.MarshalIndent(ordered(m.doc, order, ""), "", "  ")
}

// omap marshals with an explicit key order.
type omap struct {
	keys []string
	vals map[string]any
}

func (o omap) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := json.Marshal(o.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func ordered(doc map[string]any, order []string, prefix string) omap {
	o := omap{vals: map[string]any{}}
	seen := map[string]bool{}
	add := func(k string) {
		if seen[k] {
			return
		}
		v, ok := doc[k]
		if !ok {
			return
		}
		seen[k] = true
		if sub, isMap := v.(map[string]any); isMap && k != "routes" {
			v = ordered(sub, order, prefix+k+".")
		}
		o.keys = append(o.keys, k)
		o.vals[k] = v
	}
	for _, p := range order {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, prefix)
		add(strings.SplitN(rest, ".", 2)[0])
	}
	var extra []string
	for k := range doc {
		if !seen[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	for _, k := range extra {
		add(k)
	}
	return o
}

// ---------------------------------------------------------------- view ----

var (
	styTitle   = lipgloss.NewStyle().Bold(true)
	stySection = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("6"))
	styLabel   = lipgloss.NewStyle().Foreground(lipgloss.Color("7"))
	stySel     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#000000")).Background(lipgloss.Color("6"))
	styHint    = lipgloss.NewStyle().Faint(true)
	styOK      = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	styErr     = lipgloss.NewStyle().Foreground(lipgloss.Color("1"))
	styHelp    = lipgloss.NewStyle().Faint(true)
)

// View implements tea.Model.
func (m *Model) View() string {
	var b strings.Builder
	title := " nhcx-gateway · " + m.path
	if m.dirty {
		title += "  [modified]"
	}
	b.WriteString(styTitle.Render(title) + "\n")
	if m.message != "" {
		for _, line := range wrap(m.message, max(20, m.width-4)) {
			b.WriteString("  " + styErr.Render(line) + "\n")
		}
	}
	b.WriteString("\n")

	end := min(len(m.rows), m.offset+m.visibleRows())
	for i := m.offset; i < end; i++ {
		r := m.rows[i]
		if r.field == nil {
			b.WriteString("  " + stySection.Render(r.header) + "\n")
			continue
		}
		f := r.field
		label := fmt.Sprintf("%-22s", f.label)
		var value string
		switch {
		case m.editing && i == m.cursor:
			value = m.input.View()
		case f.kind == kEnum:
			value = "◂ " + orDefault(m.display(f, false)) + " ▸"
		case f.kind == kBool:
			value = "◂ " + m.display(f, false) + " ▸"
		default:
			value = m.display(f, false)
			if value == "" && f.hint != nil {
				value = styHint.Render("(" + f.hint(m.doc) + ")")
			} else if value == "" {
				value = styHint.Render("(unset)")
			}
		}
		if i == m.cursor {
			b.WriteString(stySel.Render(" ▸ "+label) + " " + value + "\n")
		} else {
			b.WriteString("   " + styLabel.Render(label) + " " + value + "\n")
		}
	}
	for i := end - m.offset; i < m.visibleRows(); i++ {
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if m.editing {
		b.WriteString(styHelp.Render(" enter save value · esc cancel") + "\n")
	} else {
		b.WriteString(styHelp.Render(" ↑↓ move · enter/←→ edit or change · backspace clear · ctrl+s save · q quit") + "\n")
	}
	if f := m.current(); f != nil && f.help != "" {
		b.WriteString(" " + styHint.Render(truncate(f.help, m.width-2)) + "\n")
	} else {
		b.WriteString("\n")
	}
	switch {
	case m.status != "" && m.statusIsErr:
		b.WriteString(" " + styErr.Render(truncate(m.status, m.width-2)) + "\n")
	case m.status != "":
		b.WriteString(" " + styOK.Render(truncate(m.status, m.width-2)) + "\n")
	case len(m.problems) > 0:
		b.WriteString(" " + styErr.Render(truncate(fmt.Sprintf("✗ %d problem(s): %s", len(m.problems), m.problems[0]), m.width-2)) + "\n")
	default:
		b.WriteString(" " + styOK.Render("✓ configuration is valid") + "\n")
	}
	return b.String()
}

// wrap breaks s into lines of at most n runes on word boundaries.
func wrap(s string, n int) []string {
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			continue
		}
		line := words[0]
		for _, w := range words[1:] {
			if len(line)+1+len(w) > n {
				lines = append(lines, line)
				line = w
				continue
			}
			line += " " + w
		}
		lines = append(lines, line)
	}
	return lines
}

func orDefault(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return s[:n-1] + "…"
}

// SetValues edits a config file in place: each dotted path is set to its
// value (nil deletes), keys are written in form order and everything else —
// ${ENV} references, @file pointers, unknown keys — is preserved verbatim.
func SetValues(path string, values map[string]any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	m, err := New(path, raw, "")
	if err != nil {
		return err
	}
	for k, v := range values {
		set(m.doc, k, v)
	}
	out, err := m.marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
}

// ----------------------------------------------------------- doc helpers ----

// get reads a dotted path; nil when absent.
func get(doc map[string]any, path string) any {
	parts := strings.Split(path, ".")
	var cur any = doc
	for _, p := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur, ok = m[p]
		if !ok {
			return nil
		}
	}
	return cur
}

// set writes a dotted path, creating objects on the way; nil deletes the
// key and prunes objects it leaves empty.
func set(doc map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	if v == nil {
		del(doc, parts)
		return
	}
	cur := doc
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur[p].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[p] = next
		}
		cur = next
	}
	cur[parts[len(parts)-1]] = v
}

func del(doc map[string]any, parts []string) bool {
	if len(parts) == 1 {
		delete(doc, parts[0])
		return len(doc) == 0
	}
	sub, ok := doc[parts[0]].(map[string]any)
	if !ok {
		return false
	}
	if del(sub, parts[1:]) {
		delete(doc, parts[0])
	}
	return len(doc) == 0
}

func formatRoutes(v any) string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		s, _ := m[k].(string)
		parts = append(parts, k+"="+s)
	}
	return strings.Join(parts, ", ")
}

func parseRoutes(text string) (map[string]any, error) {
	out := map[string]any{}
	for _, pair := range strings.Split(text, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		k, v = strings.Trim(strings.TrimSpace(k), "/"), strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("route %q must be path=url", pair)
		}
		out[k] = v
	}
	return out, nil
}
