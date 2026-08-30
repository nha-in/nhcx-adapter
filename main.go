// nhcx-adapter is a minimal, stateless NHCX adapter: it encrypts and sends
// FHIR bundles to the exchange, decrypts and delivers what the exchange
// sends back, and fetches recipient certificates on demand. Nothing else.
//
//	nhcx-adapter serve   [--config config.json]
//	nhcx-adapter send    [--config config.json] --path v1/preauth/submit --recipient CODE [--file bundle.json]
//	nhcx-adapter cert    [--config config.json] CODE [--refresh]
//	nhcx-adapter cert generate [--config config.json] [--force]
//	nhcx-adapter token   [--config config.json]
//	nhcx-adapter decrypt [--config config.json] [--file jwe.txt]
//	nhcx-adapter config init [path]
//	nhcx-adapter config edit [path]
//	nhcx-adapter update  [--list | --check | --latest | --to TAG] [-y]
//	nhcx-adapter version
package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"nhcx-adapter/internal/abdm"
	"nhcx-adapter/internal/adapter"
	"nhcx-adapter/internal/banner"
	"nhcx-adapter/internal/config"
	"nhcx-adapter/internal/keys"
	"nhcx-adapter/internal/ledger"
	"nhcx-adapter/internal/logfmt"
	"nhcx-adapter/internal/nhcx"
	"nhcx-adapter/internal/preflight"
	"nhcx-adapter/internal/probe"
	"nhcx-adapter/internal/server"
	"nhcx-adapter/internal/style"
	"nhcx-adapter/internal/tui"
	"nhcx-adapter/internal/update"
)

//go:embed config.sample.json
var sampleConfig string

// Set by the build: -ldflags "-X main.version=... -X main.commit=... -X main.builtAt=..."
var (
	version = "dev"
	commit  = "unknown"
	builtAt = "unknown"
)

const usage = `nhcx-adapter — stateless NHCX adapter (sandbox and production)

Usage:
  nhcx-adapter serve    [--config FILE] [--no-tui] [--skip-checks] [--no-banner] [--no-update-check]
                                                                 run the HTTP adapter (checks the setup first)
  nhcx-adapter check    [--config FILE] [--no-tui] [--endpoint URL] run the setup checks, offer fixes, and exit
  nhcx-adapter send     [--config FILE] --path P --recipient C   send one bundle (from --file or stdin)
                        [--sender C] [--correlation-id ID] [--workflow-id ID] [--status S]
  nhcx-adapter cert     [--config FILE] CODE [--refresh]          print a participant's encryption certificate
  nhcx-adapter cert generate [--config FILE] [--days N] [--force] generate this participant's key + certificate
  nhcx-adapter token    [--config FILE]                          print a fresh session token
  nhcx-adapter decrypt  [--config FILE] [--file FILE]            decrypt a compact JWE (from --file or stdin)
  nhcx-adapter config init [FILE]                                write a sample config (default: config.json)
  nhcx-adapter config edit [FILE]                                edit a config with an arrow-key form (creates it if missing)
  nhcx-adapter ledger list   [--direction out|in] [--entity E] [--status S] [--correlation-id ID]
                             [--participant CODE] [--since 24h] [--limit N] [--json]
  nhcx-adapter ledger show   ID [--json]                        one message in full, bundle included
  nhcx-adapter ledger thread CORRELATION_ID [--json]            an exchange and where it stands
  nhcx-adapter ledger stats  [--json]
  nhcx-adapter update   [--list] [--check] [--latest] [--to TAG] [-y] [--prerelease]
                                                                 list the GitHub releases; upgrade or downgrade this binary
  nhcx-adapter version

The config path defaults to $NHCX_ADAPTER_CONFIG, then ./config.json.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	update.CleanupOld() // a Windows update leaves the previous binary as .old
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "send":
		err = cmdSend(os.Args[2:])
	case "cert":
		err = cmdCert(os.Args[2:])
	case "token":
		err = cmdToken(os.Args[2:])
	case "decrypt":
		err = cmdDecrypt(os.Args[2:])
	case "config":
		err = cmdConfig(os.Args[2:])
	case "ledger":
		err = cmdLedger(os.Args[2:])
	case "update":
		err = cmdUpdate(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("%s %s (%s) built %s\n", style.Brand("nhcx-adapter"), version, commit, builtAt)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, style.Bad("error:"), err)
		if e := new(abdm.Error); errors.As(err, &e) && e.Body != "" {
			fmt.Fprintln(os.Stderr, style.Dim("upstream:"), style.Dim(e.Body))
		}
		os.Exit(1)
	}
}

// ------------------------------------------------------------ plumbing ----

func newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	def := os.Getenv("NHCX_ADAPTER_CONFIG")
	if def == "" {
		def = "config.json"
	}
	cfgPath := fs.String("config", def, "path to the config file")
	return fs, cfgPath
}

func load(path string) (*config.Config, *adapter.Adapter, *slog.Logger, error) {
	cfg, err := config.Load(path)
	if err != nil {
		return nil, nil, nil, err
	}
	logger := newLogger(cfg)
	gw, err := adapter.New(cfg, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, gw, logger, nil
}

// logOut is where the logger writes. It can be muted while a full-screen
// prompt is up, so server log lines cannot garble the display; lines
// written meanwhile are flushed when it is unmuted.
var logOut = &muteWriter{w: os.Stderr}

type muteWriter struct {
	mu    sync.Mutex
	w     io.Writer
	muted bool
	buf   []byte
}

func (m *muteWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.muted {
		m.buf = append(m.buf, p...)
		return len(p), nil
	}
	return m.w.Write(p)
}

func (m *muteWriter) Mute() {
	m.mu.Lock()
	m.muted = true
	m.mu.Unlock()
}

func (m *muteWriter) Unmute() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.muted = false
	if len(m.buf) > 0 {
		_, _ = m.w.Write(m.buf)
		m.buf = nil
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}
	var h slog.Handler
	if cfg.Log.Format == "json" {
		h = slog.NewJSONHandler(logOut, opts)
	} else {
		h = logfmt.New(logOut, level)
	}
	return slog.New(h).With("env", cfg.Env)
}

func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// ------------------------------------------------------------ commands ----

func cmdServe(args []string) error {
	fs, cfgPath := newFlags("serve")
	noTUI := fs.Bool("no-tui", false, "never open the configurator or prompts; fail or warn instead")
	skip := fs.Bool("skip-checks", false, "start without the session / registry / certificate / endpoint checks")
	noBanner := fs.Bool("no-banner", os.Getenv("NHCX_ADAPTER_NO_BANNER") != "", "do not print the startup banner (also NHCX_ADAPTER_NO_BANNER=1)")
	noUpdate := fs.Bool("no-update-check", os.Getenv("NHCX_ADAPTER_NO_UPDATE_CHECK") != "", "do not look for a newer release on GitHub at startup (also NHCX_ADAPTER_NO_UPDATE_CHECK=1)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	interactive := !*noTUI && isTerminal()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg, gw, logger, rep, err := prepare(ctx, *cfgPath, interactive, *skip)
	if err != nil {
		return err
	}
	if !*noBanner {
		fmt.Fprint(os.Stderr, banner.Serve(version, cfg.Env, cfg.Participant.ParticipantID, cfg.Listen))
	}
	logger.Info("nhcx-adapter starting", "version", version, "callback", gw.DeliveryURL("", ""), "nhcx", cfg.URLs.NHCX,
		"participants", gw.Profiles().Len())
	// With more than one identity, say which callback each one's traffic goes
	// to — the single "callback" field above is only the default's.
	if gw.Profiles().Hosted() {
		for _, prof := range gw.Profiles().All() {
			logger.Info("hosting participant", "participant", prof.Code(), "name", prof.Label(),
				"callback", gw.DeliveryURL("", prof.Code()), "default", prof.Default)
		}
	}
	srv := server.New(gw, logger, version)

	serveCtx, cancelServe := context.WithCancel(ctx)
	defer cancelServe()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(serveCtx) }()
	if !*noUpdate {
		notifyUpdate(serveCtx, logger)
	}

	// The registered endpoint can only be tested once we are listening; the
	// server keeps serving underneath while the operator decides what to do.
	if rep != nil && rep.Participant != nil {
		select {
		case err := <-errCh:
			return err
		case <-time.After(750 * time.Millisecond):
		}
		if err := verifyEndpoint(ctx, cfg, gw, rep, logger, interactive); err != nil {
			cancelServe()
			<-errCh
			return err
		}
	}
	return <-errCh
}

// withListener runs fn with this adapter listening on cfg.Listen. If the
// port is already taken, an instance is assumed to be running there and fn
// runs against it. Either way the local listener is confirmed with a
// /healthz call first, so a failing public URL is never mistaken for a
// adapter that is not up.
func withListener(ctx context.Context, gw *adapter.Adapter, logger *slog.Logger, fn func() error) error {
	cfg := gw.Config()
	local := "http://" + strings.Replace(cfg.Listen, "0.0.0.0:", "127.0.0.1:", 1) + "/healthz"
	if strings.HasPrefix(cfg.Listen, ":") {
		local = "http://127.0.0.1" + cfg.Listen + "/healthz"
	}
	if cfg.TLS.CertFile != "" {
		local = strings.Replace(local, "http://", "https://", 1)
	}

	probe := func() preflight.Check {
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		c := preflight.TestEndpoint(pctx, strings.TrimSuffix(local, "/healthz"), probe.Key(cfg))
		c.Name = "local listener"
		return c
	}

	if c := probe(); c.OK {
		fmt.Fprintf(os.Stderr, "  %s %-24s %s\n", style.Good("✓"), c.Name, style.Dim(cfg.Listen+" (already running)"))
		return fn()
	}

	srvCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- server.New(gw, logger, version).Run(srvCtx) }()

	var c preflight.Check
	for i := 0; i < 20; i++ {
		select {
		case err := <-errCh:
			return fmt.Errorf("could not start the listener on %s: %w", cfg.Listen, err)
		case <-time.After(150 * time.Millisecond):
		}
		if c = probe(); c.OK {
			break
		}
	}
	if !c.OK {
		cancel()
		<-errCh
		return fmt.Errorf("listener on %s did not come up: %s", cfg.Listen, c.Detail)
	}
	fmt.Fprintf(os.Stderr, "  %s %-24s %s\n", style.Good("✓"), c.Name, style.Dim(cfg.Listen+" (started for this check)"))
	err := fn()
	cancel()
	<-errCh
	return err
}

// verifyEndpoint tests the registry's endpoint_url against this adapter and,
// interactively, offers to re-register it. It returns an error only when
// the operator chooses to quit.
func verifyEndpoint(ctx context.Context, cfg *config.Config, gw *adapter.Adapter, rep *preflight.Report, logger *slog.Logger, interactive bool) error {
	registered := rep.Participant.EndpointURL
	for {
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		c := preflight.TestEndpoint(tctx, registered, probe.Key(cfg))
		cancel()
		if c.OK {
			logger.Info("registered endpoint verified", "detail", c.Detail)
			return nil
		}
		logger.Warn("registered endpoint check failed", "detail", c.Detail)
		if !interactive {
			logger.Warn("NHCX cannot deliver callbacks until endpoint_url reaches this adapter",
				"hint", "set publicUrl and run `nhcx-adapter check` in a terminal, or update endpoint_url on the registry to https://<public-host>/in")
			return nil
		}
		next, err := fixEndpoint(ctx, cfg, gw, rep, registered, c)
		if err != nil {
			return err
		}
		if next == "" { // continue without changing
			return nil
		}
		registered = next
	}
}

// fixEndpoint offers to point the registry at this adapter. It returns the
// URL to test next, "" to stop, or an error to quit.
func fixEndpoint(ctx context.Context, cfg *config.Config, gw *adapter.Adapter, rep *preflight.Report, registered string, c preflight.Check) (string, error) {
	logOut.Mute()
	defer logOut.Unmute()

	proposed := strings.TrimRight(cfg.PublicURL, "/")
	body := []string{
		"NHCX delivers every callback for " + cfg.Participant.ParticipantID + " to the endpoint_url on the participant registry, and that URL does not lead to this adapter:",
		"  " + c.Detail,
	}
	if registered != "" {
		body = append(body, "Registered now: "+registered)
	}
	var options []tui.Option
	if proposed != "" {
		options = append(options, tui.Option{Key: "update", Label: "Update the registry: endpoint_url → " + proposed + "  (publicUrl)"})
	}
	options = append(options,
		tui.Option{Key: "enter", Label: "Enter the URL to register (this adapter's public https://… base)"},
		tui.Option{Key: "retest", Label: "Test again (after a proxy / DNS / firewall change)"},
		tui.Option{Key: "continue", Label: "Continue without changing the registry"},
		tui.Option{Key: "quit", Label: "Quit"},
	)
	choice, err := tui.Choose("Registered endpoint does not reach this adapter", body, options)
	if err != nil {
		if errors.Is(err, tui.ErrCancelled) {
			return "", nil
		}
		return "", err
	}
	switch choice {
	case "quit":
		return "", errors.New("stopped: registered endpoint not resolved")
	case "continue":
		return "", nil
	case "retest":
		return registered, nil
	case "enter":
		initial := proposed
		if initial == "" {
			initial = registered
		}
		proposed, err = tui.Prompt("Endpoint to register", []string{
			"The public base URL NHCX should POST callbacks to. This adapter answers on the host root and under /in, so https://host/in is the usual value.",
			"Warning: whatever currently lives at the registered URL (another adapter, hcxkit, …) stops receiving callbacks for this participant.",
		}, "endpoint_url", initial, func(v string) error {
			u, err := url.Parse(v)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return errors.New("must be an absolute http(s) URL")
			}
			return nil
		})
		if err != nil {
			if errors.Is(err, tui.ErrCancelled) {
				return registered, nil
			}
			return "", err
		}
		proposed = strings.TrimRight(proposed, "/")
	}

	var roles []string
	if rep.Participant != nil {
		roles = rep.Participant.Roles
	}
	uctx, cancel := context.WithTimeout(ctx, time.Minute)
	resp, err := gw.ABDM().UpdateEndpoint(uctx, proposed, roles)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, style.Bad("registry update failed:"), err)
		return registered, nil
	}
	fmt.Fprintf(os.Stderr, "%s registry accepted endpoint_url %s: %s\n", style.Good("✓"), style.Key(proposed), style.Dim(string(resp)))
	fmt.Fprintln(os.Stderr, style.Warn("note: the registry may hold the update for approval before it takes effect"))
	if cfg.PublicURL == "" && cfg.Path() != "" {
		if err := tui.SetValues(cfg.Path(), map[string]any{"publicUrl": proposed}); err == nil {
			fmt.Fprintf(os.Stderr, "%s publicUrl set to %s in %s\n", style.Good("✓"), style.Key(proposed), style.Key(cfg.Path()))
		}
	}
	rep.Participant.EndpointURL = proposed
	return proposed, nil
}

// prepare loads the config and runs the setup checks, looping through the
// configurator (when interactive) until the adapter can actually serve.
func prepare(ctx context.Context, path string, interactive, skipChecks bool) (*config.Config, *adapter.Adapter, *slog.Logger, *preflight.Report, error) {
	for attempt := 0; ; attempt++ {
		cfg, gw, logger, err := loadForServe(path)
		if err != nil {
			if !interactive {
				return nil, nil, nil, nil, err
			}
			if !editBecause(path, "Configuration problem:\n"+err.Error()) {
				return nil, nil, nil, nil, err
			}
			continue
		}
		if skipChecks {
			logger.Warn("setup checks skipped (--skip-checks)")
			return cfg, gw, logger, nil, nil
		}

		fmt.Fprintf(os.Stderr, "%s %s (%s)…\n", style.Title("checking setup for"), style.Key(cfg.Participant.ParticipantID), cfg.Env)
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		rep := preflight.Run(cctx, gw)
		cancel()
		printReport(rep)

		if rep.Fatal() {
			msg := "Session token could not be obtained: " + rep.TokenErr.Error()
			if !interactive {
				return nil, nil, nil, nil, errors.New(msg)
			}
			if !editBecause(path, msg+"\nFix participant.clientId / clientSecret (and auth.mode / urls.sessions if your onboarding letter says so), then save.") {
				return nil, nil, nil, nil, errors.New(msg)
			}
			continue
		}

		if rep.Cert != preflight.CertMatch {
			if !interactive {
				return nil, nil, nil, nil, fmt.Errorf("encryption certificate check: %s — run `nhcx-adapter serve` in a terminal to fix it interactively, or `nhcx-adapter serve --skip-checks` to start anyway", rep.Cert)
			}
			again, err := fixCertificate(ctx, path, cfg, gw, rep)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			if again {
				continue
			}
		}
		return cfg, gw, logger, rep, nil
	}
}

// loadForServe is load plus the listener-only validation.
func loadForServe(path string) (*config.Config, *adapter.Adapter, *slog.Logger, error) {
	cfg, gw, logger, err := load(path)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := cfg.ValidateServe(); err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, gw, logger, nil
}

// editBecause opens the configurator with a message and reports whether
// the user saved (so the caller should try again).
func editBecause(path, message string) bool {
	logOut.Mute()
	defer logOut.Unmute()
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		raw = []byte(sampleConfig)
		message = path + " does not exist yet — fill this in and press ctrl+s.\n" + message
	} else if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return false
	}
	saved, err := tui.Run(path, raw, message)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return false
	}
	return saved
}

// fixCertificate handles a registry certificate that is missing or does
// not open with our key. It returns again=true when the setup changed and
// the checks should run once more.
func fixCertificate(ctx context.Context, path string, cfg *config.Config, gw *adapter.Adapter, rep *preflight.Report) (again bool, err error) {
	var body []string
	switch rep.Cert {
	case preflight.CertMismatch:
		body = append(body, "The encryption certificate on the participant registry does not match participant.privateKey.",
			"NHCX encrypts every message to you with the registry certificate, so nothing you receive could be decrypted.")
	case preflight.CertMissing:
		body = append(body, "The participant registry has no usable encryption certificate for "+cfg.Participant.ParticipantID+".",
			"Counterparties cannot send you anything until one is registered.")
	default:
		body = append(body, "The registry certificate could not be checked (see the report above).")
	}
	if f := cfg.PrivateKeyFile(); f != "" {
		body = append(body, "Current key: "+f)
	}
	options := []tui.Option{
		{Key: "generate-upload", Label: "Generate a new key + certificate, set it in the config, and upload it to the registry"},
		{Key: "generate", Label: "Generate a new key + certificate and set it in the config (I will upload the certificate myself)"},
	}
	if rep.RegistryPEM != "" {
		options = append(options, tui.Option{Key: "upload", Label: "Upload the certificate for my current key to the registry"})
	}
	options = append(options,
		tui.Option{Key: "edit", Label: "Open the configurator (point participant.privateKey at the right key)"},
		tui.Option{Key: "continue", Label: "Continue anyway"},
		tui.Option{Key: "quit", Label: "Quit"},
	)
	logOut.Mute()
	choice, err := tui.Choose("Encryption certificate: "+string(rep.Cert), body, options)
	logOut.Unmute()
	if err != nil {
		if errors.Is(err, tui.ErrCancelled) {
			return false, errors.New("stopped: certificate check not resolved")
		}
		return false, err
	}

	switch choice {
	case "quit":
		return false, errors.New("stopped: certificate check not resolved")
	case "continue":
		fmt.Fprintln(os.Stderr, style.Warn("continuing with an unverified certificate — inbound messages may fail to decrypt"))
		return false, nil
	case "edit":
		if !editBecause(path, "Point participant.privateKey at the key whose certificate is registered, then save.") {
			return false, errors.New("stopped: certificate check not resolved")
		}
		return true, nil
	case "upload":
		certPEM, err := certificateForCurrentKey(cfg)
		if err != nil {
			return false, err
		}
		return true, uploadCertificate(ctx, gw, rep, certPEM)
	}

	// generate / generate-upload
	res, err := generateCertificateFiles(cfg, 0, true)
	if err != nil {
		return false, err
	}
	rel := cfg.Certificate.PrivateKeyFile
	if err := tui.SetValues(path, map[string]any{"participant.privateKey": "@" + rel}); err != nil {
		return false, fmt.Errorf("update %s: %w", path, err)
	}
	fmt.Fprintf(os.Stderr, "%s participant.privateKey set to %s in %s\n", style.Good("✓"), style.Key("@"+rel), style.Key(path))
	if choice == "generate-upload" {
		if err := uploadCertificate(ctx, gw, rep, res.Certificate); err != nil {
			return false, err
		}
	} else {
		fmt.Fprintf(os.Stderr, "%s register %s as encryption_cert for %s, then restart\n", style.Warn("→"), style.Key(res.certPath), style.Key(cfg.Participant.ParticipantID))
	}
	return true, nil
}

// certificateForCurrentKey finds a certificate file next to the config that
// belongs to participant.privateKey, so it can be (re-)uploaded.
func certificateForCurrentKey(cfg *config.Config) (string, error) {
	priv, err := keys.ParsePrivateKey(cfg.Participant.PrivateKey)
	if err != nil {
		return "", err
	}
	candidates := []string{cfg.Resolve(cfg.Certificate.CertificateFile)}
	if f := cfg.PrivateKeyFile(); f != "" {
		candidates = append(candidates, strings.TrimSuffix(f, ".pem")+".crt", strings.Replace(f, "private_key", "certificate", 1))
	}
	for _, c := range candidates {
		raw, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		pub, err := keys.ParsePublicKey(string(raw))
		if err == nil && pub.Equal(&priv.PublicKey) {
			return string(raw), nil
		}
	}
	return "", fmt.Errorf("no certificate for the current key found (looked for %s); choose 'generate' instead", cfg.Resolve(cfg.Certificate.CertificateFile))
}

func uploadCertificate(ctx context.Context, gw *adapter.Adapter, rep *preflight.Report, certPEM string) error {
	var roles []string
	if rep.Participant != nil {
		roles = rep.Participant.Roles
	}
	uctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	resp, err := gw.ABDM().UpdateCertificate(uctx, certPEM, roles)
	if err != nil {
		return fmt.Errorf("registry update failed: %w (register the certificate manually and restart)", err)
	}
	fmt.Fprintf(os.Stderr, "%s registry accepted the certificate: %s\n", style.Good("✓"), style.Dim(string(resp)))
	fmt.Fprintln(os.Stderr, style.Warn("note: the registry may hold the update for approval (transactionid / passcode) before it takes effect"))
	return nil
}

func printReport(rep *preflight.Report) {
	for _, c := range rep.Checks {
		if c.OK {
			fmt.Fprintf(os.Stderr, "  %s %-24s %s\n", style.Good("✓"), c.Name, style.Dim(c.Detail))
		} else {
			fmt.Fprintf(os.Stderr, "  %s %-24s %s\n", style.Bad("✗"), c.Name, style.Bad(c.Detail))
		}
	}
}

func isTerminal() bool {
	for _, f := range []*os.File{os.Stdin, os.Stdout} {
		st, err := f.Stat()
		if err != nil || st.Mode()&os.ModeCharDevice == 0 {
			return false
		}
	}
	return true
}

func cmdCheck(args []string) error {
	fs, cfgPath := newFlags("check")
	noTUI := fs.Bool("no-tui", false, "report only; never offer to fix anything")
	endpoint := fs.String("endpoint", "", "test this public URL instead of the registry's endpoint_url (nothing is changed on the registry)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	interactive := !*noTUI && isTerminal()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		cfg, gw, logger, err := loadForServe(*cfgPath)
		if err != nil {
			if interactive && editBecause(*cfgPath, "Configuration problem:\n"+err.Error()) {
				continue
			}
			return err
		}
		fmt.Fprintf(os.Stderr, "%s %s (%s)…\n", style.Title("checking setup for"), style.Key(cfg.Participant.ParticipantID), cfg.Env)
		cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		rep := preflight.Run(cctx, gw)
		cancel()
		printReport(rep)

		if rep.Fatal() {
			if interactive && editBecause(*cfgPath, "Session token could not be obtained: "+rep.TokenErr.Error()) {
				continue
			}
			return errors.New("setup checks failed")
		}
		if rep.Cert != preflight.CertMatch && interactive {
			again, err := fixCertificate(ctx, *cfgPath, cfg, gw, rep)
			if err != nil {
				return err
			}
			if again {
				continue
			}
		}
		endpointOK := false
		if *endpoint != "" {
			if rep.Participant == nil {
				rep.Participant = &abdm.Participant{Code: cfg.Participant.ParticipantID}
			}
			rep.Participant.EndpointURL = *endpoint
			interactive = false // an explicit URL is a probe, not a registration to fix
		}
		if rep.Participant != nil {
			// The public URL can only lead somewhere if this adapter is
			// listening, so bring the listener up for the test (or use the
			// instance already on that port).
			err := withListener(ctx, gw, logger, func() error {
				if interactive {
					if err := verifyEndpoint(ctx, cfg, gw, rep, logger, true); err != nil {
						return err
					}
				}
				ectx, cancel := context.WithTimeout(ctx, 30*time.Second)
				c := preflight.TestEndpoint(ectx, rep.Participant.EndpointURL, probe.Key(cfg))
				cancel()
				printReport(&preflight.Report{Checks: []preflight.Check{c}})
				endpointOK = c.OK
				return nil
			})
			if err != nil {
				return err
			}
		}
		if !rep.Healthy() || !endpointOK {
			return errors.New("setup checks failed")
		}
		fmt.Fprintln(os.Stderr, style.Good("all checks passed"))
		return nil
	}
}

func cmdSend(args []string) error {
	fs, cfgPath := newFlags("send")
	path := fs.String("path", "", "NHCX API path, e.g. v1/preauth/submit")
	recipient := fs.String("recipient", "", "recipient participant code")
	sender := fs.String("sender", "", "sender participant code (default: configured participant)")
	corr := fs.String("correlation-id", "", "x-hcx-correlation_id (a response must reuse the request's)")
	workflow := fs.String("workflow-id", "", "x-hcx-workflow_id")
	status := fs.String("status", "", "x-hcx-status (default: request.initiated / response.complete)")
	file := fs.String("file", "", "FHIR bundle JSON file (default: stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *recipient == "" {
		return errors.New("--path and --recipient are required")
	}
	_, gw, _, err := load(*cfgPath)
	if err != nil {
		return err
	}
	bundle, err := readInput(*file)
	if err != nil {
		return err
	}
	headers := map[string]any{
		nhcx.HdrRecipient:     *recipient,
		nhcx.HdrSender:        *sender,
		nhcx.HdrCorrelationID: *corr,
		nhcx.HdrWorkflowID:    *workflow,
		nhcx.HdrStatus:        *status,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := gw.Send(ctx, adapter.OutboundRequest{Path: *path, Headers: headers, FHIR: bundle})
	if err != nil {
		return err
	}
	if err := printJSON(res); err != nil {
		return err
	}
	if !res.Accepted() {
		return fmt.Errorf("NHCX answered %d", res.GatewayStatus)
	}
	return nil
}

func cmdCert(args []string) error {
	if len(args) > 0 && args[0] == "generate" {
		return cmdCertGenerate(args[1:])
	}
	fs, cfgPath := newFlags("cert")
	refresh := fs.Bool("refresh", false, "bypass the cache")
	// Allow "cert CODE --refresh" as well as "cert --refresh CODE".
	var code string
	var rest []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") && code == "" {
			code = a
			continue
		}
		rest = append(rest, a)
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if code == "" && fs.NArg() > 0 {
		code = fs.Arg(0)
	}
	if code == "" {
		return errors.New("participant code is required")
	}
	_, gw, _, err := load(*cfgPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var pem string
	if *refresh {
		_, pem, err = gw.ABDM().FetchCertificate(ctx, code)
	} else {
		_, pem, err = gw.ABDM().Certificate(ctx, code)
	}
	if err != nil {
		return err
	}
	fmt.Println(strings.TrimSpace(pem))
	return nil
}

// cmdCertGenerate creates the participant's RSA key and self-signed
// encryption certificate. The subject is the participant id; the lifetime
// and file names come from the "certificate" section of the config.
func cmdCertGenerate(args []string) error {
	fs, cfgPath := newFlags("cert generate")
	days := fs.Int("days", 0, "validity in days (default: certificate.validityDays, 365)")
	force := fs.Bool("force", false, "replace existing files (the old ones are kept as .bak)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Read(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Participant.ParticipantID == "" {
		return errors.New("participant.participantId must be set first (it becomes the certificate subject)")
	}
	res, err := generateCertificateFiles(cfg, *days, *force)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nvalid until %s. Register %s as encryption_cert for %s in the participant registry\n"+
		"(base64 < %s if the form wants it encoded) and set participant.privateKey to %s.\n",
		style.Key(res.NotAfter.Format("2006-01-02")), style.Key(res.certPath), style.Key(cfg.Participant.ParticipantID), res.certPath, style.Key("\"@"+cfg.Certificate.PrivateKeyFile+"\""))
	return nil
}

type generated struct {
	*keys.Material
	keyPath, certPath string
}

// generateCertificateFiles writes the key (0600) and certificate next to
// the config. Without force, existing files are left alone: a regenerated
// key silently stops matching the certificate the registry holds. With
// force, the old files are renamed to .bak-<timestamp> first.
func generateCertificateFiles(cfg *config.Config, days int, force bool) (*generated, error) {
	keyPath := cfg.Resolve(cfg.Certificate.PrivateKeyFile)
	certPath := cfg.Resolve(cfg.Certificate.CertificateFile)
	if days == 0 {
		days = cfg.Certificate.ValidityDays
	}
	for _, p := range []string{keyPath, certPath} {
		if _, err := os.Stat(p); err == nil {
			if !force {
				return nil, fmt.Errorf("%s already exists; re-run with --force to replace it (the registered certificate would stop matching this key)", p)
			}
			bak := p + ".bak-" + time.Now().Format("20060102-150405")
			if err := os.Rename(p, bak); err != nil {
				return nil, err
			}
			fmt.Fprintf(os.Stderr, "%s kept previous %s as %s\n", style.Warn("→"), style.Key(p), style.Key(bak))
		}
	}
	fmt.Fprintf(os.Stderr, "%s 2048-bit RSA key and certificate for %s (%d days)…\n", style.Title("generating"), style.Key(cfg.Participant.ParticipantID), days)
	m, err := keys.Generate(keys.Subject{CommonName: cfg.Participant.ParticipantID, ValidityDays: days})
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, []byte(m.PrivateKey), 0o600); err != nil {
		return nil, err
	}
	_ = os.Chmod(keyPath, 0o600)
	if err := os.WriteFile(certPath, []byte(m.Certificate), 0o644); err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, "%s wrote %s\n%s wrote %s\n", style.Good("✓"), style.Key(keyPath), style.Good("✓"), style.Key(certPath))
	return &generated{Material: m, keyPath: keyPath, certPath: certPath}, nil
}

func cmdToken(args []string) error {
	fs, cfgPath := newFlags("token")
	as := fs.String("participant", "", "mint the token for this hosted participant (default: the default profile)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, gw, _, err := load(*cfgPath)
	if err != nil {
		return err
	}
	client := gw.ABDM()
	if *as != "" {
		if gw.Profiles().ByCode(*as) == nil {
			return fmt.Errorf("no participant %s is configured; this adapter holds %s", *as, strings.Join(gw.Profiles().Codes(), ", "))
		}
		client = gw.ABDMFor(*as)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tok, err := client.RefreshToken(ctx)
	if err != nil {
		return err
	}
	fmt.Println(tok)
	return nil
}

func cmdDecrypt(args []string) error {
	fs, cfgPath := newFlags("decrypt")
	file := fs.String("file", "", "file holding a compact JWE, or a JSON body with a \"payload\" field (default: stdin)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, gw, _, err := load(*cfgPath)
	if err != nil {
		return err
	}
	raw, err := readInput(*file)
	if err != nil {
		return err
	}
	compact := strings.TrimSpace(string(raw))
	var body struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal(raw, &body) == nil && body.Payload != "" {
		compact = body.Payload
	}
	headers, plain, err := gw.Decrypt(compact)
	if err != nil {
		return err
	}
	var payload any
	if json.Unmarshal(plain, &payload) != nil {
		payload = string(plain)
	}
	return printJSON(map[string]any{"headers": headers, "payload": payload})
}

func cmdConfig(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nhcx-adapter config init|edit [FILE]")
	}
	path := os.Getenv("NHCX_ADAPTER_CONFIG")
	if path == "" {
		path = "config.json"
	}
	if len(args) > 1 {
		path = args[1]
	}
	switch args[0] {
	case "edit":
		raw, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			raw = []byte(sampleConfig)
		} else if err != nil {
			return err
		}
		saved, err := tui.Run(path, raw, "")
		if err != nil {
			return fmt.Errorf("config edit needs an interactive terminal: %w", err)
		}
		if saved {
			fmt.Fprintf(os.Stderr, "%s saved %s\n", style.Good("✓"), style.Key(path))
		} else {
			fmt.Fprintln(os.Stderr, style.Dim("no changes saved"))
		}
		return nil
	case "init":
	default:
		return errors.New("usage: nhcx-adapter config init|edit [FILE]")
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists; not overwriting", path)
	}
	if err := os.WriteFile(path, []byte(sampleConfig), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s wrote %s — set NHCX_CLIENT_ID, NHCX_CLIENT_SECRET, NHCX_ADAPTER_API_KEY, then run\n  %s\nto create private_key.pem and the certificate to register.\n",
		style.Good("✓"), style.Key(path), style.Key("nhcx-adapter cert generate --config "+path))
	return nil
}

// ------------------------------------------------------------- ledger ----

func openLedger(cfgPath string) (*config.Config, *ledger.Store, error) {
	cfg, err := config.Read(cfgPath)
	if err != nil {
		return nil, nil, err
	}
	if !cfg.LedgerEnabled() {
		return nil, nil, errors.New("the ledger is disabled (ledger.enabled = false)")
	}
	store, err := ledger.Open(ledger.Options{Dir: cfg.Resolve(cfg.Ledger.Dir), RetentionDays: cfg.Ledger.RetentionDays, StoreBodies: cfg.LedgerStoresBodies()})
	if err != nil {
		return nil, nil, err
	}
	return cfg, store, nil
}

func cmdLedger(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: nhcx-adapter ledger list|show|thread|stats|clear …")
	}
	sub, rest := args[0], args[1:]
	fs, cfgPath := newFlags("ledger " + sub)
	asJSON := fs.Bool("json", false, "machine-readable output")
	assumeYes := fs.Bool("yes", false, "clear: do not ask for confirmation")
	var (
		direction   = fs.String("direction", "", "out or in")
		entity      = fs.String("entity", "", "preauth, claim, coverageeligibility, communication, payment, insuranceplan, task, status, error")
		kind        = fs.String("kind", "", "request or response")
		status      = fs.String("status", "", "accepted, rejected, failed, delivered, delivery_failed")
		corr        = fs.String("correlation-id", "", "only this exchange")
		workflow    = fs.String("workflow-id", "", "only this workflow")
		participant = fs.String("participant", "", "sender or recipient code")
		since       = fs.String("since", "", "RFC 3339, YYYY-MM-DD, or a duration back from now (24h)")
		until       = fs.String("until", "", "same forms as --since")
		before      = fs.String("before", "", "page: entries older than this id")
		limit       = fs.Int("limit", 50, "at most this many (1–500)")
	)
	// The positional argument (id / correlation id) may sit before or after
	// the flags; the flag package stops at the first non-flag, so split by hand.
	boolFlags := map[string]bool{"json": true, "yes": true, "y": true}
	var positional, flagArgs []string
	for i := 0; i < len(rest); i++ {
		a := rest[i]
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		name := strings.TrimLeft(a, "-")
		if !strings.Contains(name, "=") && !boolFlags[name] && i+1 < len(rest) {
			i++
			flagArgs = append(flagArgs, rest[i])
		}
	}
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	_, store, err := openLedger(*cfgPath)
	if err != nil {
		return err
	}
	switch sub {
	case "clear":
		// Destructive and not undoable, so it says what it is about to do and
		// waits — unless --yes, or there is nobody to ask.
		stats := store.Stats()
		if stats.Total == 0 {
			fmt.Fprintln(os.Stderr, style.Dim("the ledger is already empty"))
			return nil
		}
		if !*assumeYes {
			if !isTerminal() {
				return errors.New("refusing to clear the ledger without confirmation: pass --yes")
			}
			fmt.Fprintf(os.Stderr, "This deletes %s from %s.\n",
				style.Title(fmt.Sprintf("%d message(s)", stats.Total)), style.Key(stats.Dir))
			fmt.Fprint(os.Stderr, "There is no undo. Continue? [y/N] ")
			var answer string
			_, _ = fmt.Fscanln(os.Stdin, &answer)
			switch strings.ToLower(strings.TrimSpace(answer)) {
			case "y", "yes":
			default:
				fmt.Fprintln(os.Stderr, style.Dim("nothing was deleted"))
				return nil
			}
		}
		removed, err := store.Clear()
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(map[string]any{"cleared": removed, "dir": stats.Dir})
		}
		fmt.Fprintf(os.Stderr, "%s cleared %d message(s) from %s\n",
			style.Good("✓"), removed, style.Key(stats.Dir))
		return nil
	case "list":
		q := ledger.Query{Direction: *direction, Entity: *entity, Kind: *kind, Status: *status, CorrelationID: *corr,
			WorkflowID: *workflow, Participant: *participant, Before: *before, Limit: *limit}
		if q.Since, err = parseLedgerTime(*since); err != nil {
			return fmt.Errorf("--since: %w", err)
		}
		if q.Until, err = parseLedgerTime(*until); err != nil {
			return fmt.Errorf("--until: %w", err)
		}
		items := store.List(q)
		if *asJSON {
			return printJSON(map[string]any{"items": items, "count": len(items)})
		}
		if len(items) == 0 {
			fmt.Fprintln(os.Stderr, style.Dim("no messages match"))
			return nil
		}
		printLedgerTable(items)
		return nil
	case "show":
		if len(positional) == 0 {
			return errors.New("usage: nhcx-adapter ledger show ID")
		}
		e, err := store.Get(positional[0])
		if err != nil {
			return err
		}
		if *asJSON {
			return printJSON(e)
		}
		printLedgerEntry(e)
		return nil
	case "thread":
		if len(positional) == 0 {
			return errors.New("usage: nhcx-adapter ledger thread CORRELATION_ID")
		}
		t := store.Thread(positional[0], "")
		if t == nil {
			return fmt.Errorf("no messages with correlation id %s", positional[0])
		}
		if *asJSON {
			return printJSON(t)
		}
		fmt.Printf("%s %s\n", style.Title("correlation"), style.Key(t.CorrelationID))
		fmt.Printf("%-12s %s   %-12s %s   %-12s %s\n", "entity", t.Entity, "role", t.Role, "counterparty", t.Counterparty)
		fmt.Printf("%-12s %s   %-12s %s → %s\n\n", "state", styleState(t.State), "span", t.Started.Local().Format("2006-01-02 15:04:05"), t.Updated.Local().Format("15:04:05"))
		printLedgerTable(t.Messages)
		return nil
	case "stats":
		st := store.Stats()
		if *asJSON {
			return printJSON(st)
		}
		fmt.Printf("%s %d messages · %d threads · %d in the last 24h · %s\n", style.Title("ledger"), st.Total, st.Threads, st.Last24h, style.Dim(st.Dir))
		for _, group := range []struct {
			name string
			m    map[string]int
		}{{"direction", st.ByDirection}, {"status", st.ByStatus}, {"entity", st.ByEntity}} {
			keys := make([]string, 0, len(group.m))
			for k := range group.m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			parts := make([]string, 0, len(keys))
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s %d", k, group.m[k]))
			}
			fmt.Printf("  %-10s %s\n", group.name, strings.Join(parts, " · "))
		}
		if st.Oldest != nil {
			fmt.Printf("  %-10s %s → %s\n", "span", st.Oldest.Local().Format("2006-01-02 15:04"), st.Newest.Local().Format("2006-01-02 15:04"))
		}
		return nil
	}
	return fmt.Errorf("unknown ledger command %q (list, show, thread, stats)", sub)
}

func parseLedgerTime(v string) (time.Time, error) {
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

func styleState(state string) string {
	switch state {
	case ledger.ThreadCompleted:
		return style.Good(state)
	case ledger.ThreadError:
		return style.Bad(state)
	case ledger.ThreadAwaitingResponse, ledger.ThreadAwaitingOurResponse, ledger.ThreadPartial:
		return style.Warn(state)
	}
	return state
}

func styleStatus(status string) string {
	switch status {
	case ledger.StatusAccepted, ledger.StatusDelivered:
		return style.Good(fmt.Sprintf("%-15s", status))
	case ledger.StatusRejected, ledger.StatusFailed, ledger.StatusDeliveryFailed:
		return style.Bad(fmt.Sprintf("%-15s", status))
	}
	return fmt.Sprintf("%-15s", status)
}

func printLedgerTable(items []ledger.Summary) {
	fmt.Printf("%-32s %-19s %-5s %-30s %-15s %-15s %-4s %s\n", "ID", "TIME", "DIR", "PATH", "STATUS", "PEER", "HTTP", "CORRELATION")
	for _, it := range items {
		peer := it.Recipient
		arrow := "→"
		if it.Direction == ledger.In {
			peer, arrow = it.Sender, "←"
		}
		http := ""
		if it.PeerStatus != 0 {
			http = strconv.Itoa(it.PeerStatus)
		}
		extra := ""
		if it.Error != nil {
			extra = "  " + style.Bad(it.Error.Code)
		}
		if it.Redelivery {
			extra += "  " + style.Warn("redelivery")
		}
		fmt.Printf("%-32s %-19s %s %-3s %-30s %s %-15s %-4s %s%s\n",
			it.ID, it.CreatedAt.Local().Format("2006-01-02 15:04:05"), arrow, it.Direction, it.Path,
			styleStatus(it.Status), peer, http, style.Dim(it.CorrelationID), extra)
	}
}

func printLedgerEntry(e *ledger.Entry) {
	fmt.Printf("%s %s\n", style.Title("ledger entry"), style.Key(e.ID))
	rows := [][2]string{
		{"time", e.CreatedAt.Local().Format(time.RFC3339)},
		{"direction", e.Direction + " · " + e.Kind + " · " + e.Path},
		{"status", e.Status},
		{"sender", e.Sender}, {"recipient", e.Recipient},
		{"correlation", e.CorrelationID}, {"api_call", e.APICallID}, {"request", e.RequestID}, {"workflow", e.WorkflowID},
		{"hcx_status", e.HCXStatus},
		{"duration", fmt.Sprintf("%d ms", e.DurationMs)},
	}
	if e.Error != nil {
		rows = append(rows, [2]string{"error", e.Error.Code + ": " + e.Error.Message})
	}
	if e.Peer != nil {
		rows = append(rows, [2]string{"peer", fmt.Sprintf("%d %s", e.Peer.StatusCode, e.Peer.URL)})
	}
	if e.Summary != nil {
		rows = append(rows, [2]string{"bundle", fmt.Sprintf("%s/%s · %d entries · focus %s %s %s", e.Summary.ResourceType, e.Summary.BundleType, e.Summary.Entries, e.Summary.Focus, e.Summary.Identifier, e.Summary.Outcome)})
	}
	for _, r := range rows {
		if r[1] != "" {
			fmt.Printf("  %-12s %s\n", r[0], r[1])
		}
	}
	if e.Peer != nil && len(e.Peer.Response) > 0 {
		fmt.Printf("\n%s\n%s\n", style.Title("peer response"), string(e.Peer.Response))
	}
	if len(e.FHIR) > 0 {
		fmt.Printf("\n%s\n", style.Title("fhir"))
		var buf bytes.Buffer
		if json.Indent(&buf, e.FHIR, "", "  ") == nil {
			fmt.Println(buf.String())
		} else {
			fmt.Println(string(e.FHIR))
		}
	}
}

// cmdUpdate lists the releases on GitHub and installs the one picked —
// newer or older — in place of the running binary.
//
//	nhcx-adapter update                 interactive: pick a version
//	nhcx-adapter update --list          print every release and stop
//	nhcx-adapter update --check         say whether a newer release exists (exit 1 if so)
//	nhcx-adapter update --latest [-y]   install the newest stable release
//	nhcx-adapter update --to v1.2.0 [-y] install a specific tag (upgrade or downgrade)
func cmdUpdate(args []string) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	list := fs.Bool("list", false, "list the available releases and exit")
	check := fs.Bool("check", false, "report whether a newer release exists; exit 1 when it does")
	latest := fs.Bool("latest", false, "install the newest stable release without asking")
	to := fs.String("to", "", "install this tag (e.g. v1.2.0); older tags downgrade")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "same as --yes")
	pre := fs.Bool("prerelease", false, "include pre-releases")
	repo := fs.String("repo", "", "GitHub repository to consult, owner/name (default "+update.DefaultRepo+", or $NHCX_ADAPTER_UPDATE_REPO)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	c := update.NewClient(*repo)
	fmt.Fprintf(os.Stderr, "%s %s…\n", style.Dim("fetching releases from"), style.Key("github.com/"+c.Repo))
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	releases, err := c.Releases(rctx)
	cancel()
	if err != nil {
		return err
	}
	if !*pre {
		releases = stableOnly(releases)
	}
	if len(releases) == 0 {
		return fmt.Errorf("no releases found in %s", c.Repo)
	}
	ch := update.CompareCurrent(version, releases)
	if *pre && ch.Known {
		// The newest pre-release counts as "latest" when asked for.
		ch.Latest = update.Latest(releases, true)
		ch.Available = ch.Latest != nil && update.Compare(ch.Latest.Version, ch.Current) > 0
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	printUpdateStatus(ch, platform)

	switch {
	case *check:
		if ch.Available {
			os.Exit(1)
		}
		return nil
	case *list:
		printReleaseList(releases, ch, len(releases))
		return nil
	}

	var target *update.Release
	switch {
	case *to != "":
		if target = update.Find(releases, *to); target == nil {
			return fmt.Errorf("no release %s (see `nhcx-adapter update --list`)", *to)
		}
	case *latest:
		if target = update.Latest(releases, *pre); target == nil {
			return errors.New("no stable release available")
		}
		if ch.Known && !*yes && update.Compare(target.Version, ch.Current) <= 0 {
			fmt.Fprintln(os.Stderr, style.Good("already up to date"))
			return nil
		}
	case isTerminal():
		target, err = pickRelease(releases, ch, platform)
		if err != nil {
			return err
		}
		if target == nil {
			return nil
		}
	default:
		printReleaseList(releases, ch, len(releases))
		return errors.New("no terminal: pass --latest or --to TAG")
	}

	asset := target.AssetFor(runtime.GOOS, runtime.GOARCH)
	if asset == nil {
		return fmt.Errorf("release %s has no build for %s", target.Tag, platform)
	}
	exe, err := update.Executable()
	if err != nil {
		return err
	}
	direction := "install"
	if ch.Known {
		switch update.Compare(target.Version, ch.Current) {
		case 1:
			direction = "upgrade to"
		case -1:
			direction = "downgrade to"
		case 0:
			direction = "reinstall"
		}
	}
	if !*yes && !confirmInstall(target, direction, exe) {
		fmt.Fprintln(os.Stderr, style.Dim("cancelled"))
		return nil
	}

	fmt.Fprintf(os.Stderr, "%s %s %s\n", style.Title(direction), style.Key(target.Tag), style.Dim("("+asset.Name+")"))
	archive, err := c.Download(ctx, target, asset, func(done, total int64) {
		if total > 0 {
			fmt.Fprintf(os.Stderr, "\r  downloading  %5.1f / %.1f MB", float64(done)/1e6, float64(total)/1e6)
		} else {
			fmt.Fprintf(os.Stderr, "\r  downloading  %5.1f MB", float64(done)/1e6)
		}
	})
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return err
	}
	if target.Checksums() != nil {
		fmt.Fprintln(os.Stderr, "  "+style.Good("✓")+" checksum verified")
	} else {
		fmt.Fprintln(os.Stderr, "  "+style.Warn("!")+" release has no SHA256SUMS; checksum not verified")
	}
	bin, err := update.Extract(asset.Name, archive)
	if err != nil {
		return err
	}
	if err := update.Install(exe, bin); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  %s installed %s\n", style.Good("✓"), style.Key(exe))
	if line, err := update.InstalledVersion(ctx, exe); err != nil {
		fmt.Fprintf(os.Stderr, "  %s the new binary did not start: %v\n", style.Bad("✗"), err)
		return errors.New("installed binary failed its version check")
	} else {
		fmt.Fprintf(os.Stderr, "  %s %s\n", style.Good("✓"), line)
	}
	fmt.Fprintln(os.Stderr, style.Dim("restart `nhcx-adapter serve` to run the new version"))
	return nil
}

func stableOnly(releases []update.Release) []update.Release {
	out := releases[:0:0]
	for _, r := range releases {
		if !r.Prerelease && r.Version.Pre == "" {
			out = append(out, r)
		}
	}
	return out
}

func printUpdateStatus(ch update.Check, platform string) {
	cur := version
	if !ch.Known {
		cur += " (not a release build)"
	}
	fmt.Fprintf(os.Stderr, "%s %s %s\n", style.Title("installed"), style.Key(cur), style.Dim(platform))
	if ch.Latest == nil {
		return
	}
	switch {
	case ch.Available:
		fmt.Fprintf(os.Stderr, "%s %s %s\n", style.Title("latest   "), style.Key(ch.Latest.Tag), style.Warn("— update available"))
	case ch.Known && update.Compare(ch.Current, ch.Latest.Version) == 0:
		fmt.Fprintf(os.Stderr, "%s %s %s\n", style.Title("latest   "), style.Key(ch.Latest.Tag), style.Good("— up to date"))
	default:
		fmt.Fprintf(os.Stderr, "%s %s\n", style.Title("latest   "), style.Key(ch.Latest.Tag))
	}
}

// releaseLine formats one release for a list or menu.
func releaseLine(r *update.Release, ch update.Check, platform string) string {
	tags := []string{}
	if ch.Latest != nil && r.Tag == ch.Latest.Tag {
		tags = append(tags, "latest")
	}
	if ch.Known && update.Compare(r.Version, ch.Current) == 0 && r.Version.Pre == ch.Current.Pre {
		tags = append(tags, "installed")
	}
	if r.Prerelease || r.Version.Pre != "" {
		tags = append(tags, "pre-release")
	}
	if r.AssetFor(runtime.GOOS, runtime.GOARCH) == nil {
		tags = append(tags, "no build for "+platform)
	}
	date := ""
	if !r.Published.IsZero() {
		date = r.Published.Local().Format("2006-01-02")
	}
	return fmt.Sprintf("%-14s %-10s %s", r.Tag, date, strings.Join(tags, " · "))
}

func printReleaseList(releases []update.Release, ch update.Check, n int) {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	fmt.Fprintln(os.Stderr)
	for i, r := range releases {
		if i >= n {
			fmt.Fprintf(os.Stderr, "  %s\n", style.Dim(fmt.Sprintf("… %d more (--list shows all; --to TAG installs any)", len(releases)-n)))
			break
		}
		line := releaseLine(&r, ch, platform)
		if ch.Known && update.Compare(r.Version, ch.Current) == 0 {
			line = style.Key(line)
		}
		fmt.Fprintf(os.Stderr, "  %s\n", line)
	}
	fmt.Fprintln(os.Stderr)
}

// pickRelease shows the menu and returns the chosen release, or nil when
// the operator backs out.
func pickRelease(releases []update.Release, ch update.Check, platform string) (*update.Release, error) {
	const maxShown = 15
	body := []string{"Installed: " + version + " (" + platform + ")"}
	if ch.Latest != nil {
		if ch.Available {
			body = append(body, "Latest: "+ch.Latest.Tag+" — update available")
		} else {
			body = append(body, "Latest: "+ch.Latest.Tag)
		}
	}
	body = append(body, "", "Pick the version to install. Older versions are downgraded to; the running server keeps its version until restarted.")
	if len(releases) > maxShown {
		body = append(body, fmt.Sprintf("Showing the newest %d of %d; `update --to TAG` installs any.", maxShown, len(releases)))
	}
	var opts []tui.Option
	for i := range releases {
		if i >= maxShown {
			break
		}
		opts = append(opts, tui.Option{Key: releases[i].Tag, Label: releaseLine(&releases[i], ch, platform)})
	}
	opts = append(opts, tui.Option{Key: "", Label: "cancel"})
	key, err := tui.Choose("nhcx-adapter update", body, opts)
	if err != nil {
		if errors.Is(err, tui.ErrCancelled) {
			return nil, nil
		}
		return nil, err
	}
	if key == "" {
		return nil, nil
	}
	return update.Find(releases, key), nil
}

// confirmInstall asks once more, showing the release notes.
func confirmInstall(r *update.Release, direction, exe string) bool {
	body := []string{fmt.Sprintf("%s %s and replace %s", strings.ToUpper(direction[:1])+direction[1:], r.Tag, exe)}
	if !r.Published.IsZero() {
		body = append(body, "Published "+r.Published.Local().Format("2006-01-02 15:04"))
	}
	if notes := strings.TrimSpace(r.Notes); notes != "" {
		lines := strings.Split(notes, "\n")
		if len(lines) > 12 {
			lines = append(lines[:12], "…")
		}
		body = append(body, "")
		body = append(body, lines...)
	}
	if !isTerminal() {
		return true
	}
	key, err := tui.Choose("nhcx-adapter update", body, []tui.Option{
		{Key: "install", Label: direction + " " + r.Tag},
		{Key: "cancel", Label: "cancel"},
	})
	return err == nil && key == "install"
}

// notifyUpdate logs one line when a newer release exists. It never blocks
// the server: it runs in the background and gives up quietly on any error.
func notifyUpdate(ctx context.Context, logger *slog.Logger) {
	if os.Getenv("NHCX_ADAPTER_NO_UPDATE_CHECK") != "" {
		return
	}
	if _, ok := update.Parse(version); !ok {
		return // dev build: nothing to compare against
	}
	go func() {
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		c := update.NewClient("")
		releases, err := c.Releases(ctx)
		if err != nil {
			logger.Debug("update check skipped", "error", err)
			return
		}
		if ch := update.CompareCurrent(version, releases); ch.Available {
			logger.Warn("update available", "installed", version, "latest", ch.Latest.Tag, "run", "nhcx-adapter update")
		}
	}()
}
