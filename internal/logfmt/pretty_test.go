package logfmt

import (
	"bytes"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func TestLines(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(New(&buf, slog.LevelInfo)).With("env", "sandbox")

	log.Info("outbound", "path", "v1/preauth/submit", "recipient", "1000004805@hcx", "status", "accepted", "nhcx", 202, "took_ms", 412, "correlation_id", "0f4c2b2e-9c7a-4d55-8a1e-2b1b0c7d9e11", "ledger_id", "L1")
	log.Warn("inbound", "path", "v1/preauth/on_submit", "sender", "1000004805@hcx", "status", "delivery_failed", "callback", 500, "took_ms", 3, "redelivery", true, "error", "CALLBACK_HTTP_500")
	log.Error("session token refresh failed", "error", "TOKEN_HTTP_401: bad creds")
	log.Debug("hidden")

	out := ansi.ReplaceAllString(buf.String(), "")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d:\n%s", len(lines), out)
	}
	for i, want := range []string{
		"▲ OUT v1/preauth/submit → 1000004805@hcx  accepted  nhcx 202  412ms  corr 0f4c2b2e-9c7a-4d55-8a1e-2b1b0c7d9e11",
		"▼ IN  v1/preauth/on_submit ← 1000004805@hcx  delivery_failed  callback 500  3ms  redelivery  CALLBACK_HTTP_500",
		`ERR  session token refresh failed error="TOKEN_HTTP_401: bad creds"`,
	} {
		if !strings.Contains(lines[i], want) {
			t.Errorf("line %d = %q\nwant substring %q", i, lines[i], want)
		}
		if strings.Contains(lines[i], "env=") || strings.Contains(lines[i], "#L1") {
			t.Errorf("env must not be repeated on every line: %q", lines[i])
		}
	}
}
