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
	// Spacing is a column layout now, so the content check collapses runs of
	// spaces: what matters here is that the fields are present and in order.
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for i, want := range []string{
		"▲ OUT v1/preauth/submit → 1000004805@hcx accepted nhcx 202 412ms 0f4c2b2e-9c7a-4d55-8a1e-2b1b0c7d9e11",
		"▼ IN v1/preauth/on_submit ← 1000004805@hcx delivery_failed callback 500 3ms redelivery CALLBACK_HTTP_500",
		`ERR session token refresh failed error="TOKEN_HTTP_401: bad creds"`,
	} {
		if !strings.Contains(flat(lines[i]), want) {
			t.Errorf("line %d = %q\nwant fields %q", i, lines[i], want)
		}
		if strings.Contains(lines[i], "env=") || strings.Contains(lines[i], "#L1") {
			t.Errorf("env must not be repeated on every line: %q", lines[i])
		}
	}
}

// Traffic lines are laid out in columns so a screenful can be read downwards.
// Paths and statuses vary in length, so the test that matters is that the
// columns after them still start in the same place.
func TestTrafficLinesLineUp(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(New(&buf, slog.LevelInfo))

	log.Info("outbound", "path", "v1/status", "recipient", "1@hcx",
		"status", "accepted", "nhcx", 202, "took_ms", 4,
		"correlation_id", "aaaaaaaa-0000-0000-0000-000000000000")
	log.Info("inbound", "path", "v1/coverageeligibility/on_check", "sender", "1000004805@hcx",
		"status", "delivered", "callback", 200, "took_ms", 2210,
		"correlation_id", "bbbbbbbb-0000-0000-0000-000000000000")

	out := ansi.ReplaceAllString(buf.String(), "")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d:\n%s", len(lines), out)
	}
	// Two columns pin the rest: the arrow, which sits after the widest path,
	// and the correlation id, which sits after everything else. A short path
	// and a long one must put both in the same place.
	for _, col := range []struct {
		name string
		at   func(string) int
	}{
		{"arrow", func(l string) int {
			if i := strings.Index(l, "→"); i >= 0 {
				return i
			}
			return strings.Index(l, "←")
		}},
		{"correlation id", func(l string) int { return strings.LastIndex(l, " ") + 1 }},
	} {
		first, second := col.at(lines[0]), col.at(lines[1])
		if first <= 0 || second <= 0 {
			t.Fatalf("both lines should carry a %s:\n%s", col.name, out)
		}
		if first != second {
			t.Errorf("%s starts at %d on one line and %d on the other — "+
				"the columns do not line up:\n%s", col.name, first, second, out)
		}
	}
}
