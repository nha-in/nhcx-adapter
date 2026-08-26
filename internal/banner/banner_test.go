package banner

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRender(t *testing.T) {
	out := Render("NHCX GATEWAY")
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 5 {
		t.Fatalf("want 5 rows, got %d:\n%s", len(lines), out)
	}
	width := utf8.RuneCountInString(lines[0])
	for _, l := range lines {
		if w := utf8.RuneCountInString(l); w != width {
			t.Errorf("row width %d != %d: %q", w, width, l)
		}
		if !strings.Contains(l, "█") {
			t.Errorf("row without blocks: %q", l)
		}
	}
	for _, r := range "NHCXGATEWAY" {
		if g := glyphs[r]; len(g) != 5 {
			t.Errorf("glyph %c has %d rows", r, len(g))
		} else {
			for _, row := range g {
				if len(row) != len(g[0]) {
					t.Errorf("glyph %c has ragged rows", r)
				}
			}
		}
	}
	s := Serve("v1", "sandbox", "1@hcx", ":8090")
	for _, want := range []string{"v1", "sandbox", "1@hcx", "listening on", ":8090"} {
		if !strings.Contains(s, want) {
			t.Errorf("serve banner lacks %q: %s", want, s)
		}
	}
}
