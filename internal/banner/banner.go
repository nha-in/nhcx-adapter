// Package banner prints the solid block-letter "NHCX ADAPTER" shown when
// the adapter starts serving. The font is defined here, so the binary
// stays self-contained.
package banner

import (
	"fmt"
	"strings"

	"nhcx-adapter/internal/style"
)

// Each glyph is five rows with two-cell-thick strokes, so the letters read
// as solid slabs rather than outlines; "#" is a block, "." is empty.
var glyphs = map[rune][]string{
	'N': {"##..##", "###.##", "######", "##.###", "##..##"},
	'H': {"##..##", "##..##", "######", "##..##", "##..##"},
	'C': {".#####", "##....", "##....", "##....", ".#####"},
	'X': {"##..##", ".####.", "..##..", ".####.", "##..##"},
	'G': {".#####", "##....", "##.###", "##..##", ".#####"},
	'A': {".####.", "##..##", "######", "##..##", "##..##"},
	'D': {"#####.", "##..##", "##..##", "##..##", "#####."},
	'P': {"#####.", "##..##", "#####.", "##....", "##...."},
	'R': {"#####.", "##..##", "#####.", "##.##.", "##..##"},
	'T': {"######", "..##..", "..##..", "..##..", "..##.."},
	'E': {"######", "##....", "#####.", "##....", "######"},
	'W': {"##...##", "##...##", "##.#.##", "#######", "##...##"},
	'Y': {"##..##", ".####.", "..##..", "..##..", "..##.."},
	' ': {"..", "..", "..", "..", ".."},
}

// Render draws text in the block font. Unknown characters become spaces.
func Render(text string) string {
	rows := make([]string, 5)
	for _, r := range strings.ToUpper(text) {
		g, ok := glyphs[r]
		if !ok {
			g = glyphs[' ']
		}
		for i := range rows {
			rows[i] += g[i] + "."
		}
	}
	var b strings.Builder
	for _, row := range rows {
		row = strings.TrimSuffix(row, ".") // the separator after the last glyph
		row = strings.ReplaceAll(row, "#", "█")
		row = strings.ReplaceAll(row, ".", " ")
		b.WriteString(" " + style.Brand(row) + "\n")
	}
	return b.String()
}

// Serve is the banner printed by "nhcx-adapter serve": the name, then a
// line with the version, environment, participant and listen address.
func Serve(version, env, participant, listen string) string {
	return "\n" + Render("NHCX ADAPTER") + "\n  " +
		style.Dim(version) + style.Dim(" · ") + style.Key(env) + style.Dim(" · ") + style.Key(participant) +
		style.Dim(" · listening on ") + style.Key(listen) + fmt.Sprintln() + "\n"
}
