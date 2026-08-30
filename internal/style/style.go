// Package style colours the CLI's stderr output. Colour is applied only
// when stderr is a terminal and NO_COLOR is unset (lipgloss/termenv decide),
// so logs piped to a file stay plain.
package style

import (
	"os"

	"github.com/charmbracelet/lipgloss"
)

var r = lipgloss.NewRenderer(os.Stderr)

var (
	good  = r.NewStyle().Foreground(lipgloss.Color("2"))
	bad   = r.NewStyle().Foreground(lipgloss.Color("1"))
	warn  = r.NewStyle().Foreground(lipgloss.Color("3"))
	title = r.NewStyle().Bold(true)
	dim   = r.NewStyle().Faint(true)
	brand = r.NewStyle().Foreground(lipgloss.Color("6")).Bold(true)
	key   = r.NewStyle().Foreground(lipgloss.Color("6"))
	// Direction of travel. Distinct from the status colours (red/green/
	// yellow) and from the cyan of paths and participant codes, so a
	// screenful can be skimmed for "what did we send" against "what arrived"
	// without reading a word.
	out = r.NewStyle().Foreground(lipgloss.Color("5")).Bold(true)
	in  = r.NewStyle().Foreground(lipgloss.Color("4")).Bold(true)
)

// Out renders a message leaving this adapter (magenta).
func Out(s string) string { return out.Render(s) }

// In renders a message arriving at it (blue).
func In(s string) string { return in.Render(s) }

// Good renders success text (green).
func Good(s string) string { return good.Render(s) }

// Bad renders failure text (red).
func Bad(s string) string { return bad.Render(s) }

// Warn renders a caution (yellow).
func Warn(s string) string { return warn.Render(s) }

// Title renders a heading (bold).
func Title(s string) string { return title.Render(s) }

// Dim renders secondary text (faint).
func Dim(s string) string { return dim.Render(s) }

// Brand renders the product name / banner (bold cyan).
func Brand(s string) string { return brand.Render(s) }

// Key renders an identifier such as a path, URL or participant code (cyan).
func Key(s string) string { return key.Render(s) }
