package tui

import (
	"errors"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func textinputFor(v string) textinput.Model {
	in := textinput.New()
	in.SetValue(v)
	in.Focus()
	return in
}

func TestChooserModel(t *testing.T) {
	c := &chooser{title: "Pick", body: []string{"some explanation"}, width: 80,
		options: []Option{{Key: "a", Label: "First"}, {Key: "b", Label: "Second"}, {Key: "c", Label: "Third"}}}
	if v := c.View(); !strings.Contains(v, "Pick") || !strings.Contains(v, "▸ First") {
		t.Errorf("view: %s", v)
	}
	c.Update(tea.KeyMsg{Type: tea.KeyDown})
	c.Update(tea.KeyMsg{Type: tea.KeyDown})
	c.Update(tea.KeyMsg{Type: tea.KeyDown}) // clamps
	_, cmd := c.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if c.picked != "c" || cmd == nil {
		t.Errorf("picked %q", c.picked)
	}
	c2 := &chooser{options: c.options}
	c2.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	if c2.picked != "b" {
		t.Errorf("number key: %q", c2.picked)
	}
	c3 := &chooser{options: c.options}
	c3.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if c3.picked != "" || !c3.done {
		t.Error("esc cancels")
	}
}

func TestPrompterModel(t *testing.T) {
	bad := func(v string) error {
		if !strings.HasPrefix(v, "https://") {
			return errors.New("must be https")
		}
		return nil
	}
	p := &prompter{title: "URL", label: "endpoint", check: bad, width: 80}
	p.input = textinputFor("http://x")
	p.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if p.ok || p.problem == "" {
		t.Error("check must block enter")
	}
	p.input.SetValue("https://x/in")
	_, cmd := p.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if !p.ok || cmd == nil {
		t.Error("valid value must be accepted")
	}
	if v := p.View(); v != "" {
		t.Error("done prompter renders nothing")
	}
}
