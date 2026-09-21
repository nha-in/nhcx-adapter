package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type prompter struct {
	title   string
	body    []string
	label   string
	input   textinput.Model
	check   func(string) error
	problem string
	done    bool
	ok      bool
	width   int
}

// Prompt asks for one line of text. check, when set, must accept the value
// before enter is honoured; esc cancels with ErrCancelled.
func Prompt(title string, body []string, label, initial string, check func(string) error) (string, error) {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 2048
	in.Width = 70
	in.SetValue(initial)
	in.CursorEnd()
	in.Focus()
	p := &prompter{title: title, body: body, label: label, input: in, check: check, width: 100}
	final, err := tea.NewProgram(p, tea.WithAltScreen()).Run()
	if err != nil {
		return "", err
	}
	fp, _ := final.(*prompter)
	if fp == nil || !fp.ok {
		return "", ErrCancelled
	}
	return strings.TrimSpace(fp.input.Value()), nil
}

func (p *prompter) Init() tea.Cmd { return textinput.Blink }

func (p *prompter) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.width = msg.Width
		p.input.Width = max(20, msg.Width-6)
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			p.done = true
			return p, tea.Quit
		case "enter":
			v := strings.TrimSpace(p.input.Value())
			if p.check != nil {
				if err := p.check(v); err != nil {
					p.problem = err.Error()
					return p, nil
				}
			}
			p.ok, p.done = true, true
			return p, tea.Quit
		}
		p.problem = ""
	}
	var cmd tea.Cmd
	p.input, cmd = p.input.Update(msg)
	return p, cmd
}

func (p *prompter) View() string {
	if p.done {
		return ""
	}
	var b strings.Builder
	b.WriteString(" " + styTitle.Render(p.title) + "\n\n")
	for _, line := range p.body {
		for _, l := range wrap(line, max(20, p.width-4)) {
			b.WriteString("  " + l + "\n")
		}
	}
	b.WriteString("\n  " + styLabel.Render(p.label) + "\n  " + p.input.View() + "\n\n")
	if p.problem != "" {
		b.WriteString("  " + styErr.Render(p.problem) + "\n")
	}
	b.WriteString(styHelp.Render(" enter confirm · esc cancel") + "\n")
	return b.String()
}
