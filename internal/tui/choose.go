package tui

import (
	"errors"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// Option is one choice offered by Choose.
type Option struct {
	Key   string // returned when picked
	Label string
}

// ErrCancelled is returned by Choose when the user backs out.
var ErrCancelled = errors.New("cancelled")

type chooser struct {
	title   string
	body    []string
	options []Option
	cursor  int
	picked  string
	done    bool
	width   int
}

// Choose shows a message and a vertical menu; arrows move, enter picks,
// esc/q cancels. It returns the picked option's Key.
func Choose(title string, body []string, options []Option) (string, error) {
	c := &chooser{title: title, body: body, options: options, width: 100}
	final, err := tea.NewProgram(c, tea.WithAltScreen()).Run()
	if err != nil {
		return "", err
	}
	fc, _ := final.(*chooser)
	if fc == nil || fc.picked == "" {
		return "", ErrCancelled
	}
	return fc.picked, nil
}

func (c *chooser) Init() tea.Cmd { return nil }

func (c *chooser) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		c.width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc", "q":
			c.done = true
			return c, tea.Quit
		case "up", "k", "shift+tab":
			if c.cursor > 0 {
				c.cursor--
			}
		case "down", "j", "tab":
			if c.cursor < len(c.options)-1 {
				c.cursor++
			}
		case "enter", " ":
			c.picked = c.options[c.cursor].Key
			c.done = true
			return c, tea.Quit
		default:
			// Number keys jump straight to an option.
			if s := msg.String(); len(s) == 1 && s[0] >= '1' && s[0] <= '9' && int(s[0]-'1') < len(c.options) {
				c.picked = c.options[int(s[0]-'1')].Key
				c.done = true
				return c, tea.Quit
			}
		}
	}
	return c, nil
}

func (c *chooser) View() string {
	if c.done {
		return ""
	}
	var b strings.Builder
	b.WriteString(" " + styTitle.Render(c.title) + "\n\n")
	for _, line := range c.body {
		for _, l := range wrap(line, max(20, c.width-4)) {
			b.WriteString("  " + l + "\n")
		}
	}
	b.WriteString("\n")
	for i, o := range c.options {
		if i == c.cursor {
			b.WriteString(stySel.Render(" ▸ "+o.Label) + "\n")
		} else {
			b.WriteString("   " + o.Label + "\n")
		}
	}
	b.WriteString("\n" + styHelp.Render(" ↑↓ move · enter choose · esc cancel") + "\n")
	return b.String()
}
