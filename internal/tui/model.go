// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package tui

import (
	"fmt"
	"strings"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/coredds/enigoma"
)

const (
	defaultWidth   = 80
	minColumnWidth = 80 // narrower terminals hide the column view
	maxColumnAlpha = 26 // larger alphabets hide the column view
)

var sectionStyle = lipgloss.NewStyle().Bold(true).Underline(true)

// step is one keypress in the undo history.
type step struct {
	before string // rotor positions before the keypress
	trace  enigoma.Trace
}

type model struct {
	m          *enigoma.Machine
	alphabet   []rune
	upperOnly  bool // alphabet has no lowercase letters: upper-case typed keys
	reflector  string
	rotorNames []string
	rings      []rune
	history    []step
	in, out    []rune
	grouped    bool
	width      int
	status     string
}

// New returns the Bubble Tea model for a machine. The machine is used (and
// mutated) directly.
func New(m *enigoma.Machine) tea.Model {
	s := m.Settings()
	md := model{
		m:         m,
		alphabet:  []rune(s.Alphabet),
		upperOnly: true,
		reflector: s.Reflector.Name,
		width:     defaultWidth,
	}
	for _, r := range md.alphabet {
		if unicode.IsLower(r) {
			md.upperOnly = false
			break
		}
	}
	for _, r := range s.Rotors {
		md.rotorNames = append(md.rotorNames, r.Name)
		md.rings = append(md.rings, []rune(r.Ring)[0])
	}
	return md
}

// Run starts the interactive visualizer in the terminal's alternate screen.
func Run(m *enigoma.Machine) error {
	_, err := tea.NewProgram(New(m), tea.WithAltScreen()).Run()
	return err
}

func (md model) Init() tea.Cmd { return nil }

func (md model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		md.width = msg.Width
	case tea.KeyMsg:
		md.status = ""
		switch msg.Type {
		case tea.KeyEsc, tea.KeyCtrlC:
			return md, tea.Quit
		case tea.KeyBackspace:
			md.undo()
		case tea.KeyCtrlR:
			md.m.Reset()
			md.history, md.in, md.out = nil, nil, nil
		case tea.KeyTab:
			md.grouped = !md.grouped
		case tea.KeyRunes, tea.KeySpace:
			for _, r := range msg.Runes {
				md.press(r)
			}
		case tea.KeyEnter:
			md.press('\n')
		default:
			md.status = fmt.Sprintf("%s does nothing here", msg.String())
		}
	}
	return md, nil
}

func (md *model) press(r rune) {
	if md.upperOnly {
		r = unicode.ToUpper(r)
	}
	before := md.m.Positions()
	t, err := md.m.Press(r)
	if err != nil {
		md.status = fmt.Sprintf("%q is not in the alphabet", r)
		return
	}
	md.history = append(md.history, step{before: before, trace: t})
	md.in = append(md.in, t.Input)
	md.out = append(md.out, t.Output)
}

func (md *model) undo() {
	if len(md.history) == 0 {
		return
	}
	last := md.history[len(md.history)-1]
	if err := md.m.SetPositions(last.before); err != nil {
		md.status = err.Error()
		return
	}
	md.history = md.history[:len(md.history)-1]
	md.in, md.out = md.in[:len(md.in)-1], md.out[:len(md.out)-1]
}

func (md model) View() string {
	w := md.width
	var last *enigoma.Trace
	if n := len(md.history); n > 0 {
		last = &md.history[n-1].trace
	}

	window := []rune(md.m.Positions())
	rotors := make([]rotorView, len(md.rotorNames))
	for i, name := range md.rotorNames {
		rotors[i] = rotorView{Name: name, Window: window[i], Ring: md.rings[i]}
		if last != nil {
			rotors[i].Stepped = []rune(last.Before)[i] != []rune(last.After)[i]
		}
	}

	var b strings.Builder
	b.WriteString(renderHeader(summary(md.m.Settings()), w) + "\n\n")
	b.WriteString(renderRotors(md.reflector, rotors, w) + "\n\n")

	b.WriteString(sectionStyle.Render("Signal path") + "\n")
	if last == nil {
		b.WriteString(dimStyle.Render("Type a letter to send it through the machine.") + "\n")
	} else {
		b.WriteString(renderPath(*last, md.alphabet, w) + "\n")
		if len(md.alphabet) <= maxColumnAlpha && w >= minColumnWidth {
			b.WriteString("\n" + renderColumns(*last, md.alphabet, md.reflector, md.rotorNames) + "\n")
		}
	}

	b.WriteString("\n" + sectionStyle.Render("Lampboard") + "\n")
	var lit, pressed rune
	if last != nil {
		lit, pressed = last.Output, last.Input
	}
	b.WriteString(renderLampboard(md.alphabet, lit, pressed, w) + "\n\n")
	b.WriteString(renderTapes(md.in, md.out, md.grouped, w) + "\n\n")

	status := md.status
	if status == "" {
		status = dimStyle.Render("Backspace undo · Tab group by 5 · Ctrl+R reset · Enter newline · Esc quit")
	}
	b.WriteString(truncateLines(status, w))
	return b.String()
}
