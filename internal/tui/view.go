// Package tui implements the interactive terminal visualizer behind `enigoma tui`.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/coredds/enigoma"
)

var (
	titleStyle   = lipgloss.NewStyle().Bold(true).Reverse(true)
	dimStyle     = lipgloss.NewStyle().Faint(true)
	forwardStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("6")).Bold(true) // cyan
	returnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("5")).Bold(true) // magenta
	bothStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true) // yellow
	steppedStyle = lipgloss.NewStyle().Reverse(true).Bold(true)
	litStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("3")).Bold(true)
	pressedStyle = lipgloss.NewStyle().Underline(true)
)

// rotorView is the display state of one rotor.
type rotorView struct {
	Name         string
	Window, Ring rune
	Stepped      bool // moved on the last keypress
}

// renderHeader renders the title line, truncated to width.
func renderHeader(summary string, width int) string {
	line := titleStyle.Render(" ENIGOMA ") + " " + summary + dimStyle.Render("   Esc quit")
	return ansi.Truncate(line, width, "…")
}

// renderRotors renders the reflector and rotors (left to right) with their
// window and ring letters; rotors that just stepped are highlighted.
func renderRotors(reflector string, rotors []rotorView, width int) string {
	const label = 6
	cell := 3
	for _, r := range rotors {
		cell = max(cell, ansi.StringWidth(r.Name))
	}
	cell += 2
	var names, windows, rings strings.Builder
	names.WriteString(pad(reflector, label))
	windows.WriteString(pad("", label))
	rings.WriteString(pad("ring", label))
	for _, r := range rotors {
		names.WriteString(center(r.Name, cell))
		w := "[" + string(r.Window) + "]"
		if r.Stepped {
			w = steppedStyle.Render(w)
		}
		windows.WriteString(center(w, cell))
		rings.WriteString(center(dimStyle.Render(string(r.Ring)), cell))
	}
	return truncateLines(names.String()+"\n"+windows.String()+"\n"+rings.String(), width)
}

// renderPath renders the hop chain of a keypress, e.g.
// "A ─plug→ A ─III→ B ─II→ ...", wrapping between hops to fit width.
func renderPath(t enigoma.Trace, alphabet []rune, width int) string {
	tokens := []string{string(t.Input)}
	for _, h := range t.Hops {
		label := h.Component
		if h.Stage == enigoma.StagePlugboardIn || h.Stage == enigoma.StagePlugboardOut {
			label = "plug"
		}
		tokens = append(tokens, "─"+label+"→ "+string(alphabet[h.Out]))
	}
	var lines []string
	line := ""
	for _, tok := range tokens {
		switch {
		case line == "":
			line = tok
		case ansi.StringWidth(line)+1+ansi.StringWidth(tok) > width:
			lines = append(lines, line)
			line = tok
		default:
			line += " " + tok
		}
	}
	return strings.Join(append(lines, line), "\n")
}

// renderColumns draws the machine as columns of contacts — reflector, rotors
// left to right, plugboard — marking where the signal enters each component:
// ">" on the way in, "<" on the way back, "*" for both.
func renderColumns(t enigoma.Trace, alphabet []rune, reflector string, rotors []string) string {
	names := append(append([]string{reflector}, rotors...), "plug")
	plug, n := len(names)-1, len(rotors)
	marks := make([][]byte, len(names)) // marks[column][contact]: bit 1 forward, bit 2 return
	for i := range marks {
		marks[i] = make([]byte, len(alphabet))
	}
	fwd, back := 0, 0
	for _, h := range t.Hops {
		switch h.Stage {
		case enigoma.StagePlugboardIn:
			marks[plug][h.In] |= 1
		case enigoma.StageRotorForward:
			marks[n-fwd][h.In] |= 1 // rightmost rotor first; rotor i is column i+1
			fwd++
		case enigoma.StageReflector:
			marks[0][h.In] |= 1
			marks[0][h.Out] |= 2
		case enigoma.StageRotorBackward:
			marks[1+back][h.In] |= 2
			back++
		case enigoma.StagePlugboardOut:
			marks[plug][h.In] |= 2
		}
	}

	cw := 0
	for _, name := range names {
		cw = max(cw, ansi.StringWidth(name))
	}
	cw++
	var b strings.Builder
	b.WriteString("  ")
	for _, name := range names {
		b.WriteString(pad(name, cw))
	}
	for i, r := range alphabet {
		b.WriteString("\n" + string(r) + " ")
		for c := range names {
			mark := dimStyle.Render("·")
			switch marks[c][i] {
			case 1:
				mark = forwardStyle.Render(">")
			case 2:
				mark = returnStyle.Render("<")
			case 3:
				mark = bothStyle.Render("*")
			}
			b.WriteString(mark + strings.Repeat(" ", cw-1))
		}
	}
	return b.String()
}

var qwertz = []string{"QWERTZUIO", "ASDFGHJK", "PYXCVBNML"}

// renderLampboard shows every letter as a lamp: the lit output as [K], the
// pressed key as (H). The Latin alphabet uses the Enigma QWERTZ layout; other
// alphabets wrap in alphabet order.
func renderLampboard(alphabet []rune, lit, pressed rune, width int) string {
	lamp := func(r rune) string {
		switch r {
		case lit:
			return litStyle.Render("[" + string(r) + "]")
		case pressed:
			return pressedStyle.Render("(" + string(r) + ")")
		}
		return " " + string(r) + " "
	}
	var rows []string
	if string(alphabet) == enigoma.AlphabetLatinUpper {
		for i, row := range qwertz {
			line := strings.Repeat(" ", []int{0, 1, 0}[i])
			for _, r := range row {
				line += lamp(r)
			}
			rows = append(rows, line)
		}
		return truncateLines(strings.Join(rows, "\n"), width)
	}
	perRow := max(1, (width-2)/3)
	for start := 0; start < len(alphabet); start += perRow {
		var line strings.Builder
		for _, r := range alphabet[start:min(start+perRow, len(alphabet))] {
			line.WriteString(lamp(r))
		}
		rows = append(rows, line.String())
	}
	return strings.Join(rows, "\n")
}

// renderTapes renders the input and output tapes, showing the most recent
// characters that fit width. grouped inserts a space after every fifth
// character counted from the start of the tape.
func renderTapes(in, out []rune, grouped bool, width int) string {
	tape := func(prefix string, runes []rune) string {
		var b strings.Builder
		for i, r := range runes {
			if grouped && i > 0 && i%5 == 0 {
				b.WriteByte(' ')
			}
			b.WriteRune(r)
		}
		body := []rune(b.String())
		avail := max(0, width-ansi.StringWidth(prefix))
		for ansi.StringWidth(string(body)) > avail {
			body = body[1:]
		}
		return prefix + string(body)
	}
	return tape("In:  ", in) + "\n" + tape("Out: ", out)
}

func pad(s string, width int) string {
	return s + strings.Repeat(" ", max(0, width-ansi.StringWidth(s)))
}

func center(s string, width int) string {
	gap := max(0, width-ansi.StringWidth(s))
	return strings.Repeat(" ", gap/2) + s + strings.Repeat(" ", gap-gap/2)
}

func truncateLines(s string, width int) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, width, "")
	}
	return strings.Join(lines, "\n")
}

// summary describes a machine for the header line.
func summary(s enigoma.Settings) string {
	names := make([]string, len(s.Rotors))
	for i, r := range s.Rotors {
		names[i] = r.Name
	}
	pb := s.Plugboard
	if pb == "" {
		pb = "none"
	}
	return fmt.Sprintf("Rotors %s · Reflector %s · Plugboard %s", strings.Join(names, "-"), s.Reflector.Name, pb)
}
