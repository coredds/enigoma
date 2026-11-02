// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/coredds/enigoma"
)

// newTestModel wraps a constructor call: newTestModel(t)(enigoma.NewM3()).
func newTestModel(t *testing.T) func(*enigoma.Machine, error) model {
	t.Helper()
	return func(m *enigoma.Machine, err error) model {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return New(m).(model)
	}
}

func send(md model, msgs ...tea.Msg) model {
	for _, msg := range msgs {
		next, _ := md.Update(msg)
		md = next.(model)
	}
	return md
}

func keys(s string) []tea.Msg {
	var msgs []tea.Msg
	for _, r := range s {
		msgs = append(msgs, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	return msgs
}

func key(k tea.KeyType) tea.Msg { return tea.KeyMsg{Type: k} }

func TestModel_TypeMatchesEncrypt(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), keys("HELLOWORLD")...)
	ref, _ := enigoma.NewM3()
	want, _ := ref.Encrypt("HELLOWORLD")
	if string(md.out) != want || string(md.in) != "HELLOWORLD" {
		t.Errorf("tapes in=%q out=%q, want out %q", string(md.in), string(md.out), want)
	}
}

func TestModel_Undo(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3(enigoma.WithPositions("ADU"))), keys("HEL")...)
	md = send(md, key(tea.KeyBackspace))
	ref, _ := enigoma.NewM3(enigoma.WithPositions("ADU"))
	ref.Encrypt("HE")
	if md.m.Positions() != ref.Positions() {
		t.Errorf("positions after undo = %s, want %s", md.m.Positions(), ref.Positions())
	}
	if len(md.in) != 2 || len(md.out) != 2 || len(md.history) != 2 {
		t.Errorf("tapes/history not trimmed: in=%q out=%q history=%d", string(md.in), string(md.out), len(md.history))
	}
}

func TestModel_UndoEmpty(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), key(tea.KeyBackspace))
	if md.m.Positions() != "AAA" {
		t.Errorf("positions = %s", md.m.Positions())
	}
}

func TestModel_Reset(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), keys("HELLO")...)
	md = send(md, key(tea.KeyCtrlR))
	if md.m.Positions() != "AAA" || len(md.in) != 0 || len(md.out) != 0 || len(md.history) != 0 {
		t.Errorf("after reset: positions=%s in=%q out=%q history=%d", md.m.Positions(), string(md.in), string(md.out), len(md.history))
	}
}

func TestModel_InvalidKey(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), keys("é")...)
	if !strings.Contains(md.status, "not in the alphabet") {
		t.Errorf("status = %q", md.status)
	}
	if md.m.Positions() != "AAA" || len(md.in) != 0 {
		t.Errorf("invalid key changed state: %s %q", md.m.Positions(), string(md.in))
	}
	if !strings.Contains(ansi.Strip(md.View()), "not in the alphabet") {
		t.Error("status not shown in view")
	}
}

func TestModel_Uppercasing(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), keys("a")...)
	if string(md.in) != "A" {
		t.Errorf("M3: typing a pressed %q, want A", string(md.in))
	}
	md = send(newTestModel(t)(enigoma.New(
		enigoma.WithAlphabet(enigoma.AlphabetASCIIPrintable), enigoma.WithRandomComponents(3, 2))), keys("a")...)
	if string(md.in) != "a" {
		t.Errorf("ASCII: typing a pressed %q, want a", string(md.in))
	}
}

func TestModel_SpaceKey(t *testing.T) {
	md := send(newTestModel(t)(enigoma.New(
		enigoma.WithAlphabet(enigoma.AlphabetASCIIPrintable), enigoma.WithRandomComponents(3, 2))),
		tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
	if string(md.in) != " " {
		t.Errorf("space pressed %q", string(md.in))
	}
}

func TestModel_TabGroups(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), keys("HELLOWORLD")...)
	md = send(md, key(tea.KeyTab))
	if !strings.Contains(ansi.Strip(md.View()), "In:  HELLO WORLD") {
		t.Errorf("grouped tape missing:\n%s", ansi.Strip(md.View()))
	}
}

func TestModel_Quit(t *testing.T) {
	for _, k := range []tea.KeyType{tea.KeyEsc, tea.KeyCtrlC} {
		_, cmd := newTestModel(t)(enigoma.NewM3()).Update(key(k))
		if cmd == nil {
			t.Fatalf("%v: no command returned", k)
		}
		if _, ok := cmd().(tea.QuitMsg); !ok {
			t.Errorf("%v did not quit", k)
		}
	}
}

func hasColumnHeader(view string) bool {
	for _, l := range strings.Split(ansi.Strip(view), "\n") {
		if strings.Join(strings.Fields(l), " ") == "B I II III plug" {
			return true
		}
	}
	return false
}

func TestModel_ColumnViewWide(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), tea.WindowSizeMsg{Width: 100, Height: 60})
	md = send(md, keys("A")...)
	if !hasColumnHeader(md.View()) {
		t.Errorf("wide terminal should show the column view:\n%s", ansi.Strip(md.View()))
	}
}

func TestModel_TinyWidth(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), tea.WindowSizeMsg{Width: 20, Height: 20})
	md = send(md, keys("A")...)
	view := md.View()
	if hasColumnHeader(view) {
		t.Error("column view should be hidden at width 20")
	}
	if !strings.Contains(ansi.Strip(view), "─plug→") {
		t.Errorf("hop chain missing:\n%s", ansi.Strip(view))
	}
}

func TestModel_EnterPressesNewline(t *testing.T) {
	md := send(newTestModel(t)(enigoma.New(
		enigoma.WithAlphabet(enigoma.AlphabetASCIIPrintable), enigoma.WithRandomComponents(3, 2))), key(tea.KeyEnter))
	if string(md.in) != "\n" {
		t.Errorf("Enter pressed %q, want newline", string(md.in))
	}
	md = send(newTestModel(t)(enigoma.NewM3()), key(tea.KeyEnter))
	if !strings.Contains(md.status, "not in the alphabet") || len(md.in) != 0 {
		t.Errorf("Enter on M3: status %q, in %q", md.status, string(md.in))
	}
}

func TestModel_UnhandledKeyShowsStatus(t *testing.T) {
	md := send(newTestModel(t)(enigoma.NewM3()), key(tea.KeyF1))
	if md.status == "" {
		t.Error("an unhandled key should set a status message")
	}
}
