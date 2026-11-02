// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package tui

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"
	"github.com/coredds/enigoma"
)

func pressM3(t *testing.T, r rune, opts ...enigoma.Option) enigoma.Trace {
	t.Helper()
	m, err := enigoma.NewM3(opts...)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := m.Press(r)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

var latin = []rune(enigoma.AlphabetLatinUpper)

func lines(s string) []string {
	return strings.Split(strings.TrimRight(ansi.Strip(s), "\n"), "\n")
}

func TestRenderPath_M3(t *testing.T) {
	got := ansi.Strip(renderPath(pressM3(t, 'A'), latin, 200))
	if !strings.HasPrefix(got, "A ─plug→ A ─III→ ") {
		t.Errorf("prefix: %q", got)
	}
	if !strings.HasSuffix(got, "─plug→ B") {
		t.Errorf("suffix: %q", got)
	}
	if strings.Count(got, "→") != 9 {
		t.Errorf("want 9 hops: %q", got)
	}
}

func TestRenderPath_Wraps(t *testing.T) {
	tr := pressM3(t, 'A')
	full := ansi.Strip(renderPath(tr, latin, 1000))
	ls := lines(renderPath(tr, latin, 30))
	if len(ls) < 2 {
		t.Fatalf("expected wrapping at width 30, got %q", ls)
	}
	for _, l := range ls {
		if n := utf8.RuneCountInString(l); n > 30 {
			t.Errorf("line %q has %d runes (> 30)", l, n)
		}
		if strings.HasSuffix(l, "─") || strings.HasPrefix(l, "→") {
			t.Errorf("hop split across lines: %q", l)
		}
	}
	if strings.Join(ls, " ") != full {
		t.Errorf("wrapped text differs:\n%q\n%q", strings.Join(ls, " "), full)
	}
}

func TestRenderColumns_Markers(t *testing.T) {
	out := lines(renderColumns(pressM3(t, 'A'), latin, "B", []string{"I", "II", "III"}))
	header := strings.Fields(out[0])
	if strings.Join(header, " ") != "B I II III plug" {
		t.Fatalf("header = %q", out[0])
	}
	plugCol := strings.LastIndex(out[0], "plug")
	row := func(letter string) string {
		for _, l := range out[1:] {
			if strings.HasPrefix(l, letter+" ") {
				return l
			}
		}
		t.Fatalf("no row %s", letter)
		return ""
	}
	cell := func(l string) string { return strings.TrimSpace(string([]rune(l)[plugCol:])) }
	if c := cell(row("A")); c != ">" {
		t.Errorf("row A plug cell = %q, want >", c)
	}
	if c := cell(row("B")); c != "<" {
		t.Errorf("row B plug cell = %q, want <", c)
	}
	if len(out) != 27 {
		t.Errorf("want header + 26 rows, got %d lines", len(out))
	}
}

func TestRenderLampboard_QWERTZ(t *testing.T) {
	out := lines(renderLampboard(latin, 'B', 'A', 80))
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "[B]") || !strings.Contains(joined, "(A)") {
		t.Errorf("lit/pressed markers missing:\n%s", joined)
	}
	if !strings.HasPrefix(strings.TrimSpace(out[0]), "Q") || len(out) != 3 {
		t.Errorf("want 3 QWERTZ rows starting with Q:\n%s", joined)
	}
}

func TestRenderLampboard_Grid(t *testing.T) {
	greek := []rune(enigoma.AlphabetGreek)
	out := lines(renderLampboard(greek, 'β', 'α', 20))
	joined := strings.Join(out, "")
	for _, l := range out {
		if n := utf8.RuneCountInString(l); n > 20 {
			t.Errorf("line %q has %d runes (> 20)", l, n)
		}
	}
	for _, r := range greek {
		if !strings.ContainsRune(joined, r) {
			t.Errorf("missing %c", r)
		}
	}
}

func TestRenderTapes_Grouped(t *testing.T) {
	out := lines(renderTapes([]rune("HELLOWORLD"), []rune("ILBDAAMTAZ"), true, 80))
	if out[0] != "In:  HELLO WORLD" || out[1] != "Out: ILBDA AMTAZ" {
		t.Errorf("got %q", out)
	}
}

func TestRenderTapes_Truncates(t *testing.T) {
	in := []rune(strings.Repeat("ABCDEFGHIJ", 19) + "KLMNOPQRSZ")
	out := lines(renderTapes(in, in, false, 40))
	for _, l := range out {
		if n := utf8.RuneCountInString(l); n > 40 {
			t.Errorf("line %q has %d runes (> 40)", l, n)
		}
		if !strings.HasSuffix(l, "Z") {
			t.Errorf("line %q should end with the last rune", l)
		}
	}
}

func TestRenderRotors(t *testing.T) {
	out := ansi.Strip(renderRotors("B", []rotorView{
		{Name: "I", Window: 'A', Ring: 'A'},
		{Name: "II", Window: 'D', Ring: 'A', Stepped: true},
		{Name: "III", Window: 'V', Ring: 'B', Stepped: true},
	}, 80))
	for _, want := range []string{"[A]", "[D]", "[V]", "I", "II", "III", "B"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestRenderHeader_Truncates(t *testing.T) {
	out := lines(renderHeader(strings.Repeat("x", 200), 40))
	for _, l := range out {
		if n := utf8.RuneCountInString(l); n > 40 {
			t.Errorf("header line has %d runes (> 40)", n)
		}
	}
}
