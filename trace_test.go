package enigoma

import (
	"errors"
	"strings"
	"testing"
)

func TestPress_MatchesEncrypt(t *testing.T) {
	for name, m := range map[string]*Machine{
		"latin": mustMachine(t)(New(WithRandomComponents(5, 8))),
		"ascii": mustMachine(t)(New(WithAlphabet(AlphabetASCIIPrintable), WithRandomComponents(8, 20))),
	} {
		alph := []rune(m.Alphabet())
		var in strings.Builder
		for i := 0; i < 500; i++ {
			in.WriteRune(alph[(i*7+3)%len(alph)])
		}
		want := mustEncrypt(t, m.Clone(), in.String())
		var got strings.Builder
		for _, r := range in.String() {
			tr, err := m.Press(r)
			if err != nil {
				t.Fatalf("%s: Press(%q): %v", name, r, err)
			}
			got.WriteRune(tr.Output)
		}
		if got.String() != want {
			t.Errorf("%s: Press output differs from Encrypt", name)
		}
	}
}

func TestPress_TraceContinuity(t *testing.T) {
	m := mustMachine(t)(NewM4(WithPlugboard("AB CD EF")))
	alph := []rune(m.Alphabet())
	index := func(r rune) int { return strings.IndexRune(m.Alphabet(), r) }
	n := len(m.Settings().Rotors)
	wantStages := []Stage{StagePlugboardIn}
	for i := 0; i < n; i++ {
		wantStages = append(wantStages, StageRotorForward)
	}
	wantStages = append(wantStages, StageReflector)
	for i := 0; i < n; i++ {
		wantStages = append(wantStages, StageRotorBackward)
	}
	wantStages = append(wantStages, StagePlugboardOut)

	for _, r := range "ABCDEFHELLO" {
		tr, err := m.Press(r)
		if err != nil {
			t.Fatal(err)
		}
		if len(tr.Hops) != 2*n+3 {
			t.Fatalf("len(Hops) = %d, want %d", len(tr.Hops), 2*n+3)
		}
		if tr.Input != r || tr.Hops[0].In != index(r) {
			t.Errorf("first hop In = %d, want index of %c", tr.Hops[0].In, r)
		}
		for i, h := range tr.Hops {
			if h.Stage != wantStages[i] {
				t.Errorf("hop %d stage = %v, want %v", i, h.Stage, wantStages[i])
			}
			if i+1 < len(tr.Hops) && h.Out != tr.Hops[i+1].In {
				t.Errorf("hop %d Out %d != hop %d In %d", i, h.Out, i+1, tr.Hops[i+1].In)
			}
		}
		if last := tr.Hops[len(tr.Hops)-1]; alph[last.Out] != tr.Output {
			t.Errorf("last hop Out %c != Output %c", alph[last.Out], tr.Output)
		}
		// Rotor hops name the rotors right-to-left going forward, left-to-right coming back.
		if tr.Hops[1].Component != "III" || tr.Hops[n].Component != "Beta" ||
			tr.Hops[n+1].Component != "B-Thin" || tr.Hops[n+2].Component != "Beta" || tr.Hops[0].Component != "plugboard" {
			t.Errorf("unexpected components: %+v", tr.Hops)
		}
	}
}

func TestPress_BeforeAfter(t *testing.T) {
	m := mustMachine(t)(NewM3(WithPositions("ADU")))
	tr, _ := m.Press('A')
	if tr.Before != "ADU" || tr.After != "ADV" {
		t.Errorf("Before/After = %s/%s, want ADU/ADV", tr.Before, tr.After)
	}
	tr, _ = m.Press('A')
	if tr.Before != "ADV" || tr.After != "AEW" {
		t.Errorf("Before/After = %s/%s, want ADV/AEW", tr.Before, tr.After)
	}
}

func TestPress_InvalidRune(t *testing.T) {
	m := mustMachine(t)(NewM3())
	_, err := m.Press('1')
	var ce *CharError
	if !errors.As(err, &ce) || ce.Rune != '1' || ce.Offset != 0 {
		t.Fatalf("got %v, want CharError{'1', 0}", err)
	}
	if m.Positions() != "AAA" {
		t.Errorf("positions moved to %s", m.Positions())
	}
}

func TestPress_NoSelfEncryption(t *testing.T) {
	m := mustMachine(t)(New(WithRandomComponents(5, 8)))
	alph := []rune(m.Alphabet())
	for i := 0; i < 1000; i++ {
		r := alph[i%len(alph)]
		tr, err := m.Press(r)
		if err != nil {
			t.Fatal(err)
		}
		if tr.Output == r {
			t.Fatalf("%c encrypted to itself", r)
		}
	}
}

func TestStage_String(t *testing.T) {
	want := map[Stage]string{
		StagePlugboardIn:   "plugboard-in",
		StageRotorForward:  "rotor-forward",
		StageReflector:     "reflector",
		StageRotorBackward: "rotor-backward",
		StagePlugboardOut:  "plugboard-out",
	}
	for s, w := range want {
		if s.String() != w {
			t.Errorf("%d.String() = %q, want %q", s, s.String(), w)
		}
	}
}
