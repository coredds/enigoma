package enigoma

import (
	"errors"
	"strings"
	"testing"
)

func TestNew_Validation(t *testing.T) {
	I, II, III := mustRotor(t, "I"), mustRotor(t, "II"), mustRotor(t, "III")
	B := mustReflector(t, "B")
	badWiring := I
	badWiring.Wiring = strings.Replace(I.Wiring, "E", "K", 1) // K appears twice
	badNotch := I
	badNotch.Notches = "1"
	selfMap := ReflectorSpec{Name: "X", Wiring: "A" + B.Wiring[1:]}
	badPos := I
	badPos.Position = "1"

	tests := []struct {
		name string
		opts []Option
		want string
	}{
		{"odd alphabet", []Option{WithAlphabet("ABC"), WithRandomComponents(3, 0)}, "even"},
		{"duplicate alphabet", []Option{WithAlphabet("AABC"), WithRandomComponents(3, 0)}, "duplicate"},
		{"no rotors", []Option{WithReflector(B)}, "rotor"},
		{"no reflector", []Option{WithRotors(I, II, III)}, "reflector"},
		{"wiring not a permutation", []Option{WithRotors(badWiring), WithReflector(B)}, "wiring"},
		{"bad notch", []Option{WithRotors(badNotch), WithReflector(B)}, "notch"},
		{"reflector self-map", []Option{WithRotors(I), WithReflector(selfMap)}, "itself"},
		{"position count", []Option{WithRotors(I, II, III), WithReflector(B), WithPositions("AB")}, "3"},
		{"position letter", []Option{WithRotors(badPos), WithReflector(B)}, "position"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts...)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestMachine_EncryptDecryptRoundTrip(t *testing.T) {
	enc := mustMachine(t)(NewM3(WithPositions("QEV"), WithPlugboard("AB CD")))
	dec := mustMachine(t)(NewM3(WithPositions("QEV"), WithPlugboard("AB CD")))
	msg := strings.Repeat("THEQUICKBROWNFOX", 10)
	if got, _ := dec.Decrypt(mustEncrypt(t, enc, msg)); got != msg {
		t.Errorf("round trip failed: %s", got)
	}
}

func TestMachine_CharError(t *testing.T) {
	m := mustMachine(t)(NewM3())
	_, err := m.Encrypt("HEL1O")
	var ce *CharError
	if !errors.As(err, &ce) || ce.Rune != '1' || ce.Offset != 3 {
		t.Fatalf("got %v, want CharError{'1', 3}", err)
	}
	if m.Positions() != "AAA" {
		t.Errorf("positions moved to %s on error", m.Positions())
	}
}

func greekMachine(t *testing.T, opts ...Option) *Machine {
	t.Helper()
	return mustMachine(t)(New(append([]Option{WithAlphabet(AlphabetGreek), WithRandomComponents(3, 4)}, opts...)...))
}

func TestMachine_CharErrorMultibyte(t *testing.T) {
	m := greekMachine(t)
	_, err := m.Encrypt("αβγ!δ")
	var ce *CharError
	if !errors.As(err, &ce) || ce.Offset != 3 {
		t.Fatalf("got %v, want offset 3", err)
	}
}

func TestMachine_PositionsMultibyte(t *testing.T) {
	m := greekMachine(t, WithPositions("ΑΒΓ"))
	if m.Positions() != "ΑΒΓ" {
		t.Fatalf("positions = %q", m.Positions())
	}
	if err := m.SetPositions("ΓΓΓ"); err != nil || m.Positions() != "ΓΓΓ" {
		t.Errorf("SetPositions(ΓΓΓ): %v, positions %q", err, m.Positions())
	}
	if err := m.SetPositions("ΓΓ"); err == nil {
		t.Error("SetPositions with 2 letters for 3 rotors should fail")
	}
}

func TestMachine_ResetAndSetPositions(t *testing.T) {
	m := mustMachine(t)(NewM3(WithPositions("QEV")))
	mustEncrypt(t, m, "ABCDEFGHIJ")
	m.Reset()
	if m.Positions() != "QEV" {
		t.Errorf("after Reset positions = %s, want QEV", m.Positions())
	}
	if err := m.SetPositions("ZZZ"); err != nil || m.Positions() != "ZZZ" {
		t.Errorf("SetPositions(ZZZ): %v, %s", err, m.Positions())
	}
	if err := m.SetPositions("ZZ1"); err == nil {
		t.Error("SetPositions(ZZ1) should fail")
	}
}

func TestMachine_SettingsRoundTrip(t *testing.T) {
	m := mustMachine(t)(NewM3(WithPlugboard("AB CD")))
	mustEncrypt(t, m, "SEVENCH")
	s := m.Settings()
	if s.SchemaVersion != SchemaVersion {
		t.Errorf("schema version = %d", s.SchemaVersion)
	}
	m2 := mustMachine(t)(NewFromSettings(s))
	next := strings.Repeat("ENIGMA", 9)
	if a, b := mustEncrypt(t, m, next), mustEncrypt(t, m2, next); a != b {
		t.Errorf("restored machine diverged:\n%s\n%s", a, b)
	}
	m2.Reset()
	var want strings.Builder
	for _, r := range s.Rotors {
		want.WriteString(r.Position)
	}
	if m2.Positions() != want.String() || want.String() == "AAA" {
		t.Errorf("Reset after NewFromSettings = %s, want %s (not AAA)", m2.Positions(), want.String())
	}
}

func TestMachine_SettingsPlugboardOrder(t *testing.T) {
	m := mustMachine(t)(NewM3(WithPlugboard("DC BA")))
	if got := m.Settings().Plugboard; got != "AB CD" {
		t.Errorf("Settings().Plugboard = %q, want %q", got, "AB CD")
	}
}

func TestMachine_Clone(t *testing.T) {
	m := mustMachine(t)(NewM3())
	c := m.Clone()
	mustEncrypt(t, c, "HELLO")
	if m.Positions() != "AAA" || c.Positions() == "AAA" {
		t.Errorf("clone not independent: m=%s c=%s", m.Positions(), c.Positions())
	}
	if a, b := mustEncrypt(t, m, "HELLO"), mustEncrypt(t, mustMachine(t)(NewM3()), "HELLO"); a != b {
		t.Errorf("original changed by clone: %s vs %s", a, b)
	}
}

func TestMachine_Alphabet(t *testing.T) {
	if got := mustMachine(t)(NewM3()).Alphabet(); got != AlphabetLatinUpper {
		t.Errorf("Alphabet() = %q", got)
	}
}
