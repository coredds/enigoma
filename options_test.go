package enigoma

import (
	"strings"
	"testing"
)

func TestWithPlugboard_Parsing(t *testing.T) {
	m := mustMachine(t)(NewM3(WithPlugboard("  AB   CD ")))
	if got := m.Settings().Plugboard; got != "AB CD" {
		t.Errorf("whitespace-tolerant parse: got %q", got)
	}
	for _, bad := range []string{"ab", "A", "ABC", "AB BC"} {
		_, err := NewM3(WithPlugboard(bad))
		token := bad
		if bad == "AB BC" {
			token = "BC"
		}
		if err == nil || !strings.Contains(err.Error(), token) {
			t.Errorf("WithPlugboard(%q): got %v, want error naming %q", bad, err, token)
		}
	}
}

func TestWithRandomComponents(t *testing.T) {
	m := mustMachine(t)(New(WithRandomComponents(5, 8)))
	s := m.Settings()
	if len(s.Rotors) != 5 || len(strings.Fields(s.Plugboard)) != 8 {
		t.Errorf("rotors=%d pairs=%d, want 5 and 8", len(s.Rotors), len(strings.Fields(s.Plugboard)))
	}

	m = mustMachine(t)(New(WithRandomComponents(3, 100)))
	if n := len(strings.Fields(m.Settings().Plugboard)); n != 13 {
		t.Errorf("pairs capped at %d, want 13", n)
	}

	m = mustMachine(t)(New(WithRandomComponents(3, 2), WithReflector(mustReflector(t, "B"))))
	if m.Settings().Reflector.Name != "B" {
		t.Errorf("later WithReflector discarded: %+v", m.Settings().Reflector)
	}

	m = mustMachine(t)(New(WithRotors(mustRotor(t, "I")), WithRandomComponents(5, 2)))
	if n := len(m.Settings().Rotors); n != 5 {
		t.Errorf("earlier WithRotors should be replaced by random components, got %d rotors", n)
	}
}

func TestNewM3_Overrides(t *testing.T) {
	m := mustMachine(t)(NewM3(WithRotors(mustRotor(t, "IV"), mustRotor(t, "V"), mustRotor(t, "I"))))
	var names []string
	for _, r := range m.Settings().Rotors {
		names = append(names, r.Name)
	}
	if got := strings.Join(names, ","); got != "IV,V,I" {
		t.Errorf("rotors = %s", got)
	}
}

func TestWithRandomComponents_PlugboardSkipsWhitespace(t *testing.T) {
	// Space and tab cannot be written in the "AB CD" format, so only A-B can pair.
	for i := 0; i < 20; i++ {
		m := mustMachine(t)(New(WithAlphabet(" \tAB"), WithRandomComponents(1, 2)))
		if got := m.Settings().Plugboard; got != "AB" {
			t.Fatalf("plugboard = %q, want %q", got, "AB")
		}
	}
}
