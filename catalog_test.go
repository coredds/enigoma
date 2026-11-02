package enigoma

import "testing"

func TestHistoricalRotor(t *testing.T) {
	r, err := HistoricalRotor("I")
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "I" || r.Wiring != "EKMFLGDQVZNTOWYHXUSPAIBRCJ" || r.Notches != "Q" || r.Fixed {
		t.Errorf("rotor I: %+v", r)
	}
	if r.Ring != "" || r.Position != "" {
		t.Errorf("catalogue ring/position should be empty, got %+v", r)
	}
	if r, _ := HistoricalRotor("VI"); r.Notches != "ZM" {
		t.Errorf("VI notches = %q", r.Notches)
	}
	for _, name := range []string{"Beta", "Gamma"} {
		r, err := HistoricalRotor(name)
		if err != nil || !r.Fixed || r.Notches != "" {
			t.Errorf("%s: %+v, %v", name, r, err)
		}
	}
	for _, name := range []string{"II", "III", "IV", "V", "VII", "VIII"} {
		if _, err := HistoricalRotor(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := HistoricalRotor("IX"); err == nil {
		t.Error("IX should not exist")
	}
}

func TestHistoricalReflector(t *testing.T) {
	r, err := HistoricalReflector("B")
	if err != nil || r.Wiring != "YRUHQSLDPXNGOKMIEBFZCWVJAT" || r.Name != "B" {
		t.Errorf("B: %+v, %v", r, err)
	}
	for _, name := range []string{"A", "C", "B-Thin", "C-Thin"} {
		if _, err := HistoricalReflector(name); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := HistoricalReflector("D"); err == nil {
		t.Error("D should not exist")
	}
}
