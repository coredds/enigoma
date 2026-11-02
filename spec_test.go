package enigoma

import (
	"strings"
	"testing"
)

const v1Message = "config schema v1 (enigoma ≤ 0.6) is not supported; regenerate the key with enigoma ≥ 0.7"

const validV2JSON = `{
  "schema_version": 2,
  "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "rotors": [
    {"name": "Beta", "wiring": "LEYJVCNIXWPBQMDRTAKZGFUHOS", "notches": "", "ring": "A", "position": "A", "fixed": true},
    {"name": "I", "wiring": "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "notches": "Q", "ring": "B", "position": "C"}
  ],
  "reflector": {"name": "B-Thin", "wiring": "ENKQAUYWJICOPBLMDXZVFTHRGS"},
  "plugboard": "AB CD"
}`

func TestParseSettings_V2(t *testing.T) {
	s, err := ParseSettings([]byte(validV2JSON))
	if err != nil {
		t.Fatal(err)
	}
	if s.SchemaVersion != 2 || s.Alphabet != "ABCDEFGHIJKLMNOPQRSTUVWXYZ" || s.Plugboard != "AB CD" {
		t.Errorf("unexpected top-level fields: %+v", s)
	}
	if len(s.Rotors) != 2 || !s.Rotors[0].Fixed || s.Rotors[1].Fixed {
		t.Fatalf("unexpected rotors: %+v", s.Rotors)
	}
	r := s.Rotors[1]
	if r.Name != "I" || r.Notches != "Q" || r.Ring != "B" || r.Position != "C" {
		t.Errorf("unexpected rotor I: %+v", r)
	}
	if s.Reflector.Name != "B-Thin" || s.Reflector.Wiring != "ENKQAUYWJICOPBLMDXZVFTHRGS" {
		t.Errorf("unexpected reflector: %+v", s.Reflector)
	}
}

func TestParseSettings_V1Rejected(t *testing.T) {
	for name, js := range map[string]string{
		"explicit v1": `{"schema_version":1,"alphabet":"AB","rotor_specs":[]}`,
		"missing":     `{"alphabet":"AB","rotor_specs":[]}`,
	} {
		_, err := ParseSettings([]byte(js))
		if err == nil || !strings.Contains(err.Error(), v1Message) {
			t.Errorf("%s: got %v, want v1 message", name, err)
		}
	}
}

func TestParseSettings_FutureVersion(t *testing.T) {
	_, err := ParseSettings([]byte(`{"schema_version":3}`))
	if err == nil || !strings.Contains(err.Error(), "unsupported schema version 3") {
		t.Errorf("got %v", err)
	}
}

func TestParseSettings_BadJSON(t *testing.T) {
	if _, err := ParseSettings([]byte("{")); err == nil {
		t.Error("expected error for malformed JSON")
	}
}
