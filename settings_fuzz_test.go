package enigoma

import (
	"encoding/json"
	"strings"
	"testing"
)

func FuzzParseSettings(f *testing.F) {
	f.Add([]byte(validV2JSON))
	f.Add([]byte(`{"schema_version":1,"alphabet":"ABCD","rotor_specs":[]}`))
	f.Add([]byte(`{"schema_version":2,"alphabet":"AB","rotors":[{"name":"R","wiring":"BA","notches":"A","ring":"","position":"B"}],"reflector":{"name":"U","wiring":"BA"},"plugboard":""}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := ParseSettings(data)
		if err != nil {
			return
		}
		m, err := NewFromSettings(s)
		if err != nil {
			return
		}
		js, err := json.Marshal(m.Settings())
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		s2, err := ParseSettings(js)
		if err != nil {
			t.Fatalf("re-parse of own settings failed: %v\n%s", err, js)
		}
		m2, err := NewFromSettings(s2)
		if err != nil {
			t.Fatalf("rebuild from own settings failed: %v\n%s", err, js)
		}
		probe := "HELLO"
		if !allIn(probe, m.Alphabet()) {
			probe = string([]rune(m.Alphabet())[:1])
		}
		if a, b := mustEncrypt(t, m, probe), mustEncrypt(t, m2, probe); a != b {
			t.Fatalf("round-tripped machine diverged: %q vs %q", a, b)
		}
	})
}

func allIn(s, alphabet string) bool {
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return false
		}
	}
	return true
}
