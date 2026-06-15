package enigoma

import (
	"testing"
)

// FuzzNewFromJSON fuzzes NewFromJSON to ensure it doesn't panic on arbitrary input
// and that valid JSON round-trips when possible.
func FuzzNewFromJSON(f *testing.F) {
	// Seed with some interesting cases
	f.Add("")
	f.Add("not json")
	f.Add("{}")
	f.Add("{\"schema_version\":1}")
	f.Add("{\"alphabet\":\"ABC\",\"rotor_specs\":[],\"reflector_spec\":{}}")

	f.Fuzz(func(t *testing.T, data string) {
		// Function under test should never panic
		m, err := NewFromJSON(data)
		if err == nil && m != nil {
			// If it parsed, try to serialize and parse again
			jsonData, err := m.SaveSettingsToJSON()
			if err != nil {
				t.Fatalf("SaveSettingsToJSON failed after parse: %v", err)
			}
			m2, err := NewFromJSON(jsonData)
			if err != nil {
				t.Fatalf("Re-parse failed after save: %v", err)
			}
			// Light sanity checks
			if m2.GetAlphabetSize() <= 0 {
				t.Fatalf("Invalid alphabet size after round-trip")
			}
		}
	})
}
