package enigoma

import (
	"testing"
)

// TestSettingsJSONRoundTrip ensures that saving then loading settings preserves core characteristics.
func TestSettingsJSONRoundTrip(t *testing.T) {
	// Simple Latin alphabet
	alphabet := []rune{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}

	machine, err := New(
		WithAlphabet(alphabet),
		WithRandomSettings(Low),
	)
	if err != nil {
		t.Fatalf("failed to create machine: %v", err)
	}

	jsonData, err := machine.SaveSettingsToJSON()
	if err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	machine2, err := NewFromJSON(jsonData)
	if err != nil {
		t.Fatalf("failed to load settings: %v", err)
	}

	if machine2.GetAlphabetSize() != machine.GetAlphabetSize() {
		t.Fatalf("alphabet size mismatch: %d vs %d", machine2.GetAlphabetSize(), machine.GetAlphabetSize())
	}
	if machine2.GetRotorCount() != machine.GetRotorCount() {
		t.Fatalf("rotor count mismatch: %d vs %d", machine2.GetRotorCount(), machine.GetRotorCount())
	}
}

// TestSettingsJSONRoundTrip_EncryptionMatch verifies that a machine restored from JSON
// produces the same encryption output as the original machine would.
func TestSettingsJSONRoundTrip_EncryptionMatch(t *testing.T) {
	alphabet := []rune{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}
	plaintext := "HELLOWORLD"

	machine1, err := New(
		WithAlphabet(alphabet),
		WithRandomSettings(Low),
	)
	if err != nil {
		t.Fatalf("failed to create machine1: %v", err)
	}

	// Save settings BEFORE encryption
	jsonData, err := machine1.SaveSettingsToJSON()
	if err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	encrypted1, err := machine1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("machine1 Encrypt() error: %v", err)
	}

	// Create machine2 from same settings and encrypt the same text
	machine2, err := NewFromJSON(jsonData)
	if err != nil {
		t.Fatalf("failed to create machine2 from JSON: %v", err)
	}

	encrypted2, err := machine2.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("machine2 Encrypt() error: %v", err)
	}

	if encrypted1 != encrypted2 {
		t.Errorf("Encryption mismatch after round-trip: %q vs %q", encrypted1, encrypted2)
	}
}

// TestSettingsJSONRoundTrip_DecryptionWorks verifies full encrypt-save-load-decrypt cycle.
func TestSettingsJSONRoundTrip_DecryptionWorks(t *testing.T) {
	alphabet := []rune{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}
	plaintext := "HELLOWORLD"

	machine, err := New(
		WithAlphabet(alphabet),
		WithRandomSettings(Low),
	)
	if err != nil {
		t.Fatalf("failed to create machine: %v", err)
	}

	// Save settings BEFORE encryption
	jsonData, err := machine.SaveSettingsToJSON()
	if err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	encrypted, err := machine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Restore machine and decrypt
	machine2, err := NewFromJSON(jsonData)
	if err != nil {
		t.Fatalf("failed to load machine from JSON: %v", err)
	}

	decrypted, err := machine2.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decryption after round-trip: got %q, want %q", decrypted, plaintext)
	}
}

// TestSettingsJSONRoundTrip_AllSecurityLevels tests round-trip at each security level.
func TestSettingsJSONRoundTrip_AllSecurityLevels(t *testing.T) {
	alphabet := []rune{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'}
	plaintext := "TESTMESSAGE"

	levels := []struct {
		name  string
		level SecurityLevel
	}{
		{"Low", Low},
		{"Medium", Medium},
		{"High", High},
		{"Extreme", Extreme},
	}

	for _, tt := range levels {
		t.Run(tt.name, func(t *testing.T) {
			machine, err := New(
				WithAlphabet(alphabet),
				WithRandomSettings(tt.level),
			)
			if err != nil {
				t.Fatalf("failed to create machine: %v", err)
			}

			jsonData, err := machine.SaveSettingsToJSON()
			if err != nil {
				t.Fatalf("failed to save settings: %v", err)
			}

			encrypted, err := machine.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error: %v", err)
			}

			machine2, err := NewFromJSON(jsonData)
			if err != nil {
				t.Fatalf("failed to load machine from JSON: %v", err)
			}

			decrypted, err := machine2.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt() error: %v", err)
			}

			if decrypted != plaintext {
				t.Errorf("Round-trip at %s: got %q, want %q", tt.name, decrypted, plaintext)
			}
		})
	}
}

// TestNewFromJSON_InvalidInput tests error paths of NewFromJSON.
func TestNewFromJSON_InvalidInput(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{"empty string", ""},
		{"invalid json", "not json"},
		{"empty object", "{}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFromJSON(tt.json)
			if err == nil {
				t.Error("NewFromJSON() expected error for invalid input")
			}
		})
	}
}
