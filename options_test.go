package enigoma

import (
	"testing"

	"github.com/coredds/enigoma/internal/alphabet"
)

func TestWithAlphabet(t *testing.T) {
	runes := []rune{'A', 'B', 'C', 'D'}

	enigma := &Enigma{}
	opt := WithAlphabet(runes)

	err := opt(enigma)
	if err != nil {
		t.Errorf("WithAlphabet() error: %v", err)
	}

	if enigma.alphabet == nil {
		t.Errorf("WithAlphabet() did not set alphabet")
	}

	if enigma.alphabet.Size() != len(runes) {
		t.Errorf("WithAlphabet() alphabet size = %d, want %d", enigma.alphabet.Size(), len(runes))
	}
}

func TestWithAlphabet_Invalid(t *testing.T) {
	// Test with duplicate runes
	runes := []rune{'A', 'B', 'A', 'C'}

	enigma := &Enigma{}
	opt := WithAlphabet(runes)

	err := opt(enigma)
	if err == nil {
		t.Errorf("WithAlphabet() with duplicates should fail")
	}
}

func TestWithRandomSettings(t *testing.T) {
	alph, _ := alphabet.New([]rune{'A', 'B', 'C', 'D', 'E', 'F'})

	tests := []struct {
		name  string
		level SecurityLevel
	}{
		{"Low", Low},
		{"Medium", Medium},
		{"High", High},
		{"Extreme", Extreme},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enigma := &Enigma{alphabet: alph}
			opt := WithRandomSettings(tt.level)

			err := opt(enigma)
			if err != nil {
				t.Errorf("WithRandomSettings(%v) error: %v", tt.level, err)
			}

			if len(enigma.rotors) == 0 {
				t.Errorf("WithRandomSettings(%v) did not create rotors", tt.level)
			}

			if enigma.reflector == nil {
				t.Errorf("WithRandomSettings(%v) did not create reflector", tt.level)
			}

			if enigma.plugboard == nil {
				t.Errorf("WithRandomSettings(%v) did not create plugboard", tt.level)
			}
		})
	}
}

func TestWithRandomSettings_NoAlphabet(t *testing.T) {
	enigma := &Enigma{}
	opt := WithRandomSettings(Low)

	err := opt(enigma)
	if err == nil {
		t.Errorf("WithRandomSettings() without alphabet should fail")
	}
}

func TestWithRotorPositions(t *testing.T) {
	alph, _ := alphabet.New([]rune{'A', 'B', 'C', 'D'})

	// Create enigma with rotors first
	enigma := &Enigma{alphabet: alph}
	if err := WithRandomSettings(Low)(enigma); err != nil { // This creates rotors
		t.Fatalf("WithRandomSettings failed: %v", err)
	}

	positions := []int{1, 2, 0}
	opt := WithRotorPositions(positions)

	err := opt(enigma)
	if err != nil {
		t.Errorf("WithRotorPositions() error: %v", err)
	}

	currentPositions := enigma.GetCurrentRotorPositions()
	for i, pos := range positions {
		if i < len(currentPositions) && currentPositions[i] != pos {
			t.Errorf("Position %d = %d, want %d", i, currentPositions[i], pos)
		}
	}
}

func TestWithRotorPositions_WrongCount(t *testing.T) {
	alph, _ := alphabet.New([]rune{'A', 'B', 'C', 'D'})

	// Create enigma with 3 rotors
	enigma := &Enigma{alphabet: alph}
	if err := WithRandomSettings(Low)(enigma); err != nil {
		t.Fatalf("WithRandomSettings failed: %v", err)
	}

	// Try to set positions for wrong number of rotors
	positions := []int{1, 2} // Only 2 positions for 3 rotors
	opt := WithRotorPositions(positions)

	err := opt(enigma)
	if err == nil {
		t.Errorf("WithRotorPositions() with wrong count should fail")
	}
}

func TestWithRandomRotorPositions(t *testing.T) {
	alph, _ := alphabet.New([]rune{'A', 'B', 'C', 'D'})

	enigma := &Enigma{alphabet: alph}
	if err := WithRandomSettings(Low)(enigma); err != nil { // Create rotors first
		t.Fatalf("WithRandomSettings failed: %v", err)
	}

	// Get initial positions
	initialPositions := enigma.GetCurrentRotorPositions()

	opt := WithRandomRotorPositions()
	err := opt(enigma)
	if err != nil {
		t.Errorf("WithRandomRotorPositions() error: %v", err)
	}

	// Positions should be set (may or may not be different from initial)
	newPositions := enigma.GetCurrentRotorPositions()
	if len(newPositions) != len(initialPositions) {
		t.Errorf("Position count changed: %d -> %d", len(initialPositions), len(newPositions))
	}

	// All positions should be valid (within alphabet range)
	for i, pos := range newPositions {
		if pos < 0 || pos >= alph.Size() {
			t.Errorf("Position %d out of range: %d", i, pos)
		}
	}
}

func TestWithPlugboardConfiguration(t *testing.T) {
	alph, _ := alphabet.New([]rune{'A', 'B', 'C', 'D'})

	enigma := &Enigma{alphabet: alph}

	pairs := map[rune]rune{
		'A': 'B',
		'B': 'A',
		'C': 'D',
		'D': 'C',
	}

	opt := WithPlugboardConfiguration(pairs)
	err := opt(enigma)
	if err != nil {
		t.Errorf("WithPlugboardConfiguration() error: %v", err)
	}

	if enigma.plugboard == nil {
		t.Errorf("WithPlugboardConfiguration() did not create plugboard")
	}

	if enigma.plugboard.PairCount() != 2 {
		t.Errorf("Plugboard pair count = %d, want 2", enigma.plugboard.PairCount())
	}
}

func TestWithPlugboardConfiguration_NonReciprocal(t *testing.T) {
	alph, _ := alphabet.New([]rune{'A', 'B', 'C', 'D'})

	enigma := &Enigma{alphabet: alph}

	// Non-reciprocal pairs
	pairs := map[rune]rune{
		'A': 'B',
		'B': 'C', // Should be B->A
	}

	opt := WithPlugboardConfiguration(pairs)
	err := opt(enigma)
	if err == nil {
		t.Errorf("WithPlugboardConfiguration() with non-reciprocal pairs should fail")
	}
}

func TestGetSecurityConfig(t *testing.T) {
	tests := []struct {
		level             SecurityLevel
		expectedRotors    int
		expectedPlugboard int
	}{
		{Low, 3, 2},
		{Medium, 5, 8},
		{High, 8, 15},
		{Extreme, 12, 20},
	}

	for _, tt := range tests {
		config := getSecurityConfig(tt.level)
		if config.rotorCount != tt.expectedRotors {
			t.Errorf("Security level %v rotor count = %d, want %d",
				tt.level, config.rotorCount, tt.expectedRotors)
		}
		if config.plugboardPairs != tt.expectedPlugboard {
			t.Errorf("Security level %v plugboard pairs = %d, want %d",
				tt.level, config.plugboardPairs, tt.expectedPlugboard)
		}
	}
}

func TestSecurityLevels_Integration(t *testing.T) {
	alph, _ := alphabet.New([]rune{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'})

	levels := []SecurityLevel{Low, Medium, High}

	for _, level := range levels {
		t.Run(level.String(), func(t *testing.T) {
			enigma, err := New(
				WithAlphabet(alph.Runes()),
				WithRandomSettings(level),
			)
			if err != nil {
				t.Errorf("Failed to create Enigma with security level %v: %v", level, err)
				return
			}

			// Test basic functionality
			plaintext := "ABCD"
			encrypted, err := enigma.Encrypt(plaintext)
			if err != nil {
				t.Errorf("Encrypt() error with level %v: %v", level, err)
				return
			}

			if err := enigma.Reset(); err != nil {
				t.Errorf("Reset() error with level %v: %v", level, err)
				return
			}
			decrypted, err := enigma.Decrypt(encrypted)
			if err != nil {
				t.Errorf("Decrypt() error with level %v: %v", level, err)
				return
			}

			if decrypted != plaintext {
				t.Errorf("Round-trip failed for level %v: %s -> %s -> %s",
					level, plaintext, encrypted, decrypted)
			}
		})
	}
}
