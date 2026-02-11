package enigma

import (
	"strings"
	"testing"

	"github.com/coredds/enigoma/internal/alphabet"
	"github.com/coredds/enigoma/internal/plugboard"
	"github.com/coredds/enigoma/internal/reflector"
	"github.com/coredds/enigoma/internal/rotor"
)

func createTestAlphabet() *alphabet.Alphabet {
	alph, err := alphabet.New([]rune{'A', 'B', 'C', 'D', 'E', 'F'})
	if err != nil {
		panic("createTestAlphabet: " + err.Error())
	}
	return alph
}

func createTestRotor(id string, mapping string, notches []rune, alph *alphabet.Alphabet) rotor.Rotor {
	r, err := rotor.NewRotor(id, alph, mapping, notches)
	if err != nil {
		panic("createTestRotor: " + err.Error())
	}
	return r
}

func createTestReflector(id string, mapping string, alph *alphabet.Alphabet) reflector.Reflector {
	refl, err := reflector.NewReflector(id, alph, mapping)
	if err != nil {
		panic("createTestReflector: " + err.Error())
	}
	return refl
}

func TestNew(t *testing.T) {
	alph := createTestAlphabet()

	tests := []struct {
		name      string
		options   []Option
		wantError bool
	}{
		{
			name: "valid simple enigma",
			options: []Option{
				WithAlphabet(alph.Runes()),
				WithRandomSettings(Low),
			},
			wantError: false,
		},
		{
			name:      "no alphabet",
			options:   []Option{},
			wantError: true,
		},
		{
			name: "no rotors",
			options: []Option{
				WithAlphabet(alph.Runes()),
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enigma, err := New(tt.options...)
			if tt.wantError {
				if err == nil {
					t.Errorf("New() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("New() unexpected error: %v", err)
				return
			}
			if enigma == nil {
				t.Errorf("New() returned nil enigma")
			}
		})
	}
}

func TestEnigma_EncryptDecrypt(t *testing.T) {
	alph := createTestAlphabet()

	// Create a simple Enigma with known components for predictable testing
	r1 := createTestRotor("R1", "BCDEFA", []rune{'D'}, alph)
	refl := createTestReflector("UKW", "BADCFE", alph) // A<->B, C<->D, E<->F
	pb, _ := plugboard.New(alph)

	enigma, err := New(
		WithAlphabet(alph.Runes()),
		WithCustomComponents([]rotor.Rotor{r1}, refl, pb),
	)
	if err != nil {
		t.Fatalf("Failed to create enigma: %v", err)
	}

	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		{"single character", "A", false},
		{"multiple characters", "ABC", false},
		{"empty string", "", false},
		{"invalid character", "X", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset enigma to initial state
			if err := enigma.Reset(); err != nil {
				t.Fatalf("Reset failed: %v", err)
			}

			encrypted, err := enigma.Encrypt(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("Encrypt() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Encrypt() unexpected error: %v", err)
				return
			}

			// Reset enigma to initial state for decryption
			if err := enigma.Reset(); err != nil {
				t.Fatalf("Reset failed: %v", err)
			}

			decrypted, err := enigma.Decrypt(encrypted)
			if err != nil {
				t.Errorf("Decrypt() error: %v", err)
				return
			}

			if decrypted != tt.input {
				t.Errorf("Decrypt(Encrypt(%s)) = %s, want %s", tt.input, decrypted, tt.input)
			}
		})
	}
}

func TestEnigma_Reciprocal(t *testing.T) {
	// Test the fundamental property of Enigma: if A encrypts to B, then B encrypts to A
	alph := createTestAlphabet()

	enigma, err := New(
		WithAlphabet(alph.Runes()),
		WithRandomSettings(Low),
	)
	if err != nil {
		t.Fatalf("Failed to create enigma: %v", err)
	}

	// Test reciprocal property for each character
	for _, char := range alph.Runes() {
		// Reset to same initial state
		if err := enigma.Reset(); err != nil {
			t.Fatalf("Reset failed: %v", err)
		}
		encrypted1, err := enigma.Encrypt(string(char))
		if err != nil {
			t.Errorf("Encrypt(%c) error: %v", char, err)
			continue
		}

		if len(encrypted1) != 1 {
			t.Errorf("Encrypt(%c) returned multiple characters: %s", char, encrypted1)
			continue
		}

		// Reset to same initial state
		if err := enigma.Reset(); err != nil {
			t.Fatalf("Reset failed: %v", err)
		}
		encrypted2, err := enigma.Encrypt(encrypted1)
		if err != nil {
			t.Errorf("Encrypt(%s) error: %v", encrypted1, err)
			continue
		}

		if encrypted2 != string(char) {
			t.Errorf("Reciprocal property failed: %c -> %s -> %s", char, encrypted1, encrypted2)
		}
	}
}

func TestEnigma_RotorStepping(t *testing.T) {
	alph := createTestAlphabet()

	// Create enigma with specific rotor setup to test stepping
	r1 := createTestRotor("R1", "BCDEFA", []rune{'B'}, alph) // Notch at B (position 1)
	r2 := createTestRotor("R2", "CDEFAB", []rune{'C'}, alph) // Notch at C (position 2)
	refl := createTestReflector("UKW", "BADCFE", alph)

	enigma, err := New(
		WithAlphabet(alph.Runes()),
		WithCustomComponents([]rotor.Rotor{r1, r2}, refl, nil),
	)
	if err != nil {
		t.Fatalf("Failed to create enigma: %v", err)
	}

	// Set known initial positions
	if err := enigma.SetRotorPositions([]int{0, 0}); err != nil {
		t.Fatalf("SetRotorPositions failed: %v", err)
	} // Both at position A

	// Encrypt a character and check that rightmost rotor stepped
	if _, err := enigma.Encrypt("A"); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	positions := enigma.GetCurrentRotorPositions()

	if positions[1] != 1 { // Rightmost rotor should have stepped
		t.Errorf("Rightmost rotor should have stepped to position 1, got %d", positions[1])
	}
	if positions[0] != 0 { // Left rotor should not have stepped yet
		t.Errorf("Left rotor should not have stepped, got %d", positions[0])
	}
}

func TestEnigma_Reset(t *testing.T) {
	alph := createTestAlphabet()

	enigma, err := New(
		WithAlphabet(alph.Runes()),
		WithRandomSettings(Low),
	)
	if err != nil {
		t.Fatalf("Failed to create enigma: %v", err)
	}

	// Get initial positions
	initialPositions := enigma.GetCurrentRotorPositions()

	// Encrypt some text to change rotor positions
	if _, err := enigma.Encrypt("ABCDEF"); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Positions should have changed
	currentPositions := enigma.GetCurrentRotorPositions()
	if equalSlices(initialPositions, currentPositions) {
		t.Errorf("Rotor positions should have changed after encryption")
	}

	// Reset and check positions are back to initial
	if err := enigma.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	resetPositions := enigma.GetCurrentRotorPositions()

	if !equalSlices(initialPositions, resetPositions) {
		t.Errorf("Reset() failed: initial=%v, reset=%v", initialPositions, resetPositions)
	}
}

func TestEnigma_GettersAndSetters(t *testing.T) {
	alph := createTestAlphabet()

	enigma, err := New(
		WithAlphabet(alph.Runes()),
		WithRandomSettings(Medium),
	)
	if err != nil {
		t.Fatalf("Failed to create enigma: %v", err)
	}

	// Test getters
	rotorCount := enigma.GetRotorCount()
	if rotorCount <= 0 {
		t.Errorf("GetRotorCount() = %d, want > 0", rotorCount)
	}

	alphabetSize := enigma.GetAlphabetSize()
	if alphabetSize != alph.Size() {
		t.Errorf("GetAlphabetSize() = %d, want %d", alphabetSize, alph.Size())
	}

	plugboardCount := enigma.GetPlugboardPairCount()
	if plugboardCount < 0 {
		t.Errorf("GetPlugboardPairCount() = %d, want >= 0", plugboardCount)
	}

	// Test position setters
	newPositions := make([]int, rotorCount)
	for i := range newPositions {
		newPositions[i] = i % alph.Size()
	}

	err = enigma.SetRotorPositions(newPositions)
	if err != nil {
		t.Errorf("SetRotorPositions() error: %v", err)
	}

	currentPositions := enigma.GetCurrentRotorPositions()
	if !equalSlices(newPositions, currentPositions) {
		t.Errorf("SetRotorPositions() failed: set=%v, got=%v", newPositions, currentPositions)
	}

	// Test invalid position count
	err = enigma.SetRotorPositions([]int{0})
	if err == nil {
		t.Errorf("SetRotorPositions() with wrong count should fail")
	}
}

func TestEnigma_Clone(t *testing.T) {
	alph := createTestAlphabet()

	original, err := New(
		WithAlphabet(alph.Runes()),
		WithRandomSettings(Low),
	)
	if err != nil {
		t.Fatalf("Failed to create enigma: %v", err)
	}

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("Clone() error: %v", err)
	}

	// Test that clone has same properties
	if clone.GetRotorCount() != original.GetRotorCount() {
		t.Errorf("Clone rotor count = %d, want %d", clone.GetRotorCount(), original.GetRotorCount())
	}

	if clone.GetAlphabetSize() != original.GetAlphabetSize() {
		t.Errorf("Clone alphabet size = %d, want %d", clone.GetAlphabetSize(), original.GetAlphabetSize())
	}

	// Test that both produce same output initially
	input := "ABC"

	if err := original.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	originalOutput, err := original.Encrypt(input)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if err := clone.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	cloneOutput, err := clone.Encrypt(input)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if originalOutput != cloneOutput {
		t.Errorf("Clone output differs: original=%s, clone=%s", originalOutput, cloneOutput)
	}

	// Test that modifying clone doesn't affect original
	if _, err := clone.Encrypt("ABC"); err != nil { // This should change clone's rotor positions
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Reset both and check they still produce same output
	if err := original.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	if err := clone.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	originalOutput2, err := original.Encrypt(input)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	cloneOutput2, err := clone.Encrypt(input)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if originalOutput2 != cloneOutput2 {
		t.Errorf("After modification, clone behavior differs: original=%s, clone=%s", originalOutput2, cloneOutput2)
	}
}

func TestEnigma_LongMessage(t *testing.T) {
	alph := createTestAlphabet()

	enigma, err := New(
		WithAlphabet(alph.Runes()),
		WithRandomSettings(Medium),
	)
	if err != nil {
		t.Fatalf("Failed to create enigma: %v", err)
	}

	// Create a longer message
	message := strings.Repeat("ABCDEF", 10)

	encrypted, err := enigma.Encrypt(message)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if len(encrypted) != len(message) {
		t.Errorf("Encrypted length = %d, want %d", len(encrypted), len(message))
	}

	if err := enigma.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	decrypted, err := enigma.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if decrypted != message {
		t.Errorf("Long message round-trip failed")
	}
}

func TestNewEnigmaSimple(t *testing.T) {
	alph := createTestAlphabet()

	enigma, err := NewEnigmaSimple(alph.Runes())
	if err != nil {
		t.Fatalf("NewEnigmaSimple() error: %v", err)
	}

	// Test basic functionality
	plaintext := "ABC"
	encrypted, err := enigma.Encrypt(plaintext)
	if err != nil {
		t.Errorf("Encrypt() error: %v", err)
	}

	if err := enigma.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	decrypted, err := enigma.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Decrypt() error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("NewEnigmaSimple round-trip failed")
	}
}

func TestNewEnigmaClassic(t *testing.T) {
	enigma, err := NewEnigmaClassic()
	if err != nil {
		t.Fatalf("NewEnigmaClassic() error: %v", err)
	}

	// Test that it works with uppercase Latin alphabet
	plaintext := "HELLO"
	encrypted, err := enigma.Encrypt(plaintext)
	if err != nil {
		t.Errorf("Encrypt() error: %v", err)
	}

	if err := enigma.Reset(); err != nil {
		t.Fatalf("Reset failed: %v", err)
	}
	decrypted, err := enigma.Decrypt(encrypted)
	if err != nil {
		t.Errorf("Decrypt() error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("NewEnigmaClassic round-trip failed")
	}

	// Should have 3 rotors (Low security level)
	if enigma.GetRotorCount() != 3 {
		t.Errorf("NewEnigmaClassic() rotor count = %d, want 3", enigma.GetRotorCount())
	}

	// Should have 26 characters (A-Z)
	if enigma.GetAlphabetSize() != 26 {
		t.Errorf("NewEnigmaClassic() alphabet size = %d, want 26", enigma.GetAlphabetSize())
	}
}

func BenchmarkEncrypt(b *testing.B) {
	machine, _ := NewFromSettings(&EnigmaSettings{
		SchemaVersion: 1,
		Alphabet:      []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		RotorSpecs: []rotor.RotorSpec{
			{ID: "I", ForwardMapping: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", Notches: []rune{'Q'}, Position: 0, RingSetting: 0},
			{ID: "II", ForwardMapping: "AJDKSIRUXBLHWTMCQGZNPYFVOE", Notches: []rune{'E'}, Position: 0, RingSetting: 0},
			{ID: "III", ForwardMapping: "BDFHJLCPRTXVZNYEIWGAKMUSQO", Notches: []rune{'V'}, Position: 0, RingSetting: 0},
		},
		ReflectorSpec:         reflector.ReflectorSpec{ID: "B", Mapping: "YRUHQSLDPXNGOKMIEBFZCWVJAT"},
		PlugboardPairs:        map[rune]rune{'A': 'Z', 'Z': 'A'},
		CurrentRotorPositions: []int{0, 0, 0},
	})

	text := "HELLOWORLD"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := machine.Encrypt(text); err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
	}
}

func BenchmarkDecrypt(b *testing.B) {
	machine, _ := NewFromSettings(&EnigmaSettings{
		SchemaVersion: 1,
		Alphabet:      []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
		RotorSpecs: []rotor.RotorSpec{
			{ID: "I", ForwardMapping: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", Notches: []rune{'Q'}, Position: 0, RingSetting: 0},
			{ID: "II", ForwardMapping: "AJDKSIRUXBLHWTMCQGZNPYFVOE", Notches: []rune{'E'}, Position: 0, RingSetting: 0},
			{ID: "III", ForwardMapping: "BDFHJLCPRTXVZNYEIWGAKMUSQO", Notches: []rune{'V'}, Position: 0, RingSetting: 0},
		},
		ReflectorSpec:         reflector.ReflectorSpec{ID: "B", Mapping: "YRUHQSLDPXNGOKMIEBFZCWVJAT"},
		PlugboardPairs:        map[rune]rune{'A': 'Z', 'Z': 'A'},
		CurrentRotorPositions: []int{0, 0, 0},
	})

	text := "HELLOWORLD"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := machine.Decrypt(text); err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
	}
}

// Helper function to compare slices
func equalSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
