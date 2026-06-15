package reflector

import (
	"testing"

	"github.com/coredds/enigoma/internal/alphabet"
)

func createTestAlphabet() *alphabet.Alphabet {
	alph, err := alphabet.New([]rune{'A', 'B', 'C', 'D'})
	if err != nil {
		panic("createTestAlphabet: " + err.Error())
	}
	return alph
}

func createTestAlphabetOdd() *alphabet.Alphabet {
	alph, err := alphabet.New([]rune{'A', 'B', 'C'})
	if err != nil {
		panic("createTestAlphabetOdd: " + err.Error())
	}
	return alph
}

func TestNewReflector(t *testing.T) {
	alph := createTestAlphabet()

	tests := []struct {
		name      string
		id        string
		alphabet  *alphabet.Alphabet
		mapping   string
		wantError bool
	}{
		{
			name:      "valid reflector",
			id:        "B",
			alphabet:  alph,
			mapping:   "BADC", // A<->B, C<->D
			wantError: false,
		},
		{
			name:      "nil alphabet",
			id:        "B",
			alphabet:  nil,
			mapping:   "BADC",
			wantError: true,
		},
		{
			name:      "wrong mapping length",
			id:        "B",
			alphabet:  alph,
			mapping:   "BAD",
			wantError: true,
		},
		{
			name:      "invalid character in mapping",
			id:        "B",
			alphabet:  alph,
			mapping:   "BADX",
			wantError: true,
		},
		{
			name:      "self-mapping",
			id:        "B",
			alphabet:  alph,
			mapping:   "ABDC", // A maps to itself
			wantError: true,
		},
		{
			name:      "duplicate character in mapping",
			id:        "B",
			alphabet:  alph,
			mapping:   "BAAC", // A appears twice
			wantError: true,
		},
		{
			name:      "non-reciprocal mapping",
			id:        "B",
			alphabet:  alph,
			mapping:   "BCDA", // A->B, B->C, C->D, D->A (not reciprocal)
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reflector, err := NewReflector(tt.id, tt.alphabet, tt.mapping)
			if tt.wantError {
				if err == nil {
					t.Errorf("NewReflector() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("NewReflector() unexpected error: %v", err)
				return
			}
			if reflector.ID() != tt.id {
				t.Errorf("ID() = %s, want %s", reflector.ID(), tt.id)
			}
		})
	}
}

func TestRandomReflector(t *testing.T) {
	alph := createTestAlphabet()

	reflector, err := RandomReflector("random", alph)
	if err != nil {
		t.Fatalf("RandomReflector() error: %v", err)
	}

	if reflector.ID() != "random" {
		t.Errorf("ID() = %s, want %s", reflector.ID(), "random")
	}

	// Test that all mappings are reciprocal
	for i := 0; i < alph.Size(); i++ {
		output := reflector.Reflect(i)
		backOutput := reflector.Reflect(output)
		if backOutput != i {
			t.Errorf("Non-reciprocal mapping: %d->%d->%d", i, output, backOutput)
		}
	}

	// Test that no character maps to itself
	for i := 0; i < alph.Size(); i++ {
		output := reflector.Reflect(i)
		if output == i {
			t.Errorf("Self-mapping found: %d->%d", i, output)
		}
	}
}

func TestRandomReflector_OddSize(t *testing.T) {
	alph := createTestAlphabetOdd()

	_, err := RandomReflector("random", alph)
	if err == nil {
		t.Errorf("RandomReflector() with odd-sized alphabet should fail")
	}
}

func TestReflector_Reflect(t *testing.T) {
	alph := createTestAlphabet()
	// Mapping: A<->B, C<->D (BADC)
	reflector, err := NewReflector("test", alph, "BADC")
	if err != nil {
		t.Fatalf("Failed to create reflector: %v", err)
	}

	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"A->B", 0, 1}, // A (0) -> B (1)
		{"B->A", 1, 0}, // B (1) -> A (0)
		{"C->D", 2, 3}, // C (2) -> D (3)
		{"D->C", 3, 2}, // D (3) -> C (2)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := reflector.Reflect(tt.input)
			if output != tt.expected {
				t.Errorf("Reflect(%d) = %d, want %d", tt.input, output, tt.expected)
			}
		})
	}
}

func TestReflector_Reciprocity(t *testing.T) {
	alph := createTestAlphabet()
	reflector, err := NewReflector("test", alph, "BADC")
	if err != nil {
		t.Fatalf("Failed to create reflector: %v", err)
	}

	// Test that all mappings are reciprocal
	for i := 0; i < alph.Size(); i++ {
		output := reflector.Reflect(i)
		backOutput := reflector.Reflect(output)
		if backOutput != i {
			t.Errorf("Non-reciprocal mapping: %d->%d->%d", i, output, backOutput)
		}
	}
}

func TestReflector_NoSelfMapping(t *testing.T) {
	alph := createTestAlphabet()
	reflector, err := NewReflector("test", alph, "BADC")
	if err != nil {
		t.Fatalf("Failed to create reflector: %v", err)
	}

	// Test that no character maps to itself
	for i := 0; i < alph.Size(); i++ {
		output := reflector.Reflect(i)
		if output == i {
			t.Errorf("Self-mapping found: %d->%d", i, output)
		}
	}
}

func TestReflector_InvalidInput(t *testing.T) {
	alph := createTestAlphabet()
	reflector, err := NewReflector("test", alph, "BADC")
	if err != nil {
		t.Fatalf("Failed to create reflector: %v", err)
	}

	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"negative input", -1, -1},
		{"input too large", 5, 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := reflector.Reflect(tt.input)
			if output != tt.expected {
				t.Errorf("Reflect(%d) = %d, want %d", tt.input, output, tt.expected)
			}
		})
	}
}

func TestReflector_Clone(t *testing.T) {
	alph := createTestAlphabet()
	original, err := NewReflector("test", alph, "BADC")
	if err != nil {
		t.Fatalf("Failed to create reflector: %v", err)
	}

	clone := original.Clone()

	// Test that clone has same properties
	if clone.ID() != original.ID() {
		t.Errorf("Clone ID = %s, want %s", clone.ID(), original.ID())
	}

	// Test that clone has same mappings
	for i := 0; i < alph.Size(); i++ {
		if clone.Reflect(i) != original.Reflect(i) {
			t.Errorf("Clone Reflect(%d) = %d, want %d", i, clone.Reflect(i), original.Reflect(i))
		}
	}

	// Test that they are independent objects
	if &original == &clone {
		t.Errorf("Clone should be a different object")
	}
}

func TestCreateFromSpec(t *testing.T) {
	alph := createTestAlphabet()

	spec := ReflectorSpec{
		ID:      "test",
		Mapping: "BADC",
	}

	reflector, err := CreateFromSpec(spec, alph)
	if err != nil {
		t.Fatalf("CreateFromSpec() error: %v", err)
	}

	if reflector.ID() != spec.ID {
		t.Errorf("ID() = %s, want %s", reflector.ID(), spec.ID)
	}

	// Test mapping
	if reflector.Reflect(0) != 1 { // A->B
		t.Errorf("Reflect(0) = %d, want 1", reflector.Reflect(0))
	}
}

func TestToSpec(t *testing.T) {
	alph := createTestAlphabet()

	reflector, err := NewReflector("test", alph, "BADC")
	if err != nil {
		t.Fatalf("Failed to create reflector: %v", err)
	}

	spec, err := ToSpec(reflector, alph)
	if err != nil {
		t.Fatalf("ToSpec() error: %v", err)
	}

	if spec.ID != reflector.ID() {
		t.Errorf("Spec ID = %s, want %s", spec.ID, reflector.ID())
	}
	if spec.Mapping != "BADC" {
		t.Errorf("Spec mapping = %s, want BADC", spec.Mapping)
	}
}

func TestValidateReflectorMapping(t *testing.T) {
	alph := createTestAlphabet()

	tests := []struct {
		name      string
		alphabet  *alphabet.Alphabet
		mapping   string
		wantError bool
	}{
		{
			name:      "valid mapping",
			alphabet:  alph,
			mapping:   "BADC",
			wantError: false,
		},
		{
			name:      "nil alphabet",
			alphabet:  nil,
			mapping:   "BADC",
			wantError: true,
		},
		{
			name:      "wrong length",
			alphabet:  alph,
			mapping:   "BAD",
			wantError: true,
		},
		{
			name:      "invalid character",
			alphabet:  alph,
			mapping:   "BADX",
			wantError: true,
		},
		{
			name:      "self-mapping",
			alphabet:  alph,
			mapping:   "ABDC",
			wantError: true,
		},
		{
			name:      "duplicate character",
			alphabet:  alph,
			mapping:   "BAAC",
			wantError: true,
		},
		{
			name:      "non-reciprocal",
			alphabet:  alph,
			mapping:   "BCDA",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReflectorMapping(tt.alphabet, tt.mapping)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateReflectorMapping() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ValidateReflectorMapping() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestReflectorRoundtrip(t *testing.T) {
	alph := createTestAlphabet()

	// Create original reflector
	original, err := NewReflector("test", alph, "BADC")
	if err != nil {
		t.Fatalf("Failed to create reflector: %v", err)
	}

	// Convert to spec and back
	spec, err := ToSpec(original, alph)
	if err != nil {
		t.Fatalf("ToSpec() error: %v", err)
	}

	recreated, err := CreateFromSpec(spec, alph)
	if err != nil {
		t.Fatalf("CreateFromSpec() error: %v", err)
	}

	// Test that recreated has same behavior
	for i := 0; i < alph.Size(); i++ {
		if recreated.Reflect(i) != original.Reflect(i) {
			t.Errorf("Roundtrip failed: Reflect(%d) = %d, want %d",
				i, recreated.Reflect(i), original.Reflect(i))
		}
	}
}
