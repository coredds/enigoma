package rotor

import (
	"testing"

	"github.com/coredds/enigoma/internal/alphabet"
)

func createTestAlphabet() *alphabet.Alphabet {
	alph, err := alphabet.New([]rune{'A', 'B', 'C', 'D', 'E'})
	if err != nil {
		panic("createTestAlphabet: " + err.Error())
	}
	return alph
}

func TestNewRotor(t *testing.T) {
	alph := createTestAlphabet()

	tests := []struct {
		name           string
		id             string
		alphabet       *alphabet.Alphabet
		forwardMapping string
		notches        []rune
		wantError      bool
	}{
		{
			name:           "valid rotor",
			id:             "I",
			alphabet:       alph,
			forwardMapping: "EABDC",
			notches:        []rune{'B'},
			wantError:      false,
		},
		{
			name:           "nil alphabet",
			id:             "I",
			alphabet:       nil,
			forwardMapping: "EABDC",
			notches:        []rune{'B'},
			wantError:      true,
		},
		{
			name:           "wrong mapping length",
			id:             "I",
			alphabet:       alph,
			forwardMapping: "EAB",
			notches:        []rune{'B'},
			wantError:      true,
		},
		{
			name:           "invalid character in mapping",
			id:             "I",
			alphabet:       alph,
			forwardMapping: "EABDX",
			notches:        []rune{'B'},
			wantError:      true,
		},
		{
			name:           "duplicate character in mapping",
			id:             "I",
			alphabet:       alph,
			forwardMapping: "EABDA",
			notches:        []rune{'B'},
			wantError:      true,
		},
		{
			name:           "invalid notch character",
			id:             "I",
			alphabet:       alph,
			forwardMapping: "EABDC",
			notches:        []rune{'X'},
			wantError:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rotor, err := NewRotor(tt.id, tt.alphabet, tt.forwardMapping, tt.notches)
			if tt.wantError {
				if err == nil {
					t.Errorf("NewRotor() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("NewRotor() unexpected error: %v", err)
				return
			}
			if rotor.ID() != tt.id {
				t.Errorf("ID() = %s, want %s", rotor.ID(), tt.id)
			}
		})
	}
}

func TestRandomRotor(t *testing.T) {
	alph := createTestAlphabet()

	rotor, err := RandomRotor("random", alph)
	if err != nil {
		t.Fatalf("RandomRotor() error: %v", err)
	}

	if rotor.ID() != "random" {
		t.Errorf("ID() = %s, want %s", rotor.ID(), "random")
	}

	// Test that the mapping is a valid permutation
	used := make([]bool, alph.Size())
	for i := 0; i < alph.Size(); i++ {
		output := rotor.Forward(i)
		if output < 0 || output >= alph.Size() {
			t.Errorf("Forward(%d) = %d, out of bounds", i, output)
		}
		if used[output] {
			t.Errorf("Forward mapping has duplicate output: %d", output)
		}
		used[output] = true
	}
}

func TestBasicRotor_Forward(t *testing.T) {
	alph := createTestAlphabet()
	// Mapping: A->E, B->A, C->B, D->D, E->C
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"A->E", 0, 4}, // A (0) -> E (4)
		{"B->A", 1, 0}, // B (1) -> A (0)
		{"C->B", 2, 1}, // C (2) -> B (1)
		{"D->D", 3, 3}, // D (3) -> D (3)
		{"E->C", 4, 2}, // E (4) -> C (2)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := rotor.Forward(tt.input)
			if output != tt.expected {
				t.Errorf("Forward(%d) = %d, want %d", tt.input, output, tt.expected)
			}
		})
	}
}

func TestBasicRotor_Backward(t *testing.T) {
	alph := createTestAlphabet()
	// Mapping: A->E, B->A, C->B, D->D, E->C
	// Reverse: A<-B, B<-C, C<-E, D<-D, E<-A
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"A<-B", 0, 1}, // A (0) <- B (1)
		{"B<-C", 1, 2}, // B (1) <- C (2)
		{"C<-E", 2, 4}, // C (2) <- E (4)
		{"D<-D", 3, 3}, // D (3) <- D (3)
		{"E<-A", 4, 0}, // E (4) <- A (0)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := rotor.Backward(tt.input)
			if output != tt.expected {
				t.Errorf("Backward(%d) = %d, want %d", tt.input, output, tt.expected)
			}
		})
	}
}

func TestBasicRotor_ForwardBackwardRoundtrip(t *testing.T) {
	alph := createTestAlphabet()
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	for i := 0; i < alph.Size(); i++ {
		forward := rotor.Forward(i)
		backward := rotor.Backward(forward)
		if backward != i {
			t.Errorf("Roundtrip failed for %d: Forward->%d, Backward->%d", i, forward, backward)
		}
	}
}

func TestBasicRotor_IsAtNotch(t *testing.T) {
	alph := createTestAlphabet()
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B', 'D'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	tests := []struct {
		position int
		expected bool
	}{
		{0, false}, // A
		{1, true},  // B (notch)
		{2, false}, // C
		{3, true},  // D (notch)
		{4, false}, // E
	}

	for _, tt := range tests {
		rotor.SetPosition(tt.position)
		if rotor.IsAtNotch() != tt.expected {
			t.Errorf("IsAtNotch() at position %d = %v, want %v", tt.position, rotor.IsAtNotch(), tt.expected)
		}
	}
}

func TestBasicRotor_Step(t *testing.T) {
	alph := createTestAlphabet()
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	// Test normal stepping
	for i := 0; i < alph.Size(); i++ {
		expectedPos := i
		if rotor.GetPosition() != expectedPos {
			t.Errorf("Position = %d, want %d", rotor.GetPosition(), expectedPos)
		}
		rotor.Step()
	}

	// After full rotation, should be back to 0
	if rotor.GetPosition() != 0 {
		t.Errorf("After full rotation, position = %d, want 0", rotor.GetPosition())
	}
}

func TestBasicRotor_SetPosition(t *testing.T) {
	alph := createTestAlphabet()
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	tests := []struct {
		input    int
		expected int
	}{
		{0, 0},
		{3, 3},
		{5, 0},  // Wraps around
		{-1, 4}, // Negative wraps
		{7, 2},  // Multiple wraps
	}

	for _, tt := range tests {
		rotor.SetPosition(tt.input)
		if rotor.GetPosition() != tt.expected {
			t.Errorf("SetPosition(%d), GetPosition() = %d, want %d", tt.input, rotor.GetPosition(), tt.expected)
		}
	}
}

func TestBasicRotor_SetRingSetting(t *testing.T) {
	alph := createTestAlphabet()
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	tests := []struct {
		input    int
		expected int
	}{
		{0, 0},
		{3, 3},
		{5, 0},  // Wraps around
		{-1, 4}, // Negative wraps
		{7, 2},  // Multiple wraps
	}

	for _, tt := range tests {
		rotor.SetRingSetting(tt.input)
		if rotor.GetRingSetting() != tt.expected {
			t.Errorf("SetRingSetting(%d), GetRingSetting() = %d, want %d", tt.input, rotor.GetRingSetting(), tt.expected)
		}
	}
}

func TestBasicRotor_Clone(t *testing.T) {
	alph := createTestAlphabet()
	original, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	original.SetPosition(2)
	original.SetRingSetting(1)

	clone := original.Clone()

	// Test that clone has same properties
	if clone.ID() != original.ID() {
		t.Errorf("Clone ID = %s, want %s", clone.ID(), original.ID())
	}
	if clone.GetPosition() != original.GetPosition() {
		t.Errorf("Clone position = %d, want %d", clone.GetPosition(), original.GetPosition())
	}
	if clone.GetRingSetting() != original.GetRingSetting() {
		t.Errorf("Clone ring setting = %d, want %d", clone.GetRingSetting(), original.GetRingSetting())
	}

	// Test that modifying clone doesn't affect original
	clone.SetPosition(4)
	if original.GetPosition() == 4 {
		t.Errorf("Modifying clone affected original")
	}

	// Test that forward mapping is the same when both are at the same position
	clone.SetPosition(original.GetPosition()) // Reset clone to same position as original
	for i := 0; i < alph.Size(); i++ {
		if clone.Forward(i) != original.Forward(i) {
			t.Errorf("Clone Forward(%d) = %d, want %d", i, clone.Forward(i), original.Forward(i))
		}
	}
}

func TestRotorPositionEffect(t *testing.T) {
	alph := createTestAlphabet()
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	// Test that position affects the mapping
	// Try multiple inputs since some may have coincidental same outputs
	foundDifference := false
	for inputIdx := 0; inputIdx < alph.Size(); inputIdx++ {
		rotor.SetPosition(0)
		baseOutput := rotor.Forward(inputIdx)

		rotor.SetPosition(1)
		positionOutput := rotor.Forward(inputIdx)

		if baseOutput != positionOutput {
			foundDifference = true
			break
		}
	}

	if !foundDifference {
		t.Errorf("Position should affect Forward mapping for at least some inputs")
	}
}

func TestRotorRingSettingEffect(t *testing.T) {
	alph := createTestAlphabet()
	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	// Test that ring setting affects the mapping
	inputIdx := 0 // A

	baseOutput := rotor.Forward(inputIdx)

	rotor.SetRingSetting(1)
	ringOutput := rotor.Forward(inputIdx)

	if baseOutput == ringOutput {
		t.Errorf("Ring setting should affect Forward mapping")
	}
}

func TestCreateFromSpec(t *testing.T) {
	alph := createTestAlphabet()

	spec := RotorSpec{
		ID:             "test",
		ForwardMapping: "EABDC",
		Notches:        []rune{'B'},
		Position:       2,
		RingSetting:    1,
	}

	rotor, err := CreateFromSpec(spec, alph)
	if err != nil {
		t.Fatalf("CreateFromSpec() error: %v", err)
	}

	if rotor.ID() != spec.ID {
		t.Errorf("ID() = %s, want %s", rotor.ID(), spec.ID)
	}
	if rotor.GetPosition() != spec.Position {
		t.Errorf("GetPosition() = %d, want %d", rotor.GetPosition(), spec.Position)
	}
	if rotor.GetRingSetting() != spec.RingSetting {
		t.Errorf("GetRingSetting() = %d, want %d", rotor.GetRingSetting(), spec.RingSetting)
	}
}

func TestToSpec(t *testing.T) {
	alph := createTestAlphabet()

	rotor, err := NewRotor("test", alph, "EABDC", []rune{'B'})
	if err != nil {
		t.Fatalf("Failed to create rotor: %v", err)
	}

	rotor.SetPosition(2)
	rotor.SetRingSetting(1)

	spec, err := ToSpec(rotor, alph)
	if err != nil {
		t.Fatalf("ToSpec() error: %v", err)
	}

	if spec.ID != rotor.ID() {
		t.Errorf("Spec ID = %s, want %s", spec.ID, rotor.ID())
	}
	if spec.Position != rotor.GetPosition() {
		t.Errorf("Spec position = %d, want %d", spec.Position, rotor.GetPosition())
	}
	if spec.RingSetting != rotor.GetRingSetting() {
		t.Errorf("Spec ring setting = %d, want %d", spec.RingSetting, rotor.GetRingSetting())
	}
	if spec.ForwardMapping != "EABDC" {
		t.Errorf("Spec forward mapping = %s, want EABDC", spec.ForwardMapping)
	}
	if len(spec.Notches) != 1 || spec.Notches[0] != 'B' {
		t.Errorf("Spec notches = %v, want [B]", spec.Notches)
	}
}
