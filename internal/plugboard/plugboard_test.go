package plugboard

import (
	"testing"

	"github.com/coredds/enigoma/internal/alphabet"
)

func createTestAlphabet() *alphabet.Alphabet {
	alph, err := alphabet.New([]rune{'A', 'B', 'C', 'D', 'E', 'F'})
	if err != nil {
		panic("createTestAlphabet: " + err.Error())
	}
	return alph
}

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		alphabet  *alphabet.Alphabet
		wantError bool
	}{
		{
			name:      "valid alphabet",
			alphabet:  createTestAlphabet(),
			wantError: false,
		},
		{
			name:      "nil alphabet",
			alphabet:  nil,
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb, err := New(tt.alphabet)
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
			if pb.PairCount() != 0 {
				t.Errorf("New plugboard should have 0 pairs, got %d", pb.PairCount())
			}
		})
	}
}

func TestPlugboard_AddPair(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	tests := []struct {
		name      string
		r1        rune
		r2        rune
		wantError bool
	}{
		{
			name:      "valid pair",
			r1:        'A',
			r2:        'B',
			wantError: false,
		},
		{
			name:      "self pair",
			r1:        'C',
			r2:        'C',
			wantError: true,
		},
		{
			name:      "invalid character",
			r1:        'X',
			r2:        'D',
			wantError: true,
		},
		{
			name:      "already paired character",
			r1:        'A', // A is already paired with B
			r2:        'C',
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pb.AddPair(tt.r1, tt.r2)
			if tt.wantError {
				if err == nil {
					t.Errorf("AddPair() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("AddPair() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPlugboard_RemovePair(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add a pair first
	err = pb.AddPair('A', 'B')
	if err != nil {
		t.Fatalf("Failed to add pair: %v", err)
	}

	tests := []struct {
		name      string
		r         rune
		wantError bool
	}{
		{
			name:      "remove existing pair",
			r:         'A',
			wantError: false,
		},
		{
			name:      "remove non-paired character",
			r:         'C',
			wantError: true,
		},
		{
			name:      "invalid character",
			r:         'X',
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pb.RemovePair(tt.r)
			if tt.wantError {
				if err == nil {
					t.Errorf("RemovePair() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("RemovePair() unexpected error: %v", err)
				}
			}
		})
	}

	// After removing A, both A and B should be unpaired
	if pb.PairCount() != 0 {
		t.Errorf("After removing pair, count should be 0, got %d", pb.PairCount())
	}
}

func TestPlugboard_Clear(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add some pairs
	if err := pb.AddPair('A', 'B'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}
	if err := pb.AddPair('C', 'D'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}

	if pb.PairCount() != 2 {
		t.Errorf("Expected 2 pairs before clear, got %d", pb.PairCount())
	}

	pb.Clear()

	if pb.PairCount() != 0 {
		t.Errorf("Expected 0 pairs after clear, got %d", pb.PairCount())
	}
}

func TestPlugboard_Process(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add pairs: A<->B, C<->D
	if err := pb.AddPair('A', 'B'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}
	if err := pb.AddPair('C', 'D'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}

	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{"A->B", 0, 1},        // A (0) -> B (1)
		{"B->A", 1, 0},        // B (1) -> A (0)
		{"C->D", 2, 3},        // C (2) -> D (3)
		{"D->C", 3, 2},        // D (3) -> C (2)
		{"E unchanged", 4, 4}, // E (4) unchanged
		{"F unchanged", 5, 5}, // F (5) unchanged
		{"invalid negative", -1, -1},
		{"invalid too large", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := pb.Process(tt.input)
			if output != tt.expected {
				t.Errorf("Process(%d) = %d, want %d", tt.input, output, tt.expected)
			}
		})
	}
}

func TestPlugboard_ProcessRune(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add pair A<->B
	if err := pb.AddPair('A', 'B'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}

	tests := []struct {
		name      string
		input     rune
		expected  rune
		wantError bool
	}{
		{"A->B", 'A', 'B', false},
		{"B->A", 'B', 'A', false},
		{"C unchanged", 'C', 'C', false},
		{"invalid character", 'X', 'X', true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := pb.ProcessRune(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("ProcessRune() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("ProcessRune() unexpected error: %v", err)
				}
				if output != tt.expected {
					t.Errorf("ProcessRune(%c) = %c, want %c", tt.input, output, tt.expected)
				}
			}
		})
	}
}

func TestPlugboard_RandomPairs(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	tests := []struct {
		name      string
		n         int
		wantError bool
	}{
		{"zero pairs", 0, false},
		{"one pair", 1, false},
		{"two pairs", 2, false},
		{"max pairs", 3, false}, // 6 characters / 2 = 3 max pairs
		{"too many pairs", 4, true},
		{"negative pairs", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pb.RandomPairs(tt.n)
			if tt.wantError {
				if err == nil {
					t.Errorf("RandomPairs() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("RandomPairs() unexpected error: %v", err)
				return
			}

			if pb.PairCount() != tt.n {
				t.Errorf("RandomPairs(%d) resulted in %d pairs", tt.n, pb.PairCount())
			}

			// Verify all pairs are reciprocal: Process(Process(i)) == i
			alph := createTestAlphabet()
			for i := 0; i < alph.Size(); i++ {
				out := pb.Process(i)
				back := pb.Process(out)
				if back != i {
					t.Errorf("RandomPairs(%d): non-reciprocal mapping %d->%d->%d", tt.n, i, out, back)
				}
			}

			// Verify no character maps to itself among the paired characters
			if tt.n > 0 {
				pairedCount := 0
				for i := 0; i < alph.Size(); i++ {
					if pb.Process(i) != i {
						pairedCount++
					}
				}
				if pairedCount != tt.n*2 {
					t.Errorf("RandomPairs(%d): expected %d paired characters, got %d", tt.n, tt.n*2, pairedCount)
				}
			}
		})
	}
}

func TestPlugboard_GetPairs(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add pairs
	if err := pb.AddPair('A', 'B'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}
	if err := pb.AddPair('C', 'D'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}

	pairs, err := pb.GetPairs()
	if err != nil {
		t.Fatalf("GetPairs() error: %v", err)
	}

	if len(pairs) != 2 {
		t.Errorf("GetPairs() returned %d pairs, want 2", len(pairs))
	}

	// Check that we have the expected pairs (order doesn't matter)
	expectedPairs := map[[2]rune]bool{
		{'A', 'B'}: true,
		{'B', 'A'}: true,
		{'C', 'D'}: true,
		{'D', 'C'}: true,
	}

	for _, pair := range pairs {
		if !expectedPairs[pair] {
			t.Errorf("Unexpected pair: %c<->%c", pair[0], pair[1])
		}
	}
}

func TestPlugboard_GetPairsMap(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add pairs
	if err := pb.AddPair('A', 'B'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}
	if err := pb.AddPair('C', 'D'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}

	pairsMap, err := pb.GetPairsMap()
	if err != nil {
		t.Fatalf("GetPairsMap() error: %v", err)
	}

	expected := map[rune]rune{
		'A': 'B',
		'B': 'A',
		'C': 'D',
		'D': 'C',
	}

	if len(pairsMap) != len(expected) {
		t.Errorf("GetPairsMap() returned %d entries, want %d", len(pairsMap), len(expected))
	}

	for k, v := range expected {
		if pairsMap[k] != v {
			t.Errorf("GetPairsMap()[%c] = %c, want %c", k, pairsMap[k], v)
		}
	}
}

func TestPlugboard_SetPairsFromMap(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	tests := []struct {
		name      string
		pairs     map[rune]rune
		wantError bool
	}{
		{
			name: "valid pairs",
			pairs: map[rune]rune{
				'A': 'B',
				'B': 'A',
				'C': 'D',
				'D': 'C',
			},
			wantError: false,
		},
		{
			name: "non-reciprocal pairs",
			pairs: map[rune]rune{
				'A': 'B',
				'B': 'C', // B should map to A
			},
			wantError: true,
		},
		{
			name:      "empty pairs",
			pairs:     map[rune]rune{},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := pb.SetPairsFromMap(tt.pairs)
			if tt.wantError {
				if err == nil {
					t.Errorf("SetPairsFromMap() expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("SetPairsFromMap() unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPlugboard_Clone(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add pairs
	if err := pb.AddPair('A', 'B'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}
	if err := pb.AddPair('C', 'D'); err != nil {
		t.Fatalf("AddPair failed: %v", err)
	}

	clone, err := pb.Clone()
	if err != nil {
		t.Fatalf("Clone() error: %v", err)
	}

	// Test that clone has same pair count
	if clone.PairCount() != pb.PairCount() {
		t.Errorf("Clone pair count = %d, want %d", clone.PairCount(), pb.PairCount())
	}

	// Test that clone has same mappings
	alph := createTestAlphabet()
	for i := 0; i < alph.Size(); i++ {
		if clone.Process(i) != pb.Process(i) {
			t.Errorf("Clone Process(%d) = %d, want %d", i, clone.Process(i), pb.Process(i))
		}
	}

	// Test that modifying clone doesn't affect original
	if err := clone.AddPair('E', 'F'); err != nil {
		t.Fatalf("AddPair on clone failed: %v", err)
	}
	if pb.PairCount() == clone.PairCount() {
		t.Errorf("Modifying clone affected original")
	}
}

func TestPlugboard_Reciprocity(t *testing.T) {
	pb, err := New(createTestAlphabet())
	if err != nil {
		t.Fatalf("Failed to create plugboard: %v", err)
	}

	// Add some random pairs
	err = pb.RandomPairs(2)
	if err != nil {
		t.Fatalf("RandomPairs() error: %v", err)
	}

	// Test that all mappings are reciprocal
	alph := createTestAlphabet()
	for i := 0; i < alph.Size(); i++ {
		output := pb.Process(i)
		backOutput := pb.Process(output)
		if backOutput != i {
			t.Errorf("Non-reciprocal mapping: %d->%d->%d", i, output, backOutput)
		}
	}
}
