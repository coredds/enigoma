package alphabet

import (
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name      string
		runes     []rune
		wantError bool
	}{
		{
			name:      "valid alphabet",
			runes:     []rune{'A', 'B', 'C'},
			wantError: false,
		},
		{
			name:      "empty alphabet",
			runes:     []rune{},
			wantError: true,
		},
		{
			name:      "duplicate characters",
			runes:     []rune{'A', 'B', 'A'},
			wantError: true,
		},
		{
			name:      "unicode characters",
			runes:     []rune{'Ω', 'α', 'β'},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alphabet, err := New(tt.runes)
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
			if alphabet.Size() != len(tt.runes) {
				t.Errorf("Size() = %d, want %d", alphabet.Size(), len(tt.runes))
			}
		})
	}
}

func TestAlphabet_RuneToIndex(t *testing.T) {
	alphabet, err := New([]rune{'C', 'A', 'B'}) // Preserves original order: C, A, B
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	tests := []struct {
		name      string
		rune      rune
		wantIndex int
		wantError bool
	}{
		{"first character", 'C', 0, false},
		{"middle character", 'A', 1, false},
		{"last character", 'B', 2, false},
		{"not in alphabet", 'D', 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			index, err := alphabet.RuneToIndex(tt.rune)
			if tt.wantError {
				if err == nil {
					t.Errorf("RuneToIndex() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("RuneToIndex() unexpected error: %v", err)
				return
			}
			if index != tt.wantIndex {
				t.Errorf("RuneToIndex() = %d, want %d", index, tt.wantIndex)
			}
		})
	}
}

func TestAlphabet_IndexToRune(t *testing.T) {
	alphabet, err := New([]rune{'C', 'A', 'B'}) // Preserves original order: C, A, B
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	tests := []struct {
		name      string
		index     int
		wantRune  rune
		wantError bool
	}{
		{"first index", 0, 'C', false},
		{"middle index", 1, 'A', false},
		{"last index", 2, 'B', false},
		{"negative index", -1, 0, true},
		{"index too large", 3, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rune, err := alphabet.IndexToRune(tt.index)
			if tt.wantError {
				if err == nil {
					t.Errorf("IndexToRune() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("IndexToRune() unexpected error: %v", err)
				return
			}
			if rune != tt.wantRune {
				t.Errorf("IndexToRune() = %c, want %c", rune, tt.wantRune)
			}
		})
	}
}

func TestAlphabet_Contains(t *testing.T) {
	alphabet, err := New([]rune{'A', 'B', 'C'})
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	tests := []struct {
		name string
		rune rune
		want bool
	}{
		{"contains A", 'A', true},
		{"contains B", 'B', true},
		{"contains C", 'C', true},
		{"does not contain D", 'D', false},
		{"does not contain lowercase", 'a', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := alphabet.Contains(tt.rune); got != tt.want {
				t.Errorf("Contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlphabet_ValidateString(t *testing.T) {
	alphabet, err := New([]rune{'A', 'B', 'C'})
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	tests := []struct {
		name      string
		input     string
		wantError bool
		errorRune rune
	}{
		{"valid string", "ABC", false, 0},
		{"valid repeated", "AAB", false, 0},
		{"invalid character", "ABD", true, 'D'},
		{"empty string", "", false, 0},
		{"first char invalid", "XBC", true, 'X'},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidRune, err := alphabet.ValidateString(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateString() expected error but got none")
				}
				if invalidRune != tt.errorRune {
					t.Errorf("ValidateString() returned rune %c, want %c", invalidRune, tt.errorRune)
				}
				return
			}
			if err != nil {
				t.Errorf("ValidateString() unexpected error: %v", err)
			}
		})
	}
}

func TestAlphabet_StringToIndices(t *testing.T) {
	alphabet, err := New([]rune{'C', 'A', 'B'}) // Preserves original order: C, A, B
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	tests := []struct {
		name    string
		input   string
		want    []int
		wantErr bool
	}{
		{"simple conversion", "CAB", []int{0, 1, 2}, false},
		{"repeated characters", "CCA", []int{0, 0, 1}, false},
		{"empty string", "", []int{}, false},
		{"invalid character", "ABD", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := alphabet.StringToIndices(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("StringToIndices() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("StringToIndices() unexpected error: %v", err)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("StringToIndices() length = %d, want %d", len(got), len(tt.want))
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("StringToIndices()[%d] = %d, want %d", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestAlphabet_IndicesToString(t *testing.T) {
	alphabet, err := New([]rune{'C', 'A', 'B'}) // Preserves original order: C, A, B
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	tests := []struct {
		name    string
		input   []int
		want    string
		wantErr bool
	}{
		{"simple conversion", []int{0, 1, 2}, "CAB", false},
		{"repeated indices", []int{0, 0, 1}, "CCA", false},
		{"empty slice", []int{}, "", false},
		{"invalid index", []int{0, 1, 5}, "", true},
		{"negative index", []int{-1}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := alphabet.IndicesToString(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("IndicesToString() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("IndicesToString() unexpected error: %v", err)
				return
			}
			if got != tt.want {
				t.Errorf("IndicesToString() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestAlphabet_Roundtrip(t *testing.T) {
	alphabet, err := New([]rune{'A', 'B', 'C', 'D', 'E'})
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	testString := "ABCDE"
	indices, err := alphabet.StringToIndices(testString)
	if err != nil {
		t.Fatalf("StringToIndices() error: %v", err)
	}

	result, err := alphabet.IndicesToString(indices)
	if err != nil {
		t.Fatalf("IndicesToString() error: %v", err)
	}

	if result != testString {
		t.Errorf("Roundtrip failed: %s -> %v -> %s", testString, indices, result)
	}
}

// --- AutoDetectFromText tests ---

func TestAutoDetectFromText(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		options     []AutoDetectOption
		wantErr     bool
		wantEvenLen bool
		wantMinSize int
	}{
		{
			name:        "simple latin text",
			text:        "HELLO",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 4, // H, E, L, O (4 unique + possible padding = 4)
		},
		{
			name:    "empty text",
			text:    "",
			wantErr: true,
		},
		{
			name:        "unicode greek text",
			text:        "αβγδ",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 4,
		},
		{
			name:        "text with spaces",
			text:        "A B C",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 4, // A, B, C, space
		},
		{
			name:        "single character gets padded",
			text:        "A",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 2, // A + padding char
		},
		{
			name:        "odd unique chars get padded",
			text:        "ABC",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 4, // A, B, C + padding
		},
		{
			name:        "even unique chars no padding needed",
			text:        "ABCD",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 4,
		},
		{
			name:        "with max size limit",
			text:        "ABCDEFGHIJ",
			options:     []AutoDetectOption{WithMaxSize(4)},
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 2,
		},
		{
			name:        "without padding",
			text:        "ABC",
			options:     []AutoDetectOption{WithoutPadding()},
			wantErr:     false,
			wantEvenLen: false, // padding disabled, 3 unique chars
			wantMinSize: 3,
		},
		{
			name:        "with control characters included",
			text:        "AB\x01\x02",
			options:     []AutoDetectOption{WithControlCharacters()},
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 4, // A, B, \x01, \x02
		},
		{
			name:        "control characters excluded by default",
			text:        "AB\x01\x02",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 2, // only A, B (control chars excluded)
		},
		{
			name:        "text with windows line endings",
			text:        "AB\r\nCD",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 4,
		},
		{
			name:        "mixed unicode text",
			text:        "Hello Мир 世界",
			wantErr:     false,
			wantEvenLen: true,
			wantMinSize: 8,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alph, err := AutoDetectFromText(tt.text, tt.options...)
			if tt.wantErr {
				if err == nil {
					t.Errorf("AutoDetectFromText() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("AutoDetectFromText() unexpected error: %v", err)
				return
			}
			if alph == nil {
				t.Fatal("AutoDetectFromText() returned nil alphabet")
			}
			if tt.wantEvenLen && alph.Size()%2 != 0 {
				t.Errorf("AutoDetectFromText() alphabet size %d is odd, expected even", alph.Size())
			}
			if alph.Size() < tt.wantMinSize {
				t.Errorf("AutoDetectFromText() alphabet size %d < expected min %d", alph.Size(), tt.wantMinSize)
			}
		})
	}
}

func TestAutoDetectFromText_ContainsInputChars(t *testing.T) {
	text := "HELLO WORLD"
	alph, err := AutoDetectFromText(text)
	if err != nil {
		t.Fatalf("AutoDetectFromText() error: %v", err)
	}

	// Every character in the input should be in the detected alphabet
	for _, r := range text {
		if !alph.Contains(r) {
			t.Errorf("Detected alphabet missing input character %c (U+%04X)", r, r)
		}
	}
}

func TestAutoDetectFromText_Deterministic(t *testing.T) {
	text := "HELLO WORLD"
	alph1, err := AutoDetectFromText(text)
	if err != nil {
		t.Fatalf("AutoDetectFromText() first call error: %v", err)
	}
	alph2, err := AutoDetectFromText(text)
	if err != nil {
		t.Fatalf("AutoDetectFromText() second call error: %v", err)
	}

	runes1 := alph1.Runes()
	runes2 := alph2.Runes()
	if len(runes1) != len(runes2) {
		t.Fatalf("Non-deterministic: sizes differ %d vs %d", len(runes1), len(runes2))
	}
	for i := range runes1 {
		if runes1[i] != runes2[i] {
			t.Errorf("Non-deterministic: rune[%d] = %c vs %c", i, runes1[i], runes2[i])
		}
	}
}

func TestAutoDetectFromText_OnlyControlChars(t *testing.T) {
	// Text with only control characters (excluded by default) should fail
	text := "\x01\x02\x03"
	_, err := AutoDetectFromText(text)
	if err == nil {
		t.Error("AutoDetectFromText() with only control chars should return error")
	}
}

func TestPreprocessTextForAutoDetection(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"windows line endings", "Hello\r\nWorld", "Hello\nWorld"},
		{"old mac line endings", "Hello\rWorld", "Hello\nWorld"},
		{"unix line endings unchanged", "Hello\nWorld", "Hello\nWorld"},
		{"trims leading whitespace", "  Hello", "Hello"},
		{"trims trailing whitespace", "Hello  ", "Hello"},
		{"trims both", "  Hello  ", "Hello"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PreprocessTextForAutoDetection(tt.input)
			if result != tt.expected {
				t.Errorf("PreprocessTextForAutoDetection(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsControlCharacter(t *testing.T) {
	tests := []struct {
		name     string
		r        rune
		expected bool
	}{
		{"space is not control", ' ', false},
		{"tab is not control", '\t', false},
		{"newline is not control", '\n', false},
		{"null is control", '\x00', true},
		{"bell is control", '\x07', true},
		{"escape is control", '\x1b', true},
		{"DEL is control", '\x7f', true},
		{"0x80 is control", '\x80', true},
		{"0x9f is control", '\x9f', true},
		{"0xa0 is not control", '\xa0', false},
		{"regular letter is not control", 'A', false},
		{"unicode char is not control", '世', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isControlCharacter(tt.r)
			if result != tt.expected {
				t.Errorf("isControlCharacter(%q) = %v, want %v", tt.r, result, tt.expected)
			}
		})
	}
}

func TestAlphabet_Runes(t *testing.T) {
	originalRunes := []rune{'C', 'A', 'B'}
	alphabet, err := New(originalRunes)
	if err != nil {
		t.Fatalf("Failed to create alphabet: %v", err)
	}

	runes := alphabet.Runes()

	// Should preserve original order
	expected := []rune{'C', 'A', 'B'}
	if len(runes) != len(expected) {
		t.Errorf("Runes() length = %d, want %d", len(runes), len(expected))
	}

	for i, r := range runes {
		if r != expected[i] {
			t.Errorf("Runes()[%d] = %c, want %c", i, r, expected[i])
		}
	}

	// Verify it's a copy (modifying shouldn't affect original)
	runes[0] = 'X'
	newRunes := alphabet.Runes()
	if newRunes[0] == 'X' {
		t.Errorf("Runes() should return a copy, but modification affected original")
	}
}
