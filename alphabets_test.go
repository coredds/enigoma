// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package enigoma

import (
	"testing"
)

func TestAlphabetPortuguese(t *testing.T) {
	// Test alphabet properties
	if len(AlphabetPortuguese) != 88 {
		t.Errorf("AlphabetPortuguese length = %d, want 88", len(AlphabetPortuguese))
	}

	// Test that it's even (required for reflector)
	if len(AlphabetPortuguese)%2 != 0 {
		t.Errorf("AlphabetPortuguese length must be even for reflector compatibility")
	}

	// Test that it contains expected Portuguese characters
	expectedChars := []rune{'ç', 'á', 'ó', 'ã', 'é', 'ê', 'í', 'ú', 'õ', 'ô', 'â', 'à'}
	for _, char := range expectedChars {
		found := false
		for _, alphaChar := range AlphabetPortuguese {
			if char == alphaChar {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AlphabetPortuguese missing expected Portuguese character: %c", char)
		}
	}

	// Test that it contains basic Latin letters
	for c := 'A'; c <= 'Z'; c++ {
		found := false
		for _, alphaChar := range AlphabetPortuguese {
			if c == alphaChar {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AlphabetPortuguese missing uppercase letter: %c", c)
		}
	}

	for c := 'a'; c <= 'z'; c++ {
		found := false
		for _, alphaChar := range AlphabetPortuguese {
			if c == alphaChar {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AlphabetPortuguese missing lowercase letter: %c", c)
		}
	}

	// Test that it contains space and basic punctuation
	expectedPunct := []rune{' ', '.', ',', '!', '?'}
	for _, char := range expectedPunct {
		found := false
		for _, alphaChar := range AlphabetPortuguese {
			if char == alphaChar {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AlphabetPortuguese missing punctuation character: %c", char)
		}
	}
}

func TestPortugueseMessage(t *testing.T) {
	// Test that a typical Portuguese message is fully supported
	message := "Hoje eu fui almoçar na casa da vovó."
	for _, msgChar := range message {
		found := false
		for _, alphaChar := range AlphabetPortuguese {
			if msgChar == alphaChar {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("AlphabetPortuguese does not support character '%c' (U+%04X) from message", msgChar, msgChar)
		}
	}
}

func TestPortugueseVariousMessages(t *testing.T) {
	// Test various Portuguese phrases
	phrases := []string{
		"Olá, como você está?",
		"Bom dia! Está tudo bem?",
		"Vamos à praia amanhã.",
		"Não posso ir à reunião.",
		"São Paulo é uma cidade incrível!",
		"Brasília é a capital do Brasil.",
		"Açúcar, café e pão de açúcar.",
	}

	for _, phrase := range phrases {
		for _, msgChar := range phrase {
			found := false
			for _, alphaChar := range AlphabetPortuguese {
				if msgChar == alphaChar {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("AlphabetPortuguese does not support character '%c' (U+%04X) from phrase: %s", msgChar, msgChar, phrase)
				break // Only report first missing character per phrase
			}
		}
	}
}

func TestAlphabetPortugueseNoDuplicates(t *testing.T) {
	// Test that there are no duplicate characters in the alphabet
	seen := make(map[rune]bool)
	for _, char := range AlphabetPortuguese {
		if seen[char] {
			t.Errorf("AlphabetPortuguese contains duplicate character: %c", char)
		}
		seen[char] = true
	}
}
