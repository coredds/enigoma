package enigoma

import "testing"

func TestAlphabets_EvenAndUnique(t *testing.T) {
	for name, a := range map[string]string{
		"LatinUpper":     AlphabetLatinUpper,
		"LatinLower":     AlphabetLatinLower,
		"Digits":         AlphabetDigits,
		"AlphaNumeric":   AlphabetAlphaNumeric,
		"ASCIIPrintable": AlphabetASCIIPrintable,
		"Greek":          AlphabetGreek,
		"Cyrillic":       AlphabetCyrillic,
		"Portuguese":     AlphabetPortuguese,
	} {
		if _, err := New(WithAlphabet(a), WithRandomComponents(3, 2)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
