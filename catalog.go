// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package enigoma

import "fmt"

var historicalRotors = map[string]RotorSpec{
	"I":     {Name: "I", Wiring: "EKMFLGDQVZNTOWYHXUSPAIBRCJ", Notches: "Q"},
	"II":    {Name: "II", Wiring: "AJDKSIRUXBLHWTMCQGZNPYFVOE", Notches: "E"},
	"III":   {Name: "III", Wiring: "BDFHJLCPRTXVZNYEIWGAKMUSQO", Notches: "V"},
	"IV":    {Name: "IV", Wiring: "ESOVPZJAYQUIRHXLNFTGKDCMWB", Notches: "J"},
	"V":     {Name: "V", Wiring: "VZBRGITYUPSDNHLXAWMJQOFECK", Notches: "Z"},
	"VI":    {Name: "VI", Wiring: "JPGVOUMFYQBENHZRDKASXLICTW", Notches: "ZM"},
	"VII":   {Name: "VII", Wiring: "NZJHGRCXMYSWBOUFAIVLPEKQDT", Notches: "ZM"},
	"VIII":  {Name: "VIII", Wiring: "FKQHTLXOCBJSPDZRAMEWNIUYGV", Notches: "ZM"},
	"Beta":  {Name: "Beta", Wiring: "LEYJVCNIXWPBQMDRTAKZGFUHOS", Fixed: true},
	"Gamma": {Name: "Gamma", Wiring: "FSOKANUERHMBTIYCWLQPZXVGJD", Fixed: true},
}

var historicalReflectors = map[string]ReflectorSpec{
	"A":      {Name: "A", Wiring: "EJMZALYXVBWFCRQUONTSPIKHGD"},
	"B":      {Name: "B", Wiring: "YRUHQSLDPXNGOKMIEBFZCWVJAT"},
	"C":      {Name: "C", Wiring: "FVPJIAOYEDRZXWGCTKUQSBNMHL"},
	"B-Thin": {Name: "B-Thin", Wiring: "ENKQAUYWJICOPBLMDXZVFTHRGS"},
	"C-Thin": {Name: "C-Thin", Wiring: "RDOBJNTKVEHMLFCWZAXGYIPSUQ"},
}

// HistoricalRotor returns the wiring and notches of a historical Enigma rotor:
// I–VIII, or the M4 thin rotors Beta and Gamma (which are Fixed).
func HistoricalRotor(name string) (RotorSpec, error) {
	r, ok := historicalRotors[name]
	if !ok {
		return RotorSpec{}, fmt.Errorf("unknown historical rotor %q (want I-VIII, Beta or Gamma)", name)
	}
	return r, nil
}

// HistoricalReflector returns a historical Enigma reflector: A, B, C, B-Thin or C-Thin.
func HistoricalReflector(name string) (ReflectorSpec, error) {
	r, ok := historicalReflectors[name]
	if !ok {
		return ReflectorSpec{}, fmt.Errorf("unknown historical reflector %q (want A, B, C, B-Thin or C-Thin)", name)
	}
	return r, nil
}
