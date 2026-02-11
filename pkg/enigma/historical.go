// Package enigma provides historical Enigma machine variants.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package enigma

import (
	"github.com/coredds/enigoma/internal/reflector"
	"github.com/coredds/enigoma/internal/rotor"
)

// Historical rotor wirings from actual Enigma machines
const (
	// Enigma I, M3, M4 rotors
	RotorI    = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
	RotorII   = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
	RotorIII  = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
	RotorIV   = "ESOVPZJAYQUIRHXLNFTGKDCMWB"
	RotorV    = "VZBRGITYUPSDNHLXAWMJQOFECK"
	RotorVI   = "JPGVOUMFYQBENHZRDKASXLICTW"
	RotorVII  = "NZJHGRCXMYSWBOUFAIVLPEKQDT"
	RotorVIII = "FKQHTLXOCBJSPDZRAMEWNIUYGV"

	// M4 Naval Enigma additional thin rotors (used with thin reflectors)
	RotorBeta  = "LEYJVCNIXWPBQMDRTAKZGFUHOS"
	RotorGamma = "FSOKANUERHMBTIYCWLQPZXVGJD"
)

// Historical reflector wirings
const (
	// Standard reflectors
	ReflectorA = "EJMZALYXVBWFCRQUONTSPIKHGD"
	ReflectorB = "YRUHQSLDPXNGOKMIEBFZCWVJAT"
	ReflectorC = "FVPJIAOYEDRZXWGCTKUQSBNMHL"

	// M4 Naval Enigma thin reflectors (used with thin rotors)
	ReflectorBThin = "ENKQAUYWJICOPBLMDXZVFTHRGS"
	ReflectorCThin = "RDOBJNTKVEHMLFCWZAXGYIPSUQ"
)

// Historical notch positions (when stepping occurs)
var (
	NotchI    = []rune{'Q'}      // Notch at position Q
	NotchII   = []rune{'E'}      // Notch at position E
	NotchIII  = []rune{'V'}      // Notch at position V
	NotchIV   = []rune{'J'}      // Notch at position J
	NotchV    = []rune{'Z'}      // Notch at position Z
	NotchVI   = []rune{'Z', 'M'} // Notches at positions Z and M
	NotchVII  = []rune{'Z', 'M'} // Notches at positions Z and M
	NotchVIII = []rune{'Z', 'M'} // Notches at positions Z and M
)

// NewEnigmaM3 creates a historically accurate Enigma M3 machine.
// This was the standard Army and Navy Enigma with rotors I, II, and III,
// and reflector B.
func NewEnigmaM3() (*Enigma, error) {
	// Define the alphabet (uppercase Latin)
	alphabet := []rune{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	}

	// Define the rotor specifications
	rotorSpecs := []rotor.RotorSpec{
		{
			ID:             "I",
			ForwardMapping: RotorI,
			Notches:        NotchI,
			Position:       0,
			RingSetting:    0,
		},
		{
			ID:             "II",
			ForwardMapping: RotorII,
			Notches:        NotchII,
			Position:       0,
			RingSetting:    0,
		},
		{
			ID:             "III",
			ForwardMapping: RotorIII,
			Notches:        NotchIII,
			Position:       0,
			RingSetting:    0,
		},
	}

	// Define the reflector specification
	reflectorSpec := reflector.ReflectorSpec{
		ID:      "B",
		Mapping: ReflectorB,
	}

	// Create the machine
	return New(
		WithAlphabet(alphabet),
		WithRotorConfiguration(rotorSpecs),
		WithReflectorConfiguration(reflectorSpec),
	)
}

// NewEnigmaM4 creates a historically accurate Enigma M4 Naval machine.
// This was used by the German Navy (Kriegsmarine) with four rotors:
// a thin rotor (Beta or Gamma) followed by three regular rotors,
// and a thin reflector (B Thin or C Thin).
func NewEnigmaM4() (*Enigma, error) {
	// Define the alphabet (uppercase Latin)
	alphabet := []rune{
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
		'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	}

	// Define the rotor specifications
	rotorSpecs := []rotor.RotorSpec{
		{
			ID:             "Beta",
			ForwardMapping: RotorBeta,
			Notches:        []rune{}, // The thin rotor doesn't step
			Position:       0,
			RingSetting:    0,
		},
		{
			ID:             "I",
			ForwardMapping: RotorI,
			Notches:        NotchI,
			Position:       0,
			RingSetting:    0,
		},
		{
			ID:             "II",
			ForwardMapping: RotorII,
			Notches:        NotchII,
			Position:       0,
			RingSetting:    0,
		},
		{
			ID:             "III",
			ForwardMapping: RotorIII,
			Notches:        NotchIII,
			Position:       0,
			RingSetting:    0,
		},
	}

	// Define the reflector specification
	reflectorSpec := reflector.ReflectorSpec{
		ID:      "B-Thin",
		Mapping: ReflectorBThin,
	}

	// Create the machine
	return New(
		WithAlphabet(alphabet),
		WithRotorConfiguration(rotorSpecs),
		WithReflectorConfiguration(reflectorSpec),
	)
}

// Note: ReflectorSpec.Mapping expects a string, not a map.
// The reflector implementation handles converting the string to the appropriate mapping.
