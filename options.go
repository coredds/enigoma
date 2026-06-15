// package enigoma provides functional options for configuring Enigma machines.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package enigoma

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/coredds/enigoma/internal/alphabet"
	"github.com/coredds/enigoma/internal/plugboard"
	"github.com/coredds/enigoma/internal/reflector"
	"github.com/coredds/enigoma/internal/rotor"
)

// Option is a functional option for Enigma configuration.
type Option func(*Enigma) error

// SecurityLevel defines pre-set complexity levels.
type SecurityLevel int

const (
	Low SecurityLevel = iota
	Medium
	High
	Extreme
)

// String returns the name of the security level.
func (s SecurityLevel) String() string {
	switch s {
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case Extreme:
		return "Extreme"
	default:
		return "Unknown"
	}
}

// WithAlphabet sets the character set for the Enigma machine.
// All rotors, plugboard, and reflector will be built/validated against this alphabet.
func WithAlphabet(runes []rune) Option {
	return func(e *Enigma) error {
		alph, err := alphabet.New(runes)
		if err != nil {
			return fmt.Errorf("failed to create alphabet: %w", err)
		}
		e.alphabet = alph
		return nil
	}
}

// WithCustomComponents allows detailed manual configuration of components.
func WithCustomComponents(rotors []*rotor.Rotor, refl *reflector.Reflector, pb *plugboard.Plugboard) Option {
	return func(e *Enigma) error {
		if len(rotors) == 0 {
			return fmt.Errorf("at least one rotor must be provided")
		}
		if refl == nil {
			return fmt.Errorf("reflector cannot be nil")
		}

		e.rotors = make([]*rotor.Rotor, len(rotors))
		for i, r := range rotors {
			if r == nil {
				return fmt.Errorf("rotor %d cannot be nil", i)
			}
			e.rotors[i] = r.Clone() // Clone to avoid external modifications
		}
		e.reflector = refl.Clone()

		if pb != nil {
			var err error
			e.plugboard, err = pb.Clone()
			if err != nil {
				return fmt.Errorf("failed to clone plugboard: %w", err)
			}
		}

		return nil
	}
}

// WithRandomSettings configures the Enigma with random components based on a security level.
// This is a convenience for quickly setting up a machine.
func WithRandomSettings(level SecurityLevel) Option {
	return func(e *Enigma) error {
		if e.alphabet == nil {
			return fmt.Errorf("alphabet must be set before applying random settings. Try: enigma.WithAlphabet(enigoma.AlphabetLatinUpper)")
		}

		config := getSecurityConfig(level)

		// Generate random rotors
		rotors := make([]*rotor.Rotor, config.rotorCount)
		for i := 0; i < config.rotorCount; i++ {
			r, err := rotor.RandomRotor(fmt.Sprintf("R%d", i+1), e.alphabet)
			if err != nil {
				return fmt.Errorf("failed to generate random rotor %d: %w", i+1, err)
			}

			// Set random initial position
			maxPos := big.NewInt(int64(e.alphabet.Size()))
			posBig, err := rand.Int(rand.Reader, maxPos)
			if err != nil {
				return fmt.Errorf("failed to generate random position: %w", err)
			}
			r.SetPosition(int(posBig.Int64()))

			// Set random ring setting
			ringBig, err := rand.Int(rand.Reader, maxPos)
			if err != nil {
				return fmt.Errorf("failed to generate random ring setting: %w", err)
			}
			r.SetRingSetting(int(ringBig.Int64()))

			rotors[i] = r
		}

		// Generate random reflector
		refl, err := reflector.RandomReflector("UKW", e.alphabet)
		if err != nil {
			return fmt.Errorf("failed to generate random reflector: %w", err)
		}

		// Generate random plugboard
		pb, err := plugboard.New(e.alphabet)
		if err != nil {
			return fmt.Errorf("failed to create plugboard: %w", err)
		}

		if config.plugboardPairs > 0 {
			// Cap plugboard pairs at the maximum possible for this alphabet
			maxPairs := e.alphabet.Size() / 2
			actualPairs := config.plugboardPairs
			if actualPairs > maxPairs {
				actualPairs = maxPairs
			}

			err = pb.RandomPairs(actualPairs)
			if err != nil {
				return fmt.Errorf("failed to generate random plugboard pairs: %w", err)
			}
		}

		e.rotors = rotors
		e.reflector = refl
		e.plugboard = pb

		return nil
	}
}

// WithRotorConfiguration sets specific rotors with their configurations.
func WithRotorConfiguration(rotorSpecs []rotor.RotorSpec) Option {
	return func(e *Enigma) error {
		if e.alphabet == nil {
			return fmt.Errorf("alphabet must be set before configuring rotors. Try: enigma.WithAlphabet(enigoma.AlphabetLatinUpper)")
		}

		if len(rotorSpecs) == 0 {
			return fmt.Errorf("at least one rotor spec must be provided")
		}

		rotors := make([]*rotor.Rotor, len(rotorSpecs))
		for i, spec := range rotorSpecs {
			r, err := rotor.CreateFromSpec(spec, e.alphabet)
			if err != nil {
				return fmt.Errorf("failed to create rotor %d from spec: %w", i, err)
			}
			rotors[i] = r
		}

		e.rotors = rotors
		return nil
	}
}

// WithReflectorConfiguration sets a specific reflector.
func WithReflectorConfiguration(reflectorSpec reflector.ReflectorSpec) Option {
	return func(e *Enigma) error {
		if e.alphabet == nil {
			return fmt.Errorf("alphabet must be set before configuring reflector. Try: enigma.WithAlphabet(enigoma.AlphabetLatinUpper)")
		}

		refl, err := reflector.CreateFromSpec(reflectorSpec, e.alphabet)
		if err != nil {
			return fmt.Errorf("failed to create reflector from spec: %w", err)
		}

		e.reflector = refl
		return nil
	}
}

// WithPlugboardConfiguration sets specific plugboard pairs.
func WithPlugboardConfiguration(pairs map[rune]rune) Option {
	return func(e *Enigma) error {
		if e.alphabet == nil {
			return fmt.Errorf("alphabet must be set before configuring plugboard. Try: enigma.WithAlphabet(enigoma.AlphabetLatinUpper)")
		}

		pb, err := plugboard.New(e.alphabet)
		if err != nil {
			return fmt.Errorf("failed to create plugboard: %w", err)
		}

		if len(pairs) > 0 {
			err = pb.SetPairsFromMap(pairs)
			if err != nil {
				return fmt.Errorf("failed to set plugboard pairs: %w", err)
			}
		}

		e.plugboard = pb
		return nil
	}
}

// WithRandomRotorPositions sets random initial positions for all rotors.
func WithRandomRotorPositions() Option {
	return func(e *Enigma) error {
		if e.alphabet == nil {
			return fmt.Errorf("alphabet must be set before setting random positions")
		}

		maxPos := big.NewInt(int64(e.alphabet.Size()))
		for _, r := range e.rotors {
			posBig, err := rand.Int(rand.Reader, maxPos)
			if err != nil {
				return fmt.Errorf("failed to generate random position: %w", err)
			}
			r.SetPosition(int(posBig.Int64()))
		}

		return nil
	}
}

// WithRotorPositions sets specific initial positions for rotors.
func WithRotorPositions(positions []int) Option {
	return func(e *Enigma) error {
		if len(positions) != len(e.rotors) {
			return fmt.Errorf("position count (%d) must match rotor count (%d)",
				len(positions), len(e.rotors))
		}

		for i, pos := range positions {
			e.rotors[i].SetPosition(pos)
		}

		return nil
	}
}

// securityConfig holds configuration parameters for different security levels.
type securityConfig struct {
	rotorCount     int
	plugboardPairs int
}

// getSecurityConfig returns configuration for the given security level.
func getSecurityConfig(level SecurityLevel) securityConfig {
	switch level {
	case Low:
		return securityConfig{
			rotorCount:     3,
			plugboardPairs: 2,
		}
	case Medium:
		return securityConfig{
			rotorCount:     5,
			plugboardPairs: 8,
		}
	case High:
		return securityConfig{
			rotorCount:     8,
			plugboardPairs: 15,
		}
	case Extreme:
		return securityConfig{
			rotorCount:     12,
			plugboardPairs: 20,
		}
	default:
		return getSecurityConfig(Low)
	}
}

// NewEnigmaSimple creates a simple Enigma machine with the traditional setup.
// This is a convenience function for the most common use case.
func NewEnigmaSimple(alphabet []rune) (*Enigma, error) {
	return New(
		WithAlphabet(alphabet),
		WithRandomSettings(Medium),
	)
}

// NewEnigmaClassic creates an Enigma machine similar to the historical M3.
// Uses uppercase Latin alphabet and 3 rotors.
func NewEnigmaClassic() (*Enigma, error) {
	return New(
		WithAlphabet(AlphabetLatinUpper),
		WithRandomSettings(Low),
	)
}
