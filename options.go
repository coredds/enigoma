// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package enigoma

import "fmt"

// Option configures a Machine under construction. Options are applied in
// order; New validates and builds the machine after all options have run.
type Option func(*config) error

// config collects options before the machine is built. The last source wins
// per component: WithRandomComponents clears rotors, reflector and plugboard
// set earlier; a later WithRotors, WithReflector or WithPlugboard sets that
// component explicitly and random generation fills only what remains unset.
type config struct {
	alphabet  string
	rotors    []RotorSpec
	reflector *ReflectorSpec
	plugboard *string
	positions *string
	rings     *string
	random    *randomCounts
}

type randomCounts struct {
	rotors, plugPairs int
}

// WithAlphabet sets the machine's character set. The default is AlphabetLatinUpper.
func WithAlphabet(chars string) Option {
	return func(c *config) error {
		c.alphabet = chars
		return nil
	}
}

// WithRotors sets the rotors, left to right.
func WithRotors(specs ...RotorSpec) Option {
	return func(c *config) error {
		if len(specs) == 0 {
			return fmt.Errorf("WithRotors: at least one rotor is required")
		}
		c.rotors = append([]RotorSpec(nil), specs...)
		return nil
	}
}

// WithReflector sets the reflector.
func WithReflector(spec ReflectorSpec) Option {
	return func(c *config) error {
		c.reflector = &spec
		return nil
	}
}

// WithPlugboard sets plugboard pairs as space-separated two-letter tokens, e.g. "AB CD".
func WithPlugboard(pairs string) Option {
	return func(c *config) error {
		c.plugboard = &pairs
		return nil
	}
}

// WithPositions sets the starting rotor positions, one alphabet letter per rotor
// (left to right), e.g. "ADU". It applies after rotors are resolved, regardless
// of option order.
func WithPositions(p string) Option {
	return func(c *config) error {
		c.positions = &p
		return nil
	}
}

// WithRings sets the ring settings, one alphabet letter per rotor, e.g. "BUL".
func WithRings(r string) Option {
	return func(c *config) error {
		c.rings = &r
		return nil
	}
}

// WithRandomComponents generates random rotors, reflector and plugboard pairs
// (capped at half the alphabet size), with random positions and rings unless
// WithPositions/WithRings are given. Random components offer no real security.
func WithRandomComponents(rotors, plugPairs int) Option {
	return func(c *config) error {
		if rotors < 1 {
			return fmt.Errorf("WithRandomComponents: need at least one rotor, got %d", rotors)
		}
		if plugPairs < 0 {
			return fmt.Errorf("WithRandomComponents: plug pairs cannot be negative, got %d", plugPairs)
		}
		c.random = &randomCounts{rotors: rotors, plugPairs: plugPairs}
		c.rotors, c.reflector, c.plugboard = nil, nil, nil
		return nil
	}
}
