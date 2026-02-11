// Package enigma provides the main Enigma machine implementation.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package enigma

import (
	"fmt"

	"github.com/coredds/enigoma/internal/alphabet"
	"github.com/coredds/enigoma/internal/plugboard"
	"github.com/coredds/enigoma/internal/reflector"
	"github.com/coredds/enigoma/internal/rotor"
)

// Enigma represents a configurable Enigma machine.
type Enigma struct {
	alphabet        *alphabet.Alphabet
	rotors          []rotor.Rotor
	reflector       reflector.Reflector
	plugboard       *plugboard.Plugboard
	initialSettings EnigmaSettings // Store initial settings for reset
}

// New creates a new Enigma machine with the given options.
func New(opts ...Option) (*Enigma, error) {
	e := &Enigma{}

	// Apply options
	for _, opt := range opts {
		if err := opt(e); err != nil {
			return nil, fmt.Errorf("failed to apply option: %w", err)
		}
	}

	// Validate that required components are set
	if e.alphabet == nil {
		return nil, fmt.Errorf("alphabet must be set")
	}
	if len(e.rotors) == 0 {
		return nil, fmt.Errorf("at least one rotor must be configured")
	}
	if e.reflector == nil {
		return nil, fmt.Errorf("reflector must be set")
	}
	if e.plugboard == nil {
		// Create empty plugboard if none provided
		pb, err := plugboard.New(e.alphabet)
		if err != nil {
			return nil, fmt.Errorf("failed to create plugboard: %w", err)
		}
		e.plugboard = pb
	}

	// Store initial settings for reset functionality
	settings, err := e.GetSettings()
	if err != nil {
		return nil, fmt.Errorf("failed to capture initial settings: %w", err)
	}
	e.initialSettings = *settings

	return e, nil
}

// Encrypt encrypts the given plaintext using the current machine state.
func (e *Enigma) Encrypt(plaintext string) (string, error) {
	return e.processText(plaintext)
}

// Decrypt decrypts the given ciphertext using the current machine state.
// Due to the reciprocal nature of Enigma, this is identical to Encrypt.
func (e *Enigma) Decrypt(ciphertext string) (string, error) {
	return e.processText(ciphertext)
}

// processText performs the core Enigma encryption/decryption logic.
func (e *Enigma) processText(text string) (string, error) {
	if text == "" {
		return "", nil
	}

	// Validate input text
	if invalidRune, err := e.alphabet.ValidateString(text); err != nil {
		return "", fmt.Errorf("invalid character %c in input text: %w", invalidRune, err)
	}

	// Convert text to indices
	indices, err := e.alphabet.StringToIndices(text)
	if err != nil {
		return "", fmt.Errorf("failed to convert text to indices: %w", err)
	}

	// Process each character
	outputIndices := make([]int, len(indices))
	for i, inputIdx := range indices {
		outputIndices[i] = e.processCharacter(inputIdx)
	}

	// Convert back to string
	result, err := e.alphabet.IndicesToString(outputIndices)
	if err != nil {
		return "", fmt.Errorf("failed to convert indices to string: %w", err)
	}

	return result, nil
}

// processCharacter processes a single character through the Enigma machine.
func (e *Enigma) processCharacter(inputIdx int) int {
	// Step rotors before processing character (true Enigma behavior)
	e.stepRotors()

	// 1. Plugboard forward
	current := e.plugboard.Process(inputIdx)

	// 2. Rotors forward (right to left)
	for i := len(e.rotors) - 1; i >= 0; i-- {
		current = e.rotors[i].Forward(current)
	}

	// 3. Reflector
	current = e.reflector.Reflect(current)

	// 4. Rotors backward (left to right)
	for i := 0; i < len(e.rotors); i++ {
		current = e.rotors[i].Backward(current)
	}

	// 5. Plugboard backward
	current = e.plugboard.Process(current)

	return current
}

// stepRotors implements the Enigma rotor stepping mechanism including double-stepping.
func (e *Enigma) stepRotors() {
	if len(e.rotors) == 0 {
		return
	}

	// Check for double-stepping (middle rotor steps twice)
	// This happens when the middle rotor is at its notch position
	doubleStep := false
	if len(e.rotors) >= 2 {
		middleRotor := e.rotors[len(e.rotors)-2]
		doubleStep = middleRotor.IsAtNotch()
	}

	// Always step the rightmost (fastest) rotor
	e.rotors[len(e.rotors)-1].Step()

	// Step other rotors based on notch positions
	for i := len(e.rotors) - 2; i >= 0; i-- {
		nextRotor := e.rotors[i+1]

		// Step if the next rotor is at a notch
		if nextRotor.IsAtNotch() {
			e.rotors[i].Step()
		} else if i == len(e.rotors)-2 && doubleStep {
			// Double-stepping: middle rotor steps again
			e.rotors[i].Step()
		} else {
			// No more stepping needed
			break
		}
	}
}

// Reset resets the rotor positions to their initial configuration.
func (e *Enigma) Reset() error {
	// Reset rotor positions to initial values
	for i, rotorSpec := range e.initialSettings.RotorSpecs {
		if i < len(e.rotors) {
			e.rotors[i].SetPosition(rotorSpec.Position)
		}
	}
	return nil
}

// GetCurrentRotorPositions returns the current positions of all rotors.
func (e *Enigma) GetCurrentRotorPositions() []int {
	positions := make([]int, len(e.rotors))
	for i, r := range e.rotors {
		positions[i] = r.GetPosition()
	}
	return positions
}

// SetRotorPositions sets the positions of all rotors.
func (e *Enigma) SetRotorPositions(positions []int) error {
	if len(positions) != len(e.rotors) {
		return fmt.Errorf("position count (%d) must match rotor count (%d)",
			len(positions), len(e.rotors))
	}

	for i, pos := range positions {
		e.rotors[i].SetPosition(pos)
	}
	return nil
}

// GetRotorCount returns the number of rotors in the machine.
func (e *Enigma) GetRotorCount() int {
	return len(e.rotors)
}

// GetAlphabetSize returns the size of the alphabet being used.
func (e *Enigma) GetAlphabetSize() int {
	return e.alphabet.Size()
}

// GetPlugboardPairCount returns the number of plugboard pairs configured.
func (e *Enigma) GetPlugboardPairCount() int {
	return e.plugboard.PairCount()
}

// Clone creates a deep copy of the Enigma machine.
func (e *Enigma) Clone() (*Enigma, error) {
	clone := &Enigma{
		alphabet:        e.alphabet, // Alphabet is immutable, safe to share
		initialSettings: e.initialSettings,
	}

	// Clone rotors
	clone.rotors = make([]rotor.Rotor, len(e.rotors))
	for i, r := range e.rotors {
		clone.rotors[i] = r.Clone()
	}

	// Clone reflector
	clone.reflector = e.reflector.Clone()

	// Clone plugboard
	pb, err := e.plugboard.Clone()
	if err != nil {
		return nil, fmt.Errorf("failed to clone plugboard: %w", err)
	}
	clone.plugboard = pb

	return clone, nil
}
