// Package rotor provides the rotor component implementation for the Enigma machine.
// A rotor performs substitution permutations and steps during encryption.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package rotor

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/coredds/enigoma/internal/alphabet"
)

// Rotor represents a single rotor with its internal wiring and notch positions.
type Rotor interface {
	ID() string
	Forward(inputIdx int) int
	Backward(inputIdx int) int
	IsAtNotch() bool
	Step()
	SetPosition(pos int)
	SetRingSetting(ring int)
	GetPosition() int
	GetRingSetting() int
	Clone() Rotor
}

// BasicRotor implements the Rotor interface with standard Enigma behavior.
type BasicRotor struct {
	id          string
	alphabet    *alphabet.Alphabet
	forwardMap  []int
	backwardMap []int
	notches     []int
	position    int
	ringSetting int
	size        int
}

// NewRotor creates a new rotor with the specified parameters.
// forwardMapping should be a string of runes representing the output for each input
// rune in order of the alphabet.
func NewRotor(id string, alph *alphabet.Alphabet, forwardMapping string, notches []rune) (Rotor, error) {
	if alph == nil {
		return nil, fmt.Errorf("alphabet cannot be nil")
	}

	size := alph.Size()
	forwardMappingRunes := []rune(forwardMapping)
	if len(forwardMappingRunes) != size {
		return nil, fmt.Errorf("forward mapping length (%d) must match alphabet size (%d)",
			len(forwardMappingRunes), size)
	}

	// Convert forward mapping string to indices
	forwardMap := make([]int, size)
	backwardMap := make([]int, size)
	used := make([]bool, size)

	for i, r := range forwardMappingRunes {
		outputIdx, err := alph.RuneToIndex(r)
		if err != nil {
			return nil, fmt.Errorf("invalid character in forward mapping at position %d: %v", i, err)
		}

		if used[outputIdx] {
			return nil, fmt.Errorf("duplicate output character in forward mapping: %c", r)
		}

		forwardMap[i] = outputIdx
		backwardMap[outputIdx] = i
		used[outputIdx] = true
	}

	// Convert notch runes to indices
	notchIndices := make([]int, len(notches))
	for i, r := range notches {
		idx, err := alph.RuneToIndex(r)
		if err != nil {
			return nil, fmt.Errorf("invalid notch character: %v", err)
		}
		notchIndices[i] = idx
	}

	return &BasicRotor{
		id:          id,
		alphabet:    alph,
		forwardMap:  forwardMap,
		backwardMap: backwardMap,
		notches:     notchIndices,
		position:    0,
		ringSetting: 0,
		size:        size,
	}, nil
}

// RandomRotor generates a cryptographically random rotor with random notch positions.
func RandomRotor(id string, alph *alphabet.Alphabet) (Rotor, error) {
	if alph == nil {
		return nil, fmt.Errorf("alphabet cannot be nil")
	}

	size := alph.Size()
	runes := alph.Runes()

	// Generate random permutation using Fisher-Yates shuffle
	for i := size - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, fmt.Errorf("failed to generate random number: %v", err)
		}
		j := int(jBig.Int64())
		runes[i], runes[j] = runes[j], runes[i]
	}

	// Generate 1-3 random notch positions
	numNotchesBig, err := rand.Int(rand.Reader, big.NewInt(3))
	if err != nil {
		return nil, fmt.Errorf("failed to generate random notch count: %v", err)
	}
	numNotches := int(numNotchesBig.Int64()) + 1

	notches := make([]rune, numNotches)
	notchPositions := make(map[int]bool)

	for i := 0; i < numNotches; i++ {
		var pos int
		for {
			posBig, err := rand.Int(rand.Reader, big.NewInt(int64(size)))
			if err != nil {
				return nil, fmt.Errorf("failed to generate random notch position: %v", err)
			}
			pos = int(posBig.Int64())
			if !notchPositions[pos] {
				break
			}
		}
		notchPositions[pos] = true
		notches[i] = runes[pos]
	}

	return NewRotor(id, alph, string(runes), notches)
}

// ID returns the identifier of the rotor.
func (r *BasicRotor) ID() string {
	return r.id
}

// Forward performs the forward substitution through the rotor.
func (r *BasicRotor) Forward(inputIdx int) int {
	if inputIdx < 0 || inputIdx >= r.size {
		return inputIdx // Invalid input, return as-is
	}

	// Apply position offset
	adjustedInput := (inputIdx + r.position - r.ringSetting + r.size) % r.size

	// Apply rotor wiring
	output := r.forwardMap[adjustedInput]

	// Apply position offset to output
	return (output - r.position + r.ringSetting + r.size) % r.size
}

// Backward performs the backward substitution through the rotor.
func (r *BasicRotor) Backward(inputIdx int) int {
	if inputIdx < 0 || inputIdx >= r.size {
		return inputIdx // Invalid input, return as-is
	}

	// Apply position offset
	adjustedInput := (inputIdx + r.position - r.ringSetting + r.size) % r.size

	// Apply rotor wiring
	output := r.backwardMap[adjustedInput]

	// Apply position offset to output
	return (output - r.position + r.ringSetting + r.size) % r.size
}

// IsAtNotch returns true if the rotor is at a notch position.
func (r *BasicRotor) IsAtNotch() bool {
	for _, notch := range r.notches {
		if r.position == notch {
			return true
		}
	}
	return false
}

// Step advances the rotor position by one.
func (r *BasicRotor) Step() {
	r.position = (r.position + 1) % r.size
}

// SetPosition sets the rotor position.
func (r *BasicRotor) SetPosition(pos int) {
	r.position = ((pos % r.size) + r.size) % r.size
}

// SetRingSetting sets the ring setting of the rotor.
func (r *BasicRotor) SetRingSetting(ring int) {
	r.ringSetting = ((ring % r.size) + r.size) % r.size
}

// GetPosition returns the current rotor position.
func (r *BasicRotor) GetPosition() int {
	return r.position
}

// GetRingSetting returns the current ring setting.
func (r *BasicRotor) GetRingSetting() int {
	return r.ringSetting
}

// Clone creates a deep copy of the rotor.
func (r *BasicRotor) Clone() Rotor {
	forwardMap := make([]int, len(r.forwardMap))
	copy(forwardMap, r.forwardMap)

	backwardMap := make([]int, len(r.backwardMap))
	copy(backwardMap, r.backwardMap)

	notches := make([]int, len(r.notches))
	copy(notches, r.notches)

	return &BasicRotor{
		id:          r.id,
		alphabet:    r.alphabet,
		forwardMap:  forwardMap,
		backwardMap: backwardMap,
		notches:     notches,
		position:    r.position,
		ringSetting: r.ringSetting,
		size:        r.size,
	}
}

// RotorSpec represents the specification for creating and configuring a rotor.
type RotorSpec struct {
	ID             string `json:"id"`
	ForwardMapping string `json:"forward_mapping"`
	Notches        []rune `json:"notches"`
	Position       int    `json:"position"`
	RingSetting    int    `json:"ring_setting"`
}

// CreateFromSpec creates a rotor from a specification.
func CreateFromSpec(spec RotorSpec, alph *alphabet.Alphabet) (Rotor, error) {
	rotor, err := NewRotor(spec.ID, alph, spec.ForwardMapping, spec.Notches)
	if err != nil {
		return nil, err
	}

	rotor.SetPosition(spec.Position)
	rotor.SetRingSetting(spec.RingSetting)

	return rotor, nil
}

// ToSpec converts a rotor to a specification for serialization.
func ToSpec(rotor Rotor, alph *alphabet.Alphabet) (RotorSpec, error) {
	// This is a bit tricky since we need to reconstruct the forward mapping
	// We'll need to access the internal state
	if br, ok := rotor.(*BasicRotor); ok {
		forwardMapping := make([]rune, br.size)
		for i := 0; i < br.size; i++ {
			outputIdx := br.forwardMap[i]
			r, err := alph.IndexToRune(outputIdx)
			if err != nil {
				return RotorSpec{}, err
			}
			forwardMapping[i] = r
		}

		notches := make([]rune, len(br.notches))
		for i, notchIdx := range br.notches {
			r, err := alph.IndexToRune(notchIdx)
			if err != nil {
				return RotorSpec{}, err
			}
			notches[i] = r
		}

		return RotorSpec{
			ID:             br.id,
			ForwardMapping: string(forwardMapping),
			Notches:        notches,
			Position:       br.position,
			RingSetting:    br.ringSetting,
		}, nil
	}

	return RotorSpec{}, fmt.Errorf("unsupported rotor type")
}
