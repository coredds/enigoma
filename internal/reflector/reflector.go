// Package reflector provides the reflector component implementation for the Enigma machine.
// A reflector ensures reciprocal character mapping - if A maps to B, then B maps to A.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package reflector

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/coredds/enigoma/internal/alphabet"
)

// Reflector represents the reflector component of an Enigma machine.
type Reflector interface {
	ID() string
	Reflect(inputIdx int) int
	Clone() Reflector
}

// BasicReflector implements the Reflector interface with reciprocal mapping.
type BasicReflector struct {
	id       string
	alphabet *alphabet.Alphabet
	mapping  []int
	size     int
}

// NewReflector creates a new reflector with the specified mapping.
// The mapping string should represent reciprocal pairs where each character
// maps to another character bidirectionally.
func NewReflector(id string, alph *alphabet.Alphabet, mapping string) (Reflector, error) {
	if alph == nil {
		return nil, fmt.Errorf("alphabet cannot be nil")
	}

	size := alph.Size()
	mappingRunes := []rune(mapping)
	if len(mappingRunes) != size {
		return nil, fmt.Errorf("mapping length (%d) must match alphabet size (%d)",
			len(mappingRunes), size)
	}

	// Convert mapping string to indices and validate reciprocity
	reflectMap := make([]int, size)
	used := make([]bool, size)

	for i, r := range mappingRunes {
		outputIdx, err := alph.RuneToIndex(r)
		if err != nil {
			return nil, fmt.Errorf("invalid character in mapping at position %d: %v", i, err)
		}

		// Check for self-mapping (not allowed in Enigma reflectors)
		if i == outputIdx {
			inputRune, _ := alph.IndexToRune(i)
			return nil, fmt.Errorf("character %c cannot map to itself in a reflector", inputRune)
		}

		if used[outputIdx] {
			outputRune, _ := alph.IndexToRune(outputIdx)
			return nil, fmt.Errorf("character %c is used multiple times in mapping", outputRune)
		}

		reflectMap[i] = outputIdx
		used[outputIdx] = true
	}

	// Validate reciprocal mapping: if A->B then B->A
	for i := 0; i < size; i++ {
		output := reflectMap[i]
		if reflectMap[output] != i {
			inputRune, _ := alph.IndexToRune(i)
			outputRune, _ := alph.IndexToRune(output)
			backRune, _ := alph.IndexToRune(reflectMap[output])
			return nil, fmt.Errorf("non-reciprocal mapping: %c->%c but %c->%c",
				inputRune, outputRune, outputRune, backRune)
		}
	}

	return &BasicReflector{
		id:       id,
		alphabet: alph,
		mapping:  reflectMap,
		size:     size,
	}, nil
}

// RandomReflector generates a cryptographically random reflector with reciprocal mapping.
func RandomReflector(id string, alph *alphabet.Alphabet) (Reflector, error) {
	if alph == nil {
		return nil, fmt.Errorf("alphabet cannot be nil")
	}

	size := alph.Size()
	if size%2 != 0 {
		return nil, fmt.Errorf("alphabet size must be even for reflector (%d is odd)", size)
	}

	runes := alph.Runes()
	mapping := make([]rune, size)

	// Create reciprocal pairs
	available := make([]int, size)
	for i := 0; i < size; i++ {
		available[i] = i
	}

	// Shuffle the available indices
	for i := size - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return nil, fmt.Errorf("failed to generate random number: %v", err)
		}
		j := int(jBig.Int64())
		available[i], available[j] = available[j], available[i]
	}

	// Create pairs from the shuffled list
	for i := 0; i < size; i += 2 {
		idx1 := available[i]
		idx2 := available[i+1]

		mapping[idx1] = runes[idx2]
		mapping[idx2] = runes[idx1]
	}

	return NewReflector(id, alph, string(mapping))
}

// ID returns the identifier of the reflector.
func (r *BasicReflector) ID() string {
	return r.id
}

// Reflect performs the reflection operation on the input index.
func (r *BasicReflector) Reflect(inputIdx int) int {
	if inputIdx < 0 || inputIdx >= r.size {
		return inputIdx // Invalid input, return as-is
	}
	return r.mapping[inputIdx]
}

// Clone creates a deep copy of the reflector.
func (r *BasicReflector) Clone() Reflector {
	mapping := make([]int, len(r.mapping))
	copy(mapping, r.mapping)

	return &BasicReflector{
		id:       r.id,
		alphabet: r.alphabet,
		mapping:  mapping,
		size:     r.size,
	}
}

// ReflectorSpec represents the specification for creating a reflector.
type ReflectorSpec struct {
	ID      string `json:"id"`
	Mapping string `json:"mapping"`
}

// CreateFromSpec creates a reflector from a specification.
func CreateFromSpec(spec ReflectorSpec, alph *alphabet.Alphabet) (Reflector, error) {
	return NewReflector(spec.ID, alph, spec.Mapping)
}

// ToSpec converts a reflector to a specification for serialization.
func ToSpec(reflector Reflector, alph *alphabet.Alphabet) (ReflectorSpec, error) {
	if br, ok := reflector.(*BasicReflector); ok {
		mapping := make([]rune, br.size)
		for i := 0; i < br.size; i++ {
			outputIdx := br.mapping[i]
			r, err := alph.IndexToRune(outputIdx)
			if err != nil {
				return ReflectorSpec{}, err
			}
			mapping[i] = r
		}

		return ReflectorSpec{
			ID:      br.id,
			Mapping: string(mapping),
		}, nil
	}

	return ReflectorSpec{}, fmt.Errorf("unsupported reflector type")
}

// ValidateReflectorMapping validates that a mapping string represents a valid reflector.
// It checks for reciprocity and absence of self-mapping.
func ValidateReflectorMapping(alph *alphabet.Alphabet, mapping string) error {
	if alph == nil {
		return fmt.Errorf("alphabet cannot be nil")
	}

	size := alph.Size()
	mappingRunes := []rune(mapping)
	if len(mappingRunes) != size {
		return fmt.Errorf("mapping length (%d) must match alphabet size (%d)",
			len(mappingRunes), size)
	}

	// Convert to indices for validation
	indices := make([]int, size)
	used := make([]bool, size)

	for i, r := range mappingRunes {
		outputIdx, err := alph.RuneToIndex(r)
		if err != nil {
			return fmt.Errorf("invalid character in mapping at position %d: %v", i, err)
		}

		if i == outputIdx {
			return fmt.Errorf("character %c cannot map to itself in a reflector", r)
		}

		if used[outputIdx] {
			outputRune, _ := alph.IndexToRune(outputIdx)
			return fmt.Errorf("character %c is used multiple times in mapping", outputRune)
		}

		indices[i] = outputIdx
		used[outputIdx] = true
	}

	// Check reciprocity
	for i := 0; i < size; i++ {
		output := indices[i]
		if indices[output] != i {
			inputRune, _ := alph.IndexToRune(i)
			outputRune, _ := alph.IndexToRune(output)
			backRune, _ := alph.IndexToRune(indices[output])
			return fmt.Errorf("non-reciprocal mapping: %c->%c but %c->%c",
				inputRune, outputRune, outputRune, backRune)
		}
	}

	return nil
}
