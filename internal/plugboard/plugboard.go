// Package plugboard provides the plugboard (Steckerbrett) component implementation
// for the Enigma machine. It handles reciprocal character swapping.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package plugboard

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/coredds/enigoma/internal/alphabet"
)

// Plugboard represents the plugboard component of an Enigma machine.
// It implements reciprocal character swapping.
type Plugboard struct {
	alphabet *alphabet.Alphabet
	mapping  map[int]int
	pairs    map[int]int // For tracking which characters are paired
	size     int
}

// New creates a new empty plugboard.
func New(alph *alphabet.Alphabet) (*Plugboard, error) {
	if alph == nil {
		return nil, fmt.Errorf("alphabet cannot be nil")
	}

	return &Plugboard{
		alphabet: alph,
		mapping:  make(map[int]int),
		pairs:    make(map[int]int),
		size:     alph.Size(),
	}, nil
}

// AddPair adds a reciprocal swap between two runes on the plugboard.
func (p *Plugboard) AddPair(r1, r2 rune) error {
	idx1, err := p.alphabet.RuneToIndex(r1)
	if err != nil {
		return fmt.Errorf("invalid character %c: %v", r1, err)
	}

	idx2, err := p.alphabet.RuneToIndex(r2)
	if err != nil {
		return fmt.Errorf("invalid character %c: %v", r2, err)
	}

	if idx1 == idx2 {
		return fmt.Errorf("cannot pair character %c with itself", r1)
	}

	// Check if either character is already paired
	if _, exists := p.pairs[idx1]; exists {
		return fmt.Errorf("character %c is already paired", r1)
	}
	if _, exists := p.pairs[idx2]; exists {
		return fmt.Errorf("character %c is already paired", r2)
	}

	// Add the reciprocal mapping
	p.mapping[idx1] = idx2
	p.mapping[idx2] = idx1
	p.pairs[idx1] = idx2
	p.pairs[idx2] = idx1

	return nil
}

// RemovePair removes the pair involving the given rune.
func (p *Plugboard) RemovePair(r rune) error {
	idx, err := p.alphabet.RuneToIndex(r)
	if err != nil {
		return fmt.Errorf("invalid character %c: %v", r, err)
	}

	// Check if the character is paired
	partner, exists := p.pairs[idx]
	if !exists {
		return fmt.Errorf("character %c is not paired", r)
	}

	// Remove the reciprocal mapping
	delete(p.mapping, idx)
	delete(p.mapping, partner)
	delete(p.pairs, idx)
	delete(p.pairs, partner)

	return nil
}

// Clear removes all plugboard connections.
func (p *Plugboard) Clear() {
	p.mapping = make(map[int]int)
	p.pairs = make(map[int]int)
}

// Process applies the plugboard mapping to a character index.
// If the character is not wired, it returns the same index.
func (p *Plugboard) Process(inputIdx int) int {
	if inputIdx < 0 || inputIdx >= p.size {
		return inputIdx // Invalid input, return as-is
	}

	if output, exists := p.mapping[inputIdx]; exists {
		return output
	}
	return inputIdx
}

// ProcessRune applies the plugboard mapping to a rune.
func (p *Plugboard) ProcessRune(r rune) (rune, error) {
	idx, err := p.alphabet.RuneToIndex(r)
	if err != nil {
		return r, err
	}

	outputIdx := p.Process(idx)
	return p.alphabet.IndexToRune(outputIdx)
}

// RandomPairs generates n random reciprocal pairs on the plugboard.
// This clears any existing pairs first.
func (p *Plugboard) RandomPairs(n int) error {
	if n < 0 {
		return fmt.Errorf("number of pairs cannot be negative")
	}

	maxPairs := p.size / 2
	if n > maxPairs {
		return fmt.Errorf("cannot create %d pairs with alphabet size %d (max %d)", n, p.size, maxPairs)
	}

	// Clear existing pairs
	p.Clear()

	if n == 0 {
		return nil
	}

	// Create list of available indices
	available := make([]int, p.size)
	for i := 0; i < p.size; i++ {
		available[i] = i
	}

	// Shuffle the available indices
	for i := p.size - 1; i > 0; i-- {
		jBig, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return fmt.Errorf("failed to generate random number: %v", err)
		}
		j := int(jBig.Int64())
		available[i], available[j] = available[j], available[i]
	}

	// Create n pairs from the shuffled list
	for i := 0; i < n*2; i += 2 {
		idx1 := available[i]
		idx2 := available[i+1]

		p.mapping[idx1] = idx2
		p.mapping[idx2] = idx1
		p.pairs[idx1] = idx2
		p.pairs[idx2] = idx1
	}

	return nil
}

// GetPairs returns a copy of all current pairs as rune pairs.
func (p *Plugboard) GetPairs() ([][2]rune, error) {
	var pairs [][2]rune
	processed := make(map[int]bool)

	for idx1, idx2 := range p.pairs {
		if processed[idx1] {
			continue
		}

		r1, err := p.alphabet.IndexToRune(idx1)
		if err != nil {
			return nil, err
		}

		r2, err := p.alphabet.IndexToRune(idx2)
		if err != nil {
			return nil, err
		}

		pairs = append(pairs, [2]rune{r1, r2})
		processed[idx1] = true
		processed[idx2] = true
	}

	return pairs, nil
}

// GetPairsMap returns a copy of the pairs as a map for serialization.
func (p *Plugboard) GetPairsMap() (map[rune]rune, error) {
	result := make(map[rune]rune)

	for idx1, idx2 := range p.mapping {
		r1, err := p.alphabet.IndexToRune(idx1)
		if err != nil {
			return nil, err
		}

		r2, err := p.alphabet.IndexToRune(idx2)
		if err != nil {
			return nil, err
		}

		result[r1] = r2
	}

	return result, nil
}

// SetPairsFromMap sets the plugboard pairs from a map.
func (p *Plugboard) SetPairsFromMap(pairs map[rune]rune) error {
	p.Clear()

	processed := make(map[rune]bool)

	for r1, r2 := range pairs {
		if processed[r1] {
			continue
		}

		// Check if this is a reciprocal pair
		if reversePair, exists := pairs[r2]; !exists || reversePair != r1 {
			return fmt.Errorf("non-reciprocal pair: %c->%c", r1, r2)
		}

		err := p.AddPair(r1, r2)
		if err != nil {
			return err
		}

		processed[r1] = true
		processed[r2] = true
	}

	return nil
}

// PairCount returns the number of character pairs currently configured.
func (p *Plugboard) PairCount() int {
	return len(p.pairs) / 2
}

// Clone creates a deep copy of the plugboard.
func (p *Plugboard) Clone() (*Plugboard, error) {
	clone := &Plugboard{
		alphabet: p.alphabet,
		mapping:  make(map[int]int),
		pairs:    make(map[int]int),
		size:     p.size,
	}

	for k, v := range p.mapping {
		clone.mapping[k] = v
	}

	for k, v := range p.pairs {
		clone.pairs[k] = v
	}

	return clone, nil
}
