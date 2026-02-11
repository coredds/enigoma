// Package alphabet provides utilities for managing character sets (alphabets)
// used by the Enigma machine components.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package alphabet

import (
	"fmt"
	"slices"
	"strings"
)

// Alphabet represents a character set used by the Enigma machine.
// It provides bidirectional mapping between runes and their indices.
type Alphabet struct {
	runes    []rune
	runeToID map[rune]int
	size     int
}

// New creates a new Alphabet from the provided runes.
// It validates that there are no duplicate characters.
func New(runes []rune) (*Alphabet, error) {
	if len(runes) == 0 {
		return nil, fmt.Errorf("alphabet cannot be empty")
	}

	// Check for duplicates
	seen := make(map[rune]bool)
	for _, r := range runes {
		if seen[r] {
			return nil, fmt.Errorf("duplicate character found: %c", r)
		}
		seen[r] = true
	}

	// Create a copy but preserve the original ordering
	// Sorting can cause issues with carefully crafted Unicode alphabets
	runesCopy := make([]rune, len(runes))
	copy(runesCopy, runes)

	// Build the mapping
	runeToID := make(map[rune]int, len(runesCopy))
	for i, r := range runesCopy {
		runeToID[r] = i
	}

	return &Alphabet{
		runes:    runesCopy,
		runeToID: runeToID,
		size:     len(runesCopy),
	}, nil
}

// Size returns the number of characters in the alphabet.
func (a *Alphabet) Size() int {
	return a.size
}

// Runes returns a copy of the runes in the alphabet.
func (a *Alphabet) Runes() []rune {
	result := make([]rune, len(a.runes))
	copy(result, a.runes)
	return result
}

// RuneToIndex converts a rune to its index in the alphabet.
// Returns an error if the rune is not in the alphabet.
func (a *Alphabet) RuneToIndex(r rune) (int, error) {
	idx, exists := a.runeToID[r]
	if !exists {
		return 0, fmt.Errorf("character %c not found in alphabet", r)
	}
	return idx, nil
}

// IndexToRune converts an index to its corresponding rune.
// Returns an error if the index is out of bounds.
func (a *Alphabet) IndexToRune(idx int) (rune, error) {
	if idx < 0 || idx >= a.size {
		return 0, fmt.Errorf("index %d out of bounds [0, %d)", idx, a.size)
	}
	return a.runes[idx], nil
}

// Contains checks if a rune is present in the alphabet.
func (a *Alphabet) Contains(r rune) bool {
	_, exists := a.runeToID[r]
	return exists
}

// ValidateString checks if all runes in the string are present in the alphabet.
// Returns the first invalid rune found, or 0 if all are valid.
func (a *Alphabet) ValidateString(s string) (rune, error) {
	for _, r := range s {
		if !a.Contains(r) {
			return r, fmt.Errorf("character %c not found in alphabet", r)
		}
	}
	return 0, nil
}

// StringToIndices converts a string to a slice of indices.
func (a *Alphabet) StringToIndices(s string) ([]int, error) {
	result := make([]int, 0, len(s))
	for _, r := range s {
		idx, err := a.RuneToIndex(r)
		if err != nil {
			return nil, err
		}
		result = append(result, idx)
	}
	return result, nil
}

// IndicesToString converts a slice of indices to a string.
func (a *Alphabet) IndicesToString(indices []int) (string, error) {
	runes := make([]rune, 0, len(indices))
	for _, idx := range indices {
		r, err := a.IndexToRune(idx)
		if err != nil {
			return "", err
		}
		runes = append(runes, r)
	}
	return string(runes), nil
}

// AutoDetectFromText creates an alphabet by analyzing the unique characters in the input text.
// It automatically handles reflector compatibility by ensuring an even number of characters.
// nolint:gocyclo // This function is necessarily complex due to alphabet detection logic
func AutoDetectFromText(text string, options ...AutoDetectOption) (*Alphabet, error) {
	if text == "" {
		return nil, fmt.Errorf("cannot auto-detect alphabet from empty text")
	}

	// Preprocess text to handle common issues
	text = PreprocessTextForAutoDetection(text)

	config := &autoDetectConfig{
		maxSize:        1000, // Default safety limit
		addPadding:     true, // Ensure even size for reflector
		excludeControl: true, // Skip control characters
	}

	// Apply options
	for _, opt := range options {
		opt(config)
	}

	// Collect unique runes
	uniqueRunes := make(map[rune]bool)
	for _, r := range text {
		// Skip control characters if configured
		if config.excludeControl && isControlCharacter(r) {
			continue
		}
		uniqueRunes[r] = true

		// Safety limit to prevent performance issues
		if len(uniqueRunes) >= config.maxSize {
			break
		}
	}

	if len(uniqueRunes) == 0 {
		return nil, fmt.Errorf("no valid characters found in text for alphabet")
	}

	// Convert to ordered slice (deterministic ordering by Unicode codepoint)
	runes := make([]rune, 0, len(uniqueRunes))
	for r := range uniqueRunes {
		runes = append(runes, r)
	}

	// Sort by Unicode codepoint for deterministic behavior
	slices.Sort(runes)

	// Ensure even size for reflector compatibility
	if config.addPadding && len(runes)%2 != 0 {
		// Find a suitable padding character not in the text
		paddingChar := rune(' ')
		for uniqueRunes[paddingChar] {
			paddingChar++
			// Safety check to avoid infinite loop
			if paddingChar > 0x10000 {
				return nil, fmt.Errorf("unable to find suitable padding character for even-sized alphabet")
			}
		}
		runes = append(runes, paddingChar)
	}

	return New(runes)
}

// autoDetectConfig holds configuration for auto-detection
type autoDetectConfig struct {
	maxSize        int
	addPadding     bool
	excludeControl bool
}

// AutoDetectOption is a function that configures auto-detection behavior
type AutoDetectOption func(*autoDetectConfig)

// WithMaxSize sets the maximum number of characters in the auto-detected alphabet
func WithMaxSize(maxSize int) AutoDetectOption {
	return func(config *autoDetectConfig) {
		config.maxSize = maxSize
	}
}

// WithoutPadding disables automatic padding for even-sized alphabets
func WithoutPadding() AutoDetectOption {
	return func(config *autoDetectConfig) {
		config.addPadding = false
	}
}

// WithControlCharacters includes control characters in the alphabet
func WithControlCharacters() AutoDetectOption {
	return func(config *autoDetectConfig) {
		config.excludeControl = false
	}
}

// PreprocessTextForAutoDetection handles common text preprocessing issues
func PreprocessTextForAutoDetection(text string) string {
	// Normalize line endings (Windows \r\n -> \n, old Mac \r -> \n)
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")

	// Trim leading and trailing whitespace to avoid accidental inclusion
	text = strings.TrimSpace(text)

	return text
}

// isControlCharacter determines if a rune is a control character that should be excluded
func isControlCharacter(r rune) bool {
	// Allow common whitespace characters
	if r == ' ' || r == '\t' || r == '\n' {
		return false
	}

	// Exclude other control characters (0-31 and 127-159)
	return (r >= 0 && r <= 31) || (r >= 127 && r <= 159)
}
