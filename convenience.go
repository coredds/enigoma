// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package enigoma

import (
	"encoding/json"
	"fmt"

	"github.com/coredds/enigoma/internal/alphabet"
)

// NewFromText builds a machine whose alphabet is auto-detected from text, with
// random components (5 rotors, 8 plug pairs) unless opts override them.
func NewFromText(text string, opts ...Option) (*Machine, error) {
	if text == "" {
		return nil, fmt.Errorf("cannot detect an alphabet from empty text")
	}
	detected, err := alphabet.AutoDetectFromText(text)
	if err != nil {
		return nil, fmt.Errorf("detect alphabet: %w", err)
	}
	base := []Option{WithAlphabet(string(detected.Runes())), WithRandomComponents(5, 8)}
	return New(append(base, opts...)...)
}

// QuickEncrypt encrypts text on a fresh random machine whose alphabet is
// detected from the text. It returns the ciphertext and the machine's settings
// as JSON (captured before encrypting), which DecryptWithConfig needs.
func QuickEncrypt(text string, rotors, plugPairs int) (string, []byte, error) {
	m, err := NewFromText(text, WithRandomComponents(rotors, plugPairs))
	if err != nil {
		return "", nil, err
	}
	settings, err := json.MarshalIndent(m.Settings(), "", "  ")
	if err != nil {
		return "", nil, fmt.Errorf("encode settings: %w", err)
	}
	ciphertext, err := m.Encrypt(text)
	if err != nil {
		return "", nil, err
	}
	return ciphertext, settings, nil
}

// DecryptWithConfig decrypts ciphertext using settings JSON from QuickEncrypt
// or Machine.Settings.
func DecryptWithConfig(ciphertext string, settingsJSON []byte) (string, error) {
	s, err := ParseSettings(settingsJSON)
	if err != nil {
		return "", err
	}
	m, err := NewFromSettings(s)
	if err != nil {
		return "", err
	}
	return m.Decrypt(ciphertext)
}
