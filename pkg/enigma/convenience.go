// Package enigma provides convenience functions for zero-config usage.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package enigma

import (
	"fmt"

	"github.com/coredds/enigoma/internal/alphabet"
)

// QuickEncrypt encrypts text with auto-detected alphabet and specified security level.
// Returns the encrypted text, the machine configuration as JSON, and any error.
// This is perfect for one-off encryption where you want maximum convenience.
func QuickEncrypt(text string, security SecurityLevel) (encrypted string, config string, err error) {
	machine, err := NewFromText(text, security)
	if err != nil {
		return "", "", fmt.Errorf("failed to create machine: %w", err)
	}

	// Save configuration BEFORE encryption to preserve initial state
	config, err = machine.SaveSettingsToJSON()
	if err != nil {
		return "", "", fmt.Errorf("failed to save configuration: %w", err)
	}

	encrypted, err = machine.Encrypt(text)
	if err != nil {
		return "", "", fmt.Errorf("encryption failed: %w", err)
	}

	return encrypted, config, nil
}

// NewFromText creates an Enigma machine by auto-detecting the alphabet from the input text.
// This is the easiest way to create a machine - just provide your text and desired security level.
func NewFromText(text string, security SecurityLevel) (*Enigma, error) {
	if text == "" {
		return nil, fmt.Errorf("text cannot be empty for auto-detection. Provide sample text or use enigma.NewEnigmaClassic() for default setup")
	}

	// Auto-detect alphabet from text
	detectedAlphabet, err := alphabet.AutoDetectFromText(text)
	if err != nil {
		return nil, fmt.Errorf("failed to auto-detect alphabet from text %q: %w. Try using enigma.NewEnigmaSimple(enigoma.AlphabetLatinUpper) for manual setup", text, err)
	}

	// Create machine with detected alphabet and specified security
	machine, err := New(
		WithAlphabet(detectedAlphabet.Runes()),
		WithRandomSettings(security),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create machine: %w", err)
	}

	return machine, nil
}

// EncryptText is the simplest possible encryption function.
// Auto-detects alphabet, uses medium security, and returns encrypted text with config.
// Perfect for quick experiments and demos.
func EncryptText(text string) (encrypted string, config string, err error) {
	return QuickEncrypt(text, Medium)
}

// DecryptWithConfig decrypts text using a JSON configuration string.
// Companion function to QuickEncrypt and EncryptText.
func DecryptWithConfig(encryptedText string, configJSON string) (decrypted string, err error) {
	machine, err := NewFromJSON(configJSON)
	if err != nil {
		return "", fmt.Errorf("failed to load configuration: %w. Make sure you're using the same config that was used for encryption", err)
	}

	decrypted, err = machine.Decrypt(encryptedText)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w. Make sure you're using the correct configuration and encrypted text", err)
	}

	return decrypted, nil
}

// NewWithAutoDetection creates an Enigma machine with auto-detected alphabet and medium security.
// This is a convenience function for the most common use case.
func NewWithAutoDetection(text string) (*Enigma, error) {
	return NewFromText(text, Medium)
}
