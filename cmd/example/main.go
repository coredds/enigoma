// Package main demonstrates the usage of the enigoma Enigma machine library.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package main

import (
	"fmt"
	"log"

	"github.com/coredds/enigoma"
	"github.com/coredds/enigoma/pkg/enigma"
)

func main() {
	fmt.Printf("=== enigoma Enigma Machine Demo (v%s) ===\n\n", enigoma.GetVersion())

	// Demo 1: Classic Enigma (similar to historical M3)
	fmt.Println("1. Classic Enigma Demo:")
	demoClassicEnigma()

	// Demo 2: Unicode Enigma with custom alphabet
	fmt.Println("\n2. Unicode Enigma Demo:")
	demoUnicodeEnigma()

	// Demo 3: Different security levels
	fmt.Println("\n3. Security Levels Demo:")
	demoSecurityLevels()

	// Demo 4: Settings serialization
	fmt.Println("\n4. Settings Serialization Demo:")
	demoSettingsSerialization()

	// Demo 5: Custom components
	fmt.Println("\n5. Custom Components Demo:")
	demoCustomComponents()
}

func demoClassicEnigma() {
	// Create a classic Enigma machine
	machine, err := enigma.NewEnigmaClassic()
	if err != nil {
		log.Fatalf("Failed to create classic Enigma: %v", err)
	}

	message := "HELLO WORLD"
	fmt.Printf("Original message: %s\n", message)

	// Encrypt
	encrypted, err := machine.Encrypt(message)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Encrypted: %s\n", encrypted)

	// Reset machine to initial state for decryption
	if err := machine.Reset(); err != nil {
		log.Fatalf("Reset failed: %v", err)
	}

	// Decrypt
	decrypted, err := machine.Decrypt(encrypted)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)

	fmt.Printf("Round-trip successful: %t\n", message == decrypted)
}

func demoUnicodeEnigma() {
	// Create an Enigma with Greek alphabet
	machine, err := enigma.NewEnigmaSimple(enigoma.AlphabetGreek)
	if err != nil {
		log.Fatalf("Failed to create Unicode Enigma: %v", err)
	}

	message := "Αβγδε ζητα"
	fmt.Printf("Original Greek message: %s\n", message)

	// Encrypt
	encrypted, err := machine.Encrypt(message)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	fmt.Printf("Encrypted: %s\n", encrypted)

	// Reset and decrypt
	if err := machine.Reset(); err != nil {
		log.Fatalf("Reset failed: %v", err)
	}
	decrypted, err := machine.Decrypt(encrypted)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	fmt.Printf("Decrypted: %s\n", decrypted)

	fmt.Printf("Round-trip successful: %t\n", message == decrypted)
}

func demoSecurityLevels() {
	levels := []enigma.SecurityLevel{
		enigma.Low,
		enigma.Medium,
		enigma.High,
	}

	message := "SECRET MESSAGE"

	for _, level := range levels {
		fmt.Printf("Security Level: %s\n", levelToString(level))

		machine, err := enigma.New(
			enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
			enigma.WithRandomSettings(level),
		)
		if err != nil {
			log.Fatalf("Failed to create Enigma: %v", err)
		}

		fmt.Printf("  Rotors: %d\n", machine.GetRotorCount())
		fmt.Printf("  Plugboard pairs: %d\n", machine.GetPlugboardPairCount())

		encrypted, _ := machine.Encrypt(message)
		fmt.Printf("  Encrypted: %s\n", encrypted)

		if err := machine.Reset(); err != nil {
			log.Fatalf("Reset failed: %v", err)
		}
		decrypted, _ := machine.Decrypt(encrypted)
		fmt.Printf("  Round-trip: %t\n", message == decrypted)
		fmt.Println()
	}
}

func demoSettingsSerialization() {
	// Create an Enigma with specific settings
	machine, err := enigma.New(
		enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
		enigma.WithRandomSettings(enigma.Medium),
	)
	if err != nil {
		log.Fatalf("Failed to create Enigma: %v", err)
	}

	message := "SERIALIZATION TEST"
	fmt.Printf("Original message: %s\n", message)

	// Encrypt with original machine
	encrypted, _ := machine.Encrypt(message)
	fmt.Printf("Encrypted: %s\n", encrypted)

	// Export settings
	jsonSettings, err := machine.SaveSettingsToJSON()
	if err != nil {
		log.Fatalf("Failed to save settings: %v", err)
	}

	fmt.Println("Settings exported to JSON")
	fmt.Printf("JSON length: %d characters\n", len(jsonSettings))

	// Create new machine from settings
	newMachine, err := enigma.NewFromJSON(jsonSettings)
	if err != nil {
		log.Fatalf("Failed to create machine from JSON: %v", err)
	}

	// Decrypt with new machine
	decrypted, err := newMachine.Decrypt(encrypted)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	fmt.Printf("Decrypted with new machine: %s\n", decrypted)
	fmt.Printf("Settings serialization successful: %t\n", message == decrypted)
}

func demoCustomComponents() {
	// This demo shows how you might create custom components
	// (though for simplicity, we'll use the option-based approach)

	machine, err := enigma.New(
		enigma.WithAlphabet(enigoma.AlphabetASCIIPrintable),
		enigma.WithRandomSettings(enigma.Low),
		enigma.WithPlugboardConfiguration(map[rune]rune{
			'A': 'Z',
			'Z': 'A',
			'1': '9',
			'9': '1',
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create custom Enigma: %v", err)
	}

	message := "Custom123!@#"
	fmt.Printf("Original message: %s\n", message)

	encrypted, _ := machine.Encrypt(message)
	fmt.Printf("Encrypted: %s\n", encrypted)

	if err := machine.Reset(); err != nil {
		log.Fatalf("Reset failed: %v", err)
	}
	decrypted, _ := machine.Decrypt(encrypted)
	fmt.Printf("Decrypted: %s\n", decrypted)

	fmt.Printf("Custom configuration successful: %t\n", message == decrypted)
	fmt.Printf("Alphabet size: %d characters\n", machine.GetAlphabetSize())
	fmt.Printf("Plugboard pairs: %d\n", machine.GetPlugboardPairCount())
}

func levelToString(level enigma.SecurityLevel) string {
	switch level {
	case enigma.Low:
		return "Low"
	case enigma.Medium:
		return "Medium"
	case enigma.High:
		return "High"
	case enigma.Extreme:
		return "Extreme"
	default:
		return "Unknown"
	}
}

// demonstrateReciprocal is kept for reference and is not used in the demo flow.
//
//nolint:unused
func demonstrateReciprocal() {
	fmt.Println("\n=== Enigma Reciprocal Property Demo ===")

	machine, err := enigma.NewEnigmaClassic()
	if err != nil {
		log.Fatalf("Failed to create Enigma: %v", err)
	}

	// Show reciprocal property: if A encrypts to X, then X encrypts to A
	testChars := []rune{'A', 'B', 'C', 'D', 'E'}

	for _, char := range testChars {
		if err := machine.Reset(); err != nil {
			log.Fatalf("Reset failed: %v", err)
		}

		// Encrypt the character
		input := string(char)
		encrypted, _ := machine.Encrypt(input)

		if err := machine.Reset(); err != nil {
			log.Fatalf("Reset failed: %v", err)
		}

		// Encrypt the encrypted character (should give us back the original)
		backToOriginal, _ := machine.Encrypt(encrypted)

		fmt.Printf("%s -> %s -> %s (reciprocal: %t)\n",
			input, encrypted, backToOriginal, input == backToOriginal)
	}
}
