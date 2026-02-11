// Package cli provides the examples command for the enigoma CLI.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var examplesCmd = &cobra.Command{
	Use:   "examples",
	Short: "Show copy-paste ready examples for common use cases",
	Long: `Show copy-paste ready examples for common enigoma use cases.

This command provides practical examples you can copy and paste to get started quickly.
All examples are tested and ready to use!

Categories:
• Basic usage (getting started)
• Unicode and international text
• Security levels and presets
• File operations
• Advanced configurations

Example:
  enigoma examples`,
	RunE: runExamples,
}

func runExamples(cmd *cobra.Command, args []string) error {
	fmt.Println("📚 enigoma Copy-Paste Examples")
	fmt.Println("==============================")
	fmt.Println()

	// Basic Examples
	fmt.Println("🚀 QUICK START")
	fmt.Println("--------------")
	fmt.Println("# Simplest possible usage (auto-detects everything):")
	fmt.Println(`enigoma encrypt --text "Hello World!" --auto-config my-key.json`)
	fmt.Println(`enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json`)
	fmt.Println()
	fmt.Println("# Interactive wizard for beginners:")
	fmt.Println(`enigoma wizard`)
	fmt.Println()

	// Unicode Examples
	fmt.Println("🌍 UNICODE & INTERNATIONAL TEXT")
	fmt.Println("-------------------------------")
	fmt.Println("# Portuguese with accents:")
	fmt.Println(`enigoma encrypt --text "Olá mundo! Como você está?" --auto-config pt-key.json`)
	fmt.Println()
	fmt.Println("# Mixed languages:")
	fmt.Println(`enigoma encrypt --text "Hello! Привет! 日本語! 🌟" --auto-config mixed-key.json`)
	fmt.Println()
	fmt.Println("# Greek text:")
	fmt.Println(`enigoma encrypt --text "Αβγδε ζητα θικλμ" --auto-config greek-key.json`)
	fmt.Println()

	// Security Examples
	fmt.Println("🛡️  SECURITY LEVELS")
	fmt.Println("------------------")
	fmt.Println("# Low security (3 rotors, 2 plugboard pairs):")
	fmt.Println(`enigoma encrypt --text "HELLO" --preset classic --save-config classic-key.json`)
	fmt.Println()
	fmt.Println("# High security (8 rotors, 15 plugboard pairs):")
	fmt.Println(`enigoma keygen --security high --output high-key.json`)
	fmt.Println(`enigoma encrypt --text "TOP SECRET" --config high-key.json`)
	fmt.Println()
	fmt.Println("# Maximum security (12 rotors, 20 plugboard pairs):")
	fmt.Println(`enigoma keygen --security extreme --output extreme-key.json`)
	fmt.Println(`enigoma encrypt --text "CLASSIFIED" --config extreme-key.json`)
	fmt.Println()

	// File Operations
	fmt.Println("📁 FILE OPERATIONS")
	fmt.Println("------------------")
	fmt.Println("# Encrypt a file:")
	fmt.Println(`enigoma encrypt --file document.txt --auto-config doc-key.json --output encrypted.txt`)
	fmt.Println()
	fmt.Println("# Decrypt a file:")
	fmt.Println(`enigoma decrypt --file encrypted.txt --config doc-key.json --output decrypted.txt`)
	fmt.Println()
	fmt.Println("# Pipe operations:")
	fmt.Println(`echo "Secret message" | enigoma encrypt --auto-config pipe-key.json`)
	fmt.Println(`echo "ENCRYPTED" | enigoma decrypt --config pipe-key.json`)
	fmt.Println()

	// Output Formats
	fmt.Println("📊 OUTPUT FORMATS")
	fmt.Println("----------------")
	fmt.Println("# Base64 output:")
	fmt.Println(`enigoma encrypt --text "Hello" --auto-config key.json --format base64`)
	fmt.Println(`enigoma decrypt --text "SGVsbG8=" --config key.json --format base64`)
	fmt.Println()
	fmt.Println("# Hex output:")
	fmt.Println(`enigoma encrypt --text "Hello" --auto-config key.json --format hex`)
	fmt.Println(`enigoma decrypt --text "48656c6c6f" --config key.json --format hex`)
	fmt.Println()

	// Troubleshooting
	fmt.Println("🔧 TROUBLESHOOTING")
	fmt.Println("------------------")
	fmt.Println("# If you get 'character not found' errors with presets:")
	fmt.Println(`enigoma encrypt --text "Hello World!" --preset classic --remove-spaces --uppercase`)
	fmt.Println("# Or better yet, use auto-config:")
	fmt.Println(`enigoma encrypt --text "Hello World!" --auto-config key.json`)
	fmt.Println()
	fmt.Println("# Validate a configuration file:")
	fmt.Println(`enigoma config --validate my-key.json`)
	fmt.Println()
	fmt.Println("# Test a configuration:")
	fmt.Println(`enigoma config --test my-key.json --text "TEST MESSAGE"`)
	fmt.Println()

	// Advanced Examples
	fmt.Println("⚙️  ADVANCED USAGE")
	fmt.Println("-----------------")
	fmt.Println("# Custom alphabet:")
	fmt.Println(`enigoma keygen --alphabet ascii --security medium --output custom-key.json`)
	fmt.Println()
	fmt.Println("# Historical presets:")
	fmt.Println(`enigoma preset --describe m3`)
	fmt.Println(`enigoma encrypt --text "ENIGMA" --preset m3 --save-config m3-key.json`)
	fmt.Println()
	fmt.Println("# Verbose output for debugging:")
	fmt.Println(`enigoma encrypt --text "Debug me" --auto-config debug-key.json --verbose`)
	fmt.Println()

	// Library Examples
	fmt.Println("📖 LIBRARY USAGE (Go Code)")
	fmt.Println("--------------------------")
	fmt.Println("```go")
	fmt.Println("// Simplest possible usage:")
	fmt.Println(`encrypted, config, err := enigma.EncryptText("Hello World!")`)
	fmt.Println(`decrypted, err := enigma.DecryptWithConfig(encrypted, config)`)
	fmt.Println()
	fmt.Println("// Auto-detection with custom security:")
	fmt.Println(`machine, err := enigma.NewFromText("Your text", enigma.High)`)
	fmt.Println(`encrypted, err := machine.Encrypt("Your text")`)
	fmt.Println()
	fmt.Println("// Classic Enigma:")
	fmt.Println(`machine, err := enigma.NewEnigmaClassic()`)
	fmt.Println(`encrypted, err := machine.Encrypt("HELLO WORLD")`)
	fmt.Println("```")
	fmt.Println()

	// Footer
	fmt.Println("💡 TIPS")
	fmt.Println("------")
	fmt.Println("• Always use --auto-config for new projects (it's the easiest!)")
	fmt.Println("• Save your configuration files - you need them to decrypt!")
	fmt.Println("• Use --verbose to see what's happening under the hood")
	fmt.Println("• Try 'enigoma demo' for an interactive demonstration")
	fmt.Println("• Use 'enigoma wizard' if you're new to enigoma")
	fmt.Println()
	fmt.Println("🔗 More help: enigoma [command] --help")

	return nil
}
