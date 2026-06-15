// Package cli provides the decrypt command for the enigoma CLI.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt text or files using an Enigma machine",
	Long: `Decrypt ciphertext using a configured Enigma machine.

IMPORTANT: Always use the same configuration file that was used for encryption!

RECOMMENDED WORKFLOW:
  # Step 1: Encrypt with auto-config
  enigoma encrypt --text "Hello World!" --auto-config my-key.json
  
  # Step 2: Decrypt with the same config  
  enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json

INPUT METHODS:
  enigoma decrypt --text "CIPHER"              # Direct text
  enigoma decrypt --file encrypted.txt         # From file
  echo "CIPHER" | enigoma decrypt              # From stdin

INPUT FORMATS:
  enigoma decrypt --text "CIPHER" --config key.json                    # Plain text
  enigoma decrypt --text "48656c6c6f" --format hex --config key.json   # Hex input
  enigoma decrypt --text "SGVsbG8=" --format base64 --config key.json  # Base64 input

TROUBLESHOOTING:
  • "Character not found" error? Use the config file from encryption
  • Different result than expected? Check you're using the right config file
  • Spaces in cipher text? They may not belong - try --remove-spaces

LEGACY MODE (not recommended):
  enigoma decrypt --text "CIPHER" --preset classic  # Unreliable - presets are random`,
	RunE: runDecrypt,
}

func init() {
	// Input options
	decryptCmd.Flags().StringP("text", "t", "", "Text to decrypt")
	decryptCmd.Flags().StringP("file", "f", "", "File to decrypt")
	decryptCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")

	// Machine configuration
	decryptCmd.Flags().StringP("preset", "p", "", "Use a preset configuration (classic, simple, high, extreme)")
	decryptCmd.Flags().StringP("alphabet", "a", "auto", "Alphabet to use (auto, latin, greek, cyrillic, portuguese, ascii, alphanumeric)")
	decryptCmd.Flags().StringP("security", "s", "medium", "Security level (low, medium, high, extreme)")

	// Advanced options
	decryptCmd.Flags().StringSliceP("rotors", "r", nil, "Rotor positions (e.g., 1,5,12)")
	decryptCmd.Flags().StringSliceP("plugboard", "", nil, "Plugboard pairs (e.g., A:Z,B:Y)")
	decryptCmd.Flags().BoolP("reset", "", false, "Reset machine to initial state before decryption")

	// Input preprocessing (for legacy workflows)
	decryptCmd.Flags().BoolP("remove-spaces", "", false, "Remove spaces from input text")
	decryptCmd.Flags().BoolP("uppercase", "", false, "Convert input to uppercase")
	decryptCmd.Flags().BoolP("letters-only", "", false, "Keep only letters (A-Z, a-z)")
	decryptCmd.Flags().BoolP("alphanumeric-only", "", false, "Keep only letters and numbers")

	// Input format
	decryptCmd.Flags().StringP("format", "", "text", "Input format (text, hex, base64)")
}

func runDecrypt(cmd *cobra.Command, args []string) error {
	setupVerbose(cmd)

	// Get input text
	text, err := getInputTextForDecrypt(cmd)
	if err != nil {
		return fmt.Errorf("failed to get input text: %w", err)
	}

	if text == "" {
		return fmt.Errorf("no input text provided. Use --text, --file, or pipe to stdin")
	}

	// Apply input preprocessing
	text = preprocessInputForDecrypt(cmd, text)

	// Prevalidate operation
	if err := prevalidateOperation(cmd, text); err != nil {
		return err
	}

	// Create Enigma machine
	machine, err := createMachineFromFlags(cmd, text)
	if err != nil {
		return enhanceDecryptionError(err, text, cmd)
	}

	// Reset machine if requested
	if reset, _ := cmd.Flags().GetBool("reset"); reset {
		if err := machine.Reset(); err != nil {
			return fmt.Errorf("failed to reset machine: %w", err)
		}
	}

	// Decrypt text (same as encrypt due to Enigma's reciprocal nature)
	decrypted, err := machine.Decrypt(text)
	if err != nil {
		return enhanceDecryptionError(err, text, cmd)
	}

	// Write output (decrypt always outputs as text)
	return writeOutput(decrypted, cmd)
}

func getInputTextForDecrypt(cmd *cobra.Command) (string, error) {
	// Check for direct text input
	if text, _ := cmd.Flags().GetString("text"); text != "" {
		return parseInputFormat(text, cmd)
	}

	// Check for file input
	if filename, _ := cmd.Flags().GetString("file"); filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			return "", fmt.Errorf("failed to read file %s: %w", filename, err)
		}
		return parseInputFormat(string(data), cmd)
	}

	// Read from stdin if piped
	if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read stdin: %w", err)
		}
		return parseInputFormat(string(data), cmd)
	}

	return "", nil
}

func parseInputFormat(text string, cmd *cobra.Command) (string, error) {
	format, _ := cmd.Flags().GetString("format")

	switch strings.ToLower(format) {
	case "text", "":
		return text, nil
	case "hex":
		decoded, err := hex.DecodeString(strings.TrimSpace(text))
		if err != nil {
			return "", fmt.Errorf("invalid hex input: %w", err)
		}
		return string(decoded), nil
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
		if err != nil {
			return "", fmt.Errorf("invalid base64 input: %w", err)
		}
		return string(decoded), nil
	default:
		return "", fmt.Errorf("unknown format: %s. Available: text, hex, base64", format)
	}
}

// preprocessInputForDecrypt applies text preprocessing for decrypt command.
// Reuses the same preprocessing logic as the encrypt command.
func preprocessInputForDecrypt(cmd *cobra.Command, text string) string {
	return preprocessInput(cmd, text)
}

// enhanceDecryptionError provides helpful suggestions when decryption fails
func enhanceDecryptionError(err error, text string, cmd *cobra.Command) error {
	errStr := err.Error()

	// Check for character not found in alphabet errors
	if strings.Contains(errStr, "character") && strings.Contains(errStr, "not found in alphabet") {
		var suggestions []string

		// Check what configuration method is being used
		configFile, _ := cmd.Flags().GetString("config")
		preset, _ := cmd.Flags().GetString("preset")

		if configFile == "" {
			suggestions = append(suggestions, "• For decryption, always use the same configuration file used for encryption:")
			suggestions = append(suggestions, "  enigoma decrypt --text \"CIPHER\" --config my-key.json")
			suggestions = append(suggestions, "")
		}

		if preset != "" {
			suggestions = append(suggestions, "• Using presets for decryption is unreliable. Use the configuration file instead.")
		}

		// Add preprocessing suggestions
		if strings.Contains(text, " ") {
			suggestions = append(suggestions, "• If spaces weren't in the original cipher: add --remove-spaces")
		}

		suggestionText := strings.Join(suggestions, "\n")
		return fmt.Errorf("decryption failed: %v\n\nSuggestions:\n%s", err, suggestionText)
	}

	return fmt.Errorf("decryption failed: %w", err)
}
