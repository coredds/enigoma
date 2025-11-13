// Package cli provides the encrypt command for the enigoma CLI.
//
// Copyright (c) 2025 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"encoding/base64"
	"encoding/hex"

	"github.com/coredds/enigoma"
	"github.com/coredds/enigoma/internal/alphabet"
	"github.com/coredds/enigoma/pkg/enigma"
	"github.com/spf13/cobra"
)

var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "Encrypt text or files using an Enigma machine",
	Long: `Encrypt plaintext using a configured Enigma machine.

QUICK START (Recommended):
  enigoma encrypt --text "Hello World!" --auto-config my-key.json
  enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json

The auto-config approach automatically detects the best alphabet for your text
and saves a reusable configuration file for decryption.

HANDLING SPECIAL CHARACTERS:
  • Spaces in text? Use --auto-config or --remove-spaces with presets
  • Mixed case? Use --auto-config or --uppercase with presets  
  • Special symbols? Use --auto-config or --alphabet ascii

INPUT METHODS:
  enigoma encrypt --text "Hello World"           # Direct text
  enigoma encrypt --file input.txt               # From file
  echo "Hello" | enigoma encrypt                 # From stdin

CONFIGURATION OPTIONS:
  enigoma encrypt --text "Hello" --auto-config key.json    # Auto-detect (recommended)
  enigoma encrypt --text "HELLO" --preset classic         # Historical presets
  enigoma encrypt --text "Hello" --alphabet ascii         # Manual alphabet
  enigoma encrypt --text "Hello" --config existing.json   # Existing config

PREPROCESSING (for presets):
  --remove-spaces     Remove spaces from input
  --uppercase         Convert to uppercase  
  --letters-only      Keep only A-Z, a-z
  --alphanumeric-only Keep only letters and numbers

DRY RUN:
  enigoma encrypt --text "Hello World" --preset classic --dry-run
  Shows what would happen without actually encrypting`,
	RunE: runEncrypt,
}

func init() {
	// Input options
	encryptCmd.Flags().StringP("text", "t", "", "Text to encrypt")
	encryptCmd.Flags().StringP("file", "f", "", "File to encrypt")
	encryptCmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")

	// Machine configuration
	encryptCmd.Flags().StringP("preset", "p", "", "Use a preset configuration (classic, simple, high, extreme)")
	encryptCmd.Flags().StringP("alphabet", "a", "auto", "Alphabet to use (auto, latin, greek, cyrillic, portuguese, ascii, alphanumeric)")
	encryptCmd.Flags().StringP("security", "s", "medium", "Security level (low, medium, high, extreme)")

	// Advanced options
	encryptCmd.Flags().StringSliceP("rotors", "r", nil, "Rotor positions (e.g., 1,5,12)")
	encryptCmd.Flags().StringSliceP("plugboard", "", nil, "Plugboard pairs (e.g., A:Z,B:Y)")
	encryptCmd.Flags().BoolP("reset", "", false, "Reset machine to initial state before encryption")

	// Configuration workflow
	encryptCmd.Flags().String("auto-config", "", "Auto-detect alphabet from input and save configuration to file")
	encryptCmd.Flags().String("save-config", "", "Save generated configuration to file (used with --preset or manual settings)")

	// Input preprocessing
	encryptCmd.Flags().BoolP("remove-spaces", "", false, "Remove spaces from input text")
	encryptCmd.Flags().BoolP("uppercase", "", false, "Convert input to uppercase")
	encryptCmd.Flags().BoolP("letters-only", "", false, "Keep only letters (A-Z, a-z)")
	encryptCmd.Flags().BoolP("alphanumeric-only", "", false, "Keep only letters and numbers")

	// Output formatting
	encryptCmd.Flags().StringP("format", "", "text", "Output format (text, hex, base64)")
	encryptCmd.Flags().BoolP("preserve-case", "", false, "Preserve original case (when possible)")
	
	// Execution options
	encryptCmd.Flags().Bool("dry-run", false, "Show what would happen without executing")
}

// nolint:gocyclo // This function handles multiple encryption paths
func runEncrypt(cmd *cobra.Command, args []string) error {
	setupVerbose(cmd)

	// Check for dry-run mode
	dryRun, _ := cmd.Flags().GetBool("dry-run")

	// Get input text
	text, err := getInputText(cmd)
	if err != nil {
		return fmt.Errorf("failed to get input text: %v", err)
	}

	if text == "" {
		return fmt.Errorf("no input text provided. Use --text, --file, or pipe to stdin")
	}

	// Apply input preprocessing
	originalText := text
	text = preprocessInput(cmd, text)

	// Apply auto-detection preprocessing if using auto-config
	if autoConfigPath, _ := cmd.Flags().GetString("auto-config"); autoConfigPath != "" {
		text = alphabet.PreprocessTextForAutoDetection(text)
	}

	// Prevalidate operation
	if err := prevalidateOperation(cmd, text); err != nil {
		return err
	}
	
	// If dry-run, show what would happen and exit
	if dryRun {
		return showDryRunInfo(cmd, originalText, text)
	}

	// Create Enigma machine with configuration-first workflow
	var machine *enigma.Enigma

	// 1) Use explicit config if provided
	if configFile, _ := cmd.Flags().GetString("config"); configFile != "" {
		machine, err = createMachineFromConfig(configFile)
		if err != nil {
			return fmt.Errorf("failed to create Enigma machine: %v", err)
		}
	} else if autoConfigPath, _ := cmd.Flags().GetString("auto-config"); autoConfigPath != "" {
		// 2) Auto-generate configuration from input text
		machine, err = createMachineWithAutoConfig(cmd, text, autoConfigPath)
		if err != nil {
			return fmt.Errorf("failed to auto-configure Enigma machine: %v", err)
		}
	} else if preset, _ := cmd.Flags().GetString("preset"); preset != "" {
		// 3) Preset (optionally save config)
		machine, err = createMachineFromPreset(preset)
		if err != nil {
			return fmt.Errorf("failed to create Enigma machine: %v", err)
		}
		if savePath, _ := cmd.Flags().GetString("save-config"); savePath != "" {
			if err := saveMachineConfig(machine, savePath); err != nil {
				return fmt.Errorf("failed to save configuration: %v", err)
			}
		}
	} else {
		// 4) Manual flags
		machine, err = createMachineFromSettings(cmd, text)
		if err != nil {
			return fmt.Errorf("failed to create Enigma machine: %v", err)
		}
	}

	// Reset machine if requested
	if reset, _ := cmd.Flags().GetBool("reset"); reset {
		if err := machine.Reset(); err != nil {
			return fmt.Errorf("failed to reset machine: %v", err)
		}
	}

	// Encrypt text
	encrypted, err := machine.Encrypt(text)
	if err != nil {
		return enhanceEncryptionError(err, text, cmd)
	}

	// Format output
	formatted, err := formatOutput(encrypted, cmd)
	if err != nil {
		return fmt.Errorf("failed to format output: %v", err)
	}

	// Write output
	return writeOutput(formatted, cmd)
}

func getInputText(cmd *cobra.Command) (string, error) {
	// Check for direct text input
	if text, _ := cmd.Flags().GetString("text"); text != "" {
		return text, nil
	}

	// Check for file input
	if filename, _ := cmd.Flags().GetString("file"); filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			return "", fmt.Errorf("failed to read file %s: %w", filename, err)
		}
		return string(data), nil
	}

	// Read from stdin if piped
	if stat, err := os.Stdin.Stat(); err == nil && (stat.Mode()&os.ModeCharDevice) == 0 {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read stdin: %w", err)
		}
		return string(data), nil
	}

	return "", nil
}

func createMachineFromFlags(cmd *cobra.Command, inputText string) (*enigma.Enigma, error) {
	// Check if config file is specified
	if configFile, _ := cmd.Flags().GetString("config"); configFile != "" {
		return createMachineFromConfig(configFile)
	}

	// Check for preset
	if preset, _ := cmd.Flags().GetString("preset"); preset != "" {
		return createMachineFromPreset(preset)
	}

	// Create machine from individual flags
	return createMachineFromSettings(cmd, inputText)
}

func createMachineFromConfig(configFile string) (*enigma.Enigma, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	return enigma.NewFromJSON(string(data))
}

func createMachineFromPreset(preset string) (*enigma.Enigma, error) {
	switch strings.ToLower(preset) {
	case "classic":
		return enigma.NewEnigmaClassic()
	case "m3":
		return enigma.NewEnigmaM3()
	case "m4":
		return enigma.NewEnigmaM4()
	case "simple":
		return enigma.NewEnigmaSimple(enigoma.AlphabetLatinUpper)
	case "low":
		return enigma.New(
			enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
			enigma.WithRandomSettings(enigma.Low),
		)
	case "medium":
		return enigma.New(
			enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
			enigma.WithRandomSettings(enigma.Medium),
		)
	case "high":
		return enigma.New(
			enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
			enigma.WithRandomSettings(enigma.High),
		)
	case "extreme":
		return enigma.New(
			enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
			enigma.WithRandomSettings(enigma.Extreme),
		)
	default:
		return nil, fmt.Errorf("unknown preset: %s. Available: classic, m3, m4, simple, low, medium, high, extreme", preset)
	}
}

func createMachineFromSettings(cmd *cobra.Command, inputText string) (*enigma.Enigma, error) {
	// Get alphabet
	alphabet, err := getAlphabetFromFlag(cmd, inputText)
	if err != nil {
		return nil, err
	}

	// Get security level
	securityLevel, err := getSecurityLevelFromFlag(cmd)
	if err != nil {
		return nil, err
	}

	// Create machine with basic settings
	machine, err := enigma.New(
		enigma.WithAlphabet(alphabet),
		enigma.WithRandomSettings(securityLevel),
	)
	if err != nil {
		return nil, err
	}

	// Apply rotor positions if specified
	if rotorPositions, _ := cmd.Flags().GetStringSlice("rotors"); len(rotorPositions) > 0 {
		positions, err := parseRotorPositions(rotorPositions)
		if err != nil {
			return nil, fmt.Errorf("invalid rotor positions: %v", err)
		}
		if err := machine.SetRotorPositions(positions); err != nil {
			return nil, fmt.Errorf("failed to set rotor positions: %v", err)
		}
	}

	if v, _ := cmd.Flags().GetBool("verbose"); v {
		fmt.Fprintln(cmd.ErrOrStderr(), "Encrypt: using manual settings")
	}
	return machine, nil
}

func getAlphabetFromFlag(cmd *cobra.Command, inputText string) ([]rune, error) {
	alphabetName, _ := cmd.Flags().GetString("alphabet")

	switch strings.ToLower(alphabetName) {
	case "auto":
		if inputText == "" {
			return nil, fmt.Errorf("alphabet=auto requires input text. Provide --text/--file or pipe via stdin, or use --auto-config to save a reusable configuration")
		}
		detected, err := alphabet.AutoDetectFromText(inputText)
		if err != nil {
			return nil, fmt.Errorf("auto-detect alphabet: %w", err)
		}
		if v, _ := cmd.Flags().GetBool("verbose"); v {
			fmt.Fprintf(cmd.ErrOrStderr(), "Auto-detected alphabet size: %d\n", detected.Size())
		}
		return detected.Runes(), nil
	case "latin", "latin-upper":
		return enigoma.AlphabetLatinUpper, nil
	case "latin-lower":
		return enigoma.AlphabetLatinLower, nil
	case "greek":
		return enigoma.AlphabetGreek, nil
	case "cyrillic":
		return enigoma.AlphabetCyrillic, nil
	case "portuguese":
		return enigoma.AlphabetPortuguese, nil
	case "ascii":
		return enigoma.AlphabetASCIIPrintable, nil
	case "alphanumeric":
		return enigoma.AlphabetAlphaNumeric, nil
	case "digits":
		return enigoma.AlphabetDigits, nil
	default:
		return nil, fmt.Errorf("unknown alphabet: %s. Available: auto, latin, greek, cyrillic, portuguese, ascii, alphanumeric, digits", alphabetName)
	}
}

func getSecurityLevelFromFlag(cmd *cobra.Command) (enigma.SecurityLevel, error) {
	securityName, _ := cmd.Flags().GetString("security")

	switch strings.ToLower(securityName) {
	case "low":
		return enigma.Low, nil
	case "medium":
		return enigma.Medium, nil
	case "high":
		return enigma.High, nil
	case "extreme":
		return enigma.Extreme, nil
	default:
		return enigma.Medium, fmt.Errorf("unknown security level: %s. Available: low, medium, high, extreme", securityName)
	}
}

func parseRotorPositions(positions []string) ([]int, error) {
	result := make([]int, len(positions))
	for i, pos := range positions {
		var err error
		result[i], err = parseIntFromString(pos)
		if err != nil {
			return nil, fmt.Errorf("invalid position '%s': %v", pos, err)
		}
	}
	return result, nil
}

func parseIntFromString(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &result)
	return result, err
}

func formatOutput(text string, cmd *cobra.Command) (string, error) {
	format, _ := cmd.Flags().GetString("format")

	switch strings.ToLower(format) {
	case "text", "":
		return text, nil
	case "hex":
		return hex.EncodeToString([]byte(text)), nil
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(text)), nil
	default:
		return "", fmt.Errorf("unknown format: %s. Available: text, hex, base64", format)
	}
}

func writeOutput(text string, cmd *cobra.Command) error {
	outputFile, _ := cmd.Flags().GetString("output")

	if outputFile == "" {
		fmt.Fprint(cmd.OutOrStdout(), text)
		return nil
	}

	return os.WriteFile(outputFile, []byte(text), 0600)
}

// createMachineWithAutoConfig builds an Enigma machine by auto-detecting the alphabet
// from the provided text, applies random settings per selected security level, and saves
// the resulting configuration JSON to the provided path.
func createMachineWithAutoConfig(cmd *cobra.Command, text string, savePath string) (*enigma.Enigma, error) {
	// Auto-detect alphabet from input text
	detectedAlphabet, err := alphabet.AutoDetectFromText(text)
	if err != nil {
		return nil, fmt.Errorf("auto-detect alphabet: %w", err)
	}

	// Get security level
	securityLevel, err := getSecurityLevelFromFlag(cmd)
	if err != nil {
		return nil, err
	}

	// Create machine
	machine, err := enigma.New(
		enigma.WithAlphabet(detectedAlphabet.Runes()),
		enigma.WithRandomSettings(securityLevel),
	)
	if err != nil {
		return nil, err
	}

	// Apply rotor positions if specified
	if rotorPositions, _ := cmd.Flags().GetStringSlice("rotors"); len(rotorPositions) > 0 {
		positions, err := parseRotorPositions(rotorPositions)
		if err != nil {
			return nil, fmt.Errorf("invalid rotor positions: %v", err)
		}
		if err := machine.SetRotorPositions(positions); err != nil {
			return nil, fmt.Errorf("failed to set rotor positions: %v", err)
		}
	}

	// Save configuration
	if err := saveMachineConfig(machine, savePath); err != nil {
		return nil, err
	}

	if v, _ := cmd.Flags().GetBool("verbose"); v {
		fmt.Fprintf(cmd.ErrOrStderr(), "Auto-detected alphabet with %d characters\n", len(detectedAlphabet.Runes()))
		fmt.Fprintf(cmd.ErrOrStderr(), "Auto-generated configuration saved to: %s\n", savePath)
	}
	return machine, nil
}

func saveMachineConfig(machine *enigma.Enigma, path string) error {
	jsonData, err := machine.SaveSettingsToJSON()
	if err != nil {
		return fmt.Errorf("serialize configuration: %w", err)
	}
	if err := os.WriteFile(path, []byte(jsonData), 0600); err != nil {
		return fmt.Errorf("write configuration to %s: %w", path, err)
	}
	return nil
}

// preprocessInput applies various text preprocessing options based on flags
func preprocessInput(cmd *cobra.Command, text string) string {
	result := text

	// Apply basic transformations
	result = applyBasicTransformations(cmd, result)

	// Apply character filtering
	result = applyCharacterFiltering(cmd, result)

	if verbose, _ := cmd.Flags().GetBool("verbose"); verbose && result != text {
		fmt.Fprintf(cmd.ErrOrStderr(), "Input preprocessed: %q -> %q\n", text, result)
	}

	return result
}

// enhanceEncryptionError provides helpful suggestions when encryption fails
func enhanceEncryptionError(err error, text string, cmd *cobra.Command) error {
	errStr := err.Error()

	// Check for character not found in alphabet errors
	if strings.Contains(errStr, "character") && strings.Contains(errStr, "not found in alphabet") {
		// Extract the problematic character if possible
		var suggestions []string

		// Check what preset/alphabet is being used
		preset, _ := cmd.Flags().GetString("preset")
		alphabet, _ := cmd.Flags().GetString("alphabet")

		if preset != "" && preset != "auto" {
			suggestions = append(suggestions, fmt.Sprintf("• Preset '%s' uses a limited alphabet. Try --auto-config instead:", preset))
			suggestions = append(suggestions, fmt.Sprintf("  enigoma encrypt --text %q --auto-config my-key.json", text))
		}

		if alphabet == "latin" || alphabet == "latin-upper" {
			suggestions = append(suggestions, "• Latin alphabet doesn't include spaces/punctuation. Try:")
			suggestions = append(suggestions, "  --remove-spaces (remove spaces)")
			suggestions = append(suggestions, "  --letters-only (keep only A-Z, a-z)")
			suggestions = append(suggestions, "  --alphabet ascii (include all printable characters)")
			suggestions = append(suggestions, "  --alphabet auto (auto-detect from input)")
		}

		// Always suggest auto-config as the simplest solution
		if len(suggestions) == 0 {
			suggestions = append(suggestions, "• Try auto-detecting the alphabet:")
			suggestions = append(suggestions, fmt.Sprintf("  enigoma encrypt --text %q --auto-config my-key.json", text))
		}

		// Add preprocessing suggestions
		if strings.Contains(text, " ") {
			suggestions = append(suggestions, "• To remove spaces: add --remove-spaces")
		}
		if hasLowercase(text) {
			suggestions = append(suggestions, "• To convert to uppercase: add --uppercase")
		}

		suggestionText := strings.Join(suggestions, "\n")
		return fmt.Errorf("encryption failed: %v\n\nSuggestions:\n%s", err, suggestionText)
	}

	return fmt.Errorf("encryption failed: %v", err)
}

// hasLowercase checks if the text contains lowercase letters
func hasLowercase(text string) bool {
	for _, r := range text {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

// applyBasicTransformations applies remove-spaces and uppercase transformations
func applyBasicTransformations(cmd *cobra.Command, text string) string {
	result := text

	if removeSpaces, _ := cmd.Flags().GetBool("remove-spaces"); removeSpaces {
		result = strings.ReplaceAll(result, " ", "")
	}

	if uppercase, _ := cmd.Flags().GetBool("uppercase"); uppercase {
		result = strings.ToUpper(result)
	}

	return result
}

// applyCharacterFiltering applies letters-only and alphanumeric-only filtering
func applyCharacterFiltering(cmd *cobra.Command, text string) string {
	result := text

	if lettersOnly, _ := cmd.Flags().GetBool("letters-only"); lettersOnly {
		result = filterLettersOnly(result)
	}

	if alphanumericOnly, _ := cmd.Flags().GetBool("alphanumeric-only"); alphanumericOnly {
		result = filterAlphanumericOnly(result)
	}

	return result
}

// filterLettersOnly keeps only letters (A-Z, a-z)
func filterLettersOnly(text string) string {
	var filtered strings.Builder
	for _, r := range text {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			filtered.WriteRune(r)
		}
	}
	return filtered.String()
}

// filterAlphanumericOnly keeps only letters and numbers
func filterAlphanumericOnly(text string) string {
	var filtered strings.Builder
	for _, r := range text {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			filtered.WriteRune(r)
		}
	}
	return filtered.String()
}

// showDryRunInfo displays what would happen without executing the encryption
func showDryRunInfo(cmd *cobra.Command, originalText, processedText string) error {
	fmt.Println("=== DRY RUN MODE ===")
	fmt.Println("No encryption will be performed. Showing what would happen:")
	fmt.Println()
	
	// Input information
	fmt.Println("INPUT:")
	fmt.Printf("  Original text: %q\n", truncateForDisplay(originalText, 100))
	fmt.Printf("  Text length: %d characters\n", len(originalText))
	
	if originalText != processedText {
		fmt.Printf("  After preprocessing: %q\n", truncateForDisplay(processedText, 100))
		fmt.Printf("  Processed length: %d characters\n", len(processedText))
	}
	fmt.Println()
	
	// Configuration information
	fmt.Println("CONFIGURATION:")
	
	if configFile, _ := cmd.Flags().GetString("config"); configFile != "" {
		fmt.Printf("  Using config file: %s\n", configFile)
	} else if autoConfigPath, _ := cmd.Flags().GetString("auto-config"); autoConfigPath != "" {
		fmt.Printf("  Auto-config mode: Will detect alphabet and save to %s\n", autoConfigPath)
		
		// Detect unique characters
		uniqueChars := make(map[rune]bool)
		for _, r := range processedText {
			uniqueChars[r] = true
		}
		
		// Convert to sorted slice for display
		chars := make([]rune, 0, len(uniqueChars))
		for r := range uniqueChars {
			chars = append(chars, r)
		}
		
		fmt.Printf("  Detected alphabet size: %d characters\n", len(chars))
		if len(chars) > 0 {
			fmt.Printf("  Sample characters: %s\n", truncateForDisplay(string(chars), 50))
		}
		
		security, _ := cmd.Flags().GetString("security")
		fmt.Printf("  Security level: %s\n", security)
	} else if preset, _ := cmd.Flags().GetString("preset"); preset != "" {
		fmt.Printf("  Using preset: %s\n", preset)
		
		if saveConfig, _ := cmd.Flags().GetString("save-config"); saveConfig != "" {
			fmt.Printf("  Will save config to: %s\n", saveConfig)
		}
	} else {
		alphabetName, _ := cmd.Flags().GetString("alphabet")
		security, _ := cmd.Flags().GetString("security")
		fmt.Printf("  Alphabet: %s\n", alphabetName)
		fmt.Printf("  Security level: %s\n", security)
		
		if saveConfig, _ := cmd.Flags().GetString("save-config"); saveConfig != "" {
			fmt.Printf("  Will save config to: %s\n", saveConfig)
		}
	}
	fmt.Println()
	
	// Preprocessing information
	if hasPreprocessing(cmd) {
		fmt.Println("PREPROCESSING:")
		if removeSpaces, _ := cmd.Flags().GetBool("remove-spaces"); removeSpaces {
			fmt.Println("  ✓ Remove spaces")
		}
		if uppercase, _ := cmd.Flags().GetBool("uppercase"); uppercase {
			fmt.Println("  ✓ Convert to uppercase")
		}
		if lettersOnly, _ := cmd.Flags().GetBool("letters-only"); lettersOnly {
			fmt.Println("  ✓ Keep only letters (A-Z, a-z)")
		}
		if alphanumericOnly, _ := cmd.Flags().GetBool("alphanumeric-only"); alphanumericOnly {
			fmt.Println("  ✓ Keep only letters and numbers")
		}
		fmt.Println()
	}
	
	// Output information
	fmt.Println("OUTPUT:")
	format, _ := cmd.Flags().GetString("format")
	fmt.Printf("  Format: %s\n", format)
	
	if outputFile, _ := cmd.Flags().GetString("output"); outputFile != "" {
		fmt.Printf("  Output file: %s\n", outputFile)
	} else {
		fmt.Println("  Output: stdout")
	}
	fmt.Println()
	
	fmt.Println("NEXT STEPS:")
	fmt.Println("  Remove --dry-run flag to perform actual encryption")
	
	return nil
}

// hasPreprocessing checks if any preprocessing flags are enabled
func hasPreprocessing(cmd *cobra.Command) bool {
	removeSpaces, _ := cmd.Flags().GetBool("remove-spaces")
	uppercase, _ := cmd.Flags().GetBool("uppercase")
	lettersOnly, _ := cmd.Flags().GetBool("letters-only")
	alphanumericOnly, _ := cmd.Flags().GetBool("alphanumeric-only")
	
	return removeSpaces || uppercase || lettersOnly || alphanumericOnly
}

// truncateForDisplay truncates text for display purposes
func truncateForDisplay(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}
	return text[:maxLen] + "..."
}
