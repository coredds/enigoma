// Package cli provides the wizard command for the enigoma CLI.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var wizardCmd = &cobra.Command{
	Use:   "wizard",
	Short: "Interactive wizard for beginners",
	Long: `Interactive wizard to guide you through encrypting or decrypting text.

This wizard will ask you simple questions and generate the appropriate
enigoma command for you. Perfect for beginners!

The wizard will:
• Help you choose between encryption and decryption
• Guide you through providing input text
• Suggest the best configuration approach
• Generate and execute the appropriate command
• Save configuration files for later use

Example:
  enigoma wizard`,
	RunE: runWizard,
}

func init() {
	// Add wizard to root command in root.go
}

func runWizard(cmd *cobra.Command, args []string) error {
	fmt.Println("🔐 Welcome to the enigoma Interactive Wizard!")
	fmt.Println("Let's help you encrypt or decrypt your text step by step.")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	// Step 1: Choose operation
	operation, err := askOperation(reader)
	if err != nil {
		return err
	}

	if operation == "encrypt" {
		return runEncryptWizard(reader)
	} else {
		return runDecryptWizard(reader)
	}
}

func askOperation(reader *bufio.Reader) (string, error) {
	fmt.Println("📝 What would you like to do?")
	fmt.Println("1) Encrypt text (turn readable text into secret code)")
	fmt.Println("2) Decrypt text (turn secret code back into readable text)")
	fmt.Print("\nEnter your choice (1 or 2): ")

	choice, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read input: %w", err)
	}

	choice = strings.TrimSpace(choice)
	switch choice {
	case "1":
		return "encrypt", nil
	case "2":
		return "decrypt", nil
	default:
		fmt.Println("❌ Invalid choice. Please enter 1 or 2.")
		return askOperation(reader) // Recursive retry
	}
}

func runEncryptWizard(reader *bufio.Reader) error {
	fmt.Println("\n🔒 ENCRYPTION WIZARD")
	fmt.Println("=====================")

	// Step 1: Get input text
	inputText, inputFile, err := getWizardInputText(reader)
	if err != nil {
		return err
	}

	// Step 2: Choose approach
	approachChoice, err := getWizardApproach(reader)
	if err != nil {
		return err
	}

	// Step 3: Get configuration file name
	configFile, err := getWizardConfigFile(reader)
	if err != nil {
		return err
	}

	// Build command
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "encrypt")

	if inputText != "" {
		cmdArgs = append(cmdArgs, "--text", inputText)
	} else {
		cmdArgs = append(cmdArgs, "--file", inputFile)
	}

	switch approachChoice {
	case "1":
		// Auto-config
		cmdArgs = append(cmdArgs, "--auto-config", configFile)
	case "2":
		// Historical preset
		preset := askPreset(reader)
		cmdArgs = append(cmdArgs, "--preset", preset, "--save-config", configFile)

		// Check if input has special characters
		checkText := inputText
		if inputText == "" {
			// For file input, we'll trust the user or show a warning
			fmt.Println("\n⚠️  Note: If your file contains spaces or special characters,")
			fmt.Println("   the encryption might fail. Consider using auto-config instead.")
		} else if needsPreprocessing(checkText) {
			fmt.Println("\n⚠️  Your text contains spaces or special characters.")
			fmt.Println("   Adding preprocessing options to make it work with presets...")
			if strings.Contains(checkText, " ") {
				cmdArgs = append(cmdArgs, "--remove-spaces")
			}
			if hasLowercase(checkText) {
				cmdArgs = append(cmdArgs, "--uppercase")
			}
			if hasSpecialChars(checkText) {
				cmdArgs = append(cmdArgs, "--letters-only")
			}
		}
	case "3":
		// Custom settings
		alphabet := askAlphabet(reader)
		security, err := getWizardSecurityLevel(reader)
		if err != nil {
			return err
		}
		cmdArgs = append(cmdArgs, "--alphabet", alphabet, "--security", security, "--save-config", configFile)
	default:
		return fmt.Errorf("invalid approach choice: %s", approachChoice)
	}

	// Add verbose for better feedback
	cmdArgs = append(cmdArgs, "--verbose")

	// Execute command
	fmt.Printf("\n🚀 Executing command: enigoma %s\n\n", strings.Join(cmdArgs, " "))

	// Create and execute the encrypt command
	encryptCmd.SetArgs(cmdArgs[1:]) // Remove 'encrypt' from args
	err = encryptCmd.Execute()
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Success message
	fmt.Printf("\n✅ Success! Your text has been encrypted.\n")
	fmt.Printf("📋 Configuration saved to: %s\n", configFile)
	fmt.Printf("🔑 To decrypt later, use: enigoma decrypt --text \"ENCRYPTED_TEXT\" --config %s\n", configFile)

	return nil
}

func runDecryptWizard(reader *bufio.Reader) error {
	fmt.Println("\n🔓 DECRYPTION WIZARD")
	fmt.Println("====================")

	// Step 1: Get encrypted text
	fmt.Println("\n📄 How would you like to provide the encrypted text?")
	inputText, inputFile, err := getWizardInputText(reader)
	if err != nil {
		return err
	}

	// Step 2: Get configuration file
	fmt.Print("\n🔑 Enter the path to your configuration file (.json): ")
	configFile, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read config file path: %w", err)
	}
	configFile = strings.TrimSpace(configFile)

	// Validate config file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// Try with .json extension
		if !strings.HasSuffix(configFile, ".json") {
			configFile += ".json"
		}
		if _, err := os.Stat(configFile); os.IsNotExist(err) {
			return fmt.Errorf("configuration file does not exist: %s", configFile)
		}
	}

	// Step 3: Check input format
	fmt.Println("\n📋 What format is your encrypted text in?")
	fmt.Println("1) Plain text (default)")
	fmt.Println("2) Hexadecimal (like: 48656c6c6f)")
	fmt.Println("3) Base64 (like: SGVsbG8=)")
	fmt.Print("\nEnter your choice (1, 2, or 3): ")

	formatChoice, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read format choice: %w", err)
	}

	formatChoice = strings.TrimSpace(formatChoice)

	// Build command
	var cmdArgs []string
	cmdArgs = append(cmdArgs, "decrypt")

	if inputText != "" {
		cmdArgs = append(cmdArgs, "--text", inputText)
	} else {
		cmdArgs = append(cmdArgs, "--file", inputFile)
	}

	cmdArgs = append(cmdArgs, "--config", configFile)

	switch formatChoice {
	case "1", "":
		// Plain text - no format flag needed
	case "2":
		cmdArgs = append(cmdArgs, "--format", "hex")
	case "3":
		cmdArgs = append(cmdArgs, "--format", "base64")
	default:
		return fmt.Errorf("invalid format choice: %s", formatChoice)
	}

	// Add verbose for better feedback
	cmdArgs = append(cmdArgs, "--verbose")

	// Execute command
	fmt.Printf("\n🚀 Executing command: enigoma %s\n\n", strings.Join(cmdArgs, " "))

	// Create and execute the decrypt command
	decryptCmd.SetArgs(cmdArgs[1:]) // Remove 'decrypt' from args
	err = decryptCmd.Execute()
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	fmt.Println("\n✅ Decryption completed!")
	return nil
}

func askPreset(reader *bufio.Reader) string {
	fmt.Println("\n🎨 Choose a historical preset:")
	fmt.Println("1) classic - Traditional 3-rotor Enigma (low security)")
	fmt.Println("2) m3 - Historically accurate Enigma M3")
	fmt.Println("3) m4 - Historically accurate Naval Enigma M4")
	fmt.Println("4) high - High security (8 rotors, 15 plugboard pairs)")
	fmt.Println("5) extreme - Maximum security (12 rotors, 20 plugboard pairs)")
	fmt.Print("\nEnter your choice (1-5): ")

	choice, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input, defaulting to classic")
		return "classic"
	}

	choice = strings.TrimSpace(choice)
	switch choice {
	case "1":
		return "classic"
	case "2":
		return "m3"
	case "3":
		return "m4"
	case "4":
		return "high"
	case "5":
		return "extreme"
	default:
		fmt.Println("Invalid choice, defaulting to classic")
		return "classic"
	}
}

func askAlphabet(reader *bufio.Reader) string {
	fmt.Println("\n🔤 Choose an alphabet:")
	fmt.Println("1) auto - Automatically detect from your text (recommended)")
	fmt.Println("2) latin - A-Z only (classic)")
	fmt.Println("3) ascii - All printable characters (spaces, symbols, etc.)")
	fmt.Println("4) alphanumeric - Letters and numbers only")
	fmt.Println("5) greek - Greek alphabet")
	fmt.Println("6) cyrillic - Cyrillic alphabet")
	fmt.Print("\nEnter your choice (1-6): ")

	choice, err := reader.ReadString('\n')
	if err != nil {
		fmt.Println("Error reading input, defaulting to auto")
		return "auto"
	}

	choice = strings.TrimSpace(choice)
	switch choice {
	case "1":
		return "auto"
	case "2":
		return "latin"
	case "3":
		return "ascii"
	case "4":
		return "alphanumeric"
	case "5":
		return "greek"
	case "6":
		return "cyrillic"
	default:
		fmt.Println("Invalid choice, defaulting to auto")
		return "auto"
	}
}

func needsPreprocessing(text string) bool {
	return strings.Contains(text, " ") || hasLowercase(text) || hasSpecialChars(text)
}

func hasSpecialChars(text string) bool {
	for _, r := range text {
		if (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != ' ' {
			return true
		}
	}
	return false
}

// getWizardInputText handles input text collection for the wizard
func getWizardInputText(reader *bufio.Reader) (inputText, inputFile string, err error) {
	fmt.Println("\n📄 How would you like to provide the text to encrypt?")
	fmt.Println("1) Type it directly")
	fmt.Println("2) Read from a file")
	fmt.Print("\nEnter your choice (1 or 2): ")

	inputChoice, err := reader.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("failed to read input: %w", err)
	}

	inputChoice = strings.TrimSpace(inputChoice)
	switch inputChoice {
	case "1":
		fmt.Print("\n📝 Enter the text to encrypt: ")
		inputText, err = reader.ReadString('\n')
		if err != nil {
			return "", "", fmt.Errorf("failed to read text: %w", err)
		}
		inputText = strings.TrimSpace(inputText)
		return inputText, "", nil
	case "2":
		fmt.Print("\n📁 Enter the file path: ")
		inputFile, err = reader.ReadString('\n')
		if err != nil {
			return "", "", fmt.Errorf("failed to read file path: %w", err)
		}
		inputFile = strings.TrimSpace(inputFile)

		// Validate file exists
		if _, err := os.Stat(inputFile); os.IsNotExist(err) {
			return "", "", fmt.Errorf("file does not exist: %s", inputFile)
		}
		return "", inputFile, nil
	default:
		return "", "", fmt.Errorf("invalid choice. Please enter 1 or 2")
	}
}

// getWizardSecurityLevel handles security level selection for the wizard
func getWizardSecurityLevel(reader *bufio.Reader) (string, error) {
	fmt.Println("\n🛡️ Choose security level:")
	fmt.Println("1) Low (3 rotors, 2 plugboard pairs)")
	fmt.Println("2) Medium (5 rotors, 8 plugboard pairs)")
	fmt.Println("3) High (8 rotors, 15 plugboard pairs)")
	fmt.Println("4) Extreme (12 rotors, 20 plugboard pairs)")
	fmt.Print("\nEnter your choice (1-4): ")

	secChoice, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read security choice: %w", err)
	}

	secChoice = strings.TrimSpace(secChoice)
	switch secChoice {
	case "1":
		return "low", nil
	case "2":
		return "medium", nil
	case "3":
		return "high", nil
	case "4":
		return "extreme", nil
	default:
		return "", fmt.Errorf("invalid choice. Please enter 1-4")
	}
}

// getWizardApproach handles approach selection for the wizard
func getWizardApproach(reader *bufio.Reader) (string, error) {
	fmt.Println("\n⚙️  Which approach would you prefer?")
	fmt.Println("1) 🎯 Auto-config (recommended) - automatically detect the best settings")
	fmt.Println("2) 🎨 Historical preset - use classic Enigma machine settings")
	fmt.Println("3) 🔧 Custom settings - choose alphabet and security level manually")
	fmt.Print("\nEnter your choice (1, 2, or 3): ")

	approachChoice, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read approach choice: %w", err)
	}

	return strings.TrimSpace(approachChoice), nil
}

// getWizardConfigFile handles config file name input for the wizard
func getWizardConfigFile(reader *bufio.Reader) (string, error) {
	fmt.Print("\n💾 Enter a name for your configuration file (without extension): ")
	configName, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("failed to read config name: %w", err)
	}
	configName = strings.TrimSpace(configName)
	if configName == "" {
		configName = "my-enigma-config"
	}
	return configName + ".json", nil
}
