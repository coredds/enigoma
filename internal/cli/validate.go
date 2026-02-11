// Package cli provides configuration validation utilities.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/coredds/enigoma/pkg/enigma"
	"github.com/spf13/cobra"
)

// validateConfigFile validates a configuration file before using it
func validateConfigFile(configPath string, cmd *cobra.Command) error {
	if configPath == "" {
		return nil // No config file to validate
	}

	// Check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		// Try with .json extension
		if !strings.HasSuffix(configPath, ".json") {
			altPath := configPath + ".json"
			if _, err := os.Stat(altPath); err == nil {
				configPath = altPath
			} else {
				return fmt.Errorf("configuration file not found: %s (also tried %s)", configPath, altPath)
			}
		} else {
			return fmt.Errorf("configuration file not found: %s", configPath)
		}
	}

	// Try to load and validate the configuration
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file %s: %v", configPath, err)
	}

	// Attempt to create machine from config to validate
	_, err = enigma.NewFromJSON(string(data))
	if err != nil {
		return fmt.Errorf("invalid configuration file %s: %v", configPath, err)
	}

	if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
		fmt.Fprintf(cmd.ErrOrStderr(), "✅ Configuration file validated: %s\n", configPath)
	}

	return nil
}

// suggestConfigFixes provides suggestions when config validation fails
func suggestConfigFixes(err error, configPath string) string {
	errStr := err.Error()
	var suggestions []string

	if strings.Contains(errStr, "not found") {
		suggestions = append(suggestions, "• Check the file path is correct")
		suggestions = append(suggestions, "• Make sure you're in the right directory")
		suggestions = append(suggestions, "• Use an absolute path if needed")
	}

	if strings.Contains(errStr, "invalid") || strings.Contains(errStr, "unmarshal") {
		suggestions = append(suggestions, "• The configuration file may be corrupted")
		suggestions = append(suggestions, "• Try generating a new configuration:")
		suggestions = append(suggestions, "  enigoma keygen --output new-config.json")
		suggestions = append(suggestions, "• Validate the JSON syntax online")
	}

	if strings.Contains(errStr, "schema") {
		suggestions = append(suggestions, "• The configuration format may be outdated")
		suggestions = append(suggestions, "• Try updating to the latest format:")
		suggestions = append(suggestions, fmt.Sprintf("  enigoma config --convert %s --output updated-config.json", configPath))
	}

	if len(suggestions) == 0 {
		suggestions = append(suggestions, "• Try creating a new configuration file:")
		suggestions = append(suggestions, "  enigoma keygen --output new-config.json")
	}

	return strings.Join(suggestions, "\n")
}

// prevalidateOperation performs validation before encrypt/decrypt operations
func prevalidateOperation(cmd *cobra.Command, text string) error {
	// Validate configuration file if provided
	configFile, _ := cmd.Flags().GetString("config")
	if err := validateConfigFile(configFile, cmd); err != nil {
		suggestions := suggestConfigFixes(err, configFile)
		return fmt.Errorf("%v\n\nSuggestions:\n%s", err, suggestions)
	}

	// Validate input text
	if text == "" {
		return fmt.Errorf("no input text provided")
	}

	// Check for common issues with preset usage
	preset, _ := cmd.Flags().GetString("preset")
	if preset != "" && configFile == "" {
		if needsPreprocessing(text) {
			if verbose, _ := cmd.Flags().GetBool("verbose"); verbose {
				fmt.Fprintf(cmd.ErrOrStderr(), "⚠️  Warning: Your text contains spaces/special characters.\n")
				fmt.Fprintf(cmd.ErrOrStderr(), "   Consider using preprocessing flags or --auto-config instead.\n")
			}
		}
	}

	return nil
}
