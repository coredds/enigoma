// Package cli provides the command-line interface for enigoma.
//
// Copyright (c) 2025 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"

	"github.com/coredds/enigoma"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "enigoma",
	Short: "A highly customizable, Unicode-capable Enigma machine implementation",
	Long: `enigoma is a Go library and CLI tool that simulates the famous Enigma machine 
used during World War II, with modern enhancements including Unicode support,
configurable complexity, and modular design.

Examples:
  enigoma encrypt --text "Hello World" --preset classic
  enigoma decrypt --file encrypted.txt --config my-enigma.json
  enigoma keygen --security high --alphabet latin --output my-key.json
  enigoma preset --list`,
	Version: enigoma.GetVersion(),
}

// Execute runs the root command and handles errors.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(keygenCmd)
	rootCmd.AddCommand(presetCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(wizardCmd)
	rootCmd.AddCommand(demoCmd)
	rootCmd.AddCommand(examplesCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(versionCmd)

	// Global flags
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringP("config", "c", "", "Configuration file path")
}

// setupVerbose configures verbose logging if enabled.
func setupVerbose(cmd *cobra.Command) {
	verbose, _ := cmd.Flags().GetBool("verbose")
	if verbose {
		fmt.Println("Verbose mode enabled")
	}
}
