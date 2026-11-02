// Package cli provides the command-line interface for enigoma.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"

	"github.com/coredds/enigoma"
	"github.com/spf13/cobra"
)

// newRootCmd builds a fresh command tree. Tests use it to avoid shared flag state.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "enigoma",
		Short: "A historically accurate, Unicode-capable Enigma machine",
		Long: `enigoma is a Go library and CLI that simulates the Enigma machine used in
World War II, with historically accurate stepping, extensible alphabets and an
interactive terminal visualizer.

Examples:
  enigoma encrypt --text "Hello World!" --auto-config my-key.json
  enigoma decrypt --text "CIPHERTEXT" --config my-key.json
  enigoma encrypt --text "HELLO" --preset m3 --positions ADU
  enigoma keygen --security high --output my-key.json
  enigoma preset --list`,
		Version:       enigoma.GetVersion(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output (to stderr)")
	root.PersistentFlags().StringP("config", "c", "", "Configuration file path")

	root.AddCommand(
		newEncryptCmd(),
		newDecryptCmd(),
		newKeygenCmd(),
		newPresetCmd(),
		newConfigCmd(),
		newTuiCmd(),
		newWizardCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the CLI.
func Execute() error {
	return newRootCmd().Execute()
}

// verbosef prints to stderr when --verbose is set, keeping stdout clean for output.
func verbosef(cmd *cobra.Command, format string, args ...any) {
	if v, _ := cmd.Flags().GetBool("verbose"); v {
		fmt.Fprintf(cmd.ErrOrStderr(), format, args...)
	}
}
