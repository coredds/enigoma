// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Validate, inspect and test configuration files",
		Long: `Validate, inspect and test configuration files.

Examples:
  enigoma config --validate my-key.json
  enigoma config --show my-key.json
  enigoma config --test my-key.json --text "HELLO"
  enigoma config --convert my-key.json --output normalized.json`,
		RunE: runConfig,
	}
	cmd.Flags().String("validate", "", "Validate a configuration file")
	cmd.Flags().StringP("show", "s", "", "Show a configuration file")
	cmd.Flags().StringP("test", "t", "", "Round-trip test a configuration file")
	cmd.Flags().String("text", "HELLOWORLD", "Text for --test")
	cmd.Flags().String("convert", "", "Re-serialize a configuration file (schema v2)")
	cmd.Flags().StringP("output", "o", "", "Output file for --convert")
	return cmd
}

func runConfig(cmd *cobra.Command, _ []string) error {
	switch {
	case flagString(cmd, "validate") != "":
		return validateConfig(cmd, flagString(cmd, "validate"))
	case flagString(cmd, "show") != "":
		return showConfig(cmd, flagString(cmd, "show"))
	case flagString(cmd, "test") != "":
		return testConfig(cmd, flagString(cmd, "test"))
	case flagString(cmd, "convert") != "":
		return convertConfig(cmd, flagString(cmd, "convert"))
	}
	return cmd.Help()
}

func validateConfig(cmd *cobra.Command, path string) error {
	m, err := loadConfig(path)
	if err != nil {
		return fmt.Errorf("%s is invalid: %w\n\nSuggestions:\n%s", path, err, suggestConfigFixes(err))
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✅ %s is valid (schema v2)\n", path)
	describeMachine(cmd, m)
	return nil
}

func showConfig(cmd *cobra.Command, path string) error {
	m, err := loadConfig(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Configuration: %s\n", path)
	describeMachine(cmd, m)
	return nil
}

func testConfig(cmd *cobra.Command, path string) error {
	m, err := loadConfig(path)
	if err != nil {
		return err
	}
	text := flagString(cmd, "text")
	w := cmd.OutOrStdout()
	ct, err := m.Encrypt(text)
	if err != nil {
		return explainCharError(cmd, err, text)
	}
	m.Reset()
	pt, err := m.Decrypt(ct)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Text:      %s\nEncrypted: %s\nDecrypted: %s\n", text, ct, pt)
	if pt != text {
		return fmt.Errorf("round-trip test failed")
	}
	fmt.Fprintln(w, "✅ Round-trip test passed")
	return nil
}

func convertConfig(cmd *cobra.Command, path string) error {
	out := flagString(cmd, "output")
	if out == "" {
		return fmt.Errorf("--convert requires --output")
	}
	m, err := loadConfig(path)
	if err != nil {
		return err
	}
	if err := saveConfig(m, out); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Configuration written to %s\n", out)
	return nil
}
