// Package cli provides the keygen command for the enigoma CLI.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"
	mrand "math/rand"
	"os"

	"github.com/coredds/enigoma"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate random Enigma machine configurations",
	Long: `Generate random Enigma machine configurations with specified parameters.

The generated configuration can be saved to a file and used later with the
--config flag in encrypt/decrypt commands.

Examples:
  enigoma keygen --security high --alphabet latin --output my-key.json
  enigoma keygen --preset classic --output classic-key.json
  enigoma keygen --security extreme --alphabet portuguese --save-to keys/extreme-pt.json`,
	RunE: runKeygen,
}

func init() {
	// Machine configuration
	keygenCmd.Flags().StringP("preset", "p", "", "Base preset to modify (classic, simple, low, medium, high, extreme)")
	keygenCmd.Flags().StringP("alphabet", "a", "latin", "Alphabet to use (latin, greek, cyrillic, portuguese, ascii, alphanumeric)")
	keygenCmd.Flags().StringP("security", "s", "medium", "Security level (low, medium, high, extreme)")

	// Output options
	keygenCmd.Flags().StringP("output", "o", "", "Output file for the configuration (default: stdout)")
	keygenCmd.Flags().StringP("save-to", "", "", "Save configuration to file (alias for --output)")
	keygenCmd.Flags().StringP("format", "f", "json", "Output format (json, yaml)")

	// Advanced options
	keygenCmd.Flags().IntP("rotors", "r", 0, "Number of rotors (overrides security level)")
	keygenCmd.Flags().IntP("plugboard-pairs", "", 0, "Number of plugboard pairs (overrides security level)")
	keygenCmd.Flags().BoolP("random-positions", "", true, "Generate random rotor positions")
	keygenCmd.Flags().Int64("seed", 0, "Deterministic seed for rotor positions (optional)")

	// Information options
	keygenCmd.Flags().BoolP("describe", "d", false, "Show description of generated configuration")
	keygenCmd.Flags().BoolP("stats", "", false, "Show statistics about the configuration")
}

func runKeygen(cmd *cobra.Command, args []string) error {
	setupVerbose(cmd)

	// Create machine based on parameters
	machine, err := createMachineFromFlags(cmd, "")
	if err != nil {
		return fmt.Errorf("failed to create Enigma machine: %w", err)
	}

	// Apply rotor positions if requested
	if randomPos, _ := cmd.Flags().GetBool("random-positions"); randomPos {
		if cmd.Flags().Changed("seed") {
			seed, _ := cmd.Flags().GetInt64("seed")
			if err := setSeededRotorPositions(machine, seed); err != nil {
				return fmt.Errorf("failed to set seeded rotor positions: %w", err)
			}
		} else {
			if err := enigoma.WithRandomRotorPositions()(machine); err != nil {
				return fmt.Errorf("failed to set random rotor positions: %w", err)
			}
		}
	}

	// Machine is ready for configuration export

	// Show description if requested
	if describe, _ := cmd.Flags().GetBool("describe"); describe {
		showConfigurationDescription(machine, cmd)
	}

	// Show stats if requested
	if stats, _ := cmd.Flags().GetBool("stats"); stats {
		showConfigurationStats(machine, cmd)
	}

	// Convert to JSON
	jsonData, err := machine.SaveSettingsToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize settings: %w", err)
	}

	// Output the configuration
	outputFile, _ := cmd.Flags().GetString("output")
	if outputFile == "" {
		outputFile, _ = cmd.Flags().GetString("save-to")
	}

	if outputFile == "" {
		fmt.Fprint(cmd.OutOrStdout(), jsonData)
	} else {
		err := writeStringToFile(jsonData, outputFile)
		if err != nil {
			return fmt.Errorf("failed to write configuration to file: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Configuration saved to: %s\n", outputFile)
	}

	return nil
}

func showConfigurationDescription(machine *enigoma.Enigma, cmd *cobra.Command) {
	fmt.Fprintf(cmd.OutOrStdout(), "Configuration Description:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Alphabet Size: %d characters\n", machine.GetAlphabetSize())
	fmt.Fprintf(cmd.OutOrStdout(), "  Rotors: %d\n", machine.GetRotorCount())
	fmt.Fprintf(cmd.OutOrStdout(), "  Plugboard Pairs: %d\n", machine.GetPlugboardPairCount())
	fmt.Fprintf(cmd.OutOrStdout(), "  Current Rotor Positions: %v\n", machine.GetCurrentRotorPositions())
	fmt.Fprintf(cmd.OutOrStdout(), "\n")
}

func showConfigurationStats(machine *enigoma.Enigma, cmd *cobra.Command) {
	alphabetSize := machine.GetAlphabetSize()
	rotorCount := machine.GetRotorCount()
	plugboardPairs := machine.GetPlugboardPairCount()

	// Calculate approximate keyspace (simplified calculation)
	rotorCombinations := calculateFactorial(rotorCount)
	rotorPositions := calculatePower(alphabetSize, rotorCount)
	plugboardCombinations := calculatePlugboardCombinations(alphabetSize, plugboardPairs)

	fmt.Fprintf(cmd.OutOrStdout(), "Configuration Statistics:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Rotor Combinations: ~%g\n", float64(rotorCombinations))
	fmt.Fprintf(cmd.OutOrStdout(), "  Rotor Position Combinations: %d\n", rotorPositions)
	fmt.Fprintf(cmd.OutOrStdout(), "  Plugboard Combinations: ~%g\n", float64(plugboardCombinations))
	fmt.Fprintf(cmd.OutOrStdout(), "  Approximate Total Keyspace: ~%g\n",
		float64(rotorCombinations)*float64(rotorPositions)*float64(plugboardCombinations))
	fmt.Fprintf(cmd.OutOrStdout(), "\n")
}

func calculateFactorial(n int) int64 {
	if n <= 1 {
		return 1
	}
	result := int64(1)
	for i := 2; i <= n; i++ {
		result *= int64(i)
	}
	return result
}

func calculatePower(base, exp int) int {
	if exp == 0 {
		return 1
	}
	result := 1
	for i := 0; i < exp; i++ {
		result *= base
	}
	return result
}

func calculatePlugboardCombinations(alphabetSize, pairs int) int64 {
	if pairs == 0 {
		return 1
	}
	// Simplified calculation: C(n,2k) for k pairs from n characters
	// This is a rough approximation
	available := alphabetSize
	combinations := int64(1)
	for i := 0; i < pairs; i++ {
		combinations *= int64(available * (available - 1) / 2)
		available -= 2
	}
	return combinations
}

func writeStringToFile(content, filename string) error {
	return os.WriteFile(filename, []byte(content), 0600)
}

func setSeededRotorPositions(machine *enigoma.Enigma, seed int64) error {
	rng := mrand.New(mrand.NewSource(seed)) // #nosec G404
	positions := make([]int, machine.GetRotorCount())
	for i := range positions {
		positions[i] = rng.Intn(machine.GetAlphabetSize())
	}
	return machine.SetRotorPositions(positions)
}
