// Package cli provides the preset command for the enigoma CLI.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var presetCmd = &cobra.Command{
	Use:   "preset",
	Short: "List and describe available Enigma machine presets",
	Long: `List and describe available Enigma machine presets.

Presets provide quick configuration templates for common use cases,
from historical accuracy to high security applications.

Examples:
  enigoma preset --list
  enigoma preset --describe classic
  enigoma preset --describe all
  enigoma preset --export classic --output classic-config.json`,
	RunE: runPreset,
}

func init() {
	presetCmd.Flags().BoolP("list", "l", false, "List all available presets")
	presetCmd.Flags().StringP("describe", "d", "", "Describe a specific preset (or 'all' for all presets)")
	presetCmd.Flags().StringP("export", "e", "", "Export preset configuration to file")
	presetCmd.Flags().StringP("output", "o", "", "Output file for exported configuration")
	presetCmd.Flags().BoolP("verbose", "v", false, "Show detailed information")
}

func runPreset(cmd *cobra.Command, args []string) error {
	setupVerbose(cmd)

	list, _ := cmd.Flags().GetBool("list")
	describe, _ := cmd.Flags().GetString("describe")
	export, _ := cmd.Flags().GetString("export")

	// Default action if no flags specified
	if !list && describe == "" && export == "" {
		list = true
	}

	if list {
		return listPresets(cmd)
	}

	if describe != "" {
		return describePresets(describe, cmd)
	}

	if export != "" {
		return exportPreset(export, cmd)
	}

	return nil
}

func listPresets(cmd *cobra.Command) error {
	fmt.Fprintln(cmd.OutOrStdout(), "Available Enigma Machine Presets:")
	fmt.Fprintln(cmd.OutOrStdout())

	presets := getAvailablePresets()
	for _, preset := range presets {
		fmt.Fprintf(cmd.OutOrStdout(), "  %-12s - %s\n", preset.Name, preset.Description)
	}

	fmt.Println()
	fmt.Println("Use 'enigoma preset --describe <name>' for detailed information.")
	fmt.Println("Use 'enigoma preset --export <name>' to generate configuration files.")

	return nil
}

func describePresets(presetName string, cmd *cobra.Command) error {
	verbose, _ := cmd.Flags().GetBool("verbose")

	if strings.EqualFold(presetName, "all") {
		presets := getAvailablePresets()
		for i, preset := range presets {
			if i > 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "\n"+strings.Repeat("-", 60))
			}
			describePreset(preset, verbose, cmd)
		}
		return nil
	}

	preset := findPreset(presetName)
	if preset == nil {
		return fmt.Errorf("unknown preset: %s. Use --list to see available presets", presetName)
	}

	describePreset(*preset, verbose, cmd)
	return nil
}

func describePreset(preset PresetInfo, verbose bool, cmd *cobra.Command) {
	fmt.Fprintf(cmd.OutOrStdout(), "Preset: %s\n", preset.Name)
	fmt.Fprintf(cmd.OutOrStdout(), "Description: %s\n", preset.Description)
	fmt.Fprintf(cmd.OutOrStdout(), "Use Case: %s\n", preset.UseCase)
	fmt.Fprintf(cmd.OutOrStdout(), "Security Level: %s\n", preset.SecurityLevel)
	fmt.Fprintf(cmd.OutOrStdout(), "Default Alphabet: %s (%d characters)\n", preset.AlphabetName, preset.AlphabetSize)
	fmt.Fprintf(cmd.OutOrStdout(), "Rotors: %d\n", preset.RotorCount)
	fmt.Fprintf(cmd.OutOrStdout(), "Plugboard Pairs: %d\n", preset.PlugboardPairs)

	if verbose {
		fmt.Fprintf(cmd.OutOrStdout(), "\nDetailed Configuration:\n")
		fmt.Fprintf(cmd.OutOrStdout(), "  Historical Accuracy: %s\n", boolToYesNo(preset.HistoricalAccuracy))
		fmt.Fprintf(cmd.OutOrStdout(), "  Recommended For: %s\n", preset.RecommendedFor)
		fmt.Fprintf(cmd.OutOrStdout(), "  Complexity Rating: %s/5\n", preset.ComplexityRating)

		if preset.Notes != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "\nNotes: %s\n", preset.Notes)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "\nExample Usage:\n")
		fmt.Fprintf(cmd.OutOrStdout(), "  enigoma encrypt --text \"Hello World\" --preset %s\n", preset.Name)
		fmt.Fprintf(cmd.OutOrStdout(), "  enigoma keygen --preset %s --output %s-key.json\n", preset.Name, preset.Name)
	}

	fmt.Fprintln(cmd.OutOrStdout())
}

func exportPreset(presetName string, cmd *cobra.Command) error {
	// Create machine with preset
	machine, err := createMachineFromPreset(presetName)
	if err != nil {
		return fmt.Errorf("failed to create machine from preset: %w", err)
	}

	// Get configuration as JSON
	jsonData, err := machine.SaveSettingsToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize configuration: %w", err)
	}

	// Output configuration
	outputFile, _ := cmd.Flags().GetString("output")
	if outputFile == "" {
		fmt.Fprint(cmd.OutOrStdout(), jsonData)
	} else {
		err := writeStringToFile(jsonData, outputFile)
		if err != nil {
			return fmt.Errorf("failed to write configuration to file: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Preset '%s' configuration saved to: %s\n", presetName, outputFile)
	}

	return nil
}

type PresetInfo struct {
	Name               string
	Description        string
	UseCase            string
	SecurityLevel      string
	AlphabetName       string
	AlphabetSize       int
	RotorCount         int
	PlugboardPairs     int
	HistoricalAccuracy bool
	RecommendedFor     string
	ComplexityRating   string
	Notes              string
}

func getAvailablePresets() []PresetInfo {
	return []PresetInfo{
		{
			Name:               "classic",
			Description:        "Classic Enigma simulation",
			UseCase:            "Educational, historical simulation",
			SecurityLevel:      "Low",
			AlphabetName:       "Latin Uppercase",
			AlphabetSize:       26,
			RotorCount:         3,
			PlugboardPairs:     2,
			HistoricalAccuracy: true,
			RecommendedFor:     "Learning Enigma mechanics, historical projects",
			ComplexityRating:   "2",
			Notes:              "Similar to historical Enigma I configuration",
		},
		{
			Name:               "m3",
			Description:        "Historically accurate Enigma M3",
			UseCase:            "Historical simulation, WWII research",
			SecurityLevel:      "Low",
			AlphabetName:       "Latin Uppercase",
			AlphabetSize:       26,
			RotorCount:         3,
			PlugboardPairs:     0,
			HistoricalAccuracy: true,
			RecommendedFor:     "Historical accuracy, Wehrmacht/Army simulation",
			ComplexityRating:   "2",
			Notes:              "Standard Army and Navy Enigma with rotors I, II, III and reflector B",
		},
		{
			Name:               "m4",
			Description:        "Historically accurate Naval Enigma M4",
			UseCase:            "Historical simulation, naval research",
			SecurityLevel:      "Low",
			AlphabetName:       "Latin Uppercase",
			AlphabetSize:       26,
			RotorCount:         4,
			PlugboardPairs:     0,
			HistoricalAccuracy: true,
			RecommendedFor:     "Historical accuracy, Kriegsmarine/Naval simulation",
			ComplexityRating:   "2",
			Notes:              "Used by German Navy with 4 rotors including a thin Beta rotor",
		},
		{
			Name:               "simple",
			Description:        "Basic Enigma with standard settings",
			UseCase:            "General purpose, moderate security",
			SecurityLevel:      "Medium",
			AlphabetName:       "Latin Uppercase",
			AlphabetSize:       26,
			RotorCount:         5,
			PlugboardPairs:     8,
			HistoricalAccuracy: false,
			RecommendedFor:     "General encryption, file protection",
			ComplexityRating:   "3",
			Notes:              "Good balance of security and performance",
		},
		{
			Name:               "high",
			Description:        "High-security configuration",
			UseCase:            "Sensitive data, strong obfuscation",
			SecurityLevel:      "High",
			AlphabetName:       "Latin Uppercase",
			AlphabetSize:       26,
			RotorCount:         8,
			PlugboardPairs:     13,
			HistoricalAccuracy: false,
			RecommendedFor:     "Document protection, secure communication",
			ComplexityRating:   "4",
			Notes:              "Significantly more secure than historical machines",
		},
		{
			Name:               "extreme",
			Description:        "Maximum security configuration",
			UseCase:            "Maximum complexity, research",
			SecurityLevel:      "Extreme",
			AlphabetName:       "Latin Uppercase",
			AlphabetSize:       26,
			RotorCount:         12,
			PlugboardPairs:     13,
			HistoricalAccuracy: false,
			RecommendedFor:     "Research, maximum obfuscation needs",
			ComplexityRating:   "5",
			Notes:              "Extremely large keyspace, slower but most secure",
		},
	}
}

func findPreset(name string) *PresetInfo {
	presets := getAvailablePresets()
	for _, preset := range presets {
		if strings.EqualFold(preset.Name, name) {
			return &preset
		}
	}
	return nil
}

func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
