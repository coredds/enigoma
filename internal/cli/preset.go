// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// PresetInfo describes a machine preset.
type PresetInfo struct {
	Name        string
	Description string
	RotorCount  int
	PlugPairs   int
	Random      bool // generated fresh each time; must be saved to decrypt
	Notes       string
}

func getAvailablePresets() []PresetInfo {
	return []PresetInfo{
		{Name: "m3", Description: "Historical Enigma M3", RotorCount: 3,
			Notes: "Army/Navy Enigma: rotors I-II-III, reflector B, positions and rings AAA."},
		{Name: "m4", Description: "Historical naval Enigma M4", RotorCount: 4,
			Notes: "Kriegsmarine Enigma: fixed thin rotor Beta, rotors I-II-III, reflector B-Thin."},
		{Name: "low", Description: "Random machine, 3 rotors, 2 plug pairs", RotorCount: 3, PlugPairs: 2, Random: true},
		{Name: "medium", Description: "Random machine, 5 rotors, 8 plug pairs", RotorCount: 5, PlugPairs: 8, Random: true},
		{Name: "high", Description: "Random machine, 8 rotors, 15 plug pairs", RotorCount: 8, PlugPairs: 15, Random: true},
		{Name: "extreme", Description: "Random machine, 12 rotors, 20 plug pairs", RotorCount: 12, PlugPairs: 20, Random: true},
	}
}

func findPreset(name string) *PresetInfo {
	for _, p := range getAvailablePresets() {
		if strings.EqualFold(p.Name, name) {
			return &p
		}
	}
	return nil
}

func newPresetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "preset",
		Short: "List, describe and export machine presets",
		Long: `List, describe and export machine presets.

m3 and m4 are historical machines and always identical. low, medium, high and
extreme generate a new random machine every time: save it (--save-config,
--export) to be able to decrypt.

Examples:
  enigoma preset --list
  enigoma preset --describe m4
  enigoma preset --export m3 --output m3.json`,
		RunE: runPreset,
	}
	cmd.Flags().BoolP("list", "l", false, "List presets")
	cmd.Flags().StringP("describe", "d", "", "Describe a preset (or 'all')")
	cmd.Flags().StringP("export", "e", "", "Export a preset's configuration")
	cmd.Flags().StringP("output", "o", "", "Output file for --export (default: stdout)")
	return cmd
}

func runPreset(cmd *cobra.Command, _ []string) error {
	if name := flagString(cmd, "describe"); name != "" {
		return describePresets(cmd, name)
	}
	if name := flagString(cmd, "export"); name != "" {
		return exportPreset(cmd, name)
	}
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "Available presets:")
	for _, p := range getAvailablePresets() {
		fmt.Fprintf(w, "  %-8s %s\n", p.Name, p.Description)
	}
	fmt.Fprintln(w, "\nUse 'enigoma preset --describe <name>' for details.")
	return nil
}

func describePresets(cmd *cobra.Command, name string) error {
	presets := getAvailablePresets()
	if !strings.EqualFold(name, "all") {
		p := findPreset(name)
		if p == nil {
			return fmt.Errorf("unknown preset %q; available: %s", name, presetNames)
		}
		presets = []PresetInfo{*p}
	}
	w := cmd.OutOrStdout()
	for i, p := range presets {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "Preset:      %s\n", p.Name)
		fmt.Fprintf(w, "Description: %s\n", p.Description)
		fmt.Fprintf(w, "Rotors:      %d\n", p.RotorCount)
		fmt.Fprintf(w, "Plug pairs:  %d\n", p.PlugPairs)
		if p.Random {
			fmt.Fprintln(w, "Random:      yes (save the configuration to decrypt)")
		} else {
			fmt.Fprintln(w, "Random:      no (historical, deterministic)")
		}
		if p.Notes != "" {
			fmt.Fprintf(w, "Notes:       %s\n", p.Notes)
		}
	}
	return nil
}

func exportPreset(cmd *cobra.Command, name string) error {
	m, _, err := presetMachine(name)
	if err != nil {
		return err
	}
	path := flagString(cmd, "output")
	if path == "" {
		data, err := settingsJSON(m)
		if err != nil {
			return err
		}
		_, err = cmd.OutOrStdout().Write(data)
		return err
	}
	if err := saveConfig(m, path); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Preset %s saved to %s\n", name, path)
	return nil
}
