// Package cli provides unit tests for preset functionality.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"strings"
	"testing"

	"github.com/coredds/enigoma"
)

// TestGetAvailablePresets tests that all presets are properly defined.
func TestGetAvailablePresets(t *testing.T) {
	presets := getAvailablePresets()

	if len(presets) == 0 {
		t.Error("No presets available")
	}

	expectedPresets := []string{"classic", "simple", "high", "extreme"}
	presetMap := make(map[string]bool)

	for _, preset := range presets {
		presetMap[preset.Name] = true

		// Validate preset structure
		if preset.Name == "" {
			t.Error("Preset has empty name")
		}
		if preset.Description == "" {
			t.Errorf("Preset %s has empty description", preset.Name)
		}
		if preset.RotorCount <= 0 {
			t.Errorf("Preset %s has invalid rotor count: %d", preset.Name, preset.RotorCount)
		}
		if preset.PlugboardPairs < 0 {
			t.Errorf("Preset %s has negative plugboard pairs: %d", preset.Name, preset.PlugboardPairs)
		}
		if preset.AlphabetSize <= 0 {
			t.Errorf("Preset %s has invalid alphabet size: %d", preset.Name, preset.AlphabetSize)
		}
	}

	// Check that all expected presets exist
	for _, expected := range expectedPresets {
		if !presetMap[expected] {
			t.Errorf("Expected preset %s not found", expected)
		}
	}
}

// TestFindPreset tests the preset lookup functionality.
func TestFindPreset(t *testing.T) {
	tests := []struct {
		name     string
		preset   string
		expected bool
	}{
		{"find classic", "classic", true},
		{"find simple", "simple", true},
		{"find high", "high", true},
		{"find extreme", "extreme", true},
		{"find classic case insensitive", "CLASSIC", true},
		{"find nonexistent", "nonexistent", false},
		{"find empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preset := findPreset(tt.preset)
			found := preset != nil

			if found != tt.expected {
				t.Errorf("findPreset(%q) found=%v, expected=%v", tt.preset, found, tt.expected)
			}

			if found && preset.Name != tt.preset && !strings.EqualFold(preset.Name, tt.preset) {
				// Account for case insensitive matching
				if !strings.EqualFold(preset.Name, tt.preset) {
					t.Errorf("findPreset(%q) returned wrong preset: %s", tt.preset, preset.Name)
				}
			}
		})
	}
}

// TestCreateMachineFromPreset tests that all presets can create valid machines.
func TestCreateMachineFromPreset(t *testing.T) {
	presets := getAvailablePresets()

	for _, preset := range presets {
		t.Run("create_"+preset.Name, func(t *testing.T) {
			machine, err := createMachineFromPreset(preset.Name)
			if err != nil {
				t.Errorf("Failed to create machine from preset %s: %v", preset.Name, err)
				return
			}

			// Verify machine properties match preset specifications
			if machine.GetAlphabetSize() != preset.AlphabetSize {
				t.Errorf("Preset %s: alphabet size mismatch. Expected %d, got %d",
					preset.Name, preset.AlphabetSize, machine.GetAlphabetSize())
			}

			if machine.GetRotorCount() != preset.RotorCount {
				t.Errorf("Preset %s: rotor count mismatch. Expected %d, got %d",
					preset.Name, preset.RotorCount, machine.GetRotorCount())
			}

			if machine.GetPlugboardPairCount() != preset.PlugboardPairs {
				t.Errorf("Preset %s: plugboard pairs mismatch. Expected %d, got %d",
					preset.Name, preset.PlugboardPairs, machine.GetPlugboardPairCount())
			}

			// Test that the machine can actually encrypt/decrypt
			testText := "HELLO"
			encrypted, err := machine.Encrypt(testText)
			if err != nil {
				t.Errorf("Preset %s: encryption failed: %v", preset.Name, err)
				return
			}

			// Reset and decrypt
			if err := machine.Reset(); err != nil {
				t.Fatalf("Reset failed: %v", err)
			}
			decrypted, err := machine.Decrypt(encrypted)
			if err != nil {
				t.Errorf("Preset %s: decryption failed: %v", preset.Name, err)
				return
			}

			if decrypted != testText {
				t.Errorf("Preset %s: round-trip failed. Expected %q, got %q",
					preset.Name, testText, decrypted)
			}
		})
	}
}

// TestPresetComplexityProgression tests that presets have increasing complexity.
func TestPresetComplexityProgression(t *testing.T) {
	presets := getAvailablePresets()

	// Create a map for easy lookup
	presetMap := make(map[string]PresetInfo)
	for _, preset := range presets {
		presetMap[preset.Name] = preset
	}

	// Define expected complexity progression
	progression := []string{"classic", "simple", "high", "extreme"}

	for i := 1; i < len(progression); i++ {
		current := presetMap[progression[i]]
		previous := presetMap[progression[i-1]]

		// Current should have more or equal rotors
		if current.RotorCount < previous.RotorCount {
			t.Errorf("Preset %s should have >= rotors than %s. Got %d vs %d",
				current.Name, previous.Name, current.RotorCount, previous.RotorCount)
		}

		// Current should have more or equal plugboard pairs
		if current.PlugboardPairs < previous.PlugboardPairs {
			t.Errorf("Preset %s should have >= plugboard pairs than %s. Got %d vs %d",
				current.Name, previous.Name, current.PlugboardPairs, previous.PlugboardPairs)
		}
	}
}

// TestBoolToYesNo tests the utility function.
func TestBoolToYesNo(t *testing.T) {
	tests := []struct {
		input    bool
		expected string
	}{
		{true, "Yes"},
		{false, "No"},
	}

	for _, tt := range tests {
		result := boolToYesNo(tt.input)
		if result != tt.expected {
			t.Errorf("boolToYesNo(%v) = %q, expected %q", tt.input, result, tt.expected)
		}
	}
}

// TestPresetExport tests that presets can be exported to JSON.
func TestPresetExport(t *testing.T) {
	presets := getAvailablePresets()

	for _, preset := range presets {
		t.Run("export_"+preset.Name, func(t *testing.T) {
			machine, err := createMachineFromPreset(preset.Name)
			if err != nil {
				t.Errorf("Failed to create machine from preset %s: %v", preset.Name, err)
				return
			}

			jsonData, err := machine.SaveSettingsToJSON()
			if err != nil {
				t.Errorf("Failed to export preset %s to JSON: %v", preset.Name, err)
				return
			}

			if jsonData == "" {
				t.Errorf("Preset %s produced empty JSON export", preset.Name)
				return
			}

			// Verify the JSON can be imported back
			importedMachine, err := enigoma.NewFromJSON(jsonData)
			if err != nil {
				t.Errorf("Failed to import JSON for preset %s: %v", preset.Name, err)
				return
			}

			// Verify imported machine has same properties
			if importedMachine.GetAlphabetSize() != machine.GetAlphabetSize() {
				t.Errorf("Preset %s: imported alphabet size mismatch", preset.Name)
			}
			if importedMachine.GetRotorCount() != machine.GetRotorCount() {
				t.Errorf("Preset %s: imported rotor count mismatch", preset.Name)
			}
			if importedMachine.GetPlugboardPairCount() != machine.GetPlugboardPairCount() {
				t.Errorf("Preset %s: imported plugboard pairs mismatch", preset.Name)
			}
		})
	}
}
