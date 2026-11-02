// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"testing"
)

func TestPresetMachine(t *testing.T) {
	for _, p := range getAvailablePresets() {
		t.Run(p.Name, func(t *testing.T) {
			m, random, err := presetMachine(p.Name)
			if err != nil {
				t.Fatal(err)
			}
			if random != p.Random {
				t.Errorf("random = %v, want %v", random, p.Random)
			}
			s := m.Settings()
			if len(s.Rotors) != p.RotorCount {
				t.Errorf("rotors = %d, want %d", len(s.Rotors), p.RotorCount)
			}
			dec := m.Clone()
			ct, err := m.Encrypt("HELLO")
			if err != nil {
				t.Fatal(err)
			}
			if pt, _ := dec.Decrypt(ct); pt != "HELLO" {
				t.Errorf("round trip = %q", pt)
			}
		})
	}
}

func TestFindPreset(t *testing.T) {
	if findPreset("M3") == nil || findPreset("extreme") == nil {
		t.Error("expected m3 and extreme presets (case-insensitive)")
	}
	if findPreset("classic") != nil || findPreset("simple") != nil {
		t.Error("classic and simple presets were removed")
	}
}
