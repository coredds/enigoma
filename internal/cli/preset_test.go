// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/coredds/enigoma"
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

func TestPresetList(t *testing.T) {
	out, err := run(t, "preset", "--list")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"m3", "m4", "low", "medium", "high", "extreme"} {
		if !strings.Contains(out, name) {
			t.Errorf("list missing %s:\n%s", name, out)
		}
	}
	for _, gone := range []string{"classic", "simple"} {
		if strings.Contains(out, gone) {
			t.Errorf("list still mentions %s", gone)
		}
	}
}

func TestPresetDescribe(t *testing.T) {
	out, err := run(t, "preset", "--describe", "m4")
	if err != nil || !strings.Contains(out, "Beta") {
		t.Errorf("describe m4: %v\n%s", err, out)
	}
	if _, err := run(t, "preset", "--describe", "classic"); err == nil {
		t.Error("describe classic should fail")
	}
}

func TestPresetExport_M3(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m3.json")
	if _, err := run(t, "preset", "--export", "m3", "--output", path); err != nil {
		t.Fatal(err)
	}
	m, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := m.Encrypt("AAAAA"); out != "BDZGO" {
		t.Errorf("exported m3 encrypts AAAAA to %s", out)
	}
	// M4 with Beta at A encrypts like M3, so also check the rotor set.
	var names []string
	for _, r := range m.Settings().Rotors {
		names = append(names, r.Name)
	}
	if got := strings.Join(names, " "); got != "I II III" {
		t.Errorf("exported rotors = %q, want %q", got, "I II III")
	}
}

func TestKeygen_SeedDeterministic(t *testing.T) {
	a, err := run(t, "keygen", "--preset", "m3", "--seed", "42")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := run(t, "keygen", "--preset", "m3", "--seed", "42")
	c, _ := run(t, "keygen", "--preset", "m3", "--seed", "43")
	if a != b {
		t.Error("same seed produced different configurations")
	}
	if a == c {
		t.Error("different seeds produced identical configurations")
	}
	s, err := enigoma.ParseSettings([]byte(a))
	if err != nil {
		t.Fatal(err)
	}
	if s.Rotors[0].Position+s.Rotors[1].Position+s.Rotors[2].Position == "AAA" {
		t.Error("seeded positions should not all be A (seed 42)")
	}
}

func TestKeygen_Counts(t *testing.T) {
	out, err := run(t, "keygen", "--alphabet", "greek", "--rotors", "6", "--plugboard-pairs", "10")
	if err != nil {
		t.Fatal(err)
	}
	s, err := enigoma.ParseSettings([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Rotors) != 6 || len(strings.Fields(s.Plugboard)) != 10 || s.Alphabet != enigoma.AlphabetGreek {
		t.Errorf("rotors=%d pairs=%d alphabet=%q", len(s.Rotors), len(strings.Fields(s.Plugboard)), s.Alphabet)
	}
	if _, err := run(t, "keygen", "--alphabet", "klingon"); err == nil {
		t.Error("unknown alphabet should fail")
	}
}

func TestConfigValidate_V1(t *testing.T) {
	path := writeFile(t, "old.json", v1Config)
	_, err := run(t, "config", "--validate", path)
	if err == nil || !strings.Contains(err.Error(), v1Message) || !strings.Contains(err.Error(), "enigoma keygen") {
		t.Errorf("got %v", err)
	}
	if _, err := run(t, "config", "--convert", path, "--output", filepath.Join(t.TempDir(), "x.json")); err == nil || !strings.Contains(err.Error(), v1Message) {
		t.Errorf("convert v1: %v", err)
	}
}

func TestConfigShow_V2(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m4.json")
	if _, err := run(t, "preset", "--export", "m4", "--output", path); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "config", "--show", path)
	if err != nil || !strings.Contains(out, "Beta I II III") || !strings.Contains(out, "Plugboard") {
		t.Errorf("show: %v\n%s", err, out)
	}
	out, err = run(t, "config", "--test", path)
	if err != nil || !strings.Contains(out, "passed") {
		t.Errorf("test: %v\n%s", err, out)
	}
	if _, err := run(t, "config", "--validate", path); err != nil {
		t.Errorf("validate: %v", err)
	}
}
