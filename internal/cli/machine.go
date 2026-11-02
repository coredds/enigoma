// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/coredds/enigoma"
	"github.com/coredds/enigoma/internal/alphabet"
	"github.com/spf13/cobra"
)

// randomPresets maps random presets (and --security levels) to rotor and plug-pair counts.
var randomPresets = map[string][2]int{
	"low":     {3, 2},
	"medium":  {5, 8},
	"high":    {8, 15},
	"extreme": {12, 20},
}

const presetNames = "m3, m4, low, medium, high, extreme"

// buildMachine constructs the machine selected by the command's flags.
// Source precedence: --config, --preset, then --alphabet/--security (with
// --auto-config forcing alphabet detection). --positions, --rings and
// --plugboard override any source. random reports whether the machine was
// randomly generated, i.e. cannot be recreated without saving its settings.
func buildMachine(cmd *cobra.Command, inputText string) (m *enigoma.Machine, random bool, err error) {
	overrides := overrideOptions(cmd)

	if path := flagString(cmd, "config"); path != "" {
		s, err := loadSettings(path)
		if err != nil {
			return nil, false, err
		}
		m, err := enigoma.New(append(settingsOptions(s), overrides...)...)
		return m, false, err
	}
	if preset := flagString(cmd, "preset"); preset != "" {
		return presetMachine(preset, overrides...)
	}

	alphabetName := flagString(cmd, "alphabet")
	if flagString(cmd, "auto-config") != "" {
		alphabetName = "auto"
	}
	chars, err := alphabetFromName(alphabetName, inputText)
	if err != nil {
		return nil, false, err
	}
	counts, err := securityCounts(flagString(cmd, "security"))
	if err != nil {
		return nil, false, err
	}
	verbosef(cmd, "Alphabet: %d characters; %d rotors, %d plug pairs\n", len([]rune(chars)), counts[0], counts[1])
	opts := append([]enigoma.Option{
		enigoma.WithAlphabet(chars),
		enigoma.WithRandomComponents(counts[0], counts[1]),
	}, overrides...)
	m, err = enigoma.New(opts...)
	return m, true, err
}

// presetMachine builds a named preset. Random presets report random = true.
func presetMachine(name string, overrides ...enigoma.Option) (*enigoma.Machine, bool, error) {
	switch name = strings.ToLower(name); name {
	case "m3":
		m, err := enigoma.NewM3(overrides...)
		return m, false, err
	case "m4":
		m, err := enigoma.NewM4(overrides...)
		return m, false, err
	}
	counts, ok := randomPresets[name]
	if !ok {
		return nil, false, fmt.Errorf("unknown preset %q; available: %s", name, presetNames)
	}
	opts := append([]enigoma.Option{enigoma.WithRandomComponents(counts[0], counts[1])}, overrides...)
	m, err := enigoma.New(opts...)
	return m, true, err
}

func overrideOptions(cmd *cobra.Command) []enigoma.Option {
	var opts []enigoma.Option
	if p := flagString(cmd, "positions"); p != "" {
		opts = append(opts, enigoma.WithPositions(p))
	}
	if r := flagString(cmd, "rings"); r != "" {
		opts = append(opts, enigoma.WithRings(r))
	}
	if cmd.Flags().Changed("plugboard") {
		opts = append(opts, enigoma.WithPlugboard(flagString(cmd, "plugboard")))
	}
	return opts
}

func settingsOptions(s enigoma.Settings) []enigoma.Option {
	return []enigoma.Option{
		enigoma.WithAlphabet(s.Alphabet),
		enigoma.WithRotors(s.Rotors...),
		enigoma.WithReflector(s.Reflector),
		enigoma.WithPlugboard(s.Plugboard),
	}
}

// loadSettings reads and parses a configuration file. Errors from
// ParseSettings (including the schema v1 message) are returned unchanged.
func loadSettings(path string) (enigoma.Settings, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return enigoma.Settings{}, fmt.Errorf("read config: %w", err)
	}
	return enigoma.ParseSettings(data)
}

// loadConfig builds a machine from a configuration file.
func loadConfig(path string) (*enigoma.Machine, error) {
	s, err := loadSettings(path)
	if err != nil {
		return nil, err
	}
	return enigoma.NewFromSettings(s)
}

// saveConfig writes the machine's settings as indented JSON, readable only by the owner.
func saveConfig(m *enigoma.Machine, path string) error {
	data, err := settingsJSON(m)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config %s: %w", path, err)
	}
	return nil
}

func alphabetFromName(name, inputText string) (string, error) {
	switch strings.ToLower(name) {
	case "auto", "":
		if inputText == "" {
			return "", fmt.Errorf("alphabet auto-detection needs input text; use --alphabet NAME or provide --text/--file/stdin")
		}
		detected, err := alphabet.AutoDetectFromText(inputText)
		if err != nil {
			return "", fmt.Errorf("detect alphabet: %w", err)
		}
		return string(detected.Runes()), nil
	case "latin", "latin-upper":
		return enigoma.AlphabetLatinUpper, nil
	case "latin-lower":
		return enigoma.AlphabetLatinLower, nil
	case "greek":
		return enigoma.AlphabetGreek, nil
	case "cyrillic":
		return enigoma.AlphabetCyrillic, nil
	case "portuguese":
		return enigoma.AlphabetPortuguese, nil
	case "ascii":
		return enigoma.AlphabetASCIIPrintable, nil
	case "alphanumeric":
		return enigoma.AlphabetAlphaNumeric, nil
	case "digits":
		return enigoma.AlphabetDigits, nil
	}
	return "", fmt.Errorf("unknown alphabet %q; available: auto, latin, latin-lower, greek, cyrillic, portuguese, ascii, alphanumeric, digits", name)
}

func securityCounts(level string) ([2]int, error) {
	if level == "" {
		level = "medium"
	}
	counts, ok := randomPresets[strings.ToLower(level)]
	if !ok {
		return [2]int{}, fmt.Errorf("unknown security level %q; available: low, medium, high, extreme", level)
	}
	return counts, nil
}

// flagString returns a string flag's value, or "" if the command lacks the flag.
func flagString(cmd *cobra.Command, name string) string {
	v, _ := cmd.Flags().GetString(name)
	return v
}

func flagBool(cmd *cobra.Command, name string) bool {
	v, _ := cmd.Flags().GetBool(name)
	return v
}

// addMachineFlags registers the machine-selection flags shared by encrypt, decrypt and tui.
func addMachineFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("preset", "p", "", "Preset: "+presetNames)
	cmd.Flags().String("positions", "", "Starting rotor positions, one letter per rotor (e.g. ADU)")
	cmd.Flags().String("rings", "", "Ring settings, one letter per rotor (e.g. BUL)")
	cmd.Flags().String("plugboard", "", `Plugboard pairs, space-separated (e.g. "AB CD")`)
}
