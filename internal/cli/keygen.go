// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"strings"

	"github.com/coredds/enigoma"
	"github.com/spf13/cobra"
)

func newKeygenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a machine configuration file",
		Long: `Generate a machine configuration for use with --config.

Examples:
  enigoma keygen --security high --output my-key.json
  enigoma keygen --alphabet greek --rotors 6 --plugboard-pairs 10
  enigoma keygen --preset m3 --output m3-key.json   # M3 with random positions`,
		RunE: runKeygen,
	}
	cmd.Flags().StringP("preset", "p", "", "Base preset: "+presetNames)
	cmd.Flags().StringP("alphabet", "a", "latin", "Alphabet: latin, latin-lower, greek, cyrillic, portuguese, ascii, alphanumeric, digits")
	cmd.Flags().StringP("security", "s", "medium", "Machine size: low, medium, high, extreme")
	cmd.Flags().IntP("rotors", "r", 0, "Number of rotors (overrides --security)")
	cmd.Flags().Int("plugboard-pairs", 0, "Number of plugboard pairs (overrides --security)")
	cmd.Flags().Bool("random-positions", true, "Randomize the starting rotor positions")
	cmd.Flags().Int64("seed", 0, "Derive starting positions from this seed (deterministic)")
	cmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	cmd.Flags().String("save-to", "", "Alias for --output")
	cmd.Flags().BoolP("describe", "d", false, "Describe the generated configuration")
	return cmd
}

func runKeygen(cmd *cobra.Command, _ []string) error {
	var m *enigoma.Machine
	var err error
	if preset := flagString(cmd, "preset"); preset != "" {
		m, _, err = presetMachine(preset)
	} else {
		m, err = keygenRandom(cmd)
	}
	if err != nil {
		return err
	}

	if cmd.Flags().Changed("seed") {
		seed, _ := cmd.Flags().GetInt64("seed")
		rng := mrand.New(mrand.NewPCG(uint64(seed), 0)) // #nosec G404 G115 -- deterministic by request; reinterpreting the seed bits is intended
		if err := m.SetPositions(randomPositions(m, func(n int) int { return rng.IntN(n) })); err != nil {
			return err
		}
	} else if flagBool(cmd, "random-positions") {
		if err := m.SetPositions(randomPositions(m, cryptoIntN)); err != nil {
			return err
		}
	}

	if flagBool(cmd, "describe") {
		describeMachine(cmd, m)
	}
	path := flagString(cmd, "output")
	if path == "" {
		path = flagString(cmd, "save-to")
	}
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
	fmt.Fprintf(cmd.OutOrStdout(), "Configuration saved to %s\n", path)
	return nil
}

func keygenRandom(cmd *cobra.Command) (*enigoma.Machine, error) {
	chars, err := alphabetFromName(flagString(cmd, "alphabet"), "")
	if err != nil {
		return nil, err
	}
	counts, err := securityCounts(flagString(cmd, "security"))
	if err != nil {
		return nil, err
	}
	if n, _ := cmd.Flags().GetInt("rotors"); n > 0 {
		counts[0] = n
	}
	if n, _ := cmd.Flags().GetInt("plugboard-pairs"); n > 0 {
		counts[1] = n
	}
	return enigoma.New(enigoma.WithAlphabet(chars), enigoma.WithRandomComponents(counts[0], counts[1]))
}

func randomPositions(m *enigoma.Machine, intN func(int) int) string {
	alph := []rune(m.Alphabet())
	pos := make([]rune, len([]rune(m.Positions())))
	for i := range pos {
		pos[i] = alph[intN(len(alph))]
	}
	return string(pos)
}

func cryptoIntN(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return int(v.Int64())
}

// describeMachine prints a human-readable summary of a machine.
func describeMachine(cmd *cobra.Command, m *enigoma.Machine) {
	s := m.Settings()
	w := cmd.OutOrStdout()
	names := make([]string, len(s.Rotors))
	rings := make([]string, len(s.Rotors))
	for i, r := range s.Rotors {
		names[i] = r.Name
		rings[i] = r.Ring
	}
	fmt.Fprintf(w, "Alphabet:  %d characters\n", len([]rune(s.Alphabet)))
	fmt.Fprintf(w, "Rotors:    %s\n", strings.Join(names, " "))
	fmt.Fprintf(w, "Positions: %s\n", m.Positions())
	fmt.Fprintf(w, "Rings:     %s\n", strings.Join(rings, ""))
	fmt.Fprintf(w, "Reflector: %s\n", s.Reflector.Name)
	if s.Plugboard == "" {
		fmt.Fprintln(w, "Plugboard: (none)")
	} else {
		fmt.Fprintf(w, "Plugboard: %s\n", s.Plugboard)
	}
}
