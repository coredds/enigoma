// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"errors"

	"github.com/coredds/enigoma/internal/tui"
	"github.com/spf13/cobra"
)

const errRandomTui = "tui needs a deterministic machine: use --config FILE or --preset m3|m4"

func newTuiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive visualizer: type and watch the machine work",
		Long: `Open an interactive view of the machine. Each key you type steps the
rotors, lights a lamp and shows the signal's path through plugboard, rotors
and reflector and back.

Keys: Backspace undo · Tab group tape by 5 · Ctrl+R reset · Enter newline · Esc quit
Newline and space are shown as ⏎ and ␣.

Examples:
  enigoma tui
  enigoma tui --preset m4 --positions AADU
  enigoma tui --config my-key.json`,
		RunE: runTui,
	}
	addMachineFlags(cmd)
	return cmd
}

func runTui(cmd *cobra.Command, _ []string) error {
	if flagString(cmd, "config") == "" && flagString(cmd, "preset") == "" {
		if err := cmd.Flags().Set("preset", "m3"); err != nil {
			return err
		}
	}
	m, random, err := buildMachine(cmd, "")
	if err != nil {
		return err
	}
	if random {
		return errors.New(errRandomTui)
	}
	return tui.Run(m)
}
