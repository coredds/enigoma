// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
)

const errRandomDecrypt = "decrypt needs a deterministic machine: use --config FILE or --preset m3|m4"

func newDecryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt text or files",
		Long: `Decrypt text with the same machine that encrypted it.

Use the configuration file saved at encryption time, or a historical preset
with the same overrides:
  enigoma decrypt --text "CIPHERTEXT" --config my-key.json
  enigoma decrypt --text "BDZGO" --preset m3
  enigoma decrypt --file secret.txt --config my-key.json --format base64`,
		RunE: runDecrypt,
	}
	addInputFlags(cmd, "decrypt")
	addMachineFlags(cmd)
	cmd.Flags().String("format", "text", "Input format: text, hex, base64")
	return cmd
}

func runDecrypt(cmd *cobra.Command, _ []string) error {
	raw, err := readInput(cmd)
	if err != nil {
		return err
	}
	if raw == "" {
		return fmt.Errorf("no input text provided; use --text, --file, or pipe to stdin")
	}
	text, err := decodeInput(cmd, raw)
	if err != nil {
		return err
	}
	text = preprocessInput(cmd, text)

	m, random, err := buildMachine(cmd, text)
	if err != nil {
		return err
	}
	if random {
		return errors.New(errRandomDecrypt)
	}
	plaintext, err := m.Decrypt(text)
	if err != nil {
		return explainCharError(cmd, err, text)
	}
	return writeOutput(cmd, plaintext)
}
