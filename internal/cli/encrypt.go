// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/coredds/enigoma"
	"github.com/coredds/enigoma/internal/alphabet"
	"github.com/spf13/cobra"
)

const errUnsavedRandom = "refusing to encrypt with a randomly generated machine that is not saved; the ciphertext could not be decrypted. Add --save-config key.json or use --auto-config key.json"

func newEncryptCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt text or files",
		Long: `Encrypt text with an Enigma machine.

QUICK START (recommended):
  enigoma encrypt --text "Hello World!" --auto-config my-key.json
  enigoma decrypt --text "CIPHERTEXT" --config my-key.json

--auto-config detects an alphabet that fits your text, generates a random
machine and saves it so the ciphertext can be decrypted later.

MACHINE SOURCES (first match wins):
  --config FILE                     a saved configuration
  --preset m3|m4                    historical machines (deterministic)
  --preset low|medium|high|extreme  random machines (require --save-config)
  --alphabet NAME --security LEVEL  random machine (requires --save-config)

Overrides for any source: --positions ADU --rings BUL --plugboard "AB CD"

A randomly generated machine must be saved, otherwise the ciphertext could
never be decrypted; encrypt refuses to run in that case.

INPUT:
  enigoma encrypt --text "HELLO" --preset m3
  enigoma encrypt --file input.txt --config key.json
  echo HELLO | enigoma encrypt --preset m3

PREPROCESSING (useful with the 26-letter presets):
  --remove-spaces --uppercase --letters-only --alphanumeric-only`,
		RunE: runEncrypt,
	}
	addInputFlags(cmd, "encrypt")
	addMachineFlags(cmd)
	cmd.Flags().StringP("alphabet", "a", "auto", "Alphabet for random machines: auto, latin, latin-lower, greek, cyrillic, portuguese, ascii, alphanumeric, digits")
	cmd.Flags().StringP("security", "s", "medium", "Random machine size: low, medium, high, extreme")
	cmd.Flags().String("auto-config", "", "Detect the alphabet from the input, generate a machine and save it to this file")
	cmd.Flags().String("save-config", "", "Save the machine's configuration to this file")
	cmd.Flags().String("format", "text", "Output format: text, hex, base64")
	cmd.Flags().Bool("dry-run", false, "Show what would happen without encrypting")
	return cmd
}

func runEncrypt(cmd *cobra.Command, _ []string) error {
	text, err := readInput(cmd)
	if err != nil {
		return err
	}
	if text == "" {
		return fmt.Errorf("no input text provided; use --text, --file, or pipe to stdin")
	}
	original := text
	text = preprocessInput(cmd, text)
	autoConfig := flagString(cmd, "auto-config")
	if autoConfig != "" {
		text = alphabet.PreprocessTextForAutoDetection(text)
	}

	if flagBool(cmd, "dry-run") {
		return showDryRun(cmd, original, text)
	}

	m, random, err := buildMachine(cmd, text)
	if err != nil {
		return err
	}
	savePath := autoConfig
	if savePath == "" {
		savePath = flagString(cmd, "save-config")
	}
	if random && savePath == "" {
		return errors.New(errUnsavedRandom)
	}
	if savePath != "" {
		// Save before encrypting: the settings must hold the starting positions.
		if err := saveConfig(m, savePath); err != nil {
			return err
		}
		verbosef(cmd, "Configuration saved to %s\n", savePath)
	}

	ciphertext, err := m.Encrypt(text)
	if err != nil {
		return explainCharError(cmd, err, text)
	}
	out, err := encodeOutput(cmd, ciphertext)
	if err != nil {
		return err
	}
	return writeOutput(cmd, out)
}

// explainCharError adds suggestions to a *enigoma.CharError.
func explainCharError(cmd *cobra.Command, err error, text string) error {
	var ce *enigoma.CharError
	if !errors.As(err, &ce) {
		return err
	}
	var tips []string
	if strings.Contains(text, " ") {
		tips = append(tips, "remove spaces with --remove-spaces")
	}
	if hasLowercase(text) {
		tips = append(tips, "convert to uppercase with --uppercase")
	}
	if cmd.Name() == "encrypt" {
		tips = append(tips, "let enigoma pick an alphabet that fits: --auto-config key.json")
	} else {
		tips = append(tips, "decrypt with the same --config file that was used to encrypt")
	}
	return fmt.Errorf("%w\n\nSuggestions:\n  • %s", err, strings.Join(tips, "\n  • "))
}

func showDryRun(cmd *cobra.Command, original, processed string) error {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w, "=== DRY RUN: nothing will be encrypted ===")
	fmt.Fprintf(w, "Input: %d characters\n", len([]rune(original)))
	if processed != original {
		fmt.Fprintf(w, "After preprocessing: %d characters\n", len([]rune(processed)))
	}
	switch {
	case flagString(cmd, "config") != "":
		fmt.Fprintf(w, "Machine: from config %s\n", flagString(cmd, "config"))
	case flagString(cmd, "preset") != "":
		fmt.Fprintf(w, "Machine: preset %s\n", flagString(cmd, "preset"))
	case flagString(cmd, "auto-config") != "":
		fmt.Fprintf(w, "Machine: random, alphabet detected from input, saved to %s\n", flagString(cmd, "auto-config"))
	default:
		fmt.Fprintf(w, "Machine: random, alphabet %s, security %s\n", flagString(cmd, "alphabet"), flagString(cmd, "security"))
	}
	if p := flagString(cmd, "save-config"); p != "" {
		fmt.Fprintf(w, "Configuration will be saved to %s\n", p)
	}
	fmt.Fprintf(w, "Output format: %s\n", flagString(cmd, "format"))
	return nil
}
