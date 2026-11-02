// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/coredds/enigoma"
	"github.com/spf13/cobra"
)

// readInput returns text from --text, --file, or piped stdin (in that order).
func readInput(cmd *cobra.Command) (string, error) {
	if text := flagString(cmd, "text"); text != "" {
		return text, nil
	}
	if path := flagString(cmd, "file"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		return string(data), nil
	}
	in := cmd.InOrStdin()
	if f, ok := in.(*os.File); ok {
		if stat, err := f.Stat(); err != nil || stat.Mode()&os.ModeCharDevice != 0 {
			return "", nil // interactive terminal, nothing piped
		}
	}
	data, err := io.ReadAll(in)
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return string(data), nil
}

// trimInputNewline drops one trailing line ending ("\n" or "\r\n") from
// --file or stdin input when the machine's alphabet cannot encode it, so that
// `echo HELLO | enigoma encrypt --preset m3` works. --text input is untouched.
func trimInputNewline(cmd *cobra.Command, m *enigoma.Machine, text string) string {
	if flagString(cmd, "text") != "" || strings.ContainsRune(m.Alphabet(), '\n') {
		return text
	}
	if t, ok := strings.CutSuffix(text, "\n"); ok {
		if !strings.ContainsRune(m.Alphabet(), '\r') {
			t = strings.TrimSuffix(t, "\r")
		}
		return t
	}
	return text
}

// decodeInput converts --format hex/base64 input to text.
func decodeInput(cmd *cobra.Command, text string) (string, error) {
	switch format := strings.ToLower(flagString(cmd, "format")); format {
	case "text", "":
		return text, nil
	case "hex":
		b, err := hex.DecodeString(strings.TrimSpace(text))
		if err != nil {
			return "", fmt.Errorf("invalid hex input: %w", err)
		}
		return string(b), nil
	case "base64":
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(text))
		if err != nil {
			return "", fmt.Errorf("invalid base64 input: %w", err)
		}
		return string(b), nil
	default:
		return "", fmt.Errorf("unknown format %q; available: text, hex, base64", format)
	}
}

// encodeOutput converts text to --format hex/base64.
func encodeOutput(cmd *cobra.Command, text string) (string, error) {
	switch format := strings.ToLower(flagString(cmd, "format")); format {
	case "text", "":
		return text, nil
	case "hex":
		return hex.EncodeToString([]byte(text)), nil
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(text)), nil
	default:
		return "", fmt.Errorf("unknown format %q; available: text, hex, base64", format)
	}
}

// writeOutput writes to --output (mode 0600) or stdout.
func writeOutput(cmd *cobra.Command, text string) error {
	if path := flagString(cmd, "output"); path != "" {
		return os.WriteFile(path, []byte(text), 0600)
	}
	_, err := fmt.Fprint(cmd.OutOrStdout(), text)
	return err
}

func settingsJSON(m *enigoma.Machine) ([]byte, error) {
	data, err := json.MarshalIndent(m.Settings(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode settings: %w", err)
	}
	return append(data, '\n'), nil
}

// addInputFlags registers input/output and preprocessing flags shared by encrypt and decrypt.
func addInputFlags(cmd *cobra.Command, verb string) {
	cmd.Flags().StringP("text", "t", "", "Text to "+verb)
	cmd.Flags().StringP("file", "f", "", "File to "+verb)
	cmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	cmd.Flags().Bool("remove-spaces", false, "Remove spaces from input")
	cmd.Flags().Bool("uppercase", false, "Convert input to uppercase")
	cmd.Flags().Bool("letters-only", false, "Keep only letters A-Z, a-z")
	cmd.Flags().Bool("alphanumeric-only", false, "Keep only letters and digits")
}

// preprocessInput applies the preprocessing flags.
func preprocessInput(cmd *cobra.Command, text string) string {
	if flagBool(cmd, "remove-spaces") {
		text = strings.ReplaceAll(text, " ", "")
	}
	if flagBool(cmd, "uppercase") {
		text = strings.ToUpper(text)
	}
	if flagBool(cmd, "letters-only") {
		text = filterLettersOnly(text)
	}
	if flagBool(cmd, "alphanumeric-only") {
		text = filterAlphanumericOnly(text)
	}
	return text
}

func filterLettersOnly(text string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			return r
		}
		return -1
	}, text)
}

func filterAlphanumericOnly(text string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return -1
	}, text)
}

func hasLowercase(text string) bool {
	return strings.ToUpper(text) != text
}
