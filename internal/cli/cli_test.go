// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coredds/enigoma"
)

const v1Message = "config schema v1 (enigoma ≤ 0.5) is not supported; regenerate the key with enigoma ≥ 0.6"

const v1Config = `{
  "schema_version": 1,
  "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "rotor_specs": [{"id": "I", "forward_mapping": "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "notches": [81], "position": 0, "ring_setting": 0}],
  "reflector_spec": {"id": "B", "mapping": "YRUHQSLDPXNGOKMIEBFZCWVJAT"},
  "plugboard_pairs": {},
  "current_rotor_positions": [0]
}`

// run executes the CLI with args on a fresh command tree and returns stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	return runWithStdin(t, "", args...)
}

func runWithStdin(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	var out, errOut bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	if stdin != "" {
		cmd.SetIn(strings.NewReader(stdin))
	}
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRootCommand(t *testing.T) {
	out, err := run(t, "--version")
	if err != nil || !strings.Contains(out, enigoma.GetVersion()) {
		t.Errorf("--version: %v, %q", err, out)
	}
	out, err = run(t, "--help")
	if err != nil || !strings.Contains(out, "Enigma") {
		t.Errorf("--help: %v, %q", err, out)
	}
	if _, err := run(t, "invalid-command"); err == nil {
		t.Error("unknown command should fail")
	}
}

func TestEncrypt_M3Deterministic(t *testing.T) {
	out, err := run(t, "encrypt", "--text", "AAAAA", "--preset", "m3")
	if err != nil || out != "BDZGO" {
		t.Errorf("got %q, %v; want BDZGO", out, err)
	}
}

func TestEncrypt_PositionsRings(t *testing.T) {
	out, err := run(t, "encrypt", "--text", "AAAAA", "--preset", "m3", "--rings", "BBB")
	if err != nil || out != "EWTYX" {
		t.Errorf("--rings BBB: got %q, %v; want EWTYX", out, err)
	}
	if _, err := run(t, "encrypt", "--text", "AAAAA", "--preset", "m3", "--positions", "ADU"); err != nil {
		t.Errorf("--positions ADU: %v", err)
	}
	if _, err := run(t, "encrypt", "--text", "AAAAA", "--preset", "m3", "--positions", "AD"); err == nil {
		t.Error("--positions AD on 3 rotors should fail")
	}
	out, err = run(t, "encrypt", "--text", "AAAAA", "--preset", "m3", "--plugboard", "AB")
	if err != nil || out == "BDZGO" {
		t.Errorf("--plugboard AB should change output: %q, %v", out, err)
	}
}

func TestEncrypt_RefusesUnsavedRandom(t *testing.T) {
	want := "refusing to encrypt with a randomly generated machine that is not saved; the ciphertext could not be decrypted. Add --save-config key.json or use --auto-config key.json"
	for _, args := range [][]string{
		{"encrypt", "--text", "HELLO", "--preset", "low"},
		{"encrypt", "--text", "HELLO", "--alphabet", "latin", "--security", "low"},
	} {
		_, err := run(t, args...)
		if err == nil || err.Error() != want {
			t.Errorf("%v: got %v", args, err)
		}
	}
	if _, err := run(t, "encrypt", "--text", "HELLO", "--preset", "low", "--dry-run"); err != nil {
		t.Errorf("--dry-run is exempt: %v", err)
	}
}

func TestEncrypt_UnknownPreset(t *testing.T) {
	_, err := run(t, "encrypt", "--text", "HELLO", "--preset", "classic")
	want := `unknown preset "classic"; available: m3, m4, low, medium, high, extreme`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("got %v", err)
	}
}

func TestEncrypt_NoInput(t *testing.T) {
	if _, err := run(t, "encrypt", "--preset", "m3"); err == nil {
		t.Error("expected error without input")
	}
}

func TestEncrypt_FileInput(t *testing.T) {
	path := writeFile(t, "in.txt", "AAAAA")
	out, err := run(t, "encrypt", "--file", path, "--preset", "m3")
	if err != nil || out != "BDZGO" {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestEncrypt_PresetSaveConfigRoundTrip(t *testing.T) {
	key := filepath.Join(t.TempDir(), "k.json")
	ct, err := run(t, "encrypt", "--text", "HELLOWORLD", "--preset", "medium", "--save-config", key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := run(t, "decrypt", "--text", ct, "--config", key)
	if err != nil || pt != "HELLOWORLD" {
		t.Errorf("decrypt = %q, %v", pt, err)
	}
}

func TestEncrypt_AutoConfigRoundTrip(t *testing.T) {
	key := filepath.Join(t.TempDir(), "auto.json")
	in := "Hello, World! Ünïcode too."
	ct, err := run(t, "encrypt", "--text", in, "--auto-config", key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := enigoma.ParseSettings(data); err != nil || s.SchemaVersion != 2 {
		t.Errorf("auto-config file: %v, %+v", err, s)
	}
	pt, err := run(t, "decrypt", "--text", ct, "--config", key)
	if err != nil || pt != in {
		t.Errorf("decrypt = %q, %v", pt, err)
	}
}

func TestEncryptDecrypt_HexBase64(t *testing.T) {
	for _, format := range []string{"hex", "base64"} {
		key := filepath.Join(t.TempDir(), "k.json")
		ct, err := run(t, "encrypt", "--text", "HELLOWORLD", "--preset", "low", "--save-config", key, "--format", format)
		if err != nil {
			t.Fatalf("%s encrypt: %v", format, err)
		}
		pt, err := run(t, "decrypt", "--text", ct, "--config", key, "--format", format)
		if err != nil || pt != "HELLOWORLD" {
			t.Errorf("%s decrypt = %q, %v", format, pt, err)
		}
	}
}

func TestDecrypt_Stdin(t *testing.T) {
	out, err := runWithStdin(t, "BDZGO", "decrypt", "--preset", "m3")
	if err != nil || out != "AAAAA" {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestDecrypt_RefusesRandom(t *testing.T) {
	_, err := run(t, "decrypt", "--text", "HELLO", "--preset", "high")
	want := "decrypt needs a deterministic machine: use --config FILE or --preset m3|m4"
	if err == nil || err.Error() != want {
		t.Errorf("got %v", err)
	}
}

func TestLoadConfig_V1(t *testing.T) {
	path := writeFile(t, "old.json", v1Config)
	if _, err := loadConfig(path); err == nil || !strings.Contains(err.Error(), v1Message) {
		t.Errorf("loadConfig: %v", err)
	}
	if _, err := run(t, "decrypt", "--text", "ABC", "--config", path); err == nil || !strings.Contains(err.Error(), v1Message) {
		t.Errorf("decrypt --config v1: %v", err)
	}
}

func TestEncrypt_CharErrorSuggestions(t *testing.T) {
	_, err := run(t, "encrypt", "--text", "Hi there", "--preset", "m3")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"--remove-spaces", "--uppercase"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should suggest %s: %v", want, err)
		}
	}
}

func TestEncrypt_Preprocessing(t *testing.T) {
	out, err := run(t, "encrypt", "--text", "a a a a a", "--preset", "m3", "--remove-spaces", "--uppercase")
	if err != nil || out != "BDZGO" {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestFilterLettersOnly(t *testing.T) {
	if got := filterLettersOnly("Hello, World 123!"); got != "HelloWorld" {
		t.Errorf("got %q", got)
	}
}

func TestFilterAlphanumericOnly(t *testing.T) {
	if got := filterAlphanumericOnly("Hello, World 123!"); got != "HelloWorld123" {
		t.Errorf("got %q", got)
	}
}
