// Package enigma provides convenience function tests.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package enigma

import (
	"strings"
	"testing"
)

func TestQuickEncrypt_Basic(t *testing.T) {
	text := "HELLO WORLD"
	encrypted, config, err := QuickEncrypt(text, Medium)
	if err != nil {
		t.Fatalf("QuickEncrypt() error: %v", err)
	}
	if encrypted == "" {
		t.Error("QuickEncrypt() returned empty encrypted text")
	}
	if config == "" {
		t.Error("QuickEncrypt() returned empty config")
	}
	if encrypted == text {
		t.Error("QuickEncrypt() encrypted text is same as plaintext")
	}
}

func TestQuickEncrypt_SecurityLevels(t *testing.T) {
	text := "HELLO WORLD"
	levels := []struct {
		name  string
		level SecurityLevel
	}{
		{"Low", Low},
		{"Medium", Medium},
		{"High", High},
		{"Extreme", Extreme},
	}

	for _, tt := range levels {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, config, err := QuickEncrypt(text, tt.level)
			if err != nil {
				t.Fatalf("QuickEncrypt(%s) error: %v", tt.name, err)
			}
			if encrypted == "" {
				t.Error("QuickEncrypt() returned empty encrypted text")
			}
			if config == "" {
				t.Error("QuickEncrypt() returned empty config")
			}
		})
	}
}

func TestQuickEncrypt_EmptyText(t *testing.T) {
	_, _, err := QuickEncrypt("", Medium)
	if err == nil {
		t.Error("QuickEncrypt('') expected error but got none")
	}
}

func TestQuickEncrypt_RoundTrip(t *testing.T) {
	texts := []string{
		"HELLO WORLD",
		"abcdefghijklmnop",
		"MiXeD CaSe TeXt",
		"Numbers 12345",
	}

	for _, text := range texts {
		t.Run(text, func(t *testing.T) {
			encrypted, config, err := QuickEncrypt(text, Medium)
			if err != nil {
				t.Fatalf("QuickEncrypt() error: %v", err)
			}

			decrypted, err := DecryptWithConfig(encrypted, config)
			if err != nil {
				t.Fatalf("DecryptWithConfig() error: %v", err)
			}

			if decrypted != text {
				t.Errorf("Round-trip failed: got %q, want %q", decrypted, text)
			}
		})
	}
}

func TestQuickEncrypt_UnicodeRoundTrip(t *testing.T) {
	texts := []string{
		"αβγδεζ",
		"日本語テスト",
		"Héllo Wörld",
	}

	for _, text := range texts {
		t.Run(text, func(t *testing.T) {
			encrypted, config, err := QuickEncrypt(text, Low)
			if err != nil {
				t.Fatalf("QuickEncrypt() error: %v", err)
			}

			decrypted, err := DecryptWithConfig(encrypted, config)
			if err != nil {
				t.Fatalf("DecryptWithConfig() error: %v", err)
			}

			if decrypted != text {
				t.Errorf("Unicode round-trip failed: got %q, want %q", decrypted, text)
			}
		})
	}
}

func TestEncryptText_Basic(t *testing.T) {
	text := "HELLO WORLD"
	encrypted, config, err := EncryptText(text)
	if err != nil {
		t.Fatalf("EncryptText() error: %v", err)
	}
	if encrypted == "" {
		t.Error("EncryptText() returned empty encrypted text")
	}
	if config == "" {
		t.Error("EncryptText() returned empty config")
	}
}

func TestEncryptText_RoundTrip(t *testing.T) {
	text := "HELLO WORLD"
	encrypted, config, err := EncryptText(text)
	if err != nil {
		t.Fatalf("EncryptText() error: %v", err)
	}

	decrypted, err := DecryptWithConfig(encrypted, config)
	if err != nil {
		t.Fatalf("DecryptWithConfig() error: %v", err)
	}

	if decrypted != text {
		t.Errorf("EncryptText round-trip failed: got %q, want %q", decrypted, text)
	}
}

func TestDecryptWithConfig_InvalidJSON(t *testing.T) {
	_, err := DecryptWithConfig("encrypted", "not-valid-json")
	if err == nil {
		t.Error("DecryptWithConfig() with invalid JSON expected error")
	}
	if !strings.Contains(err.Error(), "failed to load configuration") {
		t.Errorf("DecryptWithConfig() error = %q, want to contain 'failed to load configuration'", err.Error())
	}
}

func TestDecryptWithConfig_EmptyConfig(t *testing.T) {
	_, err := DecryptWithConfig("encrypted", "")
	if err == nil {
		t.Error("DecryptWithConfig() with empty config expected error")
	}
}

func TestNewFromText_Basic(t *testing.T) {
	machine, err := NewFromText("HELLO WORLD", Medium)
	if err != nil {
		t.Fatalf("NewFromText() error: %v", err)
	}
	if machine == nil {
		t.Fatal("NewFromText() returned nil machine")
	}
	// Alphabet should contain all input characters
	if machine.GetAlphabetSize() < 8 { // H, E, L, O, W, R, D, space = at least 8
		t.Errorf("NewFromText() alphabet size %d too small", machine.GetAlphabetSize())
	}
}

func TestNewFromText_EmptyText(t *testing.T) {
	_, err := NewFromText("", Medium)
	if err == nil {
		t.Error("NewFromText('') expected error")
	}
}

func TestNewFromText_AllSecurityLevels(t *testing.T) {
	levels := []SecurityLevel{Low, Medium, High, Extreme}
	for _, level := range levels {
		machine, err := NewFromText("HELLO WORLD", level)
		if err != nil {
			t.Fatalf("NewFromText(level=%d) error: %v", level, err)
		}
		if machine == nil {
			t.Fatalf("NewFromText(level=%d) returned nil machine", level)
		}
	}
}

func TestNewWithAutoDetection_Basic(t *testing.T) {
	machine, err := NewWithAutoDetection("HELLO WORLD")
	if err != nil {
		t.Fatalf("NewWithAutoDetection() error: %v", err)
	}
	if machine == nil {
		t.Fatal("NewWithAutoDetection() returned nil machine")
	}
}

func TestNewWithAutoDetection_EmptyText(t *testing.T) {
	_, err := NewWithAutoDetection("")
	if err == nil {
		t.Error("NewWithAutoDetection('') expected error")
	}
}

func TestNewWithAutoDetection_EncryptDecrypt(t *testing.T) {
	text := "HELLO WORLD"
	machine, err := NewWithAutoDetection(text)
	if err != nil {
		t.Fatalf("NewWithAutoDetection() error: %v", err)
	}

	// Save config before encryption
	config, err := machine.SaveSettingsToJSON()
	if err != nil {
		t.Fatalf("SaveSettingsToJSON() error: %v", err)
	}

	encrypted, err := machine.Encrypt(text)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Decrypt using saved config
	decrypted, err := DecryptWithConfig(encrypted, config)
	if err != nil {
		t.Fatalf("DecryptWithConfig() error: %v", err)
	}

	if decrypted != text {
		t.Errorf("NewWithAutoDetection round-trip failed: got %q, want %q", decrypted, text)
	}
}

func TestQuickEncrypt_ConfigContainsJSON(t *testing.T) {
	_, config, err := QuickEncrypt("HELLO", Low)
	if err != nil {
		t.Fatalf("QuickEncrypt() error: %v", err)
	}

	// Config should be valid JSON (starts with { and ends with })
	trimmed := strings.TrimSpace(config)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		t.Errorf("QuickEncrypt() config doesn't look like JSON: %q", config[:min(50, len(config))])
	}
}
