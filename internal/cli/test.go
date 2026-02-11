// Package cli provides the test command for the enigoma CLI.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package cli

import (
	"fmt"

	"github.com/coredds/enigoma"
	"github.com/coredds/enigoma/pkg/enigma"
	"github.com/spf13/cobra"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test enigoma installation and functionality",
	Long: `Test enigoma installation and core functionality.

This command runs a series of tests to verify that enigoma is working correctly:
• Basic encryption/decryption round-trip
• Unicode support
• Auto-detection functionality
• Configuration serialization
• All security levels

Perfect for verifying your installation or troubleshooting issues.

Example:
  enigoma test`,
	RunE: runTest,
}

func runTest(cmd *cobra.Command, args []string) error {
	fmt.Printf("🧪 Testing enigoma Installation\n")
	fmt.Printf("Version: %s\n", enigoma.GetVersion())
	fmt.Println("==============================")
	fmt.Println()

	var passed, failed int

	// Test 1: Basic Functionality
	fmt.Print("📝 Basic encryption/decryption... ")
	if err := testBasicEncryption(); err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		failed++
	} else {
		fmt.Println("✅ PASSED")
		passed++
	}

	// Test 2: Unicode Support
	fmt.Print("🌍 Unicode support... ")
	if err := testUnicodeSupport(); err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		failed++
	} else {
		fmt.Println("✅ PASSED")
		passed++
	}

	// Test 3: Auto-Detection
	fmt.Print("🎯 Auto-detection... ")
	if err := testAutoDetection(); err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		failed++
	} else {
		fmt.Println("✅ PASSED")
		passed++
	}

	// Test 4: Configuration Serialization
	fmt.Print("💾 Configuration serialization... ")
	if err := testConfigSerialization(); err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		failed++
	} else {
		fmt.Println("✅ PASSED")
		passed++
	}

	// Test 5: Security Levels
	fmt.Print("🛡️  Security levels... ")
	if err := testSecurityLevels(); err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		failed++
	} else {
		fmt.Println("✅ PASSED")
		passed++
	}

	// Test 6: Convenience Functions
	fmt.Print("⚡ Convenience functions... ")
	if err := testConvenienceFunctions(); err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		failed++
	} else {
		fmt.Println("✅ PASSED")
		passed++
	}

	// Test 7: Historical Presets
	fmt.Print("🏛️  Historical presets... ")
	if err := testHistoricalPresets(); err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		failed++
	} else {
		fmt.Println("✅ PASSED")
		passed++
	}

	// Summary
	fmt.Println()
	fmt.Println("📊 TEST RESULTS")
	fmt.Println("===============")
	fmt.Printf("✅ Passed: %d\n", passed)
	fmt.Printf("❌ Failed: %d\n", failed)
	fmt.Printf("📈 Success Rate: %.1f%%\n", float64(passed)/float64(passed+failed)*100)
	fmt.Println()

	if failed == 0 {
		fmt.Println("🎉 All tests passed! enigoma is working perfectly.")
		fmt.Println()
		fmt.Println("Ready to use:")
		fmt.Println("• enigoma encrypt --text \"Your message\" --auto-config key.json")
		fmt.Println("• enigoma wizard (for interactive setup)")
		fmt.Println("• enigoma examples (for copy-paste examples)")
	} else {
		fmt.Printf("⚠️  %d test(s) failed. enigoma may not be working correctly.\n", failed)
		fmt.Println()
		fmt.Println("Troubleshooting:")
		fmt.Println("• Check your Go version (requires Go 1.23+)")
		fmt.Println("• Try reinstalling: go install github.com/coredds/enigoma/cmd/enigoma@latest")
		fmt.Println("• Report issues at: https://github.com/coredds/enigoma/issues")
		return fmt.Errorf("test suite failed with %d failures", failed)
	}

	return nil
}

func testBasicEncryption() error {
	machine, err := enigma.NewEnigmaClassic()
	if err != nil {
		return fmt.Errorf("failed to create machine: %v", err)
	}

	message := "HELLOWORLD"
	encrypted, err := machine.Encrypt(message)
	if err != nil {
		return fmt.Errorf("encryption failed: %v", err)
	}

	if err := machine.Reset(); err != nil {
		return fmt.Errorf("failed to reset machine: %v", err)
	}
	decrypted, err := machine.Decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("decryption failed: %v", err)
	}

	if message != decrypted {
		return fmt.Errorf("round-trip failed: %q != %q", message, decrypted)
	}

	return nil
}

func testUnicodeSupport() error {
	message := "Olá! Привет! 日本語!"
	machine, err := enigma.NewFromText(message, enigma.Medium)
	if err != nil {
		return fmt.Errorf("failed to create Unicode machine: %v", err)
	}

	encrypted, err := machine.Encrypt(message)
	if err != nil {
		return fmt.Errorf("unicode encryption failed: %w", err)
	}

	if err := machine.Reset(); err != nil {
		return fmt.Errorf("failed to reset Unicode machine: %v", err)
	}
	decrypted, err := machine.Decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("unicode decryption failed: %w", err)
	}

	if message != decrypted {
		return fmt.Errorf("unicode round-trip failed: %q != %q", message, decrypted)
	}

	return nil
}

func testAutoDetection() error {
	message := "Testing auto-detection! 🚀"
	machine, err := enigma.NewWithAutoDetection(message)
	if err != nil {
		return fmt.Errorf("auto-detection failed: %v", err)
	}

	if machine.GetAlphabetSize() == 0 {
		return fmt.Errorf("auto-detected alphabet is empty")
	}

	encrypted, err := machine.Encrypt(message)
	if err != nil {
		return fmt.Errorf("encryption with auto-detected alphabet failed: %v", err)
	}

	if err := machine.Reset(); err != nil {
		return fmt.Errorf("failed to reset auto-detection machine: %v", err)
	}
	decrypted, err := machine.Decrypt(encrypted)
	if err != nil {
		return fmt.Errorf("decryption with auto-detected alphabet failed: %v", err)
	}

	if message != decrypted {
		return fmt.Errorf("auto-detection round-trip failed: %q != %q", message, decrypted)
	}

	return nil
}

func testConfigSerialization() error {
	machine, err := enigma.NewEnigmaClassic()
	if err != nil {
		return fmt.Errorf("failed to create machine: %v", err)
	}

	// Serialize to JSON
	jsonConfig, err := machine.SaveSettingsToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize config: %v", err)
	}

	if len(jsonConfig) == 0 {
		return fmt.Errorf("serialized config is empty")
	}

	// Create new machine from JSON
	newMachine, err := enigma.NewFromJSON(jsonConfig)
	if err != nil {
		return fmt.Errorf("failed to deserialize config: %v", err)
	}

	// Test that both machines produce the same result
	message := "CONFIGTEST"
	encrypted1, err := machine.Encrypt(message)
	if err != nil {
		return fmt.Errorf("original machine encryption failed: %v", err)
	}

	decrypted, err := newMachine.Decrypt(encrypted1)
	if err != nil {
		return fmt.Errorf("deserialized machine decryption failed: %v", err)
	}

	if message != decrypted {
		return fmt.Errorf("config serialization round-trip failed: %q != %q", message, decrypted)
	}

	return nil
}

func testSecurityLevels() error {
	levels := []enigma.SecurityLevel{enigma.Low, enigma.Medium, enigma.High, enigma.Extreme}
	message := "SECURITYTEST"

	for _, level := range levels {
		machine, err := enigma.New(
			enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
			enigma.WithRandomSettings(level),
		)
		if err != nil {
			return fmt.Errorf("failed to create %v security machine: %v", level, err)
		}

		encrypted, err := machine.Encrypt(message)
		if err != nil {
			return fmt.Errorf("%v security encryption failed: %v", level, err)
		}

		if err := machine.Reset(); err != nil {
			return fmt.Errorf("failed to reset %v security machine: %v", level, err)
		}
		decrypted, err := machine.Decrypt(encrypted)
		if err != nil {
			return fmt.Errorf("%v security decryption failed: %v", level, err)
		}

		if message != decrypted {
			return fmt.Errorf("%v security round-trip failed: %q != %q", level, message, decrypted)
		}
	}

	return nil
}

func testConvenienceFunctions() error {
	message := "Convenience test"

	// Test EncryptText
	encrypted, config, err := enigma.EncryptText(message)
	if err != nil {
		return fmt.Errorf("EncryptText failed: %v", err)
	}

	if len(encrypted) == 0 || len(config) == 0 {
		return fmt.Errorf("EncryptText returned empty results")
	}

	// Test DecryptWithConfig
	decrypted, err := enigma.DecryptWithConfig(encrypted, config)
	if err != nil {
		return fmt.Errorf("DecryptWithConfig failed: %v", err)
	}

	if message != decrypted {
		return fmt.Errorf("convenience function round-trip failed: %q != %q", message, decrypted)
	}

	return nil
}

func testHistoricalPresets() error {
	presets := []func() (*enigma.Enigma, error){
		enigma.NewEnigmaClassic,
		enigma.NewEnigmaM3,
		enigma.NewEnigmaM4,
	}

	message := "HISTORICAL"

	for i, presetFunc := range presets {
		machine, err := presetFunc()
		if err != nil {
			return fmt.Errorf("failed to create preset %d: %v", i, err)
		}

		encrypted, err := machine.Encrypt(message)
		if err != nil {
			return fmt.Errorf("preset %d encryption failed: %v", i, err)
		}

		if err := machine.Reset(); err != nil {
			return fmt.Errorf("failed to reset preset %d machine: %v", i, err)
		}
		decrypted, err := machine.Decrypt(encrypted)
		if err != nil {
			return fmt.Errorf("preset %d decryption failed: %v", i, err)
		}

		if message != decrypted {
			return fmt.Errorf("preset %d round-trip failed: %q != %q", i, message, decrypted)
		}
	}

	return nil
}
