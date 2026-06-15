package enigoma

import (
	"testing"
)

// TestHistoricalM3 tests the historical M3 Enigma machine.
func TestHistoricalM3(t *testing.T) {
	machine, err := NewEnigmaM3()
	if err != nil {
		t.Fatalf("Failed to create M3 Enigma: %v", err)
	}

	// Verify the machine has the correct components
	if machine.GetRotorCount() != 3 {
		t.Errorf("M3 should have 3 rotors, got %d", machine.GetRotorCount())
	}

	if machine.GetAlphabetSize() != 26 {
		t.Errorf("M3 should have 26 characters, got %d", machine.GetAlphabetSize())
	}

	// Test a known encryption with the M3
	// Set specific rotor positions for a deterministic test
	if err := machine.SetRotorPositions([]int{0, 0, 0}); err != nil { // AAA
		t.Fatalf("Failed to set rotor positions: %v", err)
	}

	// Encrypt a message
	plaintext := "ENIGMA"
	ciphertext, err := machine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Reset and decrypt
	if err := machine.Reset(); err != nil {
		t.Fatalf("Failed to reset machine: %v", err)
	}
	decrypted, err := machine.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decryption failed: expected %s, got %s", plaintext, decrypted)
	}
}

// TestHistoricalM4 tests the historical M4 Naval Enigma machine.
func TestHistoricalM4(t *testing.T) {
	machine, err := NewEnigmaM4()
	if err != nil {
		t.Fatalf("Failed to create M4 Enigma: %v", err)
	}

	// Verify the machine has the correct components
	if machine.GetRotorCount() != 4 {
		t.Errorf("M4 should have 4 rotors, got %d", machine.GetRotorCount())
	}

	if machine.GetAlphabetSize() != 26 {
		t.Errorf("M4 should have 26 characters, got %d", machine.GetAlphabetSize())
	}

	// Test a known encryption with the M4
	// Set specific rotor positions for a deterministic test
	if err := machine.SetRotorPositions([]int{0, 0, 0, 0}); err != nil { // AAAA
		t.Fatalf("Failed to set rotor positions: %v", err)
	}

	// Encrypt a message
	plaintext := "UBOAT"
	ciphertext, err := machine.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Reset and decrypt
	if err := machine.Reset(); err != nil {
		t.Fatalf("Failed to reset machine: %v", err)
	}
	decrypted, err := machine.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decryption failed: expected %s, got %s", plaintext, decrypted)
	}
}

// TestHistoricalRotorWirings tests that the historical rotor wirings are valid.
func TestHistoricalRotorWirings(t *testing.T) {
	// All wirings should be 26 characters long
	wirings := []string{
		RotorI, RotorII, RotorIII, RotorIV, RotorV, RotorVI, RotorVII, RotorVIII,
		RotorBeta, RotorGamma,
		ReflectorA, ReflectorB, ReflectorC, ReflectorBThin, ReflectorCThin,
	}

	for i, wiring := range wirings {
		if len(wiring) != 26 {
			t.Errorf("Wiring %d has length %d, expected 26", i, len(wiring))
		}

		// Check for duplicate characters
		seen := make(map[rune]bool)
		for _, r := range wiring {
			if seen[r] {
				t.Errorf("Wiring %d has duplicate character %c", i, r)
			}
			seen[r] = true
		}
	}
}
