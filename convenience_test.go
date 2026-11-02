package enigoma

import (
	"strings"
	"testing"
)

func TestQuickEncrypt_RoundTrip(t *testing.T) {
	in := "Hello, Wörld!"
	ct, cfg, err := QuickEncrypt(in, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if ct == in {
		t.Error("ciphertext equals plaintext")
	}
	got, err := DecryptWithConfig(ct, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Errorf("round trip = %q, want %q", got, in)
	}
}

func TestNewFromText_Empty(t *testing.T) {
	if _, err := NewFromText(""); err == nil {
		t.Error("expected error for empty text")
	}
}

func TestNewFromText_Overrides(t *testing.T) {
	m := mustMachine(t)(NewFromText("hello world", WithRandomComponents(3, 1)))
	if n := len(m.Settings().Rotors); n != 3 {
		t.Errorf("rotors = %d, want 3", n)
	}
	if _, err := m.Encrypt("hello world"); err != nil {
		t.Errorf("detected alphabet cannot encrypt its own text: %v", err)
	}
}

func TestDecryptWithConfig_V1(t *testing.T) {
	_, err := DecryptWithConfig("ABC", []byte(`{"schema_version":1}`))
	if err == nil || !strings.Contains(err.Error(), v1Message) {
		t.Errorf("got %v, want v1 message", err)
	}
}

func TestQuickEncrypt_LineEndingsLossless(t *testing.T) {
	for _, in := range []string{"a\r\nb", "hello\n", "  padded  ", "x"} {
		ct, cfg, err := QuickEncrypt(in, 3, 2)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got, err := DecryptWithConfig(ct, cfg); err != nil || got != in {
			t.Errorf("%q: round trip = %q, %v", in, got, err)
		}
	}
}
