package enigoma

import (
	"strings"
	"testing"
)

func TestVersion(t *testing.T) {
	version := GetVersion()
	if version == "" {
		t.Error("GetVersion() returned empty string")
	}

	if version != Version {
		t.Errorf("GetVersion() = %s, want %s", version, Version)
	}

	// Check version format (should be semantic versioning)
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		t.Errorf("Version format invalid: %s (should be X.Y.Z)", version)
	}

	// Version should match the constant (already checked) and follow semver
}

func TestVersionConstant(t *testing.T) {
	if Version == "" {
		t.Error("Version constant is empty")
	}

	// Version should follow semantic versioning format (X.Y.Z)
	parts := strings.Split(Version, ".")
	if len(parts) != 3 {
		t.Errorf("Version %q does not follow semver format X.Y.Z", Version)
	}
	for i, part := range parts {
		if part == "" {
			t.Errorf("Version %q has empty component at position %d", Version, i)
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				t.Errorf("Version %q has non-numeric character %q in component %d", Version, string(c), i)
			}
		}
	}
}
