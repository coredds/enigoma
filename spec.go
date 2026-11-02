// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package enigoma

import (
	"encoding/json"
	"errors"
	"fmt"
)

// SchemaVersion is the configuration schema version produced and accepted by this package.
const SchemaVersion = 2

// errSchemaV1 is returned for configuration files written by enigoma 0.6 and earlier.
var errSchemaV1 = errors.New("config schema v1 (enigoma ≤ 0.6) is not supported; regenerate the key with enigoma ≥ 0.7")

// RotorSpec describes a rotor. Letters (notches, ring, position) are characters
// of the machine's alphabet; an empty Ring or Position means the first letter.
type RotorSpec struct {
	Name     string `json:"name"`
	Wiring   string `json:"wiring"`
	Notches  string `json:"notches"`
	Ring     string `json:"ring"`
	Position string `json:"position"`
	Fixed    bool   `json:"fixed,omitempty"` // never steps (M4 Beta/Gamma)
}

// ReflectorSpec describes a reflector. Wiring must be a reciprocal mapping with
// no character mapped to itself.
type ReflectorSpec struct {
	Name   string `json:"name"`
	Wiring string `json:"wiring"`
}

// Settings is the complete, serializable configuration of a machine,
// including the current rotor positions.
type Settings struct {
	SchemaVersion int           `json:"schema_version"`
	Alphabet      string        `json:"alphabet"`
	Rotors        []RotorSpec   `json:"rotors"`
	Reflector     ReflectorSpec `json:"reflector"`
	Plugboard     string        `json:"plugboard"` // space-separated pairs, e.g. "AB CD"
}

// ParseSettings decodes a JSON configuration. Configurations from enigoma 0.6
// and earlier (schema v1) are rejected.
func ParseSettings(data []byte) (Settings, error) {
	var probe struct {
		Version *int `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return Settings{}, fmt.Errorf("parse settings: %w", err)
	}
	switch {
	case probe.Version == nil || *probe.Version == 1:
		return Settings{}, errSchemaV1
	case *probe.Version != SchemaVersion:
		return Settings{}, fmt.Errorf("unsupported schema version %d (expected %d)", *probe.Version, SchemaVersion)
	}
	var s Settings
	if err := json.Unmarshal(data, &s); err != nil {
		return Settings{}, fmt.Errorf("parse settings: %w", err)
	}
	return s, nil
}
