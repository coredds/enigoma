// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License

package enigoma

// Stage identifies where in the machine a signal hop happens.
type Stage int

// Signal path stages, in the order a keypress passes through them.
const (
	StagePlugboardIn Stage = iota
	StageRotorForward
	StageReflector
	StageRotorBackward
	StagePlugboardOut
)

func (s Stage) String() string {
	switch s {
	case StagePlugboardIn:
		return "plugboard-in"
	case StageRotorForward:
		return "rotor-forward"
	case StageReflector:
		return "reflector"
	case StageRotorBackward:
		return "rotor-backward"
	case StagePlugboardOut:
		return "plugboard-out"
	}
	return "unknown"
}

// Hop is one component's substitution of the signal. In and Out are contact
// indices into the machine's alphabet; each hop's Out is the next hop's In.
type Hop struct {
	Stage     Stage
	Component string // rotor or reflector name, or "plugboard"
	In, Out   int
}

// Trace records one keypress: the rotor windows before and after stepping and
// every hop of the signal path. For n rotors there are 2n+3 hops: plugboard,
// rotors right to left, reflector, rotors left to right, plugboard.
type Trace struct {
	Input, Output rune
	Before, After string
	Hops          []Hop
}

// Press enciphers a single character, like Encrypt, and returns a full trace
// of the keypress. A rune outside the alphabet returns a *CharError and the
// rotors do not move.
func (m *Machine) Press(r rune) (Trace, error) {
	idx, err := m.alphabet.RuneToIndex(r)
	if err != nil {
		return Trace{}, &CharError{Rune: r, Offset: 0}
	}
	t := Trace{Input: r, Before: m.Positions(), Hops: make([]Hop, 0, 2*len(m.rotors)+3)}
	out := m.press(idx, &t.Hops)
	t.Output = m.alphabet.Runes()[out]
	t.After = m.Positions()
	return t, nil
}
