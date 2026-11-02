// Package enigoma implements a historically accurate, extensible Enigma machine.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package enigoma

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"github.com/coredds/enigoma/internal/alphabet"
	"github.com/coredds/enigoma/internal/plugboard"
	"github.com/coredds/enigoma/internal/reflector"
	"github.com/coredds/enigoma/internal/rotor"
)

// Machine is a configured Enigma machine. It is not safe for concurrent use;
// use Clone to get independent copies.
type Machine struct {
	alphabet  *alphabet.Alphabet
	rotors    []*rotor.Rotor
	reflector *reflector.Reflector
	plugboard *plugboard.Plugboard
	initial   []int // positions restored by Reset
}

// New builds a machine from options. Rotors and a reflector are required
// (directly or via WithRandomComponents); the plugboard defaults to no pairs.
func New(opts ...Option) (*Machine, error) {
	cfg := config{alphabet: AlphabetLatinUpper}
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	return cfg.build()
}

// NewFromSettings builds a machine from settings, e.g. from ParseSettings or
// Machine.Settings. The rotor positions in the settings become the Reset point.
func NewFromSettings(s Settings) (*Machine, error) {
	return New(
		WithAlphabet(s.Alphabet),
		WithRotors(s.Rotors...),
		WithReflector(s.Reflector),
		WithPlugboard(s.Plugboard),
	)
}

func (c *config) build() (*Machine, error) {
	alph, err := alphabet.New([]rune(c.alphabet))
	if err != nil {
		return nil, fmt.Errorf("alphabet: %w", err)
	}
	if alph.Size()%2 != 0 {
		return nil, fmt.Errorf("alphabet size %d must be even (the reflector pairs every character)", alph.Size())
	}
	if c.random != nil {
		if err := c.fillRandom(alph); err != nil {
			return nil, err
		}
	}
	if len(c.rotors) == 0 {
		return nil, fmt.Errorf("at least one rotor is required")
	}
	if c.reflector == nil {
		return nil, fmt.Errorf("a reflector is required")
	}

	specs := append([]RotorSpec(nil), c.rotors...)
	if err := overrideLetters(specs, c.positions, "positions", func(s *RotorSpec, l string) { s.Position = l }); err != nil {
		return nil, err
	}
	if err := overrideLetters(specs, c.rings, "rings", func(s *RotorSpec, l string) { s.Ring = l }); err != nil {
		return nil, err
	}

	m := &Machine{alphabet: alph}
	for i, spec := range specs {
		r, err := toInternalRotor(spec, alph)
		if err != nil {
			return nil, fmt.Errorf("rotor %d (%s): %w", i+1, spec.Name, err)
		}
		m.rotors = append(m.rotors, r)
	}
	m.reflector, err = reflector.NewReflector(c.reflector.Name, alph, c.reflector.Wiring)
	if err != nil {
		return nil, fmt.Errorf("reflector %s: %w", c.reflector.Name, err)
	}
	pairs := ""
	if c.plugboard != nil {
		pairs = *c.plugboard
	}
	if m.plugboard, err = parsePlugboard(pairs, alph); err != nil {
		return nil, err
	}
	m.initial = m.positionIndices()
	return m, nil
}

// fillRandom generates every component that is still unset.
func (c *config) fillRandom(alph *alphabet.Alphabet) error {
	size := alph.Size()
	if c.rotors == nil {
		for i := 0; i < c.random.rotors; i++ {
			r, err := rotor.RandomRotor(fmt.Sprintf("R%d", i+1), alph)
			if err != nil {
				return fmt.Errorf("random rotor: %w", err)
			}
			pos, err := randInt(size)
			if err != nil {
				return err
			}
			ring, err := randInt(size)
			if err != nil {
				return err
			}
			r.SetPosition(pos)
			r.SetRingSetting(ring)
			c.rotors = append(c.rotors, fromInternalRotor(r, alph))
		}
	}
	if c.reflector == nil {
		refl, err := reflector.RandomReflector("UKW", alph)
		if err != nil {
			return fmt.Errorf("random reflector: %w", err)
		}
		c.reflector = &ReflectorSpec{Name: refl.ID(), Wiring: reflectorWiring(refl, alph)}
	}
	if c.plugboard == nil {
		pairs, err := randomPlugboard(alph, c.random.plugPairs)
		if err != nil {
			return err
		}
		c.plugboard = &pairs
	}
	return nil
}

// randomPlugboard pairs random non-whitespace letters (whitespace cannot be
// written in the "AB CD" plugboard format), capped at what is available.
func randomPlugboard(alph *alphabet.Alphabet, n int) (string, error) {
	var letters []rune
	for _, r := range alph.Runes() {
		if !unicode.IsSpace(r) {
			letters = append(letters, r)
		}
	}
	for i := len(letters) - 1; i > 0; i-- {
		j, err := randInt(i + 1)
		if err != nil {
			return "", err
		}
		letters[i], letters[j] = letters[j], letters[i]
	}
	n = min(n, len(letters)/2)
	pb, err := plugboard.New(alph)
	if err != nil {
		return "", err
	}
	for i := 0; i < n; i++ {
		if err := pb.AddPair(letters[2*i], letters[2*i+1]); err != nil {
			return "", err
		}
	}
	return plugboardString(pb, alph), nil
}

func randInt(n int) (int, error) {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0, fmt.Errorf("random number: %w", err)
	}
	return int(v.Int64()), nil
}

// overrideLetters applies a WithPositions/WithRings string, one letter per rotor.
func overrideLetters(specs []RotorSpec, letters *string, what string, set func(*RotorSpec, string)) error {
	if letters == nil {
		return nil
	}
	runes := []rune(*letters)
	if len(runes) != len(specs) {
		return fmt.Errorf("%s %q: want %d letters, one per rotor", what, *letters, len(specs))
	}
	for i := range specs {
		set(&specs[i], string(runes[i]))
	}
	return nil
}

// letterIndex resolves a single-letter field; empty means the first letter.
func letterIndex(alph *alphabet.Alphabet, s, what string) (int, error) {
	if s == "" {
		return 0, nil
	}
	runes := []rune(s)
	if len(runes) != 1 || !alph.Contains(runes[0]) {
		return 0, fmt.Errorf("%s %q is not a single alphabet letter", what, s)
	}
	idx, _ := alph.RuneToIndex(runes[0])
	return idx, nil
}

func toInternalRotor(spec RotorSpec, alph *alphabet.Alphabet) (*rotor.Rotor, error) {
	wiring := []rune(spec.Wiring)
	seen := make(map[rune]bool, len(wiring))
	for _, r := range wiring {
		if !alph.Contains(r) || seen[r] {
			return nil, fmt.Errorf("wiring must be a permutation of the alphabet")
		}
		seen[r] = true
	}
	if len(wiring) != alph.Size() {
		return nil, fmt.Errorf("wiring must be a permutation of the alphabet (length %d, want %d)", len(wiring), alph.Size())
	}
	notches := []rune(spec.Notches)
	for _, n := range notches {
		if !alph.Contains(n) {
			return nil, fmt.Errorf("notch %q is not in the alphabet", n)
		}
	}
	pos, err := letterIndex(alph, spec.Position, "position")
	if err != nil {
		return nil, err
	}
	ring, err := letterIndex(alph, spec.Ring, "ring")
	if err != nil {
		return nil, err
	}
	r, err := rotor.NewRotor(spec.Name, alph, spec.Wiring, notches)
	if err != nil {
		return nil, err
	}
	r.SetPosition(pos)
	r.SetRingSetting(ring)
	r.SetFixed(spec.Fixed)
	return r, nil
}

func fromInternalRotor(r *rotor.Rotor, alph *alphabet.Alphabet) RotorSpec {
	spec, _ := rotor.ToSpec(r, alph) // indices always valid for alph
	pos, _ := alph.IndexToRune(spec.Position)
	ring, _ := alph.IndexToRune(spec.RingSetting)
	return RotorSpec{
		Name:     spec.ID,
		Wiring:   spec.ForwardMapping,
		Notches:  string(spec.Notches),
		Ring:     string(ring),
		Position: string(pos),
		Fixed:    spec.Fixed,
	}
}

func reflectorWiring(r *reflector.Reflector, alph *alphabet.Alphabet) string {
	spec, _ := reflector.ToSpec(r, alph)
	return spec.Mapping
}

func parsePlugboard(pairs string, alph *alphabet.Alphabet) (*plugboard.Plugboard, error) {
	pb, err := plugboard.New(alph)
	if err != nil {
		return nil, err
	}
	for _, tok := range strings.Fields(pairs) {
		r := []rune(tok)
		if len(r) != 2 {
			return nil, fmt.Errorf("plugboard pair %q: want exactly two letters", tok)
		}
		if err := pb.AddPair(r[0], r[1]); err != nil {
			return nil, fmt.Errorf("plugboard pair %q: %w", tok, err)
		}
	}
	return pb, nil
}

// plugboardString renders pairs ordered by the alphabet index of their first letter.
func plugboardString(pb *plugboard.Plugboard, alph *alphabet.Alphabet) string {
	runes := alph.Runes()
	var pairs []string
	for i := range runes {
		if j := pb.Process(i); j > i {
			pairs = append(pairs, string([]rune{runes[i], runes[j]}))
		}
	}
	return strings.Join(pairs, " ")
}

// Encrypt enciphers s, advancing the rotors one step per character. The whole
// input is validated first: on a *CharError the machine state is unchanged.
func (m *Machine) Encrypt(s string) (string, error) {
	runes := []rune(s)
	indices := make([]int, len(runes))
	for i, r := range runes {
		idx, err := m.alphabet.RuneToIndex(r)
		if err != nil {
			return "", &CharError{Rune: r, Offset: i}
		}
		indices[i] = idx
	}
	alph := m.alphabet.Runes()
	out := make([]rune, len(indices))
	for i, idx := range indices {
		out[i] = alph[m.press(idx, nil)]
	}
	return string(out), nil
}

// Decrypt is identical to Encrypt: Enigma is reciprocal.
func (m *Machine) Decrypt(s string) (string, error) {
	return m.Encrypt(s)
}

// press steps the rotors and routes one contact index through the machine.
// When rec is non-nil every hop is appended to it; Encrypt passes nil.
func (m *Machine) press(idx int, rec *[]Hop) int {
	m.step()
	c := idx
	hop := func(stage Stage, name string, out int) {
		if rec != nil {
			*rec = append(*rec, Hop{Stage: stage, Component: name, In: c, Out: out})
		}
		c = out
	}
	hop(StagePlugboardIn, "plugboard", m.plugboard.Process(c))
	for i := len(m.rotors) - 1; i >= 0; i-- {
		hop(StageRotorForward, m.rotors[i].ID(), m.rotors[i].Forward(c))
	}
	hop(StageReflector, m.reflector.ID(), m.reflector.Reflect(c))
	for i := 0; i < len(m.rotors); i++ {
		hop(StageRotorBackward, m.rotors[i].ID(), m.rotors[i].Backward(c))
	}
	hop(StagePlugboardOut, "plugboard", m.plugboard.Process(c))
	return c
}

// step implements historical stepping, including the double-step. All notch
// checks use positions before any rotor moves. Rotor i steps when rotor i+1 is
// at a notch, and the pushing rotor steps with it (pawl behaviour), which gives
// the middle rotor's double-step. Fixed rotors never step and block
// propagation to their left.
func (m *Machine) step() {
	n := len(m.rotors)
	right := n - 1
	for right >= 0 && m.rotors[right].IsFixed() {
		right--
	}
	if right < 0 {
		return
	}
	step := make([]bool, n)
	step[right] = true
	for i := right - 1; i >= 0; i-- {
		if m.rotors[i].IsFixed() {
			break
		}
		if m.rotors[i+1].IsAtNotch() {
			step[i] = true
			if i+1 != right {
				step[i+1] = true
			}
		}
	}
	for i, s := range step {
		if s {
			m.rotors[i].Step()
		}
	}
}

func (m *Machine) positionIndices() []int {
	p := make([]int, len(m.rotors))
	for i, r := range m.rotors {
		p[i] = r.GetPosition()
	}
	return p
}

// Positions returns the rotor window letters, left to right, e.g. "ADU".
func (m *Machine) Positions() string {
	alph := m.alphabet.Runes()
	out := make([]rune, len(m.rotors))
	for i, r := range m.rotors {
		out[i] = alph[r.GetPosition()]
	}
	return string(out)
}

// SetPositions sets the rotor window letters, one per rotor, left to right.
func (m *Machine) SetPositions(p string) error {
	runes := []rune(p)
	if len(runes) != len(m.rotors) {
		return fmt.Errorf("positions %q: want %d letters, one per rotor", p, len(m.rotors))
	}
	idx := make([]int, len(runes))
	for i, r := range runes {
		var err error
		if idx[i], err = m.alphabet.RuneToIndex(r); err != nil {
			return fmt.Errorf("positions %q: %q is not in the alphabet", p, r)
		}
	}
	for i, r := range m.rotors {
		r.SetPosition(idx[i])
	}
	return nil
}

// Reset restores the rotor positions the machine was constructed with.
func (m *Machine) Reset() {
	for i, r := range m.rotors {
		r.SetPosition(m.initial[i])
	}
}

// Settings returns the machine's full configuration with the current rotor
// positions. NewFromSettings(m.Settings()) reproduces the machine as it is now.
func (m *Machine) Settings() Settings {
	s := Settings{
		SchemaVersion: SchemaVersion,
		Alphabet:      string(m.alphabet.Runes()),
		Reflector:     ReflectorSpec{Name: m.reflector.ID(), Wiring: reflectorWiring(m.reflector, m.alphabet)},
		Plugboard:     plugboardString(m.plugboard, m.alphabet),
	}
	for _, r := range m.rotors {
		s.Rotors = append(s.Rotors, fromInternalRotor(r, m.alphabet))
	}
	return s
}

// Alphabet returns the machine's character set.
func (m *Machine) Alphabet() string {
	return string(m.alphabet.Runes())
}

// Clone returns an independent deep copy of the machine, including its state.
func (m *Machine) Clone() *Machine {
	c := &Machine{
		alphabet:  m.alphabet, // immutable
		reflector: m.reflector.Clone(),
		plugboard: m.plugboard.Clone(),
		initial:   append([]int(nil), m.initial...),
	}
	for _, r := range m.rotors {
		c.rotors = append(c.rotors, r.Clone())
	}
	return c
}
