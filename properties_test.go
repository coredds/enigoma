package enigoma

import (
	"math/rand/v2"
	"testing"
)

func TestProperty_RoundTrip(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	alphabets := []string{AlphabetLatinUpper, AlphabetGreek, AlphabetASCIIPrintable, AlphabetPortuguese}
	for i := 0; i < 50; i++ {
		alph := []rune(alphabets[i%len(alphabets)])
		m := mustMachine(t)(New(WithAlphabet(string(alph)), WithRandomComponents(1+rng.IntN(8), rng.IntN(20))))
		in := make([]rune, 1+rng.IntN(300))
		for j := range in {
			in[j] = alph[rng.IntN(len(alph))]
		}
		dec := m.Clone()
		ct := mustEncrypt(t, m, string(in))
		if got := mustEncrypt(t, dec, ct); got != string(in) {
			t.Fatalf("machine %d: round trip failed\nsettings %+v", i, m.Settings())
		}
	}
}
