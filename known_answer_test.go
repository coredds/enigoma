package enigoma

import (
	"strings"
	"testing"

	"github.com/coredds/enigoma/internal/reflector"
	"github.com/coredds/enigoma/internal/rotor"
)

func positionsAsLetters(m *Enigma) string {
	var b strings.Builder
	for _, p := range m.GetCurrentRotorPositions() {
		b.WriteRune(rune('A' + p))
	}
	return b.String()
}

func mustEncrypt(t *testing.T, m *Enigma, s string) string {
	t.Helper()
	out, err := m.Encrypt(s)
	if err != nil {
		t.Fatalf("Encrypt(%q): %v", s, err)
	}
	return out
}

func TestKAT_DoubleStep(t *testing.T) {
	m, err := NewEnigmaM3()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SetRotorPositions([]int{0, 3, 20}); err != nil { // ADU
		t.Fatal(err)
	}
	for _, want := range []string{"ADV", "AEW", "BFX", "BFY"} {
		mustEncrypt(t, m, "A")
		if got := positionsAsLetters(m); got != want {
			t.Fatalf("positions = %s, want %s", got, want)
		}
	}
}

func TestKAT_M3_AAAAA(t *testing.T) {
	m, _ := NewEnigmaM3()
	if got := mustEncrypt(t, m, "AAAAA"); got != "BDZGO" {
		t.Errorf("got %s, want BDZGO", got)
	}
}

func TestKAT_M3_RingsBBB(t *testing.T) {
	m, _ := NewEnigmaM3()
	for _, r := range m.rotors {
		r.SetRingSetting(1)
	}
	if got := mustEncrypt(t, m, "AAAAA"); got != "EWTYX" {
		t.Errorf("got %s, want EWTYX", got)
	}
}

func TestKAT_M3_Long(t *testing.T) {
	m, _ := NewEnigmaM3()
	want := "BDZGOWCXLTKSBTMCDLPBMUQOFXYHCXTGYJFLINHNXSHIUNTHEORXPQPKOVHC"
	if got := mustEncrypt(t, m, strings.Repeat("A", 60)); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestKAT_Barbarossa(t *testing.T) {
	ct := "EDPUDNRGYSZRCXNUYTPOMRMBOFKTBZREZKMLXLVEFGUEYSIOZVEQMIKUBPMMYLKLTTDEISMDICAGYKUACTCDOMOHWXMUUIAUBSTSLRNBZSZWNRFXWFYSSXJZVIJHIDISHPRKLKAYUPADTXQSPINQMATLPIFSVKDASCTACDPBOPVHJK"
	pt := "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLXSEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNGXDUBROWKIXDUBROWKIXOPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENXANGRIFFXINFXRGTX"

	idx := func(r rune) int { return int(r - 'A') }
	m, err := New(
		WithAlphabet(AlphabetLatinUpper),
		WithRotorConfiguration([]rotor.RotorSpec{
			{ID: "II", ForwardMapping: RotorII, Notches: NotchII, RingSetting: idx('B'), Position: idx('B')},
			{ID: "IV", ForwardMapping: RotorIV, Notches: NotchIV, RingSetting: idx('U'), Position: idx('L')},
			{ID: "V", ForwardMapping: RotorV, Notches: NotchV, RingSetting: idx('L'), Position: idx('A')},
		}),
		WithReflectorConfiguration(reflector.ReflectorSpec{ID: "B", Mapping: ReflectorB}),
		WithPlugboardConfiguration(reciprocal("AV BS CG DL FU HZ IN KM OW RX")),
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if got != pt {
		t.Errorf("got  %s\nwant %s", got, pt)
	}
}

func TestKAT_M4_EqualsM3(t *testing.T) {
	m3, _ := NewEnigmaM3()
	m4, _ := NewEnigmaM4()
	in := strings.Repeat("HELLOWORLD", 20)
	if a, b := mustEncrypt(t, m4, in), mustEncrypt(t, m3, in); a != b {
		t.Errorf("M4 != M3\nM4 %s\nM3 %s", a, b)
	}
}

func TestKAT_M4_ThinRotorFixed(t *testing.T) {
	m, _ := NewEnigmaM4()
	// Rotor I first reaches its notch (Q) after ~16*650 presses; go well past it.
	for i := 0; i < 20000; i++ {
		mustEncrypt(t, m, "A")
	}
	if p := m.GetCurrentRotorPositions()[0]; p != 0 {
		t.Errorf("thin rotor moved to %d", p)
	}
}

func reciprocal(pairs string) map[rune]rune {
	m := map[rune]rune{}
	for _, p := range strings.Fields(pairs) {
		r := []rune(p)
		m[r[0]], m[r[1]] = r[1], r[0]
	}
	return m
}
