package enigoma

import (
	"strings"
	"testing"
)

func mustRotor(t *testing.T, name string) RotorSpec {
	t.Helper()
	r, err := HistoricalRotor(name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func mustReflector(t *testing.T, name string) ReflectorSpec {
	t.Helper()
	r, err := HistoricalReflector(name)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// mustMachine is curried so it can wrap a constructor call: mustMachine(t)(NewM3()).
func mustMachine(t *testing.T) func(*Machine, error) *Machine {
	t.Helper()
	return func(m *Machine, err error) *Machine {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
}

func mustEncrypt(t *testing.T, m *Machine, s string) string {
	t.Helper()
	out, err := m.Encrypt(s)
	if err != nil {
		t.Fatalf("Encrypt(%q): %v", s, err)
	}
	return out
}

func TestKAT_DoubleStep(t *testing.T) {
	m := mustMachine(t)(NewM3(WithPositions("ADU")))
	for _, want := range []string{"ADV", "AEW", "BFX", "BFY"} {
		mustEncrypt(t, m, "A")
		if got := m.Positions(); got != want {
			t.Fatalf("positions = %s, want %s", got, want)
		}
	}
}

func TestKAT_M3_AAAAA(t *testing.T) {
	m := mustMachine(t)(NewM3())
	if got := mustEncrypt(t, m, "AAAAA"); got != "BDZGO" {
		t.Errorf("got %s, want BDZGO", got)
	}
}

func TestKAT_M3_RingsBBB(t *testing.T) {
	m := mustMachine(t)(NewM3(WithRings("BBB")))
	if got := mustEncrypt(t, m, "AAAAA"); got != "EWTYX" {
		t.Errorf("got %s, want EWTYX", got)
	}
}

func TestKAT_M3_Long(t *testing.T) {
	m := mustMachine(t)(NewM3())
	want := "BDZGOWCXLTKSBTMCDLPBMUQOFXYHCXTGYJFLINHNXSHIUNTHEORXPQPKOVHC"
	if got := mustEncrypt(t, m, strings.Repeat("A", 60)); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestKAT_Barbarossa(t *testing.T) {
	ct := "EDPUDNRGYSZRCXNUYTPOMRMBOFKTBZREZKMLXLVEFGUEYSIOZVEQMIKUBPMMYLKLTTDEISMDICAGYKUACTCDOMOHWXMUUIAUBSTSLRNBZSZWNRFXWFYSSXJZVIJHIDISHPRKLKAYUPADTXQSPINQMATLPIFSVKDASCTACDPBOPVHJK"
	pt := "AUFKLXABTEILUNGXVONXKURTINOWAXKURTINOWAXNORDWESTLXSEBEZXSEBEZXUAFFLIEGERSTRASZERIQTUNGXDUBROWKIXDUBROWKIXOPOTSCHKAXOPOTSCHKAXUMXEINSAQTDREINULLXUHRANGETRETENXANGRIFFXINFXRGTX"
	m := mustMachine(t)(New(
		WithRotors(mustRotor(t, "II"), mustRotor(t, "IV"), mustRotor(t, "V")),
		WithReflector(mustReflector(t, "B")),
		WithRings("BUL"),
		WithPositions("BLA"),
		WithPlugboard("AV BS CG DL FU HZ IN KM OW RX"),
	))
	got, err := m.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}
	if got != pt {
		t.Errorf("got  %s\nwant %s", got, pt)
	}
}

func TestKAT_M4_EqualsM3(t *testing.T) {
	m3 := mustMachine(t)(NewM3())
	m4 := mustMachine(t)(NewM4())
	in := strings.Repeat("HELLOWORLD", 20)
	if a, b := mustEncrypt(t, m4, in), mustEncrypt(t, m3, in); a != b {
		t.Errorf("M4 != M3\nM4 %s\nM3 %s", a, b)
	}
}

func TestKAT_M4_ThinRotorFixed(t *testing.T) {
	m := mustMachine(t)(NewM4())
	// Rotor I first reaches its notch (Q) after ~16*650 presses; go well past it.
	mustEncrypt(t, m, strings.Repeat("A", 20000))
	if p := []rune(m.Positions())[0]; p != 'A' {
		t.Errorf("thin rotor moved to %c", p)
	}
}
