package enigoma_test

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/coredds/enigoma"
)

func ExampleNewM3() {
	m, err := enigoma.NewM3()
	if err != nil {
		log.Fatal(err)
	}
	out, _ := m.Encrypt("AAAAA")
	fmt.Println(out)
	// Output: BDZGO
}

func ExampleMachine_Press() {
	m, _ := enigoma.NewM3()
	t, _ := m.Press('A')
	fmt.Printf("%c -> %c, rotors %s -> %s, %d hops\n", t.Input, t.Output, t.Before, t.After, len(t.Hops))
	// Output: A -> B, rotors AAA -> AAB, 9 hops
}

func ExampleNew() {
	II, _ := enigoma.HistoricalRotor("II")
	IV, _ := enigoma.HistoricalRotor("IV")
	V, _ := enigoma.HistoricalRotor("V")
	B, _ := enigoma.HistoricalReflector("B")

	m, err := enigoma.New(
		enigoma.WithRotors(II, IV, V),
		enigoma.WithReflector(B),
		enigoma.WithRings("BUL"),
		enigoma.WithPositions("BLA"),
		enigoma.WithPlugboard("AV BS CG DL FU HZ IN KM OW RX"),
	)
	if err != nil {
		log.Fatal(err)
	}
	out, _ := m.Decrypt("EDPUDNRGYSZRCXNUYTPOMRMBOF")
	fmt.Println(out)
	// Output: AUFKLXABTEILUNGXVONXKURTIN
}

func ExampleQuickEncrypt() {
	ciphertext, config, err := enigoma.QuickEncrypt("Meet at dawn.", 5, 8)
	if err != nil {
		log.Fatal(err)
	}
	plaintext, _ := enigoma.DecryptWithConfig(ciphertext, config)
	fmt.Println(plaintext)
	// Output: Meet at dawn.
}

func ExampleMachine_Settings() {
	m, _ := enigoma.NewM3(enigoma.WithPositions("QEV"))
	data, _ := json.Marshal(m.Settings())

	s, _ := enigoma.ParseSettings(data)
	restored, _ := enigoma.NewFromSettings(s)
	fmt.Println(restored.Positions())
	// Output: QEV
}
