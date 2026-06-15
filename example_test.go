package enigoma_test

import (
	"fmt"

	enigoma "github.com/coredds/enigoma"
)

func ExampleNewEnigmaClassic() {
	machine, err := enigoma.NewEnigmaClassic()
	if err != nil {
		panic(err)
	}

	encrypted, err := machine.Encrypt("HELLOWORLD")
	if err != nil {
		panic(err)
	}

	if err := machine.Reset(); err != nil {
		panic(err)
	}
	decrypted, _ := machine.Decrypt(encrypted)
	fmt.Println(decrypted)
	// Output:
	// HELLOWORLD
}

func ExampleNewEnigmaM3() {
	machine, err := enigoma.NewEnigmaM3()
	if err != nil {
		panic(err)
	}
	fmt.Println("Rotor count:", machine.GetRotorCount())
	// Output:
	// Rotor count: 3
}

func ExampleNewEnigmaM4() {
	machine, err := enigoma.NewEnigmaM4()
	if err != nil {
		panic(err)
	}
	fmt.Println("Rotor count:", machine.GetRotorCount())
	// Output:
	// Rotor count: 4
}

func ExampleQuickEncrypt() {
	encrypted, config, err := enigoma.QuickEncrypt("HELLOWORLD", enigoma.Low)
	if err != nil {
		panic(err)
	}

	decrypted, err := enigoma.DecryptWithConfig(encrypted, config)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
	// Output:
	// HELLOWORLD
}

func ExampleNewEnigmaSimple() {
	machine, err := enigoma.NewEnigmaSimple(enigoma.AlphabetLatinUpper)
	if err != nil {
		panic(err)
	}

	message := "HELLOWORLD"
	encrypted, _ := machine.Encrypt(message)
	if err := machine.Reset(); err != nil {
		panic(err)
	}
	decrypted, _ := machine.Decrypt(encrypted)
	fmt.Println(decrypted)
	// Output:
	// HELLOWORLD
}

func ExampleNewFromJSON() {
	machine, _ := enigoma.NewEnigmaClassic()
	jsonConfig, _ := machine.SaveSettingsToJSON()

	restored, _ := enigoma.NewFromJSON(jsonConfig)
	message := "TEST"
	encrypted, _ := machine.Encrypt(message)
	decrypted, _ := restored.Decrypt(encrypted)
	fmt.Println(decrypted)
	// Output:
	// TEST
}
