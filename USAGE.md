# enigoma Usage Guide

## Auto-Detection

The easiest way to use enigoma: just encrypt any text in any language.

```bash
# Works automatically with any language!
enigoma encrypt --text "Olá mundo! Como você está?"
enigoma encrypt --text "Mixed: Hello! Привет! 日本語!"
enigoma encrypt --text "Symbols: αβγ δεζ 🙂 test!"
```

Note: The default alphabet is auto-detected (equivalent to --alphabet=auto). No need to specify alphabets; enigoma automatically detects the optimal character set from your text.

## Brazilian Portuguese Support

enigoma includes **built-in support for Brazilian Portuguese** with both auto-detection and the `AlphabetPortuguese` predefined alphabet.

### Quick Start with Portuguese

```go
package main

import (
    "fmt"
    "log"

    "github.com/coredds/enigoma"
)

func main() {
    // Create Enigma machine with Portuguese alphabet
    machine, err := enigoma.NewEnigmaSimple(enigoma.AlphabetPortuguese)
    if err != nil {
        log.Fatal(err)
    }

    // Your message with full Portuguese accents
    message := "Hoje eu fui almoçar na casa da vovó."
    
    // Encrypt
    encrypted, err := machine.Encrypt(message)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)

    // Decrypt
    machine.Reset()
    decrypted, err := machine.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)
    
    // Perfect round-trip with all accents preserved!
}
```

### Portuguese Alphabet Features

- **88 characters total** (even number for reflector compatibility)
- **Full accent support**: à, á, â, ã, ç, é, ê, í, ó, ô, õ, ú (uppercase and lowercase)
- **Complete Latin alphabet**: A-Z, a-z
- **Common punctuation**: space, period, comma, exclamation, question mark, etc.

### Supported Characters

The `AlphabetPortuguese` includes:

```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
ÀÁÂÃÇÉÊÍÓÔÕÚàáâãçéêíóôõú .,!?;:-'"()
```

### Test Your Portuguese Text

```go
// All these phrases work perfectly:
phrases := []string{
    "Olá, como você está?",
    "Bom dia! Está tudo bem?", 
    "Vamos à praia amanhã.",
    "Não posso ir à reunião.",
    "São Paulo é uma cidade incrível!",
    "Brasília é a capital do Brasil.",
    "Açúcar, café e pão de açúcar.",
}
```

## Other Languages

### Greek Example
```go
machine, err := enigoma.NewEnigmaSimple(enigoma.AlphabetGreek)
message := "Αβγδε ζητα" // Greek text
```

### Custom Language Support
```go
// Create alphabet for any language
customAlphabet := []rune{
    'A', 'B', 'C', /* your characters */
    'ñ', 'ü', 'ß', /* special characters */
    ' ', '.', '!',  /* punctuation */
}

machine, err := enigoma.New(enigoma.WithAlphabet(customAlphabet))
```

## Advanced Portuguese Usage

### Security Levels with Portuguese
```go
machine, err := enigoma.New(
    enigoma.WithAlphabet(enigoma.AlphabetPortuguese),
    enigoma.WithRandomSettings(enigoma.High), // High security
)
```

### Save/Load Portuguese Settings
```go
// Save Portuguese machine configuration
jsonData, err := machine.SaveSettingsToJSON()

// Later: restore exact same configuration
newMachine, err := enigoma.NewFromJSON(jsonData)
```

## Example Configurations

The [`examples/`](./examples/) directory contains ready-to-use configuration files:

### Portuguese Examples
```bash
# Use the Portuguese configuration example
enigoma encrypt --text "Bom dia, Brasil!" --auto-config pt-key.json
enigoma decrypt --text "ENCRYPTED" --config pt-key.json

# Generate your own Portuguese configuration
enigoma keygen --alphabet portuguese --security medium --output my-portuguese.json
```

### Other Language Examples
```bash
# Greek text encryption
enigoma encrypt --text "Γεια σας!" --config examples/languages/greek-simple.json

# Mixed character sets
enigoma encrypt --text "Password123!" --config examples/languages/mixed-alphabet-extreme.json
```

### Security Examples
```bash
# Document protection
enigoma encrypt --file document.txt --config examples/use-cases/document-protection.json

# High security communication
enigoma encrypt --text "TOP SECRET" --config examples/security-levels/extreme-key.json

# Historical simulation
enigoma encrypt --text "ENIGMA MACHINE" --config examples/use-cases/historical-simulation.json
```

Browse all examples: [`examples/README.md`](./examples/README.md)

---

Brazilian Portuguese is now a first-class citizen in enigoma.

## CLI: Stdin and Encoding Examples

```bash
# Stdin encryption (auto-detected alphabet by default)
echo "Hello via stdin" | enigoma encrypt --auto-config my-key.json

# Base64 output and decrypt
enigoma encrypt --text "Hello" --auto-config my-key.json --format base64
enigoma decrypt --text "SGVsbG8=" --config my-key.json --format base64

# Hex output and decrypt
enigoma encrypt --text "Hello" --auto-config my-key.json --format hex
enigoma decrypt --text "48656c6c6f" --config my-key.json --format hex
```

## Presets and decryptability

Presets (e.g., `classic`, `high`, `extreme`) generate a random configuration on each run. If you encrypt with a preset and want to decrypt later, save the configuration and reuse it:

```bash
# Save configuration during encryption
enigoma encrypt --text "TOP SECRET" --preset high --save-config my-key.json

# Later, decrypt with the same saved configuration
enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json
```

## Configuration schema

Saved configuration files include a `schema_version` field. This allows the project to evolve the configuration format safely over time.

### Configuration Validation

enigoma provides a configuration validation feature to ensure your configuration files are valid:

```bash
# Validate a configuration file
enigoma config --validate my-key.json
```

This will check that:
1. The JSON is well-formed
2. The configuration follows the schema
3. All required fields are present
4. Field types are correct

If validation succeeds, you'll see:
```
Configuration is VALID
   Schema Version: 1
   Alphabet Size: 26 characters
   Rotors: 5
   Plugboard Pairs: 8
   Current Rotor Positions: [16 20 24 14 9]
```

If validation fails, you'll see detailed error messages to help you fix the issues.