# enigoma

[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)](https://github.com/coredds/enigoma/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/coredds/enigoma.svg)](https://pkg.go.dev/github.com/coredds/enigoma)
[![CI](https://github.com/coredds/enigoma/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/coredds/enigoma/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<p align="center">
  <img src="enigoma_machine.png" alt="enigoma machine" width="432" />
</p>

A highly customizable, Unicode-capable Enigma machine implementation in Go.

## Overview

enigoma is a Go library that simulates the famous Enigma machine used during World War II, with modern enhancements including:

- **Unicode Support**: Unlike traditional simulators limited to the Latin alphabet, enigoma supports any Unicode character set
- **Configurable Complexity**: Adjust encryption complexity with different security levels
- **Modular Design**: Clean, extensible architecture with well-defined interfaces
- **State Management**: Save and load complete machine configurations
- **Historical Accuracy**: Maintains core Enigma behaviors including reciprocal encryption and rotor stepping

## Features

### Core Functionality
- Encryption and decryption with reciprocal property
- Configurable rotors with custom mappings and notch positions
- Reflector with reciprocal character mapping
- Plugboard for additional character swapping
- Proper rotor stepping including double-stepping

### Unicode & Smart Features  
- **Auto-Alphabet Detection**: Automatically detects and uses the optimal character set from your input text
- Support for any Unicode character set (Latin, Greek, Cyrillic, Portuguese, Japanese, etc.)
- Mixed-language text support (e.g., "Hello! Privет! 日本語!")
- Predefined alphabets for advanced users (Latin, Greek, Cyrillic, Portuguese, ASCII)
- Custom alphabet support for specialized use cases
- Adjustable complexity levels (Low, Medium, High, Extreme)

### Usability
- **Zero-Config Functions**: `enigma.EncryptText("Hello!")` — encrypt in one line
- **Discovery Commands**: `enigoma demo`, `enigoma examples`, `enigoma test`
- **Interactive Wizard**: `enigoma wizard` for beginner-friendly setup
- **Smart Preprocessing**: `--remove-spaces`, `--uppercase`, `--letters-only` flags
- **Enhanced Error Messages**: All errors include actionable suggestions

### Developer Experience
- Functional options pattern for clean configuration
- Comprehensive error handling
- Full JSON serialization of machine state
- Deep cloning support
- Extensive unit tests with table-driven patterns and fuzz testing

## Installation

```bash
# Inside your Go module:
go get github.com/coredds/enigoma@v0.5.0
```

Or get the latest version:
```bash
# Inside your Go module:
go get github.com/coredds/enigoma@latest
```

## Quick Start

### Zero-Config Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/coredds/enigoma/pkg/enigma"
)

func main() {
    // Simplest possible usage - one line encryption!
    encrypted, config, err := enigma.EncryptText("Hello World! 🌟")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)
    
    // Decrypt using the config
    decrypted, err := enigma.DecryptWithConfig(encrypted, config)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### Traditional Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/coredds/enigoma"
    "github.com/coredds/enigoma/pkg/enigma"
)

func main() {
    // Create a classic Enigma machine
    machine, err := enigma.NewEnigmaClassic()
    if err != nil {
        log.Fatal(err)
    }

    message := "HELLO WORLD"
    
    // Encrypt
    encrypted, err := machine.Encrypt(message)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Encrypted: %s\n", encrypted)

    // Reset to initial state and decrypt
    machine.Reset()
    decrypted, err := machine.Decrypt(encrypted)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Decrypted: %s\n", decrypted)
}
```

### Command Line Interface

enigoma includes a powerful CLI with a configuration-first workflow for secure encryption, decryption, and key management.

```bash
# Install the CLI
go install github.com/coredds/enigoma/cmd/enigoma@latest

# Discovery commands
enigoma demo      # Interactive demonstration
enigoma examples  # Copy-paste ready examples  
enigoma test      # Verify installation
enigoma wizard    # Interactive setup

# Quick start with auto-config (recommended)
enigoma encrypt --text "Hello World!" --auto-config my-key.json
enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json

# Preprocessing options
enigoma encrypt --text "Hello World!" --preset classic --remove-spaces --uppercase

# Stdin usage
echo "Hello via stdin" | enigoma encrypt --auto-config my-key.json

# Output encoding (base64)
enigoma encrypt --text "Hello" --auto-config my-key.json --format base64
# Decrypt base64 input
enigoma decrypt --text "SGVsbG8=" --config my-key.json --format base64

# Output encoding (hex)
enigoma encrypt --text "Hello" --auto-config my-key.json --format hex
# Decrypt hex input
enigoma decrypt --text "48656c6c6f" --config my-key.json --format hex
```

#### CLI Commands

- **`encrypt`** - Encrypt text or files using an Enigma machine
- **`decrypt`** - Decrypt text or files using an Enigma machine  
- **`keygen`** - Generate random Enigma machine configurations
- **`preset`** - List and describe available machine presets
- **`config`** - Manage and validate configuration files
- **`demo`** - Interactive demonstration of features
- **`examples`** - Copy-paste ready examples for common use cases
- **`test`** - Test installation and functionality
- **`wizard`** - Interactive beginner-friendly setup

#### Available Presets

| Preset   | Security | Rotors | Plugboard | Use Case |
|----------|----------|---------|-----------|----------|
| `classic` | Low     | 3       | 2         | Historical simulation, learning |
| `simple`  | Medium  | 5       | 8         | General purpose encryption |
| `high`    | High    | 8       | 15        | Strong obfuscation |
| `extreme` | Extreme | 12      | 20        | Maximum complexity |

#### Comprehensive CLI Examples

```bash
# Method 1: Auto-generate config during encryption (RECOMMENDED)
enigoma encrypt --text "Hello World!" --auto-config my-key.json
enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json

# Method 2: Generate config first, then encrypt
enigoma keygen --security high --output my-key.json
enigoma encrypt --text "Secret Message" --config my-key.json
enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json

# Method 3: Use presets, but ALWAYS save the configuration
enigoma encrypt --text "TOP SECRET" --preset high --save-config classified.json
enigoma decrypt --text "ENCRYPTED_OUTPUT" --config classified.json

# Unicode and multi-language support with auto-detection
enigoma encrypt --text "Olá Mundo! Café é ótimo!" --auto-config portuguese-key.json
enigoma encrypt --text "Mixed: English Русский 日本語!" --auto-config unicode-key.json
enigoma encrypt --text "Test unicode: 🙂" --auto-config emoji-key.json --verbose

# File encryption/decryption workflows
enigoma encrypt --file document.txt --auto-config my-key.json --output encrypted.txt
enigoma decrypt --file encrypted.txt --config my-key.json --output decrypted.txt

# Advanced configuration management
enigoma config --show my-key.json --detailed
enigoma config --validate my-key.json
enigoma config --test my-key.json --text "TEST MESSAGE"
enigoma keygen --preset extreme --describe --stats --output extreme-key.json
enigoma preset --list
enigoma preset --describe classic --verbose
```

## Configuration-First Approach

enigoma uses a configuration-first approach that ensures you can always decrypt your data.

### How It Works

1. **Generate Configuration**: Create a reusable key file
2. **Encrypt with Config**: Use the configuration file for encryption  
3. **Decrypt with Same Config**: Use the same configuration file for decryption

This approach provides several benefits:

- **Always Decryptable**: Configuration file provides the decryption key
- **Smart Auto-Detection**: Automatically detects optimal character set from your input
- **Unicode Everything**: Full support for mixed languages, emojis, and symbols
- **Reusable Keys**: One configuration can encrypt multiple messages
- **Shareable**: Send the config file to enable decryption

### Basic Workflow

```bash
# Method 1: Generate config first
enigoma keygen --output my-key.json
enigoma encrypt --text "Hello World!" --config my-key.json
enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json

# Method 2: Auto-generate during encryption
enigoma encrypt --text "Hello World!" --auto-config my-key.json
enigoma decrypt --text "ENCRYPTED_OUTPUT" --config my-key.json
```

### Advanced Examples

```bash
# Auto-detection with different languages
enigoma encrypt --text "Olá Mundo! Café é ótimo!" --auto-config pt-key.json
enigoma encrypt --text "Mixed: English Русский 日本語!" --auto-config mixed-key.json

# Using presets with saved configuration
enigoma encrypt --text "TOP SECRET" --preset high --save-config classified.json
enigoma decrypt --text "ENCRYPTED" --config classified.json

# Verbose mode shows auto-detection details
enigoma encrypt --text "Test unicode: 🙂" --auto-config test.json --verbose
# Output: Auto-detected alphabet with 12 characters
#         Auto-generated configuration saved to: test.json
```



### Unicode Support

```go
// Create an Enigma with Greek alphabet
machine, err := enigma.NewEnigmaSimple(enigoma.AlphabetGreek)
if err != nil {
    log.Fatal(err)
}

message := "Αβγδε ζητα"
encrypted, _ := machine.Encrypt(message)
fmt.Printf("Encrypted Greek: %s\n", encrypted)
```

### Custom Configuration

```go
// Create a high-security Enigma
machine, err := enigma.New(
    enigma.WithAlphabet(enigoma.AlphabetASCIIPrintable),
    enigma.WithRandomSettings(enigma.High),
    enigma.WithPlugboardConfiguration(map[rune]rune{
        'A': 'Z', 'Z': 'A',
        '1': '9', '9': '1',
    }),
)
```

## Security Levels

enigoma provides predefined security levels for quick setup:

| Level    | Rotors | Plugboard Pairs | Use Case |
|----------|--------|-----------------|----------|
| Low      | 3      | 2               | Historical simulation, learning |
| Medium   | 5      | 8               | Moderate complexity |
| High     | 8      | 15              | Strong obfuscation |
| Extreme  | 12     | 20              | Maximum complexity |

## Predefined Alphabets (Advanced)

While **auto-detection is recommended** for most use cases, enigoma provides predefined alphabets for specialized scenarios or when you need deterministic character sets:

### When to Use Predefined Alphabets
- **Consistent character sets** across multiple messages
- **Legacy compatibility** with specific character requirements  
- **Performance optimization** when alphabet is known in advance
- **Educational purposes** to understand specific character mappings

### Available Alphabets

| Alphabet | Characters | Use Case |
|----------|------------|----------|
| `AlphabetLatinUpper` | A-Z (26) | Classic Enigma simulation |
| `AlphabetLatinLower` | a-z (26) | Lowercase text processing |
| `AlphabetDigits` | 0-9 (10) | Numeric data encryption |
| `AlphabetASCIIPrintable` | All printable ASCII (95) | General text with symbols |
| `AlphabetAlphaNumeric` | Letters + digits (62) | Alphanumeric codes |
| `AlphabetGreek` | Greek letters (48) | Greek text processing |
| `AlphabetCyrillic` | Cyrillic letters (66) | Russian/Slavic languages |
| `AlphabetPortuguese` | Brazilian Portuguese (88) | Portuguese with accents |

### Usage Examples

```bash
# CLI: Use predefined alphabet with keygen
enigoma keygen --alphabet latin --output latin-key.json
enigoma encrypt --text "HELLO WORLD" --config latin-key.json

# Library: Use predefined alphabet directly
machine, err := enigma.NewEnigmaSimple(enigoma.AlphabetGreek)
```

Tip: For most use cases, prefer `--auto-config` which automatically detects the optimal alphabet from your input text.

## Advanced Features

### State Serialization

```go
// Save machine state
settings, err := machine.GetSettings()
jsonData, err := machine.SaveSettingsToJSON()

// Restore machine state
newMachine, err := enigma.NewFromJSON(jsonData)
```

### Machine Cloning

```go
// Create independent copy
clone, err := machine.Clone()

// Clones maintain same initial behavior but operate independently
```

### Custom Components

```go
// Create custom rotors, reflectors, and plugboards
rotorSpecs := []rotor.RotorSpec{
    {
        ID: "CustomI",
        ForwardMapping: "EKMFLGDQVZNTOWYHXUSPAIBRCJ",
        Notches: []rune{'Q'},
        Position: 0,
        RingSetting: 0,
    },
}

machine, err := enigma.New(
    enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
    enigma.WithRotorConfiguration(rotorSpecs),
    // ... other options
)
```

## Architecture

enigoma follows a modular architecture:

```
enigoma/
├── pkg/enigma/          # Public API
│   ├── enigma.go        # Enigma struct, Encrypt/Decrypt
│   ├── options.go       # Functional options (WithAlphabet, WithRandomSettings, etc.)
│   ├── settings.go      # JSON serialization/deserialization
│   ├── convenience.go   # QuickEncrypt, EncryptText, NewFromText
│   └── historical.go    # Historical M3/M4 variants
├── internal/
│   ├── alphabet/        # Character set management with auto-detection
│   ├── rotor/           # Rotor component (permutation + stepping)
│   ├── reflector/       # Reflector with reciprocal mapping validation
│   ├── plugboard/       # Plugboard (Steckerbrett) pair management
│   └── cli/             # Cobra CLI commands
├── cmd/enigoma/         # CLI entry point
├── cmd/example/         # Library usage demo
├── alphabets.go         # Predefined alphabets (Latin, Greek, Cyrillic, etc.)
└── version.go           # Library version constant
```

### Key Interfaces

- `Rotor` - Defines rotor behavior (forward/backward mapping, stepping)
- `Reflector` - Defines reflector behavior (reciprocal mapping)
- `Plugboard` - Manages character pair swapping

## Testing

Run the test suite:

```bash
go test ./...                  # Run all tests
go test -race ./...            # With race detector
go test -coverprofile=c.out ./...  # With coverage
```

The test suite includes:
- Table-driven unit tests for all core components
- Round-trip encryption/decryption verification at all security levels
- Fuzz testing for settings serialization
- CLI integration tests for complete workflows
- Unicode and multi-language round-trip tests

## Examples

### Configuration Examples

The [`examples/`](./examples/) directory contains comprehensive configuration examples organized by category:

- **[`security-levels/`](./examples/security-levels/)** - From basic to extreme security configurations
- **[`languages/`](./examples/languages/)** - Portuguese, Greek, and mixed character set examples  
- **[`use-cases/`](./examples/use-cases/)** - Document protection, secure communication, historical simulation
- **[`configurations/`](./examples/configurations/)** - Advanced custom configuration examples

```bash
# Use an example configuration
enigoma encrypt --text "Hello World" --config examples/security-levels/high-security.json

# Generate your own from examples
enigoma keygen --security high --output my-config.json
```

### Code Examples

See the `cmd/example/` directory for complete code examples:

- Basic encryption/decryption
- Unicode alphabet usage
- Security level comparisons
- Settings serialization
- Custom component configuration

## Historical Accuracy

enigoma maintains historical Enigma machine behaviors:

- **Reciprocal encryption**: If A encrypts to B, then B encrypts to A
- **Rotor stepping**: Proper single and double-stepping mechanics
- **No self-encryption**: No character encrypts to itself (with plugboard and reflector)
- **Deterministic behavior**: Same settings always produce same results

## Version History

Current version: **0.5.0**

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and release notes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. In short:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request with short, descriptive commits

## Security Notice

**Important**: This library is for educational and simulation purposes only.

Do not use enigoma for securing sensitive data in production systems. Modern cryptographic algorithms (AES-GCM, ChaCha20-Poly1305) should be used for real-world security applications.

## License

MIT License - see [LICENSE](LICENSE) file for details.
