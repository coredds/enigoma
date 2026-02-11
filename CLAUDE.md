# CLAUDE.md — Project Guide for AI Agents

## Project Overview

**enigoma** is a Go library and CLI that implements a highly configurable, Unicode-capable Enigma machine. It simulates the historical WWII cipher machine with modern enhancements: arbitrary alphabets, configurable rotor counts, JSON-serializable settings, and auto-detection.

Module: `github.com/coredds/enigoma`
License: MIT | Author: David Duarte

## Quick Reference

```bash
# Build & run
go build -o bin/enigoma ./cmd/enigoma
go run ./cmd/enigoma --help
go run ./cmd/example

# Test
go test ./...
go test -race ./...
go test -coverprofile=coverage.out ./...

# Lint (requires golangci-lint v2)
golangci-lint run

# Vet
go vet ./...
```

## Architecture

```
├── alphabets.go              # Predefined alphabets (Latin, Greek, Cyrillic, etc.)
├── version.go                # Library version constant
├── cmd/
│   ├── enigoma/main.go       # CLI entry point → calls cli.Execute()
│   └── example/main.go       # Library usage demo
├── pkg/enigma/               # PUBLIC API
│   ├── enigma.go             # Enigma struct, Encrypt/Decrypt, processCharacter
│   ├── options.go            # Functional options: WithAlphabet, WithRandomSettings, etc.
│   ├── settings.go           # JSON serialization/deserialization of machine state
│   ├── convenience.go        # QuickEncrypt, EncryptText, NewFromText (auto-detect)
│   └── historical.go         # Historical M3/M4 variants, real rotor wirings
├── internal/
│   ├── alphabet/alphabet.go  # Alphabet type: rune↔index mapping, auto-detection
│   ├── rotor/rotor.go        # Rotor interface + BasicRotor (permutation + stepping)
│   ├── reflector/reflector.go # Reflector with reciprocal mapping validation
│   ├── plugboard/plugboard.go # Plugboard (Steckerbrett) — reciprocal swaps
│   └── cli/                  # Cobra CLI commands (encrypt, decrypt, keygen, wizard, etc.)
```

## Key Design Patterns

### Functional Options

```go
machine, err := enigma.New(
    enigma.WithAlphabet(enigoma.AlphabetLatinUpper),
    enigma.WithRandomSettings(enigma.High),
)
```

### Component Interfaces

- `rotor.Rotor` — Forward/Backward substitution, stepping, cloning
- `reflector.Reflector` — Reciprocal reflection, cloning
- Components are always cloned when accepted from callers to prevent mutation

### Encryption Flow

For each character: Step rotors → Plugboard → Rotors forward (R→L) → Reflector → Rotors backward (L→R) → Plugboard

### Settings Round-Trip

Machine state serializes to/from JSON via `EnigmaSettings`. This enables: save config → encrypt → share config → decrypt.

## Coding Standards

### Error Handling
- Always wrap errors with `%w`: `fmt.Errorf("failed to create rotor: %w", err)`
- Error strings must be lowercase, no capitalization (ST1005)
- Never use `%v` for error wrapping — it breaks `errors.Is`/`errors.As`

### Cryptographic Randomness
- Use `crypto/rand` for all security-sensitive randomness
- Use `math/rand` only for deterministic/seeded modes, with `// #nosec G404`
- gosec exclusions G401/G505 are intentional — this simulates historical crypto

### File Headers
```go
// Package <name> provides <description>.
//
// Copyright (c) 2025-2026 David Duarte
// Licensed under the MIT License
package <name>
```

### Imports
Group: stdlib first, blank line, then third-party/internal packages.

### Reflector Constraints
- Alphabet size must be **even** (reciprocal pairs)
- No character may map to itself

## CLI Commands

| Command | Purpose |
|---------|---------|
| `encrypt` | Encrypt text (supports --auto-config, --preset, --config) |
| `decrypt` | Decrypt text (requires matching config) |
| `keygen` | Generate random machine configurations |
| `config` | Validate/inspect/test configuration files |
| `preset` | List and describe available presets |
| `wizard` | Interactive guided encryption/decryption |
| `demo` | Animated demonstration |
| `test` | Self-test installation |

### Adding a CLI Command
1. Create `internal/cli/<name>.go` with `var <name>Cmd = &cobra.Command{...}`
2. Register in `internal/cli/root.go` `init()` via `rootCmd.AddCommand()`
3. Reuse shared helpers (`createMachineFromFlags`, `preprocessInput`, `writeOutput`)

## Testing

- Table-driven tests with `t.Run` subtests
- Round-trip verification: encrypt → reset → decrypt → assert equality
- Helper functions: `createTestAlphabet()`, `createTestRotor()`, etc.
- Fuzz tests for settings serialization
- Run with `-race` in CI

## CI/CD

- **golangci-lint v2** config in `.golangci.yml` (version: "2")
- **GoReleaser v2** config in `.goreleaser.yml` — triggered by `v*` tags
- Version injected via ldflags: `-X github.com/coredds/enigoma.Version={{.Version}}`
- GitHub Actions pin to major version tags (never `@master`)
- Test matrix covers two most recent Go releases

## Commit Messages

- **Short**: one line, max ~50 characters, no body unless strictly necessary
- **No emojis**: never use emojis in commit messages
- **Lowercase start**: begin with a lowercase verb (`fix`, `add`, `update`, `remove`, `refactor`)
- **No trailing period**
- Examples: `fix unicode plugboard deserialization`, `add convenience function tests`

## Do NOT

- Use `%v` for error wrapping (use `%w`)
- Capitalize error strings
- Duplicate CLI helper functions across commands
- Use `@master` for GitHub Actions
- Commit generated binaries or coverage files
- Modify gosec G401/G505 exclusions without understanding the historical crypto context
- Use emojis in commit messages
- Write long or multi-line commit messages
