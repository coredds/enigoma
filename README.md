# enigoma

[![Version](https://img.shields.io/badge/version-0.7.0-blue.svg)](https://github.com/coredds/enigoma/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/coredds/enigoma.svg)](https://pkg.go.dev/github.com/coredds/enigoma)
[![CI](https://github.com/coredds/enigoma/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/coredds/enigoma/actions/workflows/ci.yml)
[![Go Version](https://img.shields.io/badge/go-1.24+-blue.svg)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A historically accurate, Unicode-capable Enigma machine in Go: a library, a CLI,
and an interactive terminal visualizer.

- **Historically accurate**: Enigma I/M3/M4 rotors and reflectors, ring settings,
  plugboard, correct turnover and double-stepping, a non-stepping M4 thin rotor.
  Verified against the 1941 Operation Barbarossa message.
- **Any alphabet**: Latin, Greek, Cyrillic, Portuguese, ASCII, or auto-detected
  from your text, including mixed scripts and emoji.
- **Observable**: `Machine.Press` returns a trace of every hop of the signal;
  `enigoma tui` draws it live as you type.
- **Configuration-first CLI**: the CLI never produces ciphertext you cannot decrypt,
  and `--auto-config` keeps your text exactly, line endings included.

> enigoma is for education and simulation. Enigma was broken in the 1940s; do not
> use it to protect real data. Use AES-GCM or ChaCha20-Poly1305.

## Installation

```bash
go get github.com/coredds/enigoma@latest                # library
go install github.com/coredds/enigoma/cmd/enigoma@latest # CLI
```

## Library

### A historical M3

```go
m, err := enigoma.NewM3() // rotors I-II-III, reflector B, positions and rings AAA
if err != nil {
    log.Fatal(err)
}
out, _ := m.Encrypt("AAAAA")
fmt.Println(out) // BDZGO
```

`NewM3` and `NewM4` accept options that override their defaults, e.g.
`enigoma.NewM3(enigoma.WithPositions("ADU"), enigoma.WithPlugboard("AB CD"))`.

### Any machine

Build a machine from historical parts or your own wiring. This decrypts the start
of the Operation Barbarossa message (1941):

```go
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
fmt.Println(out) // AUFKLXABTEILUNGXVONXKURTIN
```

A rotor is a plain `RotorSpec{Name, Wiring, Notches, Ring, Position, Fixed}`, a
reflector a `ReflectorSpec{Name, Wiring}`, all strings over the machine's alphabet.

| Option | Purpose |
|---|---|
| `WithAlphabet(chars)` | Character set (default `AlphabetLatinUpper`); must have an even number of unique characters |
| `WithRotors(specs...)` | Rotors, left to right |
| `WithReflector(spec)` | Reflector |
| `WithPlugboard("AB CD")` | Plugboard pairs |
| `WithPositions("ADU")` / `WithRings("BUL")` | One letter per rotor |
| `WithRandomComponents(rotors, plugPairs)` | Random rotors, reflector, plugboard, positions and rings |

Historical parts: rotors `I`–`VIII`, `Beta`, `Gamma`; reflectors `A`, `B`, `C`,
`B-Thin`, `C-Thin`.

### Watching the machine work

```go
m, _ := enigoma.NewM3()
t, _ := m.Press('A')
fmt.Printf("%c -> %c, rotors %s -> %s, %d hops\n", t.Input, t.Output, t.Before, t.After, len(t.Hops))
// A -> B, rotors AAA -> AAB, 9 hops
```

Each `Hop` records a stage (plugboard, rotor forward, reflector, rotor backward,
plugboard), the component name and the contact indices in and out.

### Saving and restoring a machine

`m.Settings()` returns the full configuration including current positions;
it marshals to JSON (schema v2, see [`schemas/config.v2.schema.json`](schemas/config.v2.schema.json)).

```go
m, _ := enigoma.NewM3(enigoma.WithPositions("QEV"))
data, _ := json.Marshal(m.Settings())

s, _ := enigoma.ParseSettings(data)
restored, _ := enigoma.NewFromSettings(s)
fmt.Println(restored.Positions()) // QEV
```

### One-liners for arbitrary text

```go
ciphertext, config, err := enigoma.QuickEncrypt("Meet at dawn.", 5, 8) // 5 rotors, 8 plug pairs
if err != nil {
    log.Fatal(err)
}
plaintext, _ := enigoma.DecryptWithConfig(ciphertext, config)
fmt.Println(plaintext) // Meet at dawn.
```

`QuickEncrypt` detects an alphabet from the text and returns the settings JSON
needed to decrypt. `NewFromText(text, opts...)` does the same and returns the machine.

### Predefined alphabets

| Constant | Characters |
|---|---|
| `AlphabetLatinUpper` / `AlphabetLatinLower` | A–Z / a–z (26) |
| `AlphabetDigits` | 0–9 (10) |
| `AlphabetAlphaNumeric` | digits and letters (62) |
| `AlphabetASCIIPrintable` | newline plus space through `~` (96) |
| `AlphabetGreek` | Greek letters (48) |
| `AlphabetCyrillic` | Russian Cyrillic (66) |
| `AlphabetPortuguese` | letters, accents, space and punctuation (88) |

## Command line

```bash
# Recommended: detect an alphabet, generate a machine, save it
enigoma encrypt --text "Hello World!" --auto-config my-key.json
enigoma decrypt --text "CIPHERTEXT" --config my-key.json

# Historical machines need no key file
enigoma encrypt --text "HELLO" --preset m3 --positions ADU --rings BUL --plugboard "AB CD"
enigoma decrypt --text "..." --preset m3 --positions ADU --rings BUL --plugboard "AB CD"

# Generate a key first
enigoma keygen --security high --output my-key.json
enigoma encrypt --file message.txt --config my-key.json --format base64 --output secret.txt

# Inspect and test keys
enigoma config --show my-key.json
enigoma config --test my-key.json --text "HELLO"

# Beginner-friendly
enigoma wizard
```

| Command | Purpose |
|---|---|
| `encrypt` / `decrypt` | Encrypt or decrypt `--text`, `--file` or stdin |
| `tui` | Interactive visualizer (see below) |
| `keygen` | Generate a configuration file |
| `preset` | List, describe and export presets |
| `config` | Validate, show, test and normalize configuration files |
| `wizard` | Guided encryption and decryption |

Presets: `m3` and `m4` are the historical machines and always identical.
`low` (3 rotors, 2 plug pairs), `medium` (5, 8), `high` (8, 15) and `extreme`
(12, 20) generate a new random machine every time, so `encrypt` refuses to use
them unless the configuration is saved with `--save-config` (or `--auto-config`).

See [USAGE.md](USAGE.md) for every flag.

## Visualize

```bash
enigoma tui                       # M3 at AAA
enigoma tui --preset m4 --positions AADU
enigoma tui --config my-key.json
```

Type to press keys. The TUI shows the rotor windows stepping (including the
double-step), the lit lamp, and the signal's path through plugboard, rotors and
reflector and back, both as a chain of hops and, for alphabets of up to 26
letters on wide terminals, as columns of contacts. Backspace undoes a keypress,
Ctrl+R resets, Tab groups the tape in fives, Enter types a newline (when the
alphabet has one), Esc quits. Newline and space are shown as ⏎ and ␣.

## Historical accuracy

- Rotor turnover is decided from the positions before each keypress; the middle
  rotor double-steps, and the M4 thin rotor never moves.
- Ring settings shift wiring relative to the window letter.
- Known-answer tests: `AAAAA → BDZGO` (M3, AAA), `EWTYX` (rings BBB), the
  ADU → ADV → AEW → BFX double-step, the Operation Barbarossa message, and M4
  with Beta at A matching M3.
- Encryption is reciprocal and no letter ever encrypts to itself.

## Project layout

```
enigoma/
├── machine.go       # Machine: New, Encrypt, Positions, Settings, stepping
├── options.go       # With... options
├── trace.go         # Press, Trace, Hop, Stage
├── spec.go          # RotorSpec, ReflectorSpec, Settings, ParseSettings
├── catalog.go       # Historical rotors/reflectors, NewM3, NewM4
├── convenience.go   # NewFromText, QuickEncrypt, DecryptWithConfig
├── alphabets.go     # Predefined alphabets
├── cmd/enigoma/     # CLI entry point
└── internal/
    ├── alphabet/ rotor/ reflector/ plugboard/   # components
    ├── cli/         # cobra commands
    └── tui/         # terminal visualizer
```

## Testing

```bash
go test ./...
go test -race ./...
go test -run=^$ -fuzz=FuzzParseSettings -fuzztime=30s .
```

## Upgrading from 0.6

0.7 fixes rotor stepping, which changes the ciphertext of any message long
enough to reach a turnover, and replaces the API and configuration format.
Configuration files from 0.6 and earlier are rejected; generate new ones.
See [CHANGELOG.md](CHANGELOG.md) for the migration table.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: add tests, make sure
`go test ./...` and `golangci-lint run` pass, keep commits short and descriptive.

## License

MIT, see [LICENSE](LICENSE).
