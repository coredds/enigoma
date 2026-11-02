# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - Unreleased

This release fixes rotor stepping and replaces the public API and the
configuration format. **Ciphertext and configuration files from 0.6 and earlier
are not compatible.**

### Fixed
- **Rotor stepping**: turnover was decided after the right rotor had already
  moved, so the middle and left rotors stepped one letter early and the
  double-step was wrong (ADU went to BEV instead of ADV → AEW → BFX). Output was
  only correct until the first turnover. Machines now match historical Enigma
  I/M3/M4 behaviour, verified against the 1941 Operation Barbarossa message.
  Old ciphertexts longer than the first turnover will not decrypt.
- **M4 thin rotor**: Beta/Gamma never step (they could before).
- **ASCII alphabet**: `AlphabetASCIIPrintable` had 95 characters (odd), so no
  machine could be built with it (`--alphabet ascii` always failed). It now
  includes newline (96 characters).
- **Unrecoverable CLI output**: `encrypt` with a random preset or random machine
  printed ciphertext without saving the machine. It now refuses unless
  `--save-config` or `--auto-config` is given; `decrypt` refuses random sources.
- `--reset` (a no-op) removed; documented example commands that could not run
  now work.
- **Auto-detected alphabets are lossless**: `--auto-config`, `NewFromText` and
  `QuickEncrypt` used to trim the text and turn CRLF into LF before encrypting
  (and failed on `\r`); the alphabet now covers the text exactly.
- **Trailing newline on stdin/files**: `echo HELLO | enigoma encrypt --preset m3`
  failed on the newline; one trailing line ending is now dropped when the
  alphabet cannot encode it.
- **A failed `encrypt` no longer overwrites `--save-config`/`--auto-config`
  files**: the key is written only after encryption succeeds.
- **Random rotors on 2-letter alphabets** could hang generating notches.

### Added
- `Machine.Press(r)` returns a `Trace` of one keypress: rotor windows before and
  after stepping and every signal hop (plugboard, rotors, reflector, back).
- `enigoma tui`: interactive terminal visualizer of the machine.
- Public spec types usable outside the module: `RotorSpec`, `ReflectorSpec`,
  `Settings` (the old options used `internal/` types and could not be called).
- Historical catalogue: `HistoricalRotor("I".."VIII", "Beta", "Gamma")`,
  `HistoricalReflector("A", "B", "C", "B-Thin", "C-Thin")`.
- Letter positions and rings: `WithPositions("ADU")`, `WithRings("BUL")`,
  `Machine.Positions()`, `Machine.SetPositions("ADU")`.
- `*CharError` with the offending rune and its rune offset.
- Configuration schema v2 (`schemas/config.v2.schema.json`), string-based and
  readable.

### Changed
- `Enigma` is now `Machine`; alphabets are `string` constants.
- CLI: `--positions`, `--rings` and `--plugboard "AB CD"` replace `--rotors 1,2,3`
  and `--plugboard A:Z,B:Y`; presets are `m3`, `m4`, `low`, `medium`, `high`,
  `extreme`. `--verbose` writes to stderr.
- Configuration files from 0.6 and earlier (schema v1) are rejected with an
  explanatory error.

### Migration: library

| 0.6 | 0.7 |
|---|---|
| `*enigoma.Enigma` | `*enigoma.Machine` |
| `NewEnigmaM3()` / `NewEnigmaM4()` | `NewM3(opts...)` / `NewM4(opts...)` |
| `NewEnigmaClassic()` | `NewM3()` for the historical machine, or `New(WithRandomComponents(3, 2))` |
| `NewEnigmaSimple(alphabet)` | `New(WithAlphabet(a), WithRandomComponents(5, 8))` |
| `WithAlphabet([]rune)` | `WithAlphabet(string)` |
| `WithRandomSettings(Low/Medium/High/Extreme)` | `WithRandomComponents(3,2)` / `(5,8)` / `(8,15)` / `(12,20)` |
| `SecurityLevel`, `Low`, `Medium`, `High`, `Extreme` | removed; pass rotor and plug-pair counts |
| `WithRotorConfiguration([]rotor.RotorSpec)` | `WithRotors(specs ...RotorSpec)` |
| `WithReflectorConfiguration(reflector.ReflectorSpec)` | `WithReflector(ReflectorSpec)` |
| `WithPlugboardConfiguration(map[rune]rune)` | `WithPlugboard("AB CD")` |
| `WithCustomComponents(...)` | `WithRotors`, `WithReflector`, `WithPlugboard` |
| `WithRotorPositions([]int)` | `WithPositions("ADU")` |
| `WithRandomRotorPositions()` | `WithRandomComponents` randomizes positions; or `SetPositions` |
| `RotorI`..`RotorVIII`, `RotorBeta`, `RotorGamma`, `Notch*` | `HistoricalRotor(name)` |
| `ReflectorA`, `ReflectorB`, `ReflectorC`, `ReflectorBThin`, `ReflectorCThin` | `HistoricalReflector(name)` |
| `GetSettings()` | `Settings()` |
| `SaveSettingsToJSON()` | `json.Marshal(m.Settings())` |
| `LoadSettings`, `LoadSettingsFromJSON` | `NewFromSettings(s)` on a new machine |
| `NewFromJSON(string)` | `ParseSettings([]byte)` + `NewFromSettings` |
| `EnigmaSettings` | `Settings` |
| `GetCurrentRotorPositions() []int` | `Positions() string` |
| `SetRotorPositions([]int) error` | `SetPositions(string) error` |
| `Reset() error` | `Reset()` |
| `Clone() (*Enigma, error)` | `Clone() *Machine` |
| `GetRotorCount()`, `GetPlugboardPairCount()` | `len(m.Settings().Rotors)`, `m.Settings().Plugboard` |
| `GetAlphabetSize()` | `len([]rune(m.Alphabet()))` |
| `QuickEncrypt(text, level) (string, string, error)` | `QuickEncrypt(text, rotors, plugPairs) (string, []byte, error)` |
| `DecryptWithConfig(text, string)` | `DecryptWithConfig(text, []byte)` |
| `NewFromText(text, level)` | `NewFromText(text, opts...)` |

### Migration: CLI

| 0.6 | 0.7 |
|---|---|
| `--preset classic` | `--preset m3` (historical) or `--preset low --save-config key.json` |
| `--preset simple` | `--preset medium --save-config key.json` |
| `--rotors 1,5,12` | `--positions BFM` |
| `--plugboard A:Z,B:Y` | `--plugboard "AZ BY"` |
| `--reset` | removed (machines always start from their configured positions) |
| `--preserve-case` | removed (had no effect) |
| `decrypt --alphabet/--security` | removed: decrypt needs `--config` or `--preset m3\|m4` |
| `config --detailed`, `keygen --stats`, `preset --verbose` | removed; `config --show` and `keygen --describe` print the full summary |
| v1 key files | regenerate with `enigoma keygen` or `encrypt --auto-config` |

## [0.6.0] - 2026-06-15

### Changed
- **Flattened package layout**: `pkg/enigma/` merged into root `github.com/coredds/enigoma`
- **Removed rotor/reflector interfaces**: `rotor.Rotor` and `reflector.Reflector` interfaces replaced with concrete structs
- **Simplified public API**: removed `EncryptText`, `NewWithAutoDetection`, `WithRandomRotorPositionsSeed`, `NewAlphabetFromPredefined`, `GetAlphabetSize`
- **Removed `Metadata` struct** from settings — unused and always nil
- **Deduplicated Latin alphabet**: `NewEnigmaM3`, `NewEnigmaM4`, `NewEnigmaClassic` use single `AlphabetLatinUpper`
- **Added `SecurityLevel.String()`** method
- **Error wrapping**: switched `%v` to `%w` across all packages for proper error chains
- **Consolidated CI**: merged `lint-test.yml` into `ci.yml`, added govulncheck, coverage, and race detection

### Removed
- CLI commands `demo`, `examples`, `test`
- `cmd/example/` — replaced by `example_test.go` with runnable examples
- `pkg/enigma/` directory and import path
- Plugboard `pairs` field — redundant with `mapping`

### Fixed
- JSON schema: `reflector_spec.mapping` corrected from `object` to `string` type
- JSON schema: removed unused `metadata` property

## [0.5.0] - 2026-02-11

### Added
- Convenience function tests (`QuickEncrypt`, `EncryptText`, `DecryptWithConfig`, `NewFromText`, `NewWithAutoDetection`)
- `AutoDetectFromText` tests covering Unicode, padding, control characters, and edge cases
- `PreprocessTextForAutoDetection` and `isControlCharacter` unit tests
- Settings round-trip tests verifying encryption output matches after JSON save/load
- CLI helper unit tests (`filterLettersOnly`, `filterAlphanumericOnly`, `parseRotorPositions`, `parseIntFromString`)
- Commit message conventions (short, no emojis, lowercase verb start)

### Fixed
- Unicode plugboard deserialization bug (`len()` checked byte count instead of rune count)
- Error wrapping: replaced `%v` with `%w` across all `fmt.Errorf` calls in core packages
- Lowercase error strings to satisfy staticcheck ST1005
- Boolean simplification in `hasSpecialChars` (QF1001)
- Test helpers now panic on error instead of silently discarding with `_`
- Brittle version test replaced with structural semver validation
- Weak `RandomPairs` test now verifies reciprocity and paired character count

### Changed
- Go version requirement updated to 1.24+
- GitHub Actions updated: checkout@v4, setup-go@v5, golangci-lint-action@v6, codecov-action@v5, goreleaser-action@v6
- CI test matrix covers Go 1.24 and 1.25
- Pinned gosec to v2 and trivy-action to 0.28.0
- golangci-lint config migrated to v2 format
- Consolidated three GoReleaser configs into single `.goreleaser.yml`
- Replaced bubble sort with `slices.Sort` in `AutoDetectFromText`
- Copyright years updated to 2025-2026

### Removed
- Dead code: unused `cliutil.go` (exported functions were unreferenced)
- Duplicate CLI filter functions in `decrypt.go` (now reuses shared helpers from `encrypt.go`)
- Redundant `.goreleaser.yaml` and `.goreleaser/config.yaml`

## [0.4.2] - 2025-02-02

### Fixed
- Renamed `cmd/eniGOma` directory to `cmd/enigoma` for consistency
- Updated GoReleaser configuration to build binaries with `enigoma` name
- Renamed `eniGOma_prd.md` to `enigoma_prd.md`
- All file paths and directory names now use lowercase `enigoma`

### Note
This release will produce correctly named binaries: `enigoma` instead of `eniGOma`.

## [0.4.1] - 2025-02-02

### Changed
- Project renamed from eniGOma to enigoma for Go naming convention compliance
- Module path updated from `github.com/coredds/eniGOma` to `github.com/coredds/enigoma`
- Package name changed from `eniGOma` to `enigoma`
- All import paths updated across codebase
- Documentation updated to reflect new naming

### Migration Guide
Users upgrading from v0.4.0 need to update their imports:
```go
// Old:
import "github.com/coredds/eniGOma"
import "github.com/coredds/enigoma"

// New:
import "github.com/coredds/enigoma"
import "github.com/coredds/enigoma/pkg/enigma"
```

Update your dependencies:
```bash
go get github.com/coredds/enigoma@latest
```

## [0.4.0] - 2025-01-31

### Added
- New CLI commands: `demo`, `examples`, `test`, `wizard`
- Zero-config library functions: `EncryptText`, `DecryptWithConfig`, `NewFromText`, `NewWithAutoDetection`, `QuickEncrypt`
- CLI preprocessing flags: `--remove-spaces`, `--uppercase`, `--letters-only`, `--alphanumeric-only`

### Fixed
- Auto-detection edge cases with Windows line endings (`\r\n`)
- Character preprocessing consistency for auto-detection
- Piped input support

### Enhanced
- Error messages now include actionable suggestions
- Comprehensive help documentation
- CLI user experience with intelligent suggestions

## [0.3.4] - 2025-02-15

### Added
- Schema file inclusion in releases for validation
- Post-install hook to copy schema files to the correct location

### Fixed
- Schema validation compatibility for notches and reflector mapping formats
- Cyclomatic complexity issues in validation code
- Updated GoReleaser configuration to version 2 format

### Changed
- Updated Go version requirement to 1.23+ (to address vulnerability GO-2025-3750)
- Improved code organization with better function separation

## [0.3.3] - 2025-02-14

### Fixed
- Schema validation for configuration files
- Added schema file path resolution improvements

### Changed
- Enhanced error handling for schema validation

## [0.3.2] - 2025-02-13

### Changed
- Updated GoReleaser configuration to build CLI tool
- Added CLI tool to release artifacts

## [0.3.1] - 2025-01-31

### Added
- CLI flags: `--auto-config` and `--save-config`
- Stdin support for `encrypt` (pipe input directly)
- Proper hex/base64 encoding (encrypt) and decoding (decrypt) via stdlib
- JSON configs now include `schema_version` for forward compatibility

### Changed
- Default alphabet documented and enforced as auto-detected for `encrypt` (equivalent to `--alphabet=auto`)
- README and USAGE updated with configuration-first workflow, stdin, and encoding examples
- Docs now clarify that presets generate random configurations per run; use `--save-config` and reuse with `--config` for decryptability

### Fixed
- Version tests updated to avoid pinning an exact patch version

## [0.3.0] - 2025-01-30

### Added
- Smart auto-alphabet detection from input text
- Universal Unicode support for any language
- Mixed-language text support
- `alphabet.AutoDetectFromText()` function with configurable options
- Auto-detection as default CLI behavior (`--alphabet auto`)
- Safety limits for auto-detected alphabets (max 1000 characters)

### Changed
- CLI default changed from `--alphabet latin` to `--alphabet auto`
- Deterministic alphabet ordering for consistent behavior

## [0.2.1] - 2025-01-28

### Added
- Comprehensive CLI tool using Cobra framework
- 5 CLI commands: encrypt, decrypt, keygen, preset, config
- 4 security presets: classic, simple, high, extreme
- Unicode CLI support with all predefined alphabets
- Configuration management: JSON import/export, validation, and testing
- File I/O operations with multiple output formats

## [0.2.0] - 2025-01-27

### Added
- Complete enigoma library implementation
- Brazilian Portuguese alphabet with full accent support (88 characters)
- Unicode support for any character set
- Configurable security levels (Low, Medium, High, Extreme)
- Functional options pattern for configuration
- State management with JSON serialization/deserialization
- Modular architecture with clean interfaces
- Predefined alphabets for common use cases
- Example application demonstrating all features
