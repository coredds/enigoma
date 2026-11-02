# enigoma CLI reference

## Choosing a machine

`encrypt`, `decrypt` and `tui` pick the machine from the first source given:

| Source | Flags | Deterministic? |
|---|---|---|
| Saved configuration | `--config FILE` (`-c`) | yes |
| Historical preset | `--preset m3` or `--preset m4` | yes |
| Random preset | `--preset low\|medium\|high\|extreme` | no |
| Random machine | `--alphabet NAME --security LEVEL` (encrypt only) | no |
| Auto-config | `--auto-config FILE` (encrypt only) | no, saved to FILE |

These override any source:

| Flag | Example | Meaning |
|---|---|---|
| `--positions` | `ADU` | Starting rotor positions, one letter per rotor, left to right |
| `--rings` | `BUL` | Ring settings, one letter per rotor |
| `--plugboard` | `"AB CD EF"` | Plugboard pairs |

A random machine cannot be recreated. `encrypt` therefore refuses to run with
one unless it is saved (`--save-config FILE` or `--auto-config FILE`), and
`decrypt` refuses random sources altogether.

## encrypt

```bash
enigoma encrypt --text "Olá, mundo!" --auto-config pt-key.json
enigoma encrypt --file report.txt --config key.json --output report.enc
echo "HELLO" | enigoma encrypt --preset m3 --positions QEV
enigoma encrypt --text "TOP SECRET" --preset high --save-config key.json
```

| Flag | Default | Meaning |
|---|---|---|
| `--text`, `-t` / `--file`, `-f` | stdin | Input |
| `--output`, `-o` | stdout | Output file (written with mode 0600) |
| `--alphabet`, `-a` | `auto` | `auto`, `latin`, `latin-lower`, `greek`, `cyrillic`, `portuguese`, `ascii`, `alphanumeric`, `digits` |
| `--security`, `-s` | `medium` | Random machine size: `low` (3 rotors, 2 plug pairs), `medium` (5, 8), `high` (8, 15), `extreme` (12, 20) |
| `--auto-config` | | Detect the alphabet from the input, generate a machine, save it |
| `--save-config` | | Save the machine (before encrypting) |
| `--format` | `text` | Output encoding: `text`, `hex`, `base64` |
| `--remove-spaces`, `--uppercase`, `--letters-only`, `--alphanumeric-only` | | Preprocess the input |
| `--dry-run` | | Describe what would happen |
| `--verbose`, `-v` | | Details on stderr |

Characters outside the machine's alphabet are an error. The message suggests
preprocessing flags or `--auto-config`.

## decrypt

```bash
enigoma decrypt --text "CIPHERTEXT" --config key.json
enigoma decrypt --file report.enc --config key.json --format base64
enigoma decrypt --text "BDZGO" --preset m3
```

Same input, output, preprocessing and override flags as `encrypt`; `--format`
describes the input encoding.

## tui

```bash
enigoma tui
enigoma tui --preset m4 --positions AADU
enigoma tui --config key.json
```

Accepts `--config`, `--preset m3|m4`, `--positions`, `--rings`, `--plugboard`.
Defaults to M3 at AAA.

| Key | Action |
|---|---|
| any alphabet character | press the key (upper-cased when the alphabet has no lowercase letters) |
| Backspace | undo the last keypress |
| Ctrl+R | reset rotors and tapes |
| Tab | group the tapes in fives |
| Esc, Ctrl+C | quit |

## keygen

```bash
enigoma keygen --security high --output key.json
enigoma keygen --alphabet greek --rotors 6 --plugboard-pairs 10
enigoma keygen --preset m3 --seed 42 --describe
```

| Flag | Default | Meaning |
|---|---|---|
| `--preset`, `-p` | | Start from a preset |
| `--alphabet`, `-a` | `latin` | Alphabet for random machines |
| `--security`, `-s` | `medium` | Machine size |
| `--rotors`, `-r` / `--plugboard-pairs` | | Override the counts from `--security` |
| `--random-positions` | `true` | Randomize the starting positions |
| `--seed` | | Derive the starting positions from a seed (deterministic) |
| `--output`, `-o` / `--save-to` | stdout | Output file |
| `--describe`, `-d` | | Print a summary |

## preset

```bash
enigoma preset --list
enigoma preset --describe all
enigoma preset --export m4 --output m4.json
```

## config

```bash
enigoma config --validate key.json
enigoma config --show key.json
enigoma config --test key.json --text "HELLO"
enigoma config --convert key.json --output normalized.json
```

## Configuration files

Configuration files are JSON, schema version 2
([`schemas/config.v2.schema.json`](schemas/config.v2.schema.json)):

```json
{
  "schema_version": 2,
  "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "rotors": [
    {"name": "I", "wiring": "EKMFLGDQVZNTOWYHXUSPAIBRCJ", "notches": "Q", "ring": "A", "position": "A"},
    {"name": "II", "wiring": "AJDKSIRUXBLHWTMCQGZNPYFVOE", "notches": "E", "ring": "A", "position": "A"},
    {"name": "III", "wiring": "BDFHJLCPRTXVZNYEIWGAKMUSQO", "notches": "V", "ring": "A", "position": "A"}
  ],
  "reflector": {"name": "B", "wiring": "YRUHQSLDPXNGOKMIEBFZCWVJAT"},
  "plugboard": "AB CD"
}
```

Files from enigoma 0.6 and earlier (schema v1) are rejected: the 0.7 stepping
fix changes the cipher, so old keys would silently decrypt to garbage.

## Alphabets and languages

Auto-detection (`--auto-config`, or `--alphabet auto`) builds an alphabet from
the characters in your text, so any language or mix of scripts works:

```bash
enigoma encrypt --text "Mixed: Hello! Привет! 日本語! 🙂" --auto-config mixed.json
```

Predefined alphabets give a fixed character set that every message under one
key can use, for example `--alphabet portuguese` (letters, accents, space and
punctuation: `Hoje eu fui almoçar na casa da vovó.` works as is).
