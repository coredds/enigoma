# Historical Enigma Machine Configurations

This directory contains historically accurate Enigma machine configurations based on real machines used during World War II.

## Available Historical Presets

### M3 Enigma (`m3`)

The Enigma M3 was the standard Army and Navy Enigma machine used during most of World War II. It featured:

- 3 rotors (selected from rotors I-V)
- Reflector B
- 26-character Latin alphabet
- Standard plugboard

The M3 preset in enigoma uses rotors I, II, and III with reflector B, which was a common configuration.

```bash
# Use the M3 preset
enigoma encrypt --text "TOPSECRET" --preset m3
```

### M4 Naval Enigma (`m4`)

The Enigma M4 was used exclusively by the German Navy (Kriegsmarine) from 1942 onwards. It featured:

- 4 rotors: a non-moving "thin" rotor (Beta or Gamma) followed by 3 standard rotors
- Thin reflector (B-Thin or C-Thin)
- 26-character Latin alphabet
- Standard plugboard

The M4 preset in enigoma uses the Beta thin rotor, rotors I, II, and III, with the B-Thin reflector.

```bash
# Use the M4 preset
enigoma encrypt --text "KRIEGSMARINE" --preset m4
```

## Historical Accuracy

These presets aim to provide historically accurate simulations of the Enigma machines used during World War II. The rotor wirings, notch positions, and stepping mechanisms match those of the original machines.

## Example Configurations

- `historical-enigma.json`: the M3 preset exported with `enigoma preset --export m3`

## Historical Rotors

The following historical rotors are available:

| Rotor | Used In | Wiring | Notch |
|-------|---------|--------|-------|
| I | M1, M2, M3, M4 | EKMFLGDQVZNTOWYHXUSPAIBRCJ | Q |
| II | M1, M2, M3, M4 | AJDKSIRUXBLHWTMCQGZNPYFVOE | E |
| III | M1, M2, M3, M4 | BDFHJLCPRTXVZNYEIWGAKMUSQO | V |
| IV | M1, M2, M3, M4 | ESOVPZJAYQUIRHXLNFTGKDCMWB | J |
| V | M1, M2, M3, M4 | VZBRGITYUPSDNHLXAWMJQOFECK | Z |
| VI | M3, M4 | JPGVOUMFYQBENHZRDKASXLICTW | Z, M |
| VII | M3, M4 | NZJHGRCXMYSWBOUFAIVLPEKQDT | Z, M |
| VIII | M3, M4 | FKQHTLXOCBJSPDZRAMEWNIUYGV | Z, M |
| Beta | M4 (thin) | LEYJVCNIXWPBQMDRTAKZGFUHOS | - |
| Gamma | M4 (thin) | FSOKANUERHMBTIYCWLQPZXVGJD | - |

## Historical Reflectors

| Reflector | Used In | Wiring |
|-----------|---------|--------|
| A | M1, M2, M3 | EJMZALYXVBWFCRQUONTSPIKHGD |
| B | M1, M2, M3 | YRUHQSLDPXNGOKMIEBFZCWVJAT |
| C | M1, M2, M3 | FVPJIAOYEDRZXWGCTKUQSBNMHL |
| B-Thin | M4 | ENKQAUYWJICOPBLMDXZVFTHRGS |
| C-Thin | M4 | RDOBJNTKVEHMLFCWZAXGYIPSUQ |
