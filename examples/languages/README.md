# Language and Character Set Examples

This directory contains example configurations for different languages and character sets, demonstrating enigoma's Unicode support capabilities.

## Available Examples

### 🇵🇹 `portuguese-basic.json` - Brazilian Portuguese
- **Character Set**: Brazilian Portuguese with accents
- **Size**: 88 characters
- **Includes**: A-Z, a-z, À-Ú accented characters, basic punctuation
- **Use Case**: Portuguese text encryption with full accent support

```bash
# Example usage
enigoma encrypt --text "Olá, como você está?" --config examples/languages/portuguese-basic.json
```

**Supported Characters**:
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
ÀÁÂÃÇÉÊÍÓÔÕÚàáâãçéêíóôõú .,!?;:-'"()
```

### 🇬🇷 `greek-simple.json` - Greek Alphabet
- **Character Set**: Greek alphabet (upper and lowercase)
- **Size**: 72 characters  
- **Includes**: Α-Ω, α-ω, basic punctuation
- **Use Case**: Greek text encryption

```bash
# Example usage
enigoma encrypt --text "ΚαλημεραΚοσμε" --config examples/languages/greek-simple.json
```

**Supported Characters**:
```
ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρστυφχψω .,!?;:-'"()
```

### 🌍 `mixed-alphabet-extreme.json` - Multi-Character Set
- **Character Set**: Numbers, Latin (upper/lower), special characters
- **Size**: 62 characters
- **Includes**: 0-9, A-Z, a-z
- **Use Case**: Alphanumeric content with maximum security

```bash
# Example usage  
enigoma encrypt --text "Password123" --config examples/languages/mixed-alphabet-extreme.json
```

## Creating Language-Specific Configurations

### For Portuguese Text

```go
// Programmatic creation
machine, err := enigoma.New(
    enigoma.WithAlphabet(enigoma.AlphabetPortuguese),
    enigoma.WithRandomComponents(5, 8), // 5 rotors, 8 plug pairs
)

// CLI generation
enigoma keygen --alphabet portuguese --security medium --output portuguese-config.json
```

### For Custom Languages

```bash
# Create configuration with custom alphabet
enigoma keygen --security medium --output custom-lang.json
# Then manually edit the "alphabet" field in the JSON
```

## Language Support Guidelines

### Character Set Requirements

1. **Even Number**: Reflector requires even number of characters
2. **No Duplicates**: Each character must appear exactly once
3. **Unicode Support**: Full Unicode character support available
4. **Minimum Size**: At least 2 characters (recommended 26+)

### Recommended Alphabets

| Language | Predefined Constant | Size | Example Usage |
|----------|-------------------|------|---------------|
| English | `AlphabetLatinUpper` | 26 | Historical simulation |
| Portuguese | `AlphabetPortuguese` | 88 | Full accent support |
| Greek | `AlphabetGreek` | 48 | Academic texts |
| ASCII | `AlphabetASCIIPrintable` | 96 | Programming, mixed content |
| Numbers | `AlphabetDigits` | 10 | Numeric data only |

## Example Text Samples

### Portuguese
```
"Hoje eu fui almoçar na casa da vovó."
"São Paulo é uma cidade incrível!"
"Não posso ir à reunião."
"Brasília é a capital do Brasil."
```

### Greek  
```
"Αβγδε ζητα θάλασσα"
"Γεια σας κόσμε!"
"Καλημέρα Ελλάδα"
```

### Mixed Content
```
"User123 logged in at 14:30"
"Password: SecureP@ss2024!"
"File: document_v2.1.pdf"
```

## Testing Language Configurations

```bash
# Validate language-specific configuration
enigoma config --validate examples/languages/portuguese-basic.json

# Test round-trip encryption
enigoma encrypt --text "Olá mundo!" --config examples/languages/portuguese-basic.json | \
enigoma decrypt --config examples/languages/portuguese-basic.json

# Show character mappings
enigoma config --show examples/languages/greek-simple.json
```

## Common Issues and Solutions

### Character Not In Alphabet
```
Error: character 'ñ' not found in alphabet
```
**Solution**: Add missing characters to the alphabet or use a configuration that includes them.

### Alphabet Size Mismatch  
```
Error: mapping length (50) must match alphabet size (48)
```
**Solution**: Ensure rotor and reflector mappings match alphabet size exactly.

### Reflector Requirements
```
Error: reflector mapping must have even length
```
**Solution**: Ensure alphabet has even number of characters for reflector compatibility.

## Performance Considerations

- **Larger alphabets** = larger keyspace but slower processing
- **Unicode characters** may impact performance on some systems
- **Recommended sizes**: 26-100 characters for optimal balance

## Contributing Language Examples

When adding new language examples:

1. Test with native text samples
2. Include common punctuation and spaces
3. Ensure even character count
4. Document character set in README
5. Validate configuration before committing

---

*enigoma's Unicode support enables encryption for any language or character set while maintaining the historical Enigma machine behavior.*