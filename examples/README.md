# enigoma Configuration Examples

This directory contains example configurations for the enigoma Enigma machine implementation, organized by category to help you understand different use cases and configuration options.

## Directory Structure

### 📁 [`security-levels/`](./security-levels/)
Example configurations demonstrating different security levels from basic to extreme complexity.

### 📁 [`languages/`](./languages/) 
Configurations for different languages and character sets, including Unicode support.

### 📁 [`use-cases/`](./use-cases/)
Real-world application examples for specific scenarios like document protection, secure communication, and historical simulation.

### 📁 [`configurations/`](./configurations/)
Advanced configuration examples demonstrating custom component settings and complex machine setups.

## Quick Start

### Using an Example Configuration

```bash
# Encrypt with a specific example
enigoma encrypt --text "YOURMESSAGE" --config examples/security-levels/high-security.json

# Decrypt using the same configuration
enigoma decrypt --text "ENCRYPTED_TEXT" --config examples/security-levels/high-security.json
```

### Programmatic Usage

```go
package main

import (
    "fmt"
    "log"
    "os"
    "github.com/coredds/enigoma"
)

func main() {
    // Load configuration from example file
    data, err := os.ReadFile("examples/security-levels/high-security.json")
    if err != nil {
        log.Fatal(err)
    }
    
    // Parse the configuration and build the machine
    settings, err := enigoma.ParseSettings(data)
    if err != nil {
        log.Fatal(err)
    }
    machine, err := enigoma.NewFromSettings(settings)
    if err != nil {
        log.Fatal(err)
    }
    
    // Use the machine
    encrypted, _ := machine.Encrypt("HELLOWORLD")
    fmt.Printf("Encrypted: %s\n", encrypted)
}
```

## Configuration File Format

All example configurations follow this JSON structure:

```json
{
  "schema_version": 2,
  "alphabet": "characters the machine uses (unique, even count)",
  "rotors": [
    {
      "name": "rotor name",
      "wiring": "permutation of the alphabet",
      "notches": "letters at which the rotor turns over its left neighbour",
      "ring": "ring setting letter",
      "position": "starting position letter",
      "fixed": false
    }
  ],
  "reflector": {"name": "reflector name", "wiring": "reciprocal mapping, no letter to itself"},
  "plugboard": "AB CD"
}
```

See [`schemas/config.v2.schema.json`](../schemas/config.v2.schema.json) for the full schema.

## Customizing Examples

You can use these examples as starting points for your own configurations:

1. **Copy an example** that matches your security/complexity needs
2. **Modify the alphabet** for your language or character set requirements
3. **Adjust rotor positions** for different initial states
4. **Update plugboard pairs** for additional security
5. **Test your configuration** with the CLI validation tools

```bash
# Validate your custom configuration
enigoma config --validate my-custom-config.json

# Test with sample text
enigoma config --test my-custom-config.json --text "Test message"
```

## Security Recommendations

- **For learning/education**: Use the `m3`/`m4` presets or `classic-low-security.json`
- **For file protection**: Use `medium` or `high` security examples  
- **For sensitive data**: Use `extreme` security with custom modifications
- **For production systems**: ⚠️ Use modern cryptography (AES-GCM, ChaCha20-Poly1305)

## Contributing Examples

When adding new examples:

1. Place them in the appropriate category directory
2. Use descriptive filenames (e.g., `german-historical.json`)
3. Include comments in the filename or create accompanying `.md` files
4. Test the configuration before committing
5. Update the relevant category README

---

*These examples demonstrate the flexibility and power of enigoma while maintaining historical accuracy where appropriate.*