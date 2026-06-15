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
enigoma encrypt --text "Your message" --config examples/security-levels/high-security.json

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
    
    // Create machine from configuration
    machine, err := enigoma.NewFromJSON(string(data))
    if err != nil {
        log.Fatal(err)
    }
    
    // Use the machine
    encrypted, _ := machine.Encrypt("Hello World!")
    fmt.Printf("Encrypted: %s\n", encrypted)
}
```

## Configuration File Format

All example configurations follow this JSON structure:

```json
{
  "alphabet": "string of characters used by the machine",
  "rotor_specs": [
    {
      "id": "unique rotor identifier",
      "forward_mapping": "character mapping string",
      "notches": [positions where rotor advances next rotor],
      "position": "initial position",
      "ring_setting": "ring offset setting"
    }
  ],
  "reflector_spec": {
    "id": "reflector identifier", 
    "mapping": "reflector character mapping"
  },
  "plugboard_pairs": {
    "A": "Z",
    "Z": "A"
  },
  "current_rotor_positions": [array of current rotor positions]
}
```

## Customizing Examples

You can use these examples as starting points for your own configurations:

1. **Copy an example** that matches your security/complexity needs
2. **Modify the alphabet** for your language or character set requirements
3. **Adjust rotor positions** for different initial states
4. **Update plugboard pairs** for additional security
5. **Test your configuration** with the CLI validation tools

```bash
# Validate your custom configuration
enigoma config --validate my-custom-config.json --detailed

# Test with sample text
enigoma config --test my-custom-config.json --text "Test message"
```

## Security Recommendations

- **For learning/education**: Use `classic` or `simple` configurations
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