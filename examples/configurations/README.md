# Advanced Configuration Examples

This directory contains examples of advanced Enigma machine configurations demonstrating custom components, complex setups, and specialized configurations.

## Coming Soon

This directory will contain:

### 🔧 Custom Component Examples
- Custom rotor specifications
- Advanced reflector configurations  
- Complex plugboard setups
- Multi-stage encryption configurations

### ⚙️ Specialized Configurations
- High-performance setups
- Research configurations
- Compatibility configurations
- Edge case handling

### 🧬 Experimental Features
- Custom alphabet implementations
- Advanced security patterns
- Performance optimizations
- Integration examples

## Generating Advanced Configurations

You can create custom configurations using the CLI:

```bash
# Generate with specific parameters
enigoma keygen --rotors 6 --plugboard-pairs 15 --security high --output custom-advanced.json

# Create from preset and modify
enigoma preset --export extreme --output base-config.json
# Then manually edit the JSON for custom requirements
```

## Manual Configuration

For completely custom setups, you can manually create configuration files following this structure:

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

## Validation

Always validate custom configurations:

```bash
enigoma config --validate your-custom-config.json
```

---

*Check back soon for comprehensive advanced configuration examples!*