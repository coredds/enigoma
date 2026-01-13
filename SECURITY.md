# Security Policy

## Important Notice

Enigoma is an educational and simulation tool that implements the historical Enigma machine cipher. **Do not use Enigoma for securing sensitive data in production systems.** 

For real-world security applications, use modern cryptographic algorithms such as:
- AES-GCM
- ChaCha20-Poly1305
- Other NIST-approved algorithms

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability in Enigoma, please report it responsibly:

### How to Report

1. **Do not** open a public GitHub issue
2. Email security concerns to: **david@coredds.com**
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Status Updates**: Every 7 days until resolved
- **Resolution Timeline**: Depends on severity
  - Critical: 7 days
  - High: 14 days
  - Medium: 30 days
  - Low: 60 days

### Security Best Practices

When using Enigoma:

1. **Key Management**
   - Store configuration files securely (use `0600` permissions)
   - Never commit key files to version control
   - Rotate keys regularly

2. **Input Validation**
   - Validate all input text before encryption
   - Be cautious with untrusted configuration files
   - Use the `--validate` flag to check configurations

3. **Dependencies**
   - Keep dependencies updated (`make update-deps`)
   - Review release notes for security patches
   - Use `go mod verify` to check integrity

4. **Production Use**
   - Enigoma is for **educational purposes only**
   - Do not use for securing sensitive data
   - Use modern cryptographic libraries for real security needs

## Security Updates

Security updates are announced:
- GitHub Security Advisories
- Release notes (CHANGELOG.md)
- GitHub Releases page

Subscribe to releases to stay informed.

## Acknowledgments

We appreciate responsible disclosure of security issues. Contributors who report valid security vulnerabilities will be acknowledged in the CHANGELOG (unless they prefer to remain anonymous).
