# AuthScope - JWT Security Analysis Tool

A lightweight Python tool for analyzing and testing JWT/Cookie security in CTF challenges and penetration tests.

## Features

- **JWT Analysis**: Decode and analyze JWTs for common vulnerabilities
- **Brute-force Testing**: Test common secrets against JWT signatures
- **Attack Generation**: Create modified tokens for testing (none algorithm, tampered payloads)
- **Secure Crypto**: AES-GCM encryption for sensitive data (AEAD compliant)
- **Nuclei Integration**: Export test cases to Nuclei templates
- **Cookie Analysis**: Parse and test cookie flags

## Installation
pip install -r requirements.txt

## CLI Usage

# Analyze JWT
python -m authscope.cli analyze --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# Test secrets
python -m authscope.cli brute --token "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." --wordlist secrets.txt

# Export to Nuclei
python -m authscope.cli export --token tokens.txt --output jwt_templates.yaml
```bash

