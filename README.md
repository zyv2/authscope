# 🔐 AuthScope - Simple JWT Analysis Tool for CTF

A lightweight Python tool for analyzing JWT tokens in CTF challenges. No CLI - just import and use!

## Features

- 🔍 **JWT Analysis**: Decode and analyze tokens for vulnerabilities
- 🔑 **Secret Testing**: Test common JWT secrets
- ⚔️ **Attack Generation**: Create modified tokens for testing
- 🔒 **Secure Crypto**: AES-GCM encryption (AEAD compliant)
- 📋 **Nuclei Export**: Generate test templates
- 🚀 **Simple API**: Just import and use in your scripts

## Quick Start

```python
from authscope import AuthScope, quick_analyze

# Quick analysis (prints results)
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
quick_analyze(token)

# Or use the class directly
scope = AuthScope()
result = scope.analyze(token)

print(f"Algorithm: {result.algorithm}")
print(f"Vulnerabilities: {result.vulnerabilities}")

# Test common secrets
secret = scope.brute_force(token)
if secret:
    print(f"Found secret: {secret}")

# Generate attack token
none_token = scope.create_none_attack(token)
print(f"None attack: {none_token}")
