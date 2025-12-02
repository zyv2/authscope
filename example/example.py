#!/usr/bin/env python3
"""
Demo script for AuthScope
Run with: python demo.py
"""

import sys
sys.path.insert(0, '..')

from authscope import AuthScope, quick_analyze

def main():
    # Example JWT (from jwt.io)
    test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    
    print("🔐 AuthScope Demo - JWT Analysis Tool")
    print("-" * 40)
    
    # Method 1: Quick analysis
    print("\n1. Quick Analysis:")
    quick_analyze(test_token)
    
    # Method 2: Detailed analysis
    print("\n\n2. Detailed Analysis:")
    scope = AuthScope()
    
    # Analyze
    result = scope.analyze(test_token)
    print(f"Algorithm: {result.algorithm}")
    print(f"Vulnerabilities: {result.vulnerabilities}")
    
    # Brute force test
    print("\n3. Testing common secrets...")
    secret = scope.brute_force(test_token)
    if secret:
        print(f"✅ Found secret: {secret}")
    else:
        print("❌ No matching secret found")
    
    # Create attack tokens
    print("\n4. Generating attack tokens:")
    none_token = scope.create_none_attack(test_token)
    print(f"'None' algorithm token: {none_token[:60]}...")
    
    # Tamper with payload
    tampered = scope.tamper(test_token, {"role": "admin", "is_admin": True})
    print(f"Tampered token: {tampered[:60]}...")
    
    # Export to Nuclei
    print("\n5. Nuclei Template:")
    template = scope.export_nuclei(test_token)
    print(template[:200] + "...")

if __name__ == "__main__":
    main()
