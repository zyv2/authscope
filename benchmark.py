#!/usr/bin/env python3
"""
Benchmark AuthScope performance
"""

import time
import jwt
from authscope import AuthScope

def run_benchmark():
    scope = AuthScope()
    
    # Create test tokens
    tokens = []
    for i in range(10):
        token = jwt.encode(
            {"user": f"test{i}", "exp": int(time.time()) + 3600},
            f"secret{i}",
            algorithm="HS256"
        )
        tokens.append(token)
    
    print("🧪 AuthScope Benchmark")
    print("=" * 50)
    
    # Test 1: Analysis speed
    start = time.time()
    for token in tokens:
        scope.analyze(token)
    analysis_time = time.time() - start
    print(f"Analyze {len(tokens)} tokens: {analysis_time:.3f}s")
    print(f"Average per token: {analysis_time/len(tokens)*1000:.1f}ms")
    
    # Test 2: Brute force speed
    start = time.time()
    for token in tokens[:3]:  # Test fewer tokens for brute force
        scope.brute_force(token)
    brute_time = time.time() - start
    print(f"\nBrute force 3 tokens: {brute_time:.3f}s")
    
    # Test 3: Attack generation
    start = time.time()
    for token in tokens:
        scope.create_none_attack(token)
    attack_time = time.time() - start
    print(f"\nGenerate {len(tokens)} 'none' attacks: {attack_time:.3f}s")
    
    print("\n" + "=" * 50)
    print("✅ Benchmark complete")

if __name__ == "__main__":
    run_benchmark()
