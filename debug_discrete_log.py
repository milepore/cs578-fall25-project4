#!/usr/bin/env python3
"""
Debug discrete log computation for small-scale test
"""

from elgamal_curve25519 import ElGamalCurve25519

def test_discrete_log():
    print("Testing discrete log computation...")
    
    # Create ElGamal instance for 10 votes
    elgamal = ElGamalCurve25519(max_votes=10)
    print(f"ElGamal table size: {len(elgamal.discrete_log_table)}")
    print(f"Max votes: {elgamal.max_votes}")
    
    # Test direct discrete log computation for expected values
    for test_val in range(11):  # Test 0 through 10
        # Generate point for this value
        test_point = elgamal._point_multiply(elgamal.generator_point, test_val)
        
        # Try to solve the discrete log
        result = elgamal.solve_discrete_log(test_point)
        
        print(f"Value {test_val}: Point hash {test_point.hex()[:16]}... -> Result: {result}")
        
        if result != test_val:
            print(f"  ❌ MISMATCH! Expected {test_val}, got {result}")
        else:
            print(f"  ✓ Correct")
    
    print("\nTesting lookup table contents:")
    for i, (point_hash, value) in enumerate(list(elgamal.discrete_log_table.items())[:5]):
        print(f"  Entry {i}: {point_hash.hex()[:16]}... -> {value}")

if __name__ == "__main__":
    test_discrete_log()