#!/usr/bin/env python3
"""
Test the new ThresholdElGamal implementation
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threshold_elgamal import ThresholdElGamal
import time

def test_basic_encryption():
    """Test basic encryption and decryption."""
    print("=== Testing Basic Encryption ===")
    
    elgamal = ThresholdElGamal(max_votes=10)
    
    # Generate keypair
    private_key, public_key = elgamal.generate_keypair()
    print(f"Generated keypair: private={private_key}, public={public_key.hex()[:16]}...")
    
    # Test encrypting 0 and 1
    for message in [0, 1]:
        print(f"\nTesting message: {message}")
        
        # Encrypt
        ciphertext = elgamal.encrypt(message, public_key)
        c1, c2 = ciphertext
        print(f"Ciphertext: c1={c1.hex()[:16]}..., c2={c2.hex()[:16]}...")
        
        # Test serialization
        serialized = elgamal.serialize_ciphertext(ciphertext)
        print(f"Serialized: {serialized[:50]}...")
        
        deserialized = elgamal.deserialize_ciphertext(serialized)
        assert deserialized == ciphertext, "Serialization failed"
        print("✓ Serialization works")

def test_homomorphic_addition():
    """Test homomorphic addition of ciphertexts."""
    print("\n=== Testing Homomorphic Addition ===")
    
    elgamal = ThresholdElGamal(max_votes=10)
    private_key, public_key = elgamal.generate_keypair()
    
    # Encrypt some votes
    votes = [1, 0, 1, 1, 0]  # Total should be 3
    ciphertexts = []
    
    for i, vote in enumerate(votes):
        ciphertext = elgamal.encrypt(vote, public_key)
        ciphertexts.append(ciphertext)
        print(f"Vote {i}: {vote} -> encrypted")
    
    # Homomorphically add all ciphertexts
    total_ciphertext = ciphertexts[0]
    for i in range(1, len(ciphertexts)):
        total_ciphertext = elgamal.homomorphic_add(total_ciphertext, ciphertexts[i])
        print(f"Added ciphertext {i}")
    
    print(f"Homomorphic sum computed: {total_ciphertext[0].hex()[:16]}..., {total_ciphertext[1].hex()[:16]}...")
    print(f"Expected total: {sum(votes)}")

def test_threshold_decryption_simulation():
    """Test threshold decryption with simulated Shamir shares."""
    print("\n=== Testing Threshold Decryption ===")
    
    elgamal = ThresholdElGamal(max_votes=10)
    private_key, public_key = elgamal.generate_keypair()
    
    # Create a homomorphic sum of votes
    votes = [1, 0, 1, 1, 0, 1]  # Total = 4
    total_ciphertext = elgamal.encrypt(votes[0], public_key)
    
    for vote in votes[1:]:
        ciphertext = elgamal.encrypt(vote, public_key)
        total_ciphertext = elgamal.homomorphic_add(total_ciphertext, ciphertext)
    
    print(f"Created homomorphic sum of {len(votes)} votes (expected total: {sum(votes)})")
    
    # Simulate Shamir shares (simplified)
    # In reality, these would be proper Shamir shares of the private key
    num_shares = 5
    threshold = 3
    
    # Create mock shares - in reality these would be from Shamir's secret sharing
    shares = []
    for i in range(threshold):
        # Simplified share simulation
        share_value = private_key // num_shares + i  # Simple division
        shares.append(share_value)
    
    # Perform partial decryptions
    partial_results = []
    for i, share in enumerate(shares):
        partial_result = elgamal.partial_decrypt(total_ciphertext, share)
        partial_results.append(partial_result)
        print(f"Partial decryption {i}: {partial_result.hex()[:16]}...")
    
    # Create mock Lagrange coefficients (simplified)
    lagrange_coeffs = [1, -2, 1]  # Simple coefficients for 3 shares
    
    # Combine partial decryptions
    try:
        recovered_total = elgamal.combine_partial_decryptions(
            total_ciphertext, partial_results, lagrange_coeffs
        )
        
        print(f"Recovered total: {recovered_total}")
        print(f"Expected total: {sum(votes)}")
        print(f"Accuracy: {'✓ CORRECT' if recovered_total == sum(votes) else '✗ INCORRECT'}")
        
        return recovered_total == sum(votes)
        
    except Exception as e:
        print(f"Threshold decryption failed: {e}")
        return False

def test_discrete_log_performance():
    """Test discrete log solving performance."""
    print("\n=== Testing Discrete Log Performance ===")
    
    elgamal = ThresholdElGamal(max_votes=100)
    
    # Test discrete log solving for various values
    test_values = [0, 1, 5, 10, 50, 99, 100]
    
    for value in test_values:
        start_time = time.time()
        
        # Generate point for this value
        point = elgamal._scalar_multiply(value)
        
        # Solve discrete log
        recovered = elgamal.solve_discrete_log(point)
        
        elapsed = time.time() - start_time
        
        accuracy = "✓" if recovered == value else "✗"
        print(f"Value {value:3d}: recovered {recovered:3d} in {elapsed:.6f}s {accuracy}")

def main():
    """Run all tests."""
    print("Testing New ThresholdElGamal Implementation")
    print("=" * 50)
    
    try:
        test_basic_encryption()
        test_homomorphic_addition()
        test_discrete_log_performance()
        
        # The main test
        success = test_threshold_decryption_simulation()
        
        print("\n" + "=" * 50)
        if success:
            print("🎉 ThresholdElGamal implementation shows promise!")
            print("Ready to integrate with decision server.")
        else:
            print("❌ ThresholdElGamal needs more work on threshold decryption.")
            
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()