#!/usr/bin/env python3
"""
Test the optimized ElGamal implementation with discrete log precomputation
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision_server import DecisionServer
from voter import Voter

def test_optimized_elgamal():
    """Test the ElGamal optimization with discrete log solving"""
    
    print("=== Testing Optimized ElGamal with Discrete Log Precomputation ===")
    
    # Create a decision server with 5 voters (will precompute discrete log table for 0-5)
    print("1. Creating DecisionServer with optimized ElGamal...")
    server = DecisionServer(number_voters=5, quorum=3)
    
    # Create voters
    print("2. Creating voters...")
    voters = [Voter(server, i) for i in range(5)]
    
    # Set up the cryptographic keys
    print("3. Setting up cryptographic keys...")
    secret_key = server.create_and_distribute_key(voters)
    
    # Test vote casting
    print("4. Testing vote casting...")
    voters[0].castVote(1)  # Vote: 1
    voters[1].castVote(0)  # Vote: 0  
    voters[2].castVote(1)  # Vote: 1
    voters[3].castVote(0)  # Vote: 0
    voters[4].castVote(1)  # Vote: 1
    print("   Expected total: 3 votes")
    
    # Perform homomorphic tally
    print("5. Performing homomorphic tally...")
    encrypted_total = server.tally_vote()
    print(f"   Encrypted total: {encrypted_total[:50]}...")
    
    # Decrypt with threshold decryption
    print("6. Decrypting with threshold secret sharing...")
    plaintext_total = server.decrypt_results([0, 1, 2], [voters[0], voters[1], voters[2]])
    
    print(f"7. Results:")
    print(f"   Decrypted total: {plaintext_total}")
    print(f"   Expected total: 3")
    print(f"   Success: {'✓' if plaintext_total == 3 else '✗'}")
    
    # Test the discrete log optimization directly
    print("8. Testing discrete log optimization directly...")
    elgamal = server.elgamal
    
    # Test that we can solve discrete logs for vote totals 0-5
    for i in range(6):
        test_point = elgamal.encrypt_with_generator(i)
        solved_value = elgamal.solve_discrete_log(test_point)
        print(f"   g^{i} -> discrete_log() -> {solved_value} {'✓' if solved_value == i else '✗'}")

if __name__ == "__main__":
    test_optimized_elgamal()