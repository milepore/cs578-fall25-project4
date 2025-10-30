#!/usr/bin/env python3
"""
Test the optimized ElGamal implementation with a larger number of voters
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision_server import DecisionServer
from voter import Voter
import time

def test_large_scale_optimization():
    """Test the ElGamal optimization with a larger number of voters"""
    
    print("=== Testing Large Scale ElGamal Optimization ===")
    
    # Test parameters  
    num_voters = 50
    quorum = 25
    
    print(f"1. Creating DecisionServer with {num_voters} voters...")
    start_time = time.time()
    server = DecisionServer(number_voters=num_voters, quorum=quorum)
    setup_time = time.time() - start_time
    print(f"   Setup time (including discrete log precomputation): {setup_time:.3f}s")
    
    # Create voters
    print(f"2. Creating {num_voters} voters...")
    voters = [Voter(server, i) for i in range(num_voters)]
    
    # Set up the cryptographic keys
    print("3. Setting up cryptographic keys...")
    secret_key = server.create_and_distribute_key(voters)
    
    # Test vote casting - simulate about 60% voting "yes" (1)
    print("4. Casting votes...")
    expected_yes_votes = 0
    for i, voter in enumerate(voters):
        # Vote pattern: roughly 60% vote 1, 40% vote 0
        vote = 1 if i % 5 != 0 and i % 5 != 1 else 0  # 3 out of 5 vote 1
        voter.castVote(vote)
        if vote == 1:
            expected_yes_votes += 1
    
    print(f"   Expected 'yes' votes: {expected_yes_votes}")
    
    # Perform homomorphic tally
    print("5. Performing homomorphic tally...")
    tally_start = time.time()
    encrypted_total = server.tally_vote()
    tally_time = time.time() - tally_start
    print(f"   Tally time: {tally_time:.3f}s")
    
    # Decrypt with threshold decryption using the first 'quorum' voters
    print(f"6. Decrypting with threshold secret sharing ({quorum} voters)...")
    decrypt_start = time.time()
    plaintext_total = server.decrypt_results(
        list(range(quorum)), 
        voters[:quorum]
    )
    decrypt_time = time.time() - decrypt_start
    print(f"   Decryption time: {decrypt_time:.3f}s")
    
    print(f"7. Results:")
    print(f"   Decrypted total: {plaintext_total}")
    print(f"   Expected total: {expected_yes_votes}")
    print(f"   Success: {'✓' if plaintext_total == expected_yes_votes else '✗'}")
    
    total_time = setup_time + tally_time + decrypt_time
    print(f"   Total computation time: {total_time:.3f}s")
    
    # Test discrete log performance on different vote totals
    print("8. Testing discrete log performance...")
    elgamal = server.elgamal
    test_values = [0, 1, 10, 25, 50, 100, 500]
    
    for value in test_values:
        if value <= num_voters:
            start = time.time()
            test_point = elgamal.encrypt_with_generator(value)
            solved_value = elgamal.solve_discrete_log(test_point)
            solve_time = time.time() - start
            print(f"   discrete_log({value}) = {solved_value} in {solve_time*1000:.3f}ms {'✓' if solved_value == value else '✗'}")

if __name__ == "__main__":
    test_large_scale_optimization()