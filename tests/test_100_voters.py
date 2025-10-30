#!/usr/bin/env python3
"""
Test the optimized ElGamal implementation with 100 voters to identify the lookup table issue
"""

import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision_server import DecisionServer
from voter import Voter

def test_100_voter_scale():
    print("=== Testing 100-Voter Scale to Identify Lookup Table Issue ===")
    
    # Configuration
    num_voters = 100
    quorum_size = 25  # 25% quorum
    
    # Expected votes (60 yes, 40 no)
    expected_votes = [1] * 60 + [0] * 40
    expected_total = sum(expected_votes)
    
    print(f"1. Creating DecisionServer with {num_voters} voters...")
    start_time = time.time()
    server = DecisionServer(num_voters, quorum_size)
    setup_time = time.time() - start_time
    print(f"   Server setup time: {setup_time:.2f}s")
    print(f"   Expected total: {expected_total} votes")
    
    print(f"2. Creating {num_voters} voters...")
    voters = [Voter(server, i) for i in range(num_voters)]
    
    print("3. Setting up cryptographic keys...")
    start_time = time.time()
    server.create_and_distribute_key(voters)
    crypto_time = time.time() - start_time
    print(f"   Crypto setup time: {crypto_time:.2f}s")
    
    print("4. Testing vote casting (25 votes to meet quorum)...")
    start_time = time.time()
    for i in range(25):  # Cast 25 votes to meet quorum
        voters[i].castVote(expected_votes[i])
        if (i + 1) % 10 == 0:
            print(f"   Cast {i + 1}/25 votes")
    voting_time = time.time() - start_time
    print(f"   Voting time: {voting_time:.2f}s")
    
    print("5. Performing homomorphic tally...")
    start_time = time.time()
    encrypted_total = server.tally_vote()
    tally_time = time.time() - start_time
    print(f"   Tally time: {tally_time:.2f}s")
    
    print("6. Attempting decryption with threshold secret sharing...")
    start_time = time.time()
    try:
        voter_ids = list(range(quorum_size))
        final_total = server.decrypt_results(voter_ids, voters)
        decrypt_time = time.time() - start_time
        print(f"   Decryption time: {decrypt_time:.2f}s")
        print(f"   Decrypted total: {final_total}")
        print(f"   Expected for 25 votes: {sum(expected_votes[:25])}")
        success = final_total == sum(expected_votes[:25])
        print(f"   Success: {'✓' if success else '✗'}")
    except Exception as e:
        decrypt_time = time.time() - start_time
        print(f"   Decryption failed after {decrypt_time:.2f}s")
        print(f"   Error: {e}")
        print("   ❌ This confirms the lookup table issue with large voter counts")
    
    # Test discrete log optimization directly
    print("\n7. Testing discrete log table coverage...")
    elgamal = server.elgamal
    print(f"   Discrete log table size: {len(elgamal.discrete_log_table)} entries")
    print(f"   Table covers votes: 0 to {len(elgamal.discrete_log_table)-1}")
    
    # Try to identify what's happening with Lagrange coefficients
    print("\n8. Analyzing Lagrange coefficient size with 25 voters...")
    sample_shares = [(i+1, 1000 + i*100) for i in range(25)]  # Sample shares
    print("   Sample Lagrange coefficients:")
    for i in range(min(5, len(sample_shares))):
        x_i = sample_shares[i][0]
        coeff = 1
        for j in range(len(sample_shares)):
            if i != j:
                x_j = sample_shares[j][0]
                coeff *= (-x_j) // (x_i - x_j)
        print(f"   Voter {i}: Lagrange coeff = {coeff}")
        if abs(coeff) > 1000:
            print(f"     ⚠️  Large coefficient detected: {abs(coeff)}")

if __name__ == "__main__":
    test_100_voter_scale()