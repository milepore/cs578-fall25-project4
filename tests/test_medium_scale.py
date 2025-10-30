#!/usr/bin/env python3
"""
Test the optimized ElGamal implementation with medium scale (15 voters)
to validate discrete log optimization performance.
"""

import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision_server import DecisionServer
from voter import Voter

def test_medium_scale_voting():
    print("=== Testing Medium Scale ElGamal Optimization (15 voters) ===")
    
    # Configuration
    num_voters = 15
    quorum_size = 8  # Smaller quorum for faster testing
    
    # Expected votes (10 yes, 5 no)
    expected_votes = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
    expected_total = sum(expected_votes)
    
    print(f"1. Creating DecisionServer with {num_voters} voters...")
    start_time = time.time()
    server = DecisionServer(num_voters, quorum_size)
    setup_time = time.time() - start_time
    print(f"   Server setup time: {setup_time:.2f}s")
    
    print(f"2. Creating {num_voters} voters...")
    voters = [Voter(server, i) for i in range(num_voters)]
    
    print("3. Setting up cryptographic keys...")
    start_time = time.time()
    server.create_and_distribute_key(voters)
    crypto_time = time.time() - start_time
    print(f"   Crypto setup time: {crypto_time:.2f}s")
    
    print("4. Testing vote casting...")
    start_time = time.time()
    for i, (voter, vote) in enumerate(zip(voters, expected_votes)):
        voter.castVote(vote)
        if (i + 1) % 5 == 0:
            print(f"   Cast {i + 1}/{num_voters} votes")
    voting_time = time.time() - start_time
    print(f"   Voting time: {voting_time:.2f}s")
    print(f"   Expected total: {expected_total} votes")
    
    print("5. Performing homomorphic tally...")
    start_time = time.time()
    encrypted_total = server.tally_vote()
    tally_time = time.time() - start_time
    print(f"   Tally time: {tally_time:.2f}s")
    
    print("6. Decrypting with threshold secret sharing...")
    start_time = time.time()
    voter_ids = list(range(quorum_size))
    final_total = server.decrypt_results(voter_ids, voters)
    decrypt_time = time.time() - start_time
    print(f"   Decryption time: {decrypt_time:.2f}s")
    
    # Results
    total_time = setup_time + crypto_time + voting_time + tally_time + decrypt_time
    print("\n7. Performance Results:")
    print(f"   Setup time:      {setup_time:.2f}s")
    print(f"   Crypto time:     {crypto_time:.2f}s")
    print(f"   Voting time:     {voting_time:.2f}s")
    print(f"   Tally time:      {tally_time:.2f}s")
    print(f"   Decryption time: {decrypt_time:.2f}s")
    print(f"   Total time:      {total_time:.2f}s")
    
    print("\n8. Results:")
    print(f"   Decrypted total: {final_total}")
    print(f"   Expected total:  {expected_total}")
    success = final_total == expected_total
    print(f"   Success: {'✓' if success else '✗'}")
    
    return success

if __name__ == "__main__":
    test_medium_scale_voting()