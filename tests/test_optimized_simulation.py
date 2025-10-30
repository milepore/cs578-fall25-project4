#!/usr/bin/env python3
"""
Test the optimized ElGamal simulation with fewer voters to demonstrate performance
"""

import time
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from decision_server import DecisionServer
from voter import Voter

def test_optimized_simulation():
    # Use smaller scale to show optimization works
    num_voters = 10
    quorum = 7
    
    print(f"Testing optimized ElGamal simulation with {num_voters} voters, quorum {quorum}")
    
    # Setup phase
    start_time = time.time()
    server = DecisionServer(number_voters=num_voters, quorum=quorum)
    voters = []
    for i in range(num_voters):
        voter = Voter(server, voter_id=i)
        voters.append(voter)
        
    # Create and distribute secret key
    secret_key = server.create_and_distribute_key(voters)
        
    setup_time = time.time() - start_time
    print(f"✓ Setup completed in {setup_time:.3f}s")
    
    # Voting phase
    votes = [1, 0, 1, 1, 0, 1, 0, 1, 1, 0]  # 6 yes votes out of 10
    print(f"Casting {len(votes)} votes: {votes}")
    
    vote_start = time.time()
    for i, vote in enumerate(votes):
        voters[i].castVote(vote)
        
    vote_time = time.time() - vote_start
    print(f"✓ Voting completed in {vote_time:.3f}s")
    
    # Homomorphic tally
    tally_start = time.time()
    encrypted_total = server.tally_vote()
    tally_time = time.time() - tally_start
    print(f"✓ Homomorphic tally completed in {tally_time:.3f}s")
    
    # Threshold decryption
    decrypt_start = time.time()
    decryption_voters = list(range(quorum))  # Use first 7 voter IDs for quorum
    
    print(f"Using {len(decryption_voters)} voters for threshold decryption...")
    
    # Check server's ElGamal configuration
    print(f"Server ElGamal configured for max_votes={server.elgamal.max_votes}")
    print(f"Server discrete log table size: {len(server.elgamal.discrete_log_table)}")
    
    plaintext_total = server.decrypt_results(decryption_voters, voters)
    
    decrypt_time = time.time() - decrypt_start
    print(f"✓ Threshold decryption completed in {decrypt_time:.3f}s")
    
    # Results
    total_time = time.time() - start_time
    expected = sum(votes)
    
    print(f"\n=== OPTIMIZED SIMULATION RESULTS ===")
    print(f"Expected vote total: {expected}")
    print(f"Computed vote total: {plaintext_total}")
    print(f"Accuracy: {'✓ CORRECT' if plaintext_total == expected else '✗ INCORRECT'}")
    print(f"Total execution time: {total_time:.3f}s")
    print(f"  - Setup: {setup_time:.3f}s")
    print(f"  - Voting: {vote_time:.3f}s") 
    print(f"  - Tally: {tally_time:.3f}s")
    print(f"  - Decryption: {decrypt_time:.3f}s")
    
    print(f"\n=== DISCRETE LOG OPTIMIZATION STATS ===")
    print(f"Server table size: {len(server.elgamal.discrete_log_table)} entries")
    print(f"Expected range: 0-{server.elgamal.max_votes} votes")
    print(f"Optimization active: {'✓ YES' if len(server.elgamal.discrete_log_table) > 100 else '✗ NO'}")
    
    return plaintext_total == expected

if __name__ == "__main__":
    success = test_optimized_simulation()
    if success:
        print("\n🎉 OPTIMIZATION SUCCESSFUL - ElGamal discrete log problem is now manageable!")
    else:
        print("\n❌ Test failed")