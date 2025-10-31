#!/usr/bin/env python3
"""
Simulation script for the DecisionServer and Voter classes.
"""

from decision_server import DecisionServer
from voter import Voter
import random



def main():
    """
    Main function to run the decision-making simulation.
    Creates a voting server, and the right number of voters,
    distributes keys, casts votes, tallies the encrypted results,
    and decrypts the results using only a quorum of voters.
    """
    print("Decision Server Simulation")
    print("=" * 30)
    
    # Create a DecisionServer with 50 voters and a quorum of 35
    try:
        server = DecisionServer(number_voters=50, quorum=35)
        print(f"Created: {server}")
        
        # Create voters
        voters = []
        for i in range(server.number_voters):
            voter = Voter(server, voter_id=i)
            voters.append(voter)

        print(f"\nCreated {len(voters)} voters") 

        # Create and distribute secret key using Shamir's scheme
        print(f"\nCreating and distributing secret key...")
        server.create_and_distribute_key(voters)
        print(f"Secret key created and distributed to all voters")
        
        # Demonstrate voting process
        print(f"\nStarting voting process...")
        print(f"Quorum required: {server.quorum} votes")
        
        # create votes_to_cast as a list of length equal to number_voters with random 0/1 votes
        votes_to_cast = [random.randint(0, 1) for _ in range(server.number_voters)]
        
        for i, vote_value in enumerate(votes_to_cast):
            if i < len(voters):
                voter = voters[i]
                try:
                    success = voter.castVote(vote_value)
                    if success:
                        print(f"✓ Voter {voter.voter_id} successfully voted")
                    else:
                        print(f"✗ Voter {voter.voter_id} failed to vote")
                except Exception as e:
                    print(f"✗ Voter {voter.voter_id} vote error: {e}")
        
        # Check voting results
        print(f"\nVoting Results:")
        print(f"Total votes cast: {server.get_vote_count()}")
        print(f"Quorum met: {'Yes' if server.has_quorum() else 'No'}")
        
        # Perform homomorphic tallying if quorum is met
        if server.has_quorum():
            print(f"\nPerforming homomorphic tally...")
            try:
                encrypted_tally = server.tally_vote()
                print(f"✓ Homomorphic tally completed successfully")
                print(f"Encrypted total: {encrypted_tally[:50]}...")
                
                # Get complete results with verification proof
                print(f"\nRetrieving tallied results with verification proof...")
                results = server.get_tallied_results()
                
                print(f"✓ Results retrieved successfully:")
                print(f"  - Total ciphertext: {results['total_ciphertext'][:40]}...")
                print(f"  - Number of votes: {results['num_votes']}")
                print(f"  - Quorum requirement: {results['quorum']}")
                print(f"  - Timestamp: {results['timestamp']}")
                print(f"  - Voter IDs: {results['voter_ids']}")
                
                # Perform decryption using threshold secret sharing
                print(f"\nDecrypting results using threshold secret sharing...")
                try:
                    # Use first 'quorum' voters for decryption (could be any quorum-sized subset)
                    decryption_voters = list(range(server.quorum))  # Use voter IDs 0, 1, 2 (first 3)
                    
                    print(f"Using voters {decryption_voters} for decryption (quorum = {server.quorum})")
                    
                    # Decrypt the results
                    plaintext_total = server.decrypt_results(decryption_voters, voters)
                    
                    print(f"✓ Decryption successful!")
                    print(f"Final vote total (plaintext): {plaintext_total}")
                    
                    # Show what the expected result should be based on votes cast
                    expected_total = sum(votes_to_cast[:len(voters)])
                    print(f"Expected total based on votes cast: {expected_total}")
                    print(f"Decryption matches expectation: {'Yes' if plaintext_total == expected_total else 'No'}")
                    
                except Exception as e:
                    print(f"✗ Decryption failed: {e}")
                
            except Exception as e:
                print(f"✗ Tally failed: {e}")
        else:
            print(f"\nCannot perform tally - quorum not met")
            print(f"Need {server.quorum - server.get_vote_count()} more votes")
        
        print(f"\nSimulation complete!")
        print(f"Server has {server.number_voters} voters with quorum of {server.quorum}")
        print(f"Can tally: {'Yes' if server.can_tally() else 'No'}")
        
    except (ValueError, TypeError) as e:
        print(f"Error creating simulation: {e}")


if __name__ == "__main__":
    main()