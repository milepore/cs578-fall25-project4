#!/usr/bin/env python3
"""
Simulation script for the DecisionServer and Voter classes.
"""

from decision_server import DecisionServer
from voter import Voter


def main():
    """
    Main function to run the decision-making simulation.
    """
    print("Decision Server Simulation")
    print("=" * 30)
    
    # Create a DecisionServer with 5 voters and a quorum of 3
    try:
        server = DecisionServer(number_voters=5, quorum=3)
        print(f"Created: {server}")
        
        # Create voters
        voters = []
        for i in range(server.number_voters):
            voter = Voter(server, voter_id=i)
            voters.append(voter)
            print(f"Created: {voter}")
        
        # Create and distribute secret key using Shamir's scheme
        print(f"\nCreating and distributing secret key...")
        secret_key = server.create_and_distribute_key(voters)
        print(f"Secret key created and distributed to all voters")
        
        # Verify all voters received their shares and public key
        print(f"\nVerifying key share and public key distribution:")
        for voter in voters:
            if voter.has_key_share() and voter.has_shared_public_key():
                share = voter.get_key_share()
                public_key = voter.get_shared_public_key()
                print(f"Voter {voter.voter_id}: Has share ({share[0]}, {str(share[1])[:10]}...) and public key: {public_key[:20]}...")
            else:
                print(f"Voter {voter.voter_id}: Missing share or public key")
        
        # Demonstrate voting process
        print(f"\nStarting voting process...")
        print(f"Quorum required: {server.quorum} votes")
        
        # Have some voters cast votes
        votes_to_cast = [1, 0, 1, 0, 1]  # Mix of yes/no votes
        
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
        
        print(f"\nSimulation complete!")
        print(f"Server has {server.number_voters} voters with quorum of {server.quorum}")
        print(f"Secret key length: {len(secret_key)} bytes")
        
    except (ValueError, TypeError) as e:
        print(f"Error creating simulation: {e}")


if __name__ == "__main__":
    main()