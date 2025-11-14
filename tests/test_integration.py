#!/usr/bin/env python3
"""
Integration test for the updated Voter class with real zero-knowledge proofs.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from voter import Voter
from schnorr_zkp import SchnorrDisjunctiveProof, verify_zkp_from_json
from decision_server import DecisionServer

class MockDecisionServer(DecisionServer):
    """Mock DecisionServer for testing purposes."""
    
    def __init__(self):
        # Initialize parent with minimal parameters
        super().__init__(number_voters=5, quorum=3)
        self.votes = []
    
    @staticmethod
    def register_voter(server, voter_id, public_key_hex):
        # Use the parent's register_voter method
        server.register_voter(voter_id, public_key_hex)
        print(f"MockDecisionServer: Registered voter {voter_id}")
    
    def castVote(self, encrypted_vote, zkp, voter_id, signature):
        """Mock vote casting that verifies the ZKP."""
        print(f"MockDecisionServer: Processing vote from voter {voter_id}")
        
        # Verify the zero-knowledge proof using the standalone function
        try:
            is_valid = verify_zkp_from_json(zkp, encrypted_vote)
            if is_valid:
                print(f"MockDecisionServer: ZKP verification PASSED for voter {voter_id}")
                self.votes.append({
                    'voter_id': voter_id,
                    'encrypted_vote': encrypted_vote,
                    'zkp': zkp,
                    'signature': signature
                })
                return True
            else:
                print(f"MockDecisionServer: ZKP verification FAILED for voter {voter_id}")
                return False
                
        except Exception as e:
            print(f"MockDecisionServer: Error processing vote: {e}")
            return False

def test_voter_with_real_zkp():
    """Test the Voter class with real zero-knowledge proofs."""
    print("Testing Voter with Real Zero-Knowledge Proofs")
    print("=" * 60)
    
    # Create mock decision server
    mock_server = MockDecisionServer()
    
    # Create voters
    voter1 = Voter(mock_server, voter_id=1)
    voter2 = Voter(mock_server, voter_id=2)
    
    print(f"\nCreated voters: {voter1}, {voter2}")
    
    # Simulate receiving shared public key (using mock data)
    mock_public_key = b"mock_bgv_public_context_for_testing_purposes_12345"
    
    voter1.receive_key_share_and_public_key((1, 12345), mock_public_key)
    voter2.receive_key_share_and_public_key((2, 67890), mock_public_key)
    
    print("\nVoters received key shares and public keys")
    
    # Test vote casting with real ZKPs
    print("\n" + "=" * 40)
    print("Testing vote casting with ZKP verification")
    
    # Voter 1 casts vote 0
    print(f"\nVoter 1 casting vote: 0")
    try:
        # We need to mock the BGV encryption since we don't have a full setup
        # Let's modify the voter's _encrypt_vote method temporarily for testing
        original_encrypt = voter1._encrypt_vote
        
        def mock_encrypt_vote(vote, public_context):
            return f'{{"mock_encrypted_vote": {vote}, "voter_id": {voter1.voter_id}}}'
        
        voter1._encrypt_vote = mock_encrypt_vote
        
        result1 = voter1.cast_vote(0)
        print(f"Vote 0 casting result: {'SUCCESS' if result1 else 'FAILURE'}")
        
        # Restore original method
        voter1._encrypt_vote = original_encrypt
        
    except Exception as e:
        print(f"Error casting vote 0: {e}")
        result1 = False
    
    # Voter 2 casts vote 1
    print(f"\nVoter 2 casting vote: 1")
    try:
        # Mock encryption for voter 2
        original_encrypt2 = voter2._encrypt_vote
        
        def mock_encrypt_vote2(vote, public_context):
            return f'{{"mock_encrypted_vote": {vote}, "voter_id": {voter2.voter_id}}}'
        
        voter2._encrypt_vote = mock_encrypt_vote2
        
        result2 = voter2.cast_vote(1)
        print(f"Vote 1 casting result: {'SUCCESS' if result2 else 'FAILURE'}")
        
        # Restore original method
        voter2._encrypt_vote = original_encrypt2
        
    except Exception as e:
        print(f"Error casting vote 1: {e}")
        result2 = False
    
    # Summary
    print(f"\n" + "=" * 60)
    print(f"Integration Test Summary:")
    print(f"- Voters created: 2")
    print(f"- Votes cast successfully: {sum([result1, result2])}")
    print(f"- Total votes in server: {len(mock_server.votes)}")
    
    if len(mock_server.votes) == 2:
        print("✓ All votes were successfully cast and verified!")
        
        # Show proof details
        for i, vote_data in enumerate(mock_server.votes):
            proof_dict = json.loads(vote_data['zkp'])
            print(f"  Vote {i+1}: Voter {vote_data['voter_id']}, Proof type: {proof_dict['type']}")
        
        return True
    else:
        print("✗ Some votes failed to cast or verify")
        return False

if __name__ == "__main__":
    success = test_voter_with_real_zkp()
    print(f"\nIntegration test result: {'PASSED' if success else 'FAILED'}")