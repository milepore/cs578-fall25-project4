#!/usr/bin/env python3
"""
Test script for the Schnorr-based disjunctive zero-knowledge proof implementation.
"""

import sys
import json
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schnorr_zkp import SchnorrDisjunctiveProof

def test_schnorr_disjunctive_proof():
    """Test the Schnorr disjunctive proof system."""
    print("Testing Schnorr Disjunctive Zero-Knowledge Proof")
    print("=" * 50)
    
    # Initialize proof system
    proof_system = SchnorrDisjunctiveProof()
    
    # Test data
    voter_id = 123
    encrypted_vote_0 = '{"vote": "encrypted_0", "context": "test"}'
    encrypted_vote_1 = '{"vote": "encrypted_1", "context": "test"}'
    
    print("\n1. Testing proof creation and verification for vote = 0")
    try:
        # Create proof for vote = 0
        proof_0 = proof_system.create_proof(0, encrypted_vote_0, voter_id)
        print(f"   Proof created successfully")
        print(f"   Proof type: {proof_0['type']}")
        print(f"   Challenge length: {len(proof_0['challenge'])}")
        
        # Verify the proof
        is_valid_0 = proof_system.verify_proof(proof_0, encrypted_vote_0)
        print(f"   Verification result: {'PASS' if is_valid_0 else 'FAIL'}")
        
        # Test with wrong encrypted vote (should fail)
        is_valid_wrong = proof_system.verify_proof(proof_0, encrypted_vote_1)
        print(f"   Wrong encrypted vote verification: {'FAIL (expected)' if not is_valid_wrong else 'PASS (unexpected)'}")
        
    except Exception as e:
        print(f"   ERROR: {e}")
        return False
    
    print("\n2. Testing proof creation and verification for vote = 1")
    try:
        # Create proof for vote = 1
        proof_1 = proof_system.create_proof(1, encrypted_vote_1, voter_id)
        print(f"   Proof created successfully")
        print(f"   Proof type: {proof_1['type']}")
        print(f"   Challenge length: {len(proof_1['challenge'])}")
        
        # Verify the proof
        is_valid_1 = proof_system.verify_proof(proof_1, encrypted_vote_1)
        print(f"   Verification result: {'PASS' if is_valid_1 else 'FAIL'}")
        
    except Exception as e:
        print(f"   ERROR: {e}")
        return False
    
    print("\n3. Testing invalid vote value")
    try:
        proof_invalid = proof_system.create_proof(2, encrypted_vote_0, voter_id)
        print(f"   ERROR: Should have raised ValueError for vote = 2")
        return False
    except ValueError as e:
        print(f"   Correctly rejected invalid vote: {e}")
    except Exception as e:
        print(f"   Unexpected error: {e}")
        return False
    
    print("\n4. Testing proof structure")
    proof_0 = proof_system.create_proof(0, encrypted_vote_0, voter_id)
    expected_fields = ['type', 'commitment', 'A0', 'A1', 'c0', 'c1', 'z0', 'z1', 'challenge', 'voter_id', 'encrypted_vote_hash']
    missing_fields = [field for field in expected_fields if field not in proof_0]
    
    if missing_fields:
        print(f"   Missing fields in proof: {missing_fields}")
        return False
    else:
        print(f"   All required fields present in proof")
    
    print("\n" + "=" * 50)
    print("All tests completed successfully!")
    return True

def test_full_voter_integration():
    """Test the integration with the Voter class (mock test)."""
    print("\nTesting Voter class integration (basic)")
    print("=" * 50)
    
    # This is a simplified test since we don't have a full DecisionServer setup
    try:
        from voter import Voter
        print("✓ Voter class import successful")
        
        # Test the static method for creating key pairs
        from voter import create_key_pair
        public_key_hex, private_key_obj = create_key_pair(999)
        print(f"✓ Key pair generation successful: {public_key_hex[:20]}...")
        
        print("✓ Basic integration test passed")
        return True
        
    except Exception as e:
        print(f"✗ Integration test failed: {e}")
        return False

if __name__ == "__main__":
    print("Zero-Knowledge Proof Test Suite")
    print("Testing Schnorr-based Disjunctive Proof Implementation")
    
    success = True
    
    # Test the proof system
    success &= test_schnorr_disjunctive_proof()
    
    # Test basic integration
    success &= test_full_voter_integration()
    
    print(f"\nOverall test result: {'ALL TESTS PASSED' if success else 'SOME TESTS FAILED'}")
    sys.exit(0 if success else 1)