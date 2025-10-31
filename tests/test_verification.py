#!/usr/bin/env python3
"""
Test the verify_vote_zkp method in the Voter class.
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from schnorr_zkp import SchnorrDisjunctiveProof, verify_zkp_from_json

def test_voter_zkp_verification():
    """Test the ZKP verification method."""
    print("Testing Voter ZKP Verification Method")
    print("=" * 40)
    
    # Create proof system
    proof_system = SchnorrDisjunctiveProof()
    
    # Test data
    voter_id = 42
    encrypted_vote = '{"test": "encrypted_data", "voter": 42}'
    
    # Create a proof for vote = 1
    print("Creating proof for vote = 1...")
    proof_dict = proof_system.create_proof(1, encrypted_vote, voter_id)
    zkp_json = json.dumps(proof_dict)
    
    print(f"Proof created: {len(zkp_json)} bytes")
    print(f"Proof type: {proof_dict['type']}")
    
    # Test direct verification using the proof system
    print("\nTesting direct proof system verification...")
    is_valid_direct = proof_system.verify_proof(proof_dict, encrypted_vote)
    print(f"Direct verification: {'PASS' if is_valid_direct else 'FAIL'}")
    
    # Test the standalone JSON verification function
    print("\nTesting standalone JSON verification function...")
    is_valid_standalone = verify_zkp_from_json(zkp_json, encrypted_vote)
    print(f"Standalone verification: {'PASS' if is_valid_standalone else 'FAIL'}")
    
    # Test with wrong encrypted vote using standalone function
    wrong_encrypted_vote = '{"test": "wrong_data", "voter": 99}'
    print(f"\nTesting with wrong encrypted vote...")
    is_valid_wrong = verify_zkp_from_json(zkp_json, wrong_encrypted_vote)
    print(f"Wrong encrypted vote verification: {'FAIL (expected)' if not is_valid_wrong else 'PASS (unexpected)'}")
    
    # Test with malformed JSON using standalone function
    print(f"\nTesting with malformed JSON...")
    is_valid_malformed = verify_zkp_from_json("invalid json", encrypted_vote)
    print(f"Malformed JSON verification: {'FAIL (expected)' if not is_valid_malformed else 'PASS (unexpected)'}")
    
    # Summary
    success = is_valid_direct and is_valid_standalone and not is_valid_wrong and not is_valid_malformed
    print(f"\n" + "=" * 40)
    print(f"Standalone ZKP Verification Test: {'ALL TESTS PASSED' if success else 'SOME TESTS FAILED'}")
    
    return success

if __name__ == "__main__":
    test_voter_zkp_verification()