#!/usr/bin/env python3
"""
Test script for the Schnorr-based zero-knowledge proof implementations.

Tests both the disjunctive proof system (for vote validity) and the 
partial decryption proof system using the refactored base class.
"""

import sys
import os
import json

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from schnorr_zkp import (
    SchnorrDisjunctiveProof, 
    SchnorrPartialDecryptionProof, 
    verify_zkp_from_json, 
    verify_partial_decryption_zkp_from_json
)


def test_schnorr_disjunctive_proof():
    """Test the Schnorr disjunctive proof system for vote validity."""
    print("Testing Schnorr Disjunctive Proof System...")
    
    proof_system = SchnorrDisjunctiveProof()
    
    # Test vote = 0
    encrypted_vote = '{"test": "data", "vote": "encrypted"}'
    proof_0 = proof_system.create_proof(0, encrypted_vote, voter_id=123)
    valid_0 = proof_system.verify_proof(proof_0, encrypted_vote)
    
    # Test vote = 1  
    proof_1 = proof_system.create_proof(1, encrypted_vote, voter_id=124)
    valid_1 = proof_system.verify_proof(proof_1, encrypted_vote)
    
    print(f"Vote 0 proof: {'VALID' if valid_0 else 'INVALID'}")
    print(f"Vote 1 proof: {'VALID' if valid_1 else 'INVALID'}")
    
    # Test the JSON verification function
    print("\nTesting JSON verification function...")
    proof_0_json = json.dumps(proof_0)
    valid_json = verify_zkp_from_json(proof_0_json, encrypted_vote)
    print(f"JSON verification: {'VALID' if valid_json else 'INVALID'}")
    
    return valid_0 and valid_1 and valid_json


def test_schnorr_partial_decryption_proof():
    """Test the Schnorr partial decryption proof system."""
    print("\nTesting Schnorr Partial Decryption Proof System...")
    
    proof_system = SchnorrPartialDecryptionProof()
    
    # Test data
    secret_share = (1, 12345)  # (x, y) where y is the secret
    encrypted_tally = '{"encrypted": "tally", "data": "test"}'
    partial_result = {
        'share_index': 1,
        'partial_value': 67890,
        'computation_metadata': {'voter_id': 42, 'decryption_type': 'bgv_threshold_partial'}
    }
    voter_id = 42
    
    # Create proof
    proof = proof_system.create_proof(secret_share, encrypted_tally, partial_result, voter_id)
    print(f"Partial decryption proof created successfully")
    print(f"Proof type: {proof['type']}")
    print(f"Share index: {proof['share_index']}")
    
    # Verify the proof
    is_valid = proof_system.verify_proof(proof, encrypted_tally, partial_result)
    print(f"Verification result: {'VALID' if is_valid else 'INVALID'}")
    
    # Test JSON verification function
    proof_json = json.dumps(proof)
    valid_json = verify_partial_decryption_zkp_from_json(proof_json, encrypted_tally, partial_result)
    print(f"JSON verification: {'VALID' if valid_json else 'INVALID'}")
    
    # Test with wrong encrypted tally (should fail)
    wrong_tally = '{"encrypted": "wrong", "data": "test"}'
    is_valid_wrong = proof_system.verify_proof(proof, wrong_tally, partial_result)
    print(f"Wrong tally verification: {'INVALID (expected)' if not is_valid_wrong else 'VALID (unexpected)'}")
    
    return is_valid and valid_json and not is_valid_wrong


def test_base_class_functionality():
    """Test that both proof systems properly inherit from the base class."""
    print("\nTesting Base Class Inheritance...")
    
    disjunctive_proof = SchnorrDisjunctiveProof()
    partial_proof = SchnorrPartialDecryptionProof()
    
    # Test that both have the same base methods
    base_methods = ['_get_generator_point', '_point_to_bytes', '_scalar_mult', '_hash_to_scalar']
    
    for method in base_methods:
        if not hasattr(disjunctive_proof, method):
            print(f"✗ SchnorrDisjunctiveProof missing method: {method}")
            return False
        if not hasattr(partial_proof, method):
            print(f"✗ SchnorrPartialDecryptionProof missing method: {method}")
            return False
    
    # Test that both have the same curve parameters
    if disjunctive_proof.q != partial_proof.q:
        print(f"✗ Different field orders: {disjunctive_proof.q} vs {partial_proof.q}")
        return False
    
    print("✓ Both proof classes properly inherit from SchnorrProofBase")
    print("✓ All base methods available")
    print("✓ Same curve parameters")
    
    return True


def test_invalid_inputs():
    """Test error handling for invalid inputs."""
    print("\nTesting Invalid Input Handling...")
    
    disjunctive_proof = SchnorrDisjunctiveProof()
    partial_proof = SchnorrPartialDecryptionProof()
    
    # Test invalid vote for disjunctive proof
    try:
        encrypted_vote = '{"test": "data"}'
        disjunctive_proof.create_proof(2, encrypted_vote, voter_id=123)  # Invalid vote
        print("✗ Should have raised ValueError for invalid vote")
        return False
    except ValueError as e:
        print(f"✓ Correctly rejected invalid vote: {e}")
    
    # Test invalid secret share for partial decryption proof
    try:
        encrypted_tally = '{"test": "tally"}'
        partial_result = {'share_index': 1, 'partial_value': 123}
        partial_proof.create_proof("invalid_share", encrypted_tally, partial_result, voter_id=42)
        print("✗ Should have raised ValueError for invalid secret share")
        return False
    except ValueError as e:
        print(f"✓ Correctly rejected invalid secret share: {e}")
    
    print("✓ Error handling working correctly")
    return True


def run_all_tests():
    """Run all Schnorr ZKP tests."""
    print("Running Comprehensive Schnorr ZKP Tests")
    print("=" * 60)
    
    tests = [
        ("Disjunctive Proof System", test_schnorr_disjunctive_proof),
        ("Partial Decryption Proof System", test_schnorr_partial_decryption_proof),
        ("Base Class Functionality", test_base_class_functionality),
        ("Invalid Input Handling", test_invalid_inputs)
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            success = test_func()
            results.append((test_name, success))
            print(f"Result: {'✓ PASSED' if success else '✗ FAILED'}")
        except Exception as e:
            print(f"Result: ✗ FAILED - Exception: {e}")
            results.append((test_name, False))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = 0
    for test_name, success in results:
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"{test_name:<35} {status}")
        if success:
            passed += 1
    
    total = len(results)
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL SCHNORR ZKP TESTS PASSED!")
        return True
    else:
        print("💥 Some tests failed. Check output above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)