"""
Tests for BGV threshold cryptography implementation.

This module contains comprehensive tests for the BGV-based threshold
homomorphic encryption system used in the voting system.
"""

import sys
import os

# Add the parent directory to the path so we can import from the main modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from bgv_threshold_crypto import BGVThresholdCrypto, create_shares, PRIME
import secrets


def test_bgv_threshold():
    """Test the BGV threshold crypto system with proper key separation."""
    print("Testing BGV Threshold Crypto System")
    
    # SECURITY: Simulate Key Generation Authority pattern
    # Generate master secret and shares (normally done by KGA)
    threshold, num_participants = 3, 5
    master_secret = secrets.randbits(127) % PRIME
    secret_shares = create_shares(master_secret, threshold, num_participants)
    
    # Initialize BGV system (without master secret - like DecisionServer)
    crypto_system = BGVThresholdCrypto(threshold=threshold, num_participants=num_participants)
    
    # Encrypt some votes
    vote1 = crypto_system.encrypt(5)
    vote2 = crypto_system.encrypt(3)
    vote3 = crypto_system.encrypt(7)
    
    # Homomorphically add votes
    combined = crypto_system.homomorphic_add(vote1, vote2)
    combined = crypto_system.homomorphic_add(combined, vote3)
    
    # Partial decryptions from 3 participants (threshold)
    # Each participant uses their own secret share
    partial_results = []
    for i in range(3):  # Use first 3 participants
        participant_share = secret_shares[i]  # Simulate voter having their share
        partial_result = crypto_system.partial_decrypt(combined, i, participant_share)
        partial_results.append(partial_result)
    
    # Combine and decrypt
    final_result = crypto_system.combine_shares_and_decrypt(combined, partial_results)
    
    # Securely delete master secret (simulate KGA behavior)
    master_secret = 0
    del master_secret
    
    expected = 5 + 3 + 7
    print(f"Expected total: {expected}")
    print(f"Actual total: {final_result}")
    print(f"Test {'PASSED' if final_result == expected else 'FAILED'}")
    
    return final_result == expected


def test_bgv_threshold_insufficient_shares():
    """Test that BGV system rejects insufficient shares for decryption."""
    print("\nTesting BGV Threshold with Insufficient Shares")
    
    # Generate secret shares for testing
    threshold, num_participants = 3, 5
    master_secret = secrets.randbits(127) % PRIME
    secret_shares = create_shares(master_secret, threshold, num_participants)
    
    crypto_system = BGVThresholdCrypto(threshold=threshold, num_participants=num_participants)
    
    # Encrypt a vote
    vote = crypto_system.encrypt(10)
    
    # Try with only 2 partial results when threshold is 3
    partial_results = []
    for i in range(2):  # Only 2 participants, need 3
        participant_share = secret_shares[i]
        partial_result = crypto_system.partial_decrypt(vote, i, participant_share)
        partial_results.append(partial_result)
    
    try:
        result = crypto_system.combine_shares_and_decrypt(vote, partial_results)
        print("❌ FAILED: Decryption succeeded with insufficient shares")
        return False
    except ValueError as e:
        if "Need at least" in str(e):
            print("✅ PASSED: Correctly rejected insufficient shares")
            return True
        else:
            print(f"❌ FAILED: Wrong error type: {e}")
            return False
    except Exception as e:
        print(f"❌ FAILED: Unexpected error: {e}")
        return False


def test_bgv_threshold_excess_shares():
    """Test that BGV system handles excess shares gracefully."""
    print("\nTesting BGV Threshold with Excess Shares")
    
    # Generate secret shares for testing
    threshold, num_participants = 3, 5
    master_secret = secrets.randbits(127) % PRIME
    secret_shares = create_shares(master_secret, threshold, num_participants)
    
    crypto_system = BGVThresholdCrypto(threshold=threshold, num_participants=num_participants)
    
    # Encrypt a vote
    vote = crypto_system.encrypt(8)
    
    # Use 4 partial results when threshold is 3
    partial_results = []
    for i in range(4):  # 4 participants when threshold is 3
        participant_share = secret_shares[i]
        partial_result = crypto_system.partial_decrypt(vote, i, participant_share)
        partial_results.append(partial_result)
    
    try:
        result = crypto_system.combine_shares_and_decrypt(vote, partial_results)
        expected = 8
        if result == expected:
            print(f"✅ PASSED: Correctly handled excess shares, result: {result}")
            return True
        else:
            print(f"❌ FAILED: Wrong result with excess shares: expected {expected}, got {result}")
            return False
    except Exception as e:
        print(f"❌ FAILED: Error with excess shares: {e}")
        return False


def test_bgv_invalid_threshold():
    """Test that BGV system rejects invalid threshold parameters."""
    print("\nTesting BGV Threshold with Invalid Parameters")
    
    try:
        # Try to create system with threshold > participants
        crypto_system = BGVThresholdCrypto(threshold=6, num_participants=5)
        print("❌ FAILED: System created with invalid threshold")
        return False
    except ValueError as e:
        if "Threshold cannot be greater" in str(e):
            print("✅ PASSED: Correctly rejected invalid threshold")
            return True
        else:
            print(f"❌ FAILED: Wrong error type: {e}")
            return False
    except Exception as e:
        print(f"❌ FAILED: Unexpected error: {e}")
        return False


def test_bgv_homomorphic_properties():
    """Test the homomorphic properties of BGV encryption."""
    print("\nTesting BGV Homomorphic Properties")
    
    # Generate secret shares for testing
    threshold, num_participants = 2, 3
    master_secret = secrets.randbits(127) % PRIME
    secret_shares = create_shares(master_secret, threshold, num_participants)
    
    crypto_system = BGVThresholdCrypto(threshold=threshold, num_participants=num_participants)
    
    # Test additive homomorphism: Enc(a) + Enc(b) = Enc(a + b)
    a, b = 12, 8
    enc_a = crypto_system.encrypt(a)
    enc_b = crypto_system.encrypt(b)
    
    # Homomorphic addition
    enc_sum = crypto_system.homomorphic_add(enc_a, enc_b)
    
    # Decrypt to verify
    partial_results = []
    for i in range(2):  # Use threshold number of participants
        participant_share = secret_shares[i]
        partial_result = crypto_system.partial_decrypt(enc_sum, i, participant_share)
        partial_results.append(partial_result)
    
    try:
        decrypted_sum = crypto_system.combine_shares_and_decrypt(enc_sum, partial_results)
        expected_sum = a + b
        
        if decrypted_sum == expected_sum:
            print(f"✅ PASSED: Homomorphic addition works: {a} + {b} = {decrypted_sum}")
            return True
        else:
            print(f"❌ FAILED: Homomorphic addition: expected {expected_sum}, got {decrypted_sum}")
            return False
    except Exception as e:
        print(f"❌ FAILED: Error in homomorphic addition test: {e}")
        return False


def run_all_tests():
    """Run all BGV threshold crypto tests."""
    print("=" * 60)
    print("BGV THRESHOLD CRYPTOGRAPHY TEST SUITE")
    print("=" * 60)
    
    tests = [
        test_bgv_threshold,
        test_bgv_threshold_insufficient_shares,
        test_bgv_threshold_excess_shares,
        test_bgv_invalid_threshold,
        test_bgv_homomorphic_properties
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed}/{total} tests passed")
    print("=" * 60)
    
    return passed == total


if __name__ == "__main__":
    run_all_tests()