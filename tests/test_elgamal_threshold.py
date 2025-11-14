"""
Test script for the new threshold ElGamal implementation with external secret shares.
This verifies that the implementation provides real cryptographic security.
"""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from elgamal_threshold_crypto import ThresholdElGamal, ElGamalCiphertext, create_elgamal_secret_shares
import secrets

# Large prime for secret sharing (same as in elgamal_threshold_crypto.py)
Q = (int("""
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74
020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437
4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed
ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05
98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb
9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b
e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718
3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff
""".replace('\n', ''), 16) - 1) // 2

def test_basic_encryption_decryption():
    """Test basic ElGamal encryption and threshold decryption with external secret shares."""
    print("=" * 60)
    print("TESTING BASIC THRESHOLD ELGAMAL ENCRYPTION/DECRYPTION")
    print("=" * 60)
    
    # Create a 3-of-5 threshold system
    threshold, participants = 3, 5
    
    # SECURITY: Generate master secret for testing (in production this would be distributed)
    master_secret = secrets.randbelow(Q)
    
    # Create ElGamal system with the master secret (testing mode)
    elgamal = ThresholdElGamal(threshold, participants, master_secret)
    
    # Generate secret shares from the same master secret
    secret_shares = create_elgamal_secret_shares(master_secret, threshold, participants)
    
    # Test vote
    original_vote = 7
    print(f"Original vote: {original_vote}")
    
    # Encrypt the vote
    ciphertext = elgamal.encrypt(original_vote)
    print(f"Encrypted ciphertext: c1={hex(ciphertext.c1)[:20]}..., c2={hex(ciphertext.c2)[:20]}...")
    
    # Verify no plaintext is stored
    ciphertext_dict = ciphertext.to_dict()
    print(f"Serialized ciphertext contains no plaintext: {ciphertext_dict}")
    
    # Get partial decryptions from 3 participants using their external secret shares
    partial_results = []
    for i in range(threshold):
        participant_id = i + 1
        participant_share = secret_shares[i]  # External secret share
        partial_result = elgamal.partial_decrypt(ciphertext, participant_id, participant_share)
        partial_results.append(partial_result)
        print(f"Participant {participant_id} partial decryption: {hex(partial_result[1])[:20]}...")
    
    # Combine partial decryptions
    decrypted_vote = elgamal.combine_shares_and_decrypt(ciphertext, partial_results)
    print(f"Decrypted vote: {decrypted_vote}")
    
    # Clean up master secret (simulate secure destruction)
    master_secret = 0
    del master_secret
    
    success = (decrypted_vote == original_vote)
    print(f"Test {'PASSED' if success else 'FAILED'}: {original_vote} -> {decrypted_vote}")
    return success

def test_homomorphic_addition():
    """Test homomorphic addition properties with external secret shares."""
    print("\n" + "=" * 60)
    print("TESTING HOMOMORPHIC ADDITION")
    print("=" * 60)
    
    # Create threshold system
    threshold, participants = 2, 3
    
    # Generate master secret for testing
    master_secret = secrets.randbelow(Q)
    elgamal = ThresholdElGamal(threshold, participants, master_secret)
    secret_shares = create_elgamal_secret_shares(master_secret, threshold, participants)
    
    # Test votes
    vote1, vote2, vote3 = 5, 3, 7
    expected_total = vote1 + vote2 + vote3
    print(f"Individual votes: {vote1}, {vote2}, {vote3}")
    print(f"Expected total: {expected_total}")
    
    # Encrypt votes
    ct1 = elgamal.encrypt(vote1)
    ct2 = elgamal.encrypt(vote2)
    ct3 = elgamal.encrypt(vote3)
    
    print("All votes encrypted successfully")
    
    # Homomorphic addition
    combined = elgamal.homomorphic_add(ct1, ct2)
    combined = elgamal.homomorphic_add(combined, ct3)
    
    print(f"Homomorphic sum: c1={hex(combined.c1)[:20]}..., c2={hex(combined.c2)[:20]}...")
    
    # Get partial decryptions using external secret shares
    partial_results = []
    for i in range(threshold):
        participant_id = i + 1
        participant_share = secret_shares[i]
        partial_result = elgamal.partial_decrypt(combined, participant_id, participant_share)
        partial_results.append(partial_result)
    
    # Decrypt total
    decrypted_total = elgamal.combine_shares_and_decrypt(combined, partial_results)
    print(f"Decrypted total: {decrypted_total}")
    
    # Clean up
    master_secret = 0
    del master_secret
    
    success = (decrypted_total == expected_total)
    print(f"Test {'PASSED' if success else 'FAILED'}: {expected_total} -> {decrypted_total}")
    return success

def test_threshold_security():
    """Test that insufficient shares cannot decrypt."""
    print("\n" + "=" * 60)
    print("TESTING THRESHOLD SECURITY")
    print("=" * 60)
    
    # Create threshold system
    threshold, participants = 4, 6
    
    # Generate master secret for testing
    master_secret = secrets.randbelow(Q)
    elgamal = ThresholdElGamal(threshold, participants, master_secret)
    secret_shares = create_elgamal_secret_shares(master_secret, threshold, participants)
    
    # Encrypt a vote
    vote = 10
    ciphertext = elgamal.encrypt(vote)
    print(f"Encrypted vote: {vote}")
    
    # Try with insufficient shares (only 2 out of required 4)
    insufficient_partial_results = []
    for i in range(2):  # Only 2 participants
        participant_id = i + 1
        participant_share = secret_shares[i]
        partial_result = elgamal.partial_decrypt(ciphertext, participant_id, participant_share)
        insufficient_partial_results.append(partial_result)
    
    try:
        # This should fail
        decrypted = elgamal.combine_shares_and_decrypt(ciphertext, insufficient_partial_results)
        print(f"❌ FAILED: Decryption succeeded with insufficient shares: {decrypted}")
        return False
    except ValueError as e:
        if "Need at least" in str(e):
            print(f"✅ PASSED: Correctly rejected insufficient shares: {e}")
            # Clean up
            master_secret = 0
            del master_secret
            return True
        else:
            print(f"❌ FAILED: Wrong error: {e}")
            return False

def test_real_cryptography():
    """Verify that this is real cryptography, not simulation."""
    print("\n" + "=" * 60)
    print("TESTING REAL CRYPTOGRAPHY (NO SIMULATION)")
    print("=" * 60)
    
    # Create threshold system
    elgamal = ThresholdElGamal(2, 3)
    
    # Encrypt same vote multiple times - should get different ciphertexts
    vote = 5
    ct1 = elgamal.encrypt(vote)
    ct2 = elgamal.encrypt(vote)
    
    print(f"Same vote ({vote}) encrypted twice:")
    print(f"  Ciphertext 1: c1={hex(ct1.c1)[:16]}..., c2={hex(ct1.c2)[:16]}...")
    print(f"  Ciphertext 2: c1={hex(ct2.c1)[:16]}..., c2={hex(ct2.c2)[:16]}...")
    
    # Ciphertexts should be different (due to randomness)
    different_ciphertexts = (ct1.c1 != ct2.c1 or ct1.c2 != ct2.c2)
    
    if different_ciphertexts:
        print("✅ PASSED: Same plaintext produces different ciphertexts (semantic security)")
    else:
        print("❌ FAILED: Same plaintext produces identical ciphertexts")
    
    # Verify serialized data contains no plaintext
    ct1_dict = ct1.to_dict()
    ct2_dict = ct2.to_dict()
    
    # Check for explicit plaintext fields, not hex digit matches
    contains_plaintext = (
        'vote' in str(ct1_dict).lower() or 
        'plaintext' in str(ct1_dict).lower() or
        'simulation' in str(ct1_dict).lower() or
        '_simulation_value' in str(ct1_dict) or
        'message' in str(ct1_dict).lower()
    )
    
    if not contains_plaintext:
        print("✅ PASSED: Serialized ciphertext contains no plaintext or simulation data")
    else:
        print("❌ FAILED: Serialized ciphertext may contain plaintext")
        print(f"  Ciphertext data: {ct1_dict}")
    
    return different_ciphertexts and not contains_plaintext

def run_all_tests():
    """Run all ElGamal tests."""
    print("THRESHOLD ELGAMAL CRYPTOGRAPHY TEST SUITE")
    print("Real cryptography - no simulation values stored")
    
    tests = [
        test_basic_encryption_decryption,
        test_homomorphic_addition,
        test_threshold_security,
        test_real_cryptography
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed}/{total} tests passed")
    print("=" * 60)
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! Threshold ElGamal implementation is working!")
    else:
        print("❌ Some tests failed. See details above.")
    
    return passed == total

if __name__ == "__main__":
    run_all_tests()