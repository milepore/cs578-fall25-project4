#!/usr/bin/env python3
"""
Comprehensive test suite for the refactored zero-knowledge proof system.
Tests all components after extracting SchnorrDisjunctiveProof to separate module.
"""

import subprocess
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def run_test(test_file, description):
    """Run a test file and return success status."""
    print(f"\n{'='*60}")
    print(f"Running {description}")
    print(f"{'='*60}")
    
    try:
        # Determine the correct path for the test file
        if test_file.startswith('test_'):
            # Test files are in the tests directory
            test_path = os.path.join(os.path.dirname(__file__), test_file)
        else:
            # Module files are in the parent directory
            test_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), test_file)
        
        result = subprocess.run([
            "/Users/mlepore/git/cs578-fall25-project4/.venv/bin/python", 
            test_path
        ], capture_output=True, text=True, cwd="/Users/mlepore/git/cs578-fall25-project4")
        
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        
        success = result.returncode == 0
        print(f"\nResult: {'✅ PASSED' if success else '❌ FAILED'}")
        return success
        
    except Exception as e:
        print(f"❌ FAILED - Exception: {e}")
        return False

def main():
    """Run all tests in sequence."""
    print("Comprehensive Test Suite for Refactored ZKP System")
    print("Testing refactored Schnorr ZKP base class and extracted test modules")
    
    tests = [
        ("test_schnorr_zkp.py", "Comprehensive Schnorr ZKP Tests"),
        ("test_bgv_threshold.py", "BGV Threshold Cryptography Tests"),
        ("test_elgamal_threshold.py", "ElGamal Threshold Cryptography Tests"),
        ("test_zkp.py", "Core ZKP Functionality Tests"),
        ("test_verification.py", "ZKP Verification Method Tests"),
        ("test_integration.py", "Full Voting Integration Tests")
    ]
    
    results = []
    for test_file, description in tests:
        success = run_test(test_file, description)
        results.append((test_file, success))
    
    # Summary
    print(f"\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    
    passed = 0
    for test_file, success in results:
        status = "✅ PASSED" if success else "❌ FAILED"
        print(f"{test_file:<25} {status}")
        if success:
            passed += 1
    
    total = len(results)
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED! Refactoring successful!")
        return True
    else:
        print("💥 Some tests failed. Check output above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)