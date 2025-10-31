# Tests Directory

This directory contains all test files for the CS578 Fall 2025 Project 4 - Secure Voting System with Zero-Knowledge Proofs.

## Test Files

### Core Tests
- **`test_schnorr_zkp.py`** - Comprehensive tests for refactored Schnorr ZKP base class and both proof systems
- **`test_zkp.py`** - Tests core ZKP functionality and SchnorrDisjunctiveProof class
- **`test_verification.py`** - Tests the standalone ZKP verification function
- **`test_integration.py`** - Full integration tests with mock DecisionServer

### Test Runner
- **`test_all.py`** - Comprehensive test runner that executes all tests

## Running Tests

### Run Individual Tests
```bash
# From the project root directory:
python tests/test_schnorr_zkp.py
python tests/test_zkp.py
python tests/test_verification.py
python tests/test_integration.py
```

### Run All Tests
```bash
# From the project root directory:
python tests/test_all.py
```

### Expected Output
All tests should pass with output like:
```
============================================================
TEST SUMMARY
============================================================
test_schnorr_zkp.py       ✅ PASSED
test_zkp.py               ✅ PASSED
test_verification.py      ✅ PASSED
test_integration.py       ✅ PASSED

Overall: 4/4 tests passed
🎉 ALL TESTS PASSED!
```

## Test Coverage

The tests cover:
- ✅ Zero-knowledge proof generation and verification
- ✅ Schnorr disjunctive proofs for vote validity (0 or 1)
- ✅ JSON serialization/deserialization of proofs
- ✅ Error handling for malformed proofs
- ✅ Integration with BGV homomorphic encryption
- ✅ Full voting workflow with ZKP verification
- ✅ DecisionServer proof verification

## Dependencies

Tests require the same dependencies as the main project:
- `cryptography` - For elliptic curve operations
- `tenseal` - For BGV homomorphic encryption
- `secrets` - For cryptographically secure randomness

## Test Architecture

The tests are designed to be:
- **Independent** - Each test file can run standalone
- **Comprehensive** - Cover all major functionality
- **Realistic** - Use actual cryptographic operations (not mocks)
- **Fast** - Complete test suite runs in under 10 seconds