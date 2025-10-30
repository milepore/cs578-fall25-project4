# Test Suite

This directory contains all test files for the ElGamal voting system project.

## Test Files

### Core Algorithm Tests
- **`test_threshold_elgamal.py`** - Tests the new ThresholdElGamal implementation with proper threshold cryptography support
- **`optimization_demo.py`** - Demonstrates the discrete logarithm optimization performance improvements

### Original ElGamal Tests
- **`test_optimized_elgamal.py`** - Tests the original optimized ElGamal implementation
- **`test_1000_vote_optimization.py`** - Validates that discrete log optimization works for 1000 votes

### Scale Testing
- **`test_optimized_simulation.py`** - Small scale test (10 voters) with optimized ElGamal
- **`test_medium_scale.py`** - Medium scale test (15 voters) for performance validation
- **`test_large_scale.py`** - Large scale test (50 voters) to identify bottlenecks
- **`test_100_voters.py`** - 100 voter test to validate lookup table improvements

## Running Tests

From the project root directory:

```bash
# Run individual tests
python3 tests/test_threshold_elgamal.py
python3 tests/optimization_demo.py

# Run all tests
for test in tests/test_*.py; do python3 "$test"; done
```

## Test Organization

All tests automatically handle import paths to access modules in the parent directory. The test files include proper path setup to import:
- `threshold_elgamal.py`
- `elgamal_curve25519.py` 
- `decision_server.py`
- `voter.py`

## Performance Benchmarks

The `optimization_demo.py` file provides comprehensive performance benchmarks showing the discrete logarithm optimization improvements across different scales (10, 50, 100, 1000 votes).