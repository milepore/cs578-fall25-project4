## Code left todo

* Create NIZKP implementation for partial decription per voter

## Quick Start

### **Installation**
```bash
pip install tenseal numpy cryptography
```

### **Run the Simulation**
```bash
python simulation.py
```

This will run a complete voting simulation with 50 voters and a 35-voter threshold, demonstrating:
- BGV homomorphic encryption of individual votes
- Privacy-preserving homomorphic tallying  
- Threshold decryption with Shamir's Secret Sharing
- Complete vote privacy (no plaintext leakage)

## Code Requirements

- Python 3.13
- tenseal (BGV/BFV homomorphic encryption)
- numpy (numerical operations for TenSEAL)
- cryptography (Ed25519 signatures, X25519 key exchange)

## Group Decisioning Protocol Implementation and Simulation

This package contains a group decisioning server built upon cryptographic methods that allows a group to cast secret votes and get results as a group while ensuring Vote Secrecy and Threshold Access.

## Decision Server Design and Implementation

The **DecisionServer** is the central component of a privacy-preserving group decision-making system that implements a secure e-voting protocol with homomorphic encryption and threshold decryption. Here's a detailed breakdown:

### **Core Architecture**

The system implements a **threshold cryptographic voting scheme** with the following key components:

1. **DecisionServer**: Central authority managing the voting process
2. **Voters**: Individual participants with cryptographic identities
3. **BGV/BFV Encryption**: Fully homomorphic encryption using TenSEAL library
4. **Shamir's Secret Sharing**: Key splitting and distribution

### **Key Design Features**

#### **1. Voter Registration & Authentication**
- **Ed25519 Digital Signatures**: Each voter has a unique Ed25519 keypair for authentication
- **Public Key Registration**: Voters register their public keys with the decision server
- **Challenge-Response Authentication**: Server authenticates voters using cryptographic challenges before key distribution

#### **2. Threshold Cryptography Setup**
- **BGV Context Generation**: Server generates BGV homomorphic encryption context using TenSEAL
- **Shamir's Secret Sharing**: A master secret is split into `n` shares using Shamir's scheme
- **Quorum Requirement**: Only `k` out of `n` voters are needed for decryption (configurable quorum)
- **Key Distribution**: Each authenticated voter receives their secret share and the public BGV context

#### **3. Secure Voting Process**
```python
def castVote(self, encrypted_vote: str, zkp: str, voter_id: int, signature: str) -> bool
```
- **Vote Encryption**: Voters encrypt their binary votes (0 or 1) using BGV/BFV homomorphic encryption
- **Complete Privacy**: Vote contents are fully hidden within BGV ciphertext structure - no plaintext leakage
- **Zero-Knowledge Proofs**: Each vote includes a ZKP proving the encrypted value is either 0 or 1
- **Digital Signatures**: All vote submissions are digitally signed for authenticity
- **Double-Voting Prevention**: Server prevents the same voter from voting multiple times

#### **4. Privacy-Preserving Tallying**
```python
def tally_vote(self) -> str
```
- **Homomorphic Addition**: Uses BGV's additive homomorphism (Enc(a) + Enc(b) = Enc(a + b))
- **Batch Processing**: Combines all encrypted votes without decrypting individual votes
- **No Discrete Logarithm**: BGV eliminates the need for discrete log solving, providing exact results
- **Verification Proofs**: Generates Non-Interactive Zero-Knowledge proofs of correct tallying
- **Quorum Enforcement**: Only performs tallying when minimum vote threshold is met

#### **5. Threshold Decryption**
```python
def decrypt_results(self, voter_ids_for_decryption: List[int], voters: List) -> int
```
- **Partial Decryptions**: Each participating voter provides a partial decryption using their secret share
- **Lagrange Interpolation**: Combines partial decryptions to recover the plaintext total
- **Proof Verification**: Validates tallying proofs before allowing decryption
- **Flexible Participation**: Any subset of `k` voters can participate in decryption

### **Security Properties**

#### **Privacy**
- **Vote Secrecy**: Individual votes remain encrypted throughout the process
- **Homomorphic Tallying**: Vote totals are computed without revealing individual choices
- **Threshold Access**: No single entity can decrypt results alone

#### **Integrity**
- **Digital Signatures**: All voter actions are cryptographically signed
- **Zero-Knowledge Proofs**: Prevents invalid votes (not 0 or 1) without revealing the actual vote
- **Verification Proofs**: Tallying process includes proofs of correctness

#### **Availability**
- **Fault Tolerance**: System continues functioning as long as quorum is maintained
- **Flexible Decryption**: Any `k` out of `n` voters can participate in final decryption

### **Implementation Details**

#### **Cryptographic Primitives**
- **BGVThresholdCrypto**: BGV/BFV threshold encryption implementation using TenSEAL
- **TenSEAL BFV**: Industry-standard fully homomorphic encryption for integer arithmetic
- **Ed25519**: Digital signatures for authentication
- **SHA-256**: Cryptographic hashing for proofs and commitments
- **Mersenne Prime (2^127 - 1)**: Finite field for Shamir's secret sharing

#### **Data Flow**
1. **Setup Phase**: Server generates keys, creates shares, distributes to authenticated voters
2. **Voting Phase**: Voters encrypt votes, create proofs, submit to server
3. **Tallying Phase**: Server performs homomorphic addition, generates verification proofs
4. **Decryption Phase**: Subset of voters collaborate to decrypt final results

#### **Error Handling**
- Comprehensive input validation
- Graceful degradation when insufficient voters participate
- Detailed logging for security audit trails

### **Usage Example**
```python
# Create server with 5 voters, requiring 3 for quorum
server = DecisionServer(number_voters=5, quorum=3)

# Create and authenticate voters
voters = [Voter(server, i) for i in range(5)]

# Distribute BGV context and secret shares
public_context = server.create_and_distribute_key(voters)

# Voters cast encrypted votes using BGV
for i, voter in enumerate(voters):
    voter.castVote(vote_value)  # 0 or 1, encrypted with BGV/BFV

# Homomorphic tallying (BGV addition)
encrypted_total = server.tally_vote()

# Threshold decryption using Shamir reconstruction
plaintext_total = server.decrypt_results(voter_ids[:3], voters[:3])
```

This design provides a robust, privacy-preserving voting system suitable for group decision-making scenarios where vote privacy and result integrity are critical requirements.

### **Repository Structure**

#### **Core Implementation Files**
- **`decision_server.py`**: Main DecisionServer class implementing the voting protocol
- **`voter.py`**: Voter class handling individual participant operations  
- **`bgv_threshold_crypto.py`**: BGV/BFV homomorphic encryption with threshold decryption
- **`simulation.py`**: Complete voting simulation demonstrating the system

#### **Legacy/Alternative Implementations**  
- **`threshold_elgamal.py`**: Previous ElGamal-based implementation (replaced by BGV)
- **`simple_threshold_crypto.py`**: Simplified crypto implementation (replaced by BGV)

#### **Testing and Validation**
- **`tests/`**: Comprehensive test suite for various scenarios
  - `test_threshold_elgamal.py`: Tests for the original ElGamal implementation
  - `test_100_voters.py`: Large-scale voting scenario tests
  - `test_optimized_*.py`: Performance and optimization validation

#### **Utilities**
- **`debug_discrete_log.py`**: Debugging tools for discrete logarithm operations (legacy)

## Architecture Decisions

### **BGV/BFV vs ElGamal**

This implementation uses **BGV (Brakerski-Gentry-Vaikuntanathan)** fully homomorphic encryption via the TenSEAL library instead of ElGamal for several key advantages:

**Benefits of BGV/BFV:**
- **No Discrete Logarithm**: Eliminates the need to solve discrete log problems, providing exact integer results
- **Scalable**: Handles large vote totals without precomputed lookup tables
- **Industry Standard**: Uses well-tested, production-ready cryptographic libraries
- **Complete Privacy**: Vote contents are fully hidden within the ciphertext structure
- **Efficient Arithmetic**: Native support for integer addition with optimal performance

**Previous ElGamal Limitations:**
- Required solving discrete logarithm problems for decryption
- Needed precomputed tables for vote totals (limited scalability)
- Multiplicative homomorphism required careful handling
- Mathematical overflow issues with large Lagrange coefficients in threshold scenarios

### **Implementation Trade-offs**

**Current BGV Approach:**
- ✅ Exact arithmetic with no approximation errors
- ✅ Scales to large vote counts without performance degradation  
- ✅ Leverages battle-tested TenSEAL library
- ✅ Complete elimination of vote content leakage
- ⚠️ Requires additional dependency (TenSEAL/numpy)

**Alternative Considerations:**
- **Paillier**: Would provide similar homomorphic properties but with more complex key management
- **CKKS**: Better for approximate arithmetic but unnecessary for integer vote counting
- **Custom ElGamal**: Lower dependencies but significant mathematical complexity for threshold scenarios

## Other choices

We used Shamir's secret sharing algorithm.  We could have instead used a verifiable secret sharing algorithm like Feldman's or Pedersen's scheme to distribute the keys and then allow a party to validate their share to ensure that its correct.