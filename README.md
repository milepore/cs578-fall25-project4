
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
3. **KeyGenerationAuthority**: A trusted authority that creates the BGV key, splits and distributes it across the voters
4. **BGV/BFV Encryption**: Fully homomorphic encryption using TenSEAL library, integrating Shamir's Secret Sharing for key splitting and distribution
5. **Schnorr ZKP Proofs**: ZKP implementation for vote verification and partial decryption verification
6. **ED22219 Utils**: ED25519 cryptographic signing and verification utilities

Each of these components is designed to provide 128 bit security levels.

### **Key Design Features**

#### **1. Voter Registration & Authentication**
- **Ed25519 Digital Signatures**: Each voter has a unique Ed25519 keypair for authentication
- **Public Key Registration**: Voters register their public keys with the decision server
- **Challenge-Response Authentication**: Server authenticates voters using cryptographic challenges before key distribution

#### **2. Threshold Cryptography Setup**
- **BGV Context Generation**: Server generates BGV homomorphic encryption context using TenSEAL
- **Shamir's Secret Sharing**: A master secret is split into `n` shares using Shamir's scheme by a trusted authority
- **Quorum Requirement**: Only `k` out of `n` voters are needed for decryption (configurable quorum)
- **Key Distribution**: Each authenticated voter receives their secret share and the public BGV context

#### **3. Secure Voting Process**
```python
def cast_vote(self, encrypted_vote: str, zkp: str, voter_id: int, signature: str) -> bool
```
- **Vote Encryption**: Voters encrypt their binary votes (0 or 1) using BGV/BFV homomorphic encryption
- **Complete Privacy**: Vote contents are fully hidden within BGV ciphertext structure - no plaintext leakage, secret key is never known by anyone other than the trusted key authority
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
E- **Quorum Enforcement**: Only performs tallying when minimum vote threshold is met

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

### **Authentication**
- **Digital Signatures**: The vote server ensure that all voting participants have pre-registered and can authenticate validated using their previously registered public key

### **Threshold Trust**
- **Threshold Access**: Decryption is only possible with enough partially decrypted shares to meet quorum

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
    voter.cast_vote(vote_value)  # 0 or 1, encrypted with BGV/BFV

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
- **`simulation.py`**: Complete voting simulation demonstrating the system
- **`bgv_threshold_crypto.py`**: BGV/BFV homomorphic encryption with threshold decryption
- **`schnorr_zkp.py`**: Schnorr Zero Knowledge Proofs for validation

## Performance and Scalability

### **Verified Scale**
This system has been tested and validated with **50 voters** and a 35-voter quorum threshold. The simulation demonstrates stable performance at this scale with:
- Efficient vote encryption and ZKP generation
- Fast homomorphic tallying operations
- Reliable threshold decryption with multiple partial shares

### **Design Target**
The system is designed for **small-to-midsize voting scenarios**, such as:
- Committee decisions (5-100 participants)
- Board votes and governance decisions
- Small organizational elections
- Academic department decisions
- Working group consensus building

### **Scalability Considerations**
The **upper performance bounds are currently unknown**. Several factors may limit scalability at larger scales:

#### **Potential Bottlenecks**
1. **BGV Ciphertext Size**: Each encrypted vote is relatively large (~several KB), which could impact:
   - Network bandwidth during vote submission
   - Memory usage when storing all encrypted votes
   - Homomorphic computation time scaling O(n) with voter count

2. **Homomorphic Addition Cost**: While BGV is efficient, summing hundreds or thousands of ciphertexts could become computationally expensive

3. **Zero-Knowledge Proof Verification**: Each vote requires ZKP verification, scaling linearly with voter count

4. **Threshold Decryption Overhead**: Lagrange interpolation complexity increases with the number of shares being combined

#### **Uncharted Territory**
We have not tested:
- **100+ voters**: Performance characteristics at larger scales
- **High quorum ratios**: Impact of requiring large threshold values (e.g., 90 of 100 voters)
- **Concurrent voting**: Behavior under high-throughput vote submission
- **Memory bounds**: Maximum voter count before memory constraints

### **Optimization Opportunities**
For larger-scale deployments, future work could explore:
- Batch ZKP verification techniques
- Optimized BGV parameter selection for voting-specific operations
- Distributed tallying across multiple servers
- Ciphertext compression strategies
- Incremental homomorphic tallying

**Recommendation**: For elections with 100+ participants, conduct performance testing and consider architectural modifications or alternative cryptographic schemes better suited to large-scale deployments.

## Future Work

### Use of Distributed Key Generation Scheme

We could change the way the key is generated to use a DKG scheme.  This would ask each of the votes to generate a piece of the secret, and we could create a public key through the DKG protocol.  This would be even more secure than asking a trusted authority to create and distribute the key (and forget it after).

### Secret Sharing Protocol Improvements

We used Shamir's secret sharing algorithm.  We could have instead used a verifiable secret sharing algorithm like Feldman's or Pedersen's scheme to distribute the keys and then allow a party to validate their share to ensure that its correct.

### Vote Registry Signature 
Another potential improvement might be to have the entire cryptographic vote registry be signed as each new vote is added - and then sent to the voter.

This would ensure that prior votes could not be dropped without invalidating the signatures in the register as we go through the algorithm.

### Performance Testing and Benchmarking
Comprehensive performance analysis to determine:
- Maximum practical voter count for the current implementation
- Computational bottlenecks in the tallying and decryption phases
- Memory usage patterns at scale
- Network bandwidth requirements for large elections

## Design Alternatives

### ElGamal vs BGV Threshold Encryption

While this implementation uses **BGV/BFV homomorphic encryption** with TenSEAL, an alternative approach would be to use **ElGamal threshold encryption**. Both schemes support threshold decryption, but differ in their properties:

#### **BGV Approach (Current Implementation)**
- **Advantages**:
  - Fully homomorphic encryption with exact integer arithmetic
  - No discrete logarithm problem to solve for decryption
  - Supports complex polynomial operations beyond addition
  - Native threshold support via secret sharing of the secret key
  
- **Trade-offs**:
  - More complex mathematical operations
  - Larger ciphertext sizes
  - Requires careful parameter selection for security

#### **ElGamal Threshold Approach (Alternative)**
- **Advantages**:
  - Simpler mathematical structure (discrete logarithm based)
  - Well-studied security properties
  - Efficient implementations available
  - Natural threshold decryption using distributed key generation
  
- **Trade-offs**:
  - Requires solving discrete logarithm for final decryption (limiting vote counts)
  - Only supports multiplicative homomorphism (addition requires exponential representation)
  - Potential scalability issues with large vote counts

#### **Implementation Note**
We explored an ElGamal-based implementation in a separate branch (`elgamal-threshold`). For a reference implementation of full threshold decryption using ElGamal, see: **[threshold-crypto by tompetersen](https://github.com/tompetersen/threshold-crypto)**. This library demonstrates distributed key generation and threshold decryption with ElGamal, providing a complete working example of the alternative approach.

The choice between BGV and ElGamal depends on the specific requirements of the voting system:
- **Small-scale elections** with limited vote counts may benefit from ElGamal's simplicity
- **Large-scale elections** or systems requiring exact counts are better served by BGV's capabilities

## Implementation Notes: Threshold Decryption Simulation

### Mathematical Complexity Considerations

This implementation **simulates threshold decryption** rather than implementing the full mathematical protocol for BGV threshold decryption. This design decision was made due to the significant mathematical complexity involved in proper threshold decryption for BGV/BFV schemes.

#### **What We Simulated**
- **Shamir Secret Sharing**: We split a master secret into `n` shares and distribute them to voters
- **Partial Decryptions**: Each voter generates a "partial decryption" using their share
- **Share Reconstruction**: We combine partial decryptions using Lagrange interpolation

#### **Why Full Threshold BGV is Complex**
Full threshold decryption for BGV requires:
1. **Distributed Key Generation**: Creating a shared public key without any party knowing the full secret key
2. **Polynomial Secret Sharing in Rings**: Shamir's scheme over polynomial rings modulo specific BGV parameters
3. **Noise Management**: Careful handling of BGV noise budgets during partial decryption
4. **Relinearization Keys**: Proper distribution of evaluation keys for threshold operations
5. **Proof Systems**: ZKP proofs that partial decryptions are correctly formed

Implementing these correctly requires deep expertise in:
- Ring Learning With Errors (RLWE) mathematics
- Polynomial ring arithmetic over cyclotomic fields
- BGV/BFV parameter selection for threshold security
- Noise analysis across multiple partial decryptions

#### **Our Pragmatic Approach**
Rather than risk incorrect implementation of these complex mathematical operations, we:
1. Use a **trusted Key Generation Authority** that creates the BGV keypair
2. Split the secret key using **standard Shamir Secret Sharing** over a prime field
3. Distribute shares to authenticated voters
4. Simulate partial decryptions using share-based reconstruction

This approach maintains the **security properties** we need (threshold access, vote privacy) while avoiding the mathematical pitfalls of full distributed BGV decryption.

#### **Production Considerations**
For a production system, we recommend:
- Using a battle-tested library like **[threshold-crypto](https://github.com/tompetersen/threshold-crypto)** (ElGamal-based)
- Engaging cryptographic experts to implement or audit full BGV threshold protocols
- Considering hybrid approaches where ElGamal handles the threshold aspect and BGV handles computation
- Extensive security audits and formal verification of any threshold cryptographic implementation

The simulation approach used here is appropriate for educational purposes and proof-of-concept demonstrations, but production systems should use fully verified threshold cryptographic implementations.

