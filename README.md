## Group Decisioning Protocol Implementation and Simulation

This package contains a group decisioning server built upon cryptographic methods that allows a group to cast secret votes and get results as a group while ensuring Vote Secrecy and Threshold Access.

## Decision Server Design and Implementation

The **DecisionServer** is the central component of a privacy-preserving group decision-making system that implements a secure e-voting protocol with homomorphic encryption and threshold decryption. Here's a detailed breakdown:

### **Core Architecture**

The system implements a **threshold cryptographic voting scheme** with the following key components:

1. **DecisionServer**: Central authority managing the voting process
2. **Voters**: Individual participants with cryptographic identities
3. **Paillier Encryption**: Additive homomorphic encryption
4. **Shamir's Secret Sharing**: Threshold decryption mechanism

### **Key Design Features**

#### **1. Voter Registration & Authentication**
- **Ed25519 Digital Signatures**: Each voter has a unique Ed25519 keypair for authentication
- **Public Key Registration**: Voters register their public keys with the decision server
- **Challenge-Response Authentication**: Server authenticates voters using cryptographic challenges before key distribution

#### **2. Threshold Cryptography Setup**
- **Paillier Keypair Generation**: Server generates a master Paillier keypair
- **Shamir's Secret Sharing**: The private key is split into `n` shares using Shamir's scheme
- **Quorum Requirement**: Only `k` out of `n` voters are needed for decryption (configurable quorum)
- **Key Distribution**: Each authenticated voter receives their secret share and the public key

#### **3. Secure Voting Process**
```python
def castVote(self, encrypted_vote: str, zkp: str, voter_id: int, signature: str) -> bool
```
- **Vote Encryption**: Voters encrypt their binary votes (0 or 1) using Paillier
- **Zero-Knowledge Proofs**: Each vote includes a ZKP proving the encrypted value is either 0 or 1
- **Digital Signatures**: All vote submissions are digitally signed for authenticity
- **Double-Voting Prevention**: Server prevents the same voter from voting multiple times

#### **4. Privacy-Preserving Tallying**
```python
def tally_vote(self) -> str
```
- **Homomorphic Addition**: Uses Paillier's additive homomorphism (Enc(a) × Enc(b) = Enc(a + b))
- **Batch Processing**: Combines all encrypted votes without decrypting individual votes
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
- **Paillier Cryptosystem**: RSA-based homomorphic encryption (1024-bit keys)
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

# Distribute cryptographic keys
secret_key = server.create_and_distribute_key(voters)

# Voters cast encrypted votes
for i, voter in enumerate(voters):
    voter.castVote(vote_value)  # 0 or 1

# Homomorphic tallying
encrypted_total = server.tally_vote()

# Threshold decryption
plaintext_total = server.decrypt_results(voter_ids[:3], voters[:3])
```

This design provides a robust, privacy-preserving voting system suitable for group decision-making scenarios where vote privacy and result integrity are critical requirements.

## Choice of Paillier Encryption

This implementation uses **Paillier encryption** instead of ElGamal for several critical advantages:

### **ElGamal Limitations**
- **Discrete Logarithm Problem**: Decryption requires solving `g^x = result` where `x` is the vote total
- **Computational Bottleneck**: Exponential time complexity - impractical for large elections
- **Scalability Issues**: Works for small votes (<1000) but fails for large elections (>100,000)
- **Performance Degradation**: Decryption time grows exponentially with vote total

### **Paillier Advantages**
- **Direct Integer Decryption**: Returns plaintext vote total directly (no discrete log solving)
- **Linear Performance**: Decryption time is constant regardless of vote total
- **Better Scalability**: Suitable for large-scale elections with millions of voters
- **Production Ready**: Used in real-world e-voting systems

### **Trade-offs**
- **Larger Ciphertexts**: Paillier ciphertexts are larger than ElGamal (acceptable for voting)
- **Different Security Assumption**: Based on Composite Residuosity instead of Discrete Log
- **RSA-style Keys**: Requires prime generation instead of elliptic curve points

The switch to Paillier eliminates the fundamental scalability bottleneck that would make ElGamal impractical for real-world voting applications.