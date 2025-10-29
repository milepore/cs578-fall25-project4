import secrets
import random
from typing import List, Tuple


class DecisionServer:
    """
    A server that manages decision-making processes with voter quorum requirements.
    """
    
    def __init__(self, number_voters, quorum):
        """
        Initialize the DecisionServer.
        
        Args:
            number_voters (int): The total number of voters in the system
            quorum (int): The minimum number of voters required to make a decision
        """
        self.number_voters = number_voters
        self.quorum = quorum
        self.registered_voters = {}  # Dictionary to store voter_id -> public_key mappings
        
        # Validate inputs
        if not isinstance(number_voters, int) or number_voters <= 0:
            raise ValueError("number_voters must be a positive integer")
        
        if not isinstance(quorum, int) or quorum <= 0:
            raise ValueError("quorum must be a positive integer")
            
        if quorum > number_voters:
            raise ValueError("quorum cannot be greater than number_voters")
    
    def register_voter(self, voter_identity, public_key):
        """
        Register a voter with their identity and public key for validation.
        
        Args:
            voter_identity: Unique identifier for the voter
            public_key: Public key used to validate future calls from this voter
            
        Returns:
            bool: True if registration was successful, False if voter already registered
            
        Raises:
            ValueError: If trying to register more voters than allowed
        """
        if len(self.registered_voters) >= self.number_voters:
            raise ValueError(f"Cannot register more than {self.number_voters} voters")
        
        if voter_identity in self.registered_voters:
            return False  # Voter already registered
        
        self.registered_voters[voter_identity] = public_key
        return True
    
    def is_voter_registered(self, voter_identity):
        """
        Check if a voter is registered.
        
        Args:
            voter_identity: The voter identity to check
            
        Returns:
            bool: True if voter is registered, False otherwise
        """
        return voter_identity in self.registered_voters
    
    def get_voter_public_key(self, voter_identity):
        """
        Get the public key for a registered voter.
        
        Args:
            voter_identity: The voter identity
            
        Returns:
            The public key for the voter, or None if not registered
        """
        return self.registered_voters.get(voter_identity)

    def create_and_distribute_key(self, voters: List) -> bytes:
        """
        Create a secret key using Shamir's secret sharing scheme and distribute 
        shares to all registered voters after authentication challenge.
        
        Args:
            voters: List of Voter objects to distribute key shares to
            
        Returns:
            bytes: The original secret key
            
        Raises:
            ValueError: If not enough voters are registered or provided
            Exception: If authentication challenge fails for any voter
        """
        if len(voters) != self.number_voters:
            raise ValueError(f"Expected {self.number_voters} voters, got {len(voters)}")
        
        if len(self.registered_voters) < self.number_voters:
            raise ValueError("Not all voters are registered")
        
        # Step 1: Authenticate all voters using public key signature challenge
        print("Starting authentication challenge for all voters...")
        for voter in voters:
            if not self._authenticate_voter(voter):
                raise Exception(f"Authentication failed for voter {voter.voter_id}")
        print("All voters authenticated successfully!")
        
        # Step 2: Generate a random secret key (32 bytes for AES-256)
        secret_key = secrets.token_bytes(32)
        
        # Step 3: Generate corresponding public key for the secret
        public_key = self._generate_public_key_from_secret(secret_key)
        print(f"Generated public key: {public_key[:20]}...")
        
        # Step 4: Convert secret to integer for Shamir's scheme
        secret_int = int.from_bytes(secret_key, byteorder='big')
        
        # Step 5: Create shares using Shamir's secret sharing
        shares = self._create_shamir_shares(secret_int, self.number_voters, self.quorum)
        
        # Step 6: Distribute shares and public key to authenticated voters
        for i, voter in enumerate(voters):
            voter.receive_key_share_and_public_key(shares[i], public_key)
        
        return secret_key
    
    def _create_shamir_shares(self, secret: int, n: int, k: int) -> List[Tuple[int, int]]:
        """
        Create Shamir's secret shares.
        
        Args:
            secret: The secret to be shared (as integer)
            n: Total number of shares to create
            k: Minimum number of shares needed to reconstruct secret (quorum)
            
        Returns:
            List of (x, y) tuples representing the shares
        """
        # Use a large prime for the finite field
        prime = 2**127 - 1  # Mersenne prime
        
        # Generate random coefficients for polynomial of degree k-1
        coefficients = [secret] + [random.randrange(1, prime) for _ in range(k - 1)]
        
        # Create shares by evaluating polynomial at different x values
        shares = []
        for x in range(1, n + 1):
            y = self._evaluate_polynomial(coefficients, x, prime)
            shares.append((x, y))
        
        return shares
    
    def _evaluate_polynomial(self, coefficients: List[int], x: int, prime: int) -> int:
        """
        Evaluate polynomial at given x using Horner's method in finite field.
        
        Args:
            coefficients: Polynomial coefficients [a0, a1, a2, ...]
            x: Point to evaluate at
            prime: Prime for finite field arithmetic
            
        Returns:
            Value of polynomial at x mod prime
        """
        result = 0
        for coeff in reversed(coefficients):
            result = (result * x + coeff) % prime
        return result
    
    def _authenticate_voter(self, voter) -> bool:
        """
        Authenticate a voter using public key signature challenge (stub implementation).
        
        In a real implementation, this would:
        1. Generate a random challenge message
        2. Send challenge to voter
        3. Voter signs challenge with their private key
        4. Server verifies signature using voter's registered public key
        
        Args:
            voter: The Voter object to authenticate
            
        Returns:
            bool: True if authentication succeeds, False otherwise
        """
        # Stub implementation - always returns True for now
        # In practice, this would involve cryptographic signature verification
        
        # Check if voter is registered
        if not self.is_voter_registered(voter.voter_id):
            print(f"Authentication failed: Voter {voter.voter_id} not registered")
            return False
        
        # Generate challenge (stub)
        challenge = secrets.token_bytes(32)
        print(f"Sending authentication challenge to voter {voter.voter_id}")
        
        # Get voter's signature response (stub)
        signature = voter.sign_challenge(challenge)
        
        # Verify signature using registered public key (stub)
        registered_public_key = self.get_voter_public_key(voter.voter_id)
        if registered_public_key is None:
            print(f"Authentication failed: No public key found for voter {voter.voter_id}")
            return False
        
        is_valid = self._verify_signature(challenge, signature, registered_public_key)
        
        if is_valid:
            print(f"Voter {voter.voter_id} authentication successful")
        else:
            print(f"Voter {voter.voter_id} authentication failed - invalid signature")
        
        return is_valid
    
    def _verify_signature(self, message: bytes, signature: str, public_key: str) -> bool:
        """
        Verify a digital signature (stub implementation).
        
        Args:
            message: The original message that was signed
            signature: The signature to verify
            public_key: The public key to use for verification
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Stub implementation - simple string matching for now
        # In practice, this would use cryptographic signature verification
        expected_signature = f"signed_{message.hex()}_with_{public_key}"
        return signature == expected_signature
    
    def _generate_public_key_from_secret(self, secret_key: bytes) -> str:
        """
        Generate a corresponding public key from the secret key (stub implementation).
        
        In a real implementation, this would use proper cryptographic key derivation:
        - For ECC: derive public key point from private key scalar
        - For RSA: compute public key from private key components
        - For symmetric schemes: derive a verification key or use key commitment
        
        Args:
            secret_key: The secret key bytes
            
        Returns:
            str: The corresponding public key
        """
        # Stub implementation - derive public key from secret using hash
        # In practice, this would use proper cryptographic key derivation
        import hashlib
        
        # Create a deterministic public key from the secret
        hash_input = b"public_key_derivation:" + secret_key
        public_key_hash = hashlib.sha256(hash_input).hexdigest()
        public_key = f"pk_{public_key_hash[:32]}"
        
        return public_key
    
    def castVote(self, encrypted_vote: str, zkp: str, voter_id: int, signature: str) -> bool:
        """
        Accept and validate a vote from a registered voter.
        
        Args:
            encrypted_vote: The encrypted vote ciphertext
            zkp: Zero-knowledge proof that vote is 0 or 1
            voter_id: ID of the voting voter
            signature: Digital signature of the vote message
            
        Returns:
            bool: True if vote was accepted, False otherwise
        """
        print(f"DecisionServer: Receiving vote from voter {voter_id}")
        
        # Step 1: Verify voter is registered
        if not self.is_voter_registered(voter_id):
            print(f"DecisionServer: Vote rejected - voter {voter_id} not registered")
            return False
        
        # Step 2: Verify signature
        vote_message = f"{encrypted_vote}|{zkp}|{voter_id}"
        if not self._verify_vote_signature(vote_message, signature, voter_id):
            print(f"DecisionServer: Vote rejected - invalid signature from voter {voter_id}")
            return False
        
        # Step 3: Verify zero-knowledge proof
        if not self._verify_vote_zkp(encrypted_vote, zkp, voter_id):
            print(f"DecisionServer: Vote rejected - invalid ZKP from voter {voter_id}")
            return False
        
        # Step 4: Store the vote (in practice, would check for double voting)
        if not hasattr(self, 'votes'):
            self.votes = {}
        
        if voter_id in self.votes:
            print(f"DecisionServer: Vote rejected - voter {voter_id} already voted")
            return False
        
        self.votes[voter_id] = {
            'encrypted_vote': encrypted_vote,
            'zkp': zkp,
            'signature': signature
        }
        
        print(f"DecisionServer: Vote accepted from voter {voter_id}")
        print(f"DecisionServer: Total votes received: {len(self.votes)}")
        
        return True
    
    def _verify_vote_signature(self, message: str, signature: str, voter_id: int) -> bool:
        """
        Verify the digital signature on a vote message.
        
        Args:
            message: The vote message that was signed
            signature: The signature to verify
            voter_id: The voter's ID
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Get the voter's registered public key
        public_key = self.get_voter_public_key(voter_id)
        if public_key is None:
            return False
        
        # Verify using the same method as challenge verification
        message_bytes = message.encode()
        expected_signature = f"signed_{message_bytes.hex()}_with_{public_key}"
        
        return signature == expected_signature
    
    def _verify_vote_zkp(self, encrypted_vote: str, zkp: str, voter_id: int) -> bool:
        """
        Verify the zero-knowledge proof for a vote (stub implementation).
        
        In a real implementation, this would:
        1. Parse the ZKP components (challenge, response, commitments)
        2. Verify the proof using the public parameters
        3. Ensure the proof demonstrates knowledge of plaintext ∈ {0,1}
        
        Args:
            encrypted_vote: The encrypted vote
            zkp: The zero-knowledge proof
            voter_id: The voter's ID
            
        Returns:
            bool: True if ZKP is valid, False otherwise
        """
        # Stub implementation - basic format validation
        # In practice, this would be proper cryptographic verification
        
        if not zkp.startswith("zkp_proof|"):
            print(f"DecisionServer: Invalid ZKP format from voter {voter_id}")
            return False
        
        # Check if ZKP contains required components
        required_components = ["challenge:", "response:", "vote_range:0-1"]
        for component in required_components:
            if component not in zkp:
                print(f"DecisionServer: Missing ZKP component '{component}' from voter {voter_id}")
                return False
        
        print(f"DecisionServer: ZKP verification passed for voter {voter_id}")
        return True
    
    def get_vote_count(self) -> int:
        """
        Get the current number of votes cast.
        
        Returns:
            int: Number of votes received
        """
        if not hasattr(self, 'votes'):
            return 0
        return len(self.votes)
    
    def has_quorum(self) -> bool:
        """
        Check if enough votes have been received to meet quorum requirements.
        
        Returns:
            bool: True if quorum is met, False otherwise
        """
        return self.get_vote_count() >= self.quorum

    def __repr__(self):
        return f"DecisionServer(number_voters={self.number_voters}, quorum={self.quorum})"