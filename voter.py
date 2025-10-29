from decision_server import DecisionServer


class Voter:
    """
    A voter that participates in decision-making processes through a DecisionServer.
    """
    
    def __init__(self, decision_server, voter_id):
        """
        Initialize the Voter.
        
        Args:
            decision_server (DecisionServer): The DecisionServer this voter belongs to
            voter_id (int): Unique identifier for this voter
        """
        if not isinstance(decision_server, DecisionServer):
            raise TypeError("decision_server must be an instance of DecisionServer")
        
        if not isinstance(voter_id, int) or voter_id < 0:
            raise ValueError("voter_id must be a non-negative integer")
            
        self.decision_server = decision_server
        self.voter_id = voter_id
        self.key_share = None  # Will store the Shamir's secret share
        self.shared_public_key = None  # Will store the public key corresponding to the shared secret

        self.public_key, self.private_key = create_key_pair(self.voter_id)
        DecisionServer.register_voter(self.decision_server, self.voter_id, self.public_key)

    def receive_key_share(self, share):
        """
        Receive and store a Shamir's secret sharing key share.
        
        Args:
            share: A tuple (x, y) representing the voter's share of the secret
        """
        self.key_share = share
        print(f"Voter {self.voter_id} received key share: ({share[0]}, {share[1]})")
    
    def receive_key_share_and_public_key(self, share, public_key):
        """
        Receive and store both a Shamir's secret sharing key share and the corresponding public key.
        
        Args:
            share: A tuple (x, y) representing the voter's share of the secret
            public_key: The public key corresponding to the shared secret
        """
        self.key_share = share
        self.shared_public_key = public_key
        print(f"Voter {self.voter_id} received key share: ({share[0]}, {str(share[1])[:10]}...) and public key: {public_key[:20]}...")
    
    def get_key_share(self):
        """
        Get the stored key share.
        
        Returns:
            The stored key share tuple (x, y), or None if no share received
        """
        return self.key_share
    
    def has_key_share(self):
        """
        Check if this voter has received a key share.
        
        Returns:
            bool: True if voter has a key share, False otherwise
        """
        return self.key_share is not None
    
    def get_shared_public_key(self):
        """
        Get the shared public key corresponding to the secret.
        
        Returns:
            The shared public key, or None if not received
        """
        return self.shared_public_key
    
    def has_shared_public_key(self):
        """
        Check if this voter has received the shared public key.
        
        Returns:
            bool: True if voter has the shared public key, False otherwise
        """
        return self.shared_public_key is not None
    
    def sign_challenge(self, challenge: bytes) -> str:
        """
        Sign an authentication challenge using the voter's private key (stub implementation).
        
        In a real implementation, this would use cryptographic signing with the private key.
        
        Args:
            challenge: The challenge bytes to sign
            
        Returns:
            str: The signature string
        """
        # Stub implementation - simple string concatenation for now
        # In practice, this would use cryptographic signature algorithms
        signature = f"signed_{challenge.hex()}_with_{self.public_key}"
        print(f"Voter {self.voter_id} signed challenge")
        return signature
    
    def castVote(self, vote: int) -> bool:
        """
        Cast a vote by encrypting it and creating a zero-knowledge proof.
        
        Args:
            vote: The vote (0 or 1)
            
        Returns:
            bool: True if vote was successfully cast, False otherwise
            
        Raises:
            ValueError: If vote is not 0 or 1, or if shared public key not available
        """
        # Validate input
        if vote not in [0, 1]:
            raise ValueError("Vote must be 0 or 1")
        
        if not self.has_shared_public_key():
            raise ValueError("Cannot cast vote: shared public key not available")
        
        print(f"Voter {self.voter_id} casting vote: {vote}")
        
        # Step 1: Encrypt the vote using the shared public key
        encrypted_vote = self._encrypt_vote(vote, str(self.shared_public_key))
        print(f"Voter {self.voter_id} encrypted vote: {encrypted_vote[:20]}...")
        
        # Step 2: Create a zero-knowledge proof that the vote is 0 or 1
        zkp = self._create_vote_zkp(vote, encrypted_vote)
        print(f"Voter {self.voter_id} created ZKP: {zkp[:30]}...")
        
        # Step 3: Create message to sign (vote data + voter identity)
        vote_message = f"{encrypted_vote}|{zkp}|{self.voter_id}"
        vote_signature = self._sign_vote_message(vote_message)
        
        # Step 4: Send to DecisionServer
        try:
            result = self.decision_server.castVote(
                encrypted_vote=encrypted_vote,
                zkp=zkp,
                voter_id=self.voter_id,
                signature=vote_signature
            )
            
            if result:
                print(f"Voter {self.voter_id} successfully cast vote")
            else:
                print(f"Voter {self.voter_id} failed to cast vote")
            
            return result
            
        except Exception as e:
            print(f"Voter {self.voter_id} vote casting failed: {e}")
            return False
    
    def _encrypt_vote(self, vote: int, public_key: str) -> str:
        """
        Encrypt a vote using the shared public key (stub implementation).
        
        In a real implementation, this would use proper public key encryption
        like ElGamal, RSA, or ECC-based encryption.
        
        Args:
            vote: The vote to encrypt (0 or 1)
            public_key: The public key to encrypt with
            
        Returns:
            str: The encrypted vote (ciphertext)
        """
        import hashlib
        import secrets
        
        # Stub implementation using simple obfuscation
        # In practice, this would use proper encryption like ElGamal
        nonce = secrets.token_hex(16)
        hash_input = f"{vote}|{public_key}|{nonce}".encode()
        ciphertext = hashlib.sha256(hash_input).hexdigest()
        
        # Include nonce in ciphertext for "decryption"
        encrypted_vote = f"{ciphertext}:{nonce}:{vote}"  # In real implementation, vote wouldn't be here
        
        return encrypted_vote
    
    def _create_vote_zkp(self, vote: int, encrypted_vote: str) -> str:
        """
        Create a Non-Interactive Zero-Knowledge Proof that the vote is 0 or 1 (stub implementation).
        
        In a real implementation, this would create a proper NIZK proof demonstrating:
        1. The prover knows the plaintext of the encrypted vote
        2. The plaintext is either 0 or 1
        
        This could use techniques like:
        - Schnorr proofs for discrete log knowledge
        - Sigma protocols for OR statements
        - Fiat-Shamir heuristic for non-interactivity
        
        Args:
            vote: The actual vote value
            encrypted_vote: The encrypted vote
            
        Returns:
            str: The zero-knowledge proof
        """
        import hashlib
        import secrets
        
        # Stub implementation - create a "proof" that includes necessary components
        # In practice, this would be a proper cryptographic proof
        
        # Generate challenge (in real NIZK, this would be from Fiat-Shamir)
        challenge_input = f"{encrypted_vote}|{self.voter_id}|zkp_challenge".encode()
        challenge = hashlib.sha256(challenge_input).hexdigest()[:16]
        
        # Generate response (in real ZKP, this would be computed properly)
        response = secrets.token_hex(32)
        
        # Create proof structure
        zkp = f"zkp_proof|challenge:{challenge}|response:{response}|vote_range:0-1"
        
        return zkp
    
    def _sign_vote_message(self, message: str) -> str:
        """
        Sign a vote message using the voter's private key.
        
        Args:
            message: The message to sign
            
        Returns:
            str: The signature
        """
        # Use the same signing mechanism as challenge signing
        message_bytes = message.encode()
        signature = f"signed_{message_bytes.hex()}_with_{self.public_key}"
        return signature

    def __repr__(self):
        return f"Voter(voter_id={self.voter_id}, decision_server={self.decision_server})"
    

def create_key_pair(voter_id):
    """
    Create a public/private key pair for the voter.
    
    Args:
        voter_id (int): Unique identifier for the voter

    Returns:
        tuple: A tuple containing the public key and private key
    """
    # In a real implementation, you would use a cryptographic library to generate keys
    public_key = f"public_key_{voter_id}"
    private_key = f"private_key_{voter_id}"
    return public_key, private_key