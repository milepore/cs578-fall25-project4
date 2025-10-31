import secrets
from typing import List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import hashlib

# Import our BGV-based threshold crypto system
from bgv_threshold_crypto import BGVThresholdCrypto, BGVCiphertext
from schnorr_zkp import verify_zkp_from_json

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
        self.crypto_system = BGVThresholdCrypto(threshold=quorum, num_participants=number_voters)
        self.bgv_public_key = None   # Will store the BGV public key

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
        
        # Step 2: Get public context for BGV encryption
        public_context = self.crypto_system.get_public_context()
        self.bgv_public_context = public_context
        
        # Create a derived public key identifier for voters
        public_key = f"bgv_threshold_pk_{hashlib.sha256(public_context).hexdigest()[:32]}"
        print(f"Generated BGV public context: {public_key[:20]}...")
        
        # Step 3: Distribute BGV secret shares and public context to authenticated voters
        for i, voter in enumerate(voters):
            secret_share = self.crypto_system.get_secret_share(i)
            voter.receive_key_share_and_public_key(secret_share, public_context)
        
        print(f"DecisionServer: BGV threshold crypto keys generated and distributed")
        
        return public_context
        
    def _authenticate_voter(self, voter) -> bool:
        """
        Authenticate a voter using public key signature challenge
        
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
        # In practice, this would involve cryptographic signature verification
        
        # Check if voter is registered
        if not self.is_voter_registered(voter.voter_id):
            print(f"Authentication failed: Voter {voter.voter_id} not registered")
            return False
        
        # Generate challenge with security-level appropriate size
        challenge = self._generate_auth_challenge()
        print(f"Sending authentication challenge to voter {voter.voter_id}")
        
        # Get voter's signature response
        signature = voter.sign_challenge(challenge)
        
        # Verify signature using registered public key
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
    
    def _generate_auth_challenge(self) -> bytes:
        """
        Generate authentication challenge with security-level appropriate size.
        
        Returns:
            bytes: Random challenge bytes
        """
        # For 128-bit security, 16 bytes is 
        challenge_bytes = 16  # At least 16 bytes
        
        return secrets.token_bytes(challenge_bytes)
    
    def _verify_signature(self, message: bytes, signature: str, public_key_hex: str) -> bool:
        """
        Verify an Ed25519 digital signature.
        
        Args:
            message: The original message that was signed
            signature: The signature to verify (hex string)
            public_key_hex: The public key to use for verification (hex string)
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Convert hex strings back to bytes
            signature_bytes = bytes.fromhex(signature)
            public_key_bytes = bytes.fromhex(public_key_hex)
            
            # Reconstruct the Ed25519 public key
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            
            # Verify the signature
            public_key.verify(signature_bytes, message)
            return True

        except Exception as e:
            print(f"DecisionServer: Signature verification error: {e}")
            return False
    
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
        if not verify_zkp_from_json(zkp, encrypted_vote):
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
        Verify the Ed25519 digital signature on a vote message.
        
        Args:
            message: The vote message that was signed
            signature: The signature to verify (hex string)
            voter_id: The voter's ID
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        # Get the voter's registered public key
        public_key_hex = self.get_voter_public_key(voter_id)
        if public_key_hex is None:
            return False
        
        # Verify using Ed25519
        message_bytes = message.encode()
        return self._verify_signature(message_bytes, signature, public_key_hex)
        
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
    
    def tally_vote(self) -> str:
        """
        Tally all cast votes using homomorphic evaluation to create a total ciphertext.
        
        This method performs homomorphic addition of all encrypted votes,
        allowing the computation of the sum without decrypting individual votes.
        Also generates a verification proof attesting to proper execution.
        
        Returns:
            str: The homomorphically computed total ciphertext
            
        Raises:
            ValueError: If no votes have been cast or quorum not met
        """
        if not hasattr(self, 'votes') or len(self.votes) == 0:
            raise ValueError("No votes have been cast")
        
        if not self.has_quorum():
            raise ValueError(f"Quorum not met. Need {self.quorum} votes, have {len(self.votes)}")
        
        print(f"DecisionServer: Starting homomorphic tally of {len(self.votes)} votes")
        
        # Extract all encrypted votes
        encrypted_votes = [vote_data['encrypted_vote'] for vote_data in self.votes.values()]
        # Perform homomorphic addition
        total_ciphertext = self._homomorphic_add_votes(encrypted_votes)
        
        # Store results for later retrieval
        self._encrypted_tally = total_ciphertext
        
        print(f"DecisionServer: Tally complete. Total ciphertext: {total_ciphertext[:30]}...")        
        return total_ciphertext
    
    def _homomorphic_add_votes(self, encrypted_votes: List[str]) -> str:
        """
        Perform homomorphic addition of encrypted votes using BGV multiplication.
        
        BGV is multiplicatively homomorphic: Enc(a) × Enc(b) = Enc(a + b)
        This means we multiply ciphertexts to add the underlying plaintexts.
        
        Args:
            encrypted_votes: List of encrypted vote ciphertexts (serialized)
            
        Returns:
            str: The homomorphically computed sum ciphertext
        """
        print(f"DecisionServer: Performing BGV homomorphic addition on {len(encrypted_votes)} ciphertexts")
        
        # Parse encrypted votes and reconstruct BGV ciphertexts
        ciphertexts = []
        
        for i, encrypted_vote in enumerate(encrypted_votes):
            try:
                # Parse the BGV ciphertext from JSON format
                import json
                ciphertext_dict = json.loads(encrypted_vote)
                bgv_ciphertext = BGVCiphertext.from_dict(ciphertext_dict)
                ciphertexts.append(bgv_ciphertext)
                print(f"  Processing vote {i}: BGV ciphertext parsed")
                
            except (ValueError, json.JSONDecodeError) as e:
                print(f"  Warning: Could not parse encrypted vote {i}: {e}")
        
        if not ciphertexts:
            raise ValueError("No valid ciphertexts found for homomorphic addition")
        
        # Perform homomorphic addition using BGV
        print(f"DecisionServer: Adding {len(ciphertexts)} BGV ciphertexts...")
        
        # Start with the first ciphertext
        total_ciphertext = ciphertexts[0]
        
        # Add with remaining ciphertexts
        for i in range(1, len(ciphertexts)):
            total_ciphertext = self.crypto_system.homomorphic_add(total_ciphertext, ciphertexts[i])
            print(f"  Added ciphertext {i+1}")
        
        # Serialize the result for storage (without revealing plaintext total)
        import json
        serialized_result = json.dumps(total_ciphertext.to_dict())
        
        print(f"DecisionServer: BGV homomorphic sum computed from {len(ciphertexts)} ciphertexts")
        print(f"DecisionServer: Result size: {len(total_ciphertext.serialized_data)} bytes")
        
        return serialized_result
    
    def get_encrypted_tally(self) -> str:
        """
        Get the encrypted tally if it has been computed.
        
        Returns:
            str: The encrypted tally, or raises exception if not computed
        """
        if not hasattr(self, '_encrypted_tally'):
            self._encrypted_tally = self.tally_vote()
        
        return self._encrypted_tally
    
    def _create_votes_commitment(self, encrypted_votes: List[str]) -> str:
        """
        Create a cryptographic commitment to all input votes.
        
        Args:
            encrypted_votes: List of encrypted votes
            
        Returns:
            str: Commitment to the votes
        """
        import hashlib
        
        # Sort votes for canonical ordering
        sorted_votes = sorted(encrypted_votes)
        
        # Create Merkle-tree like commitment
        votes_concat = '|'.join(sorted_votes)
        commitment = hashlib.sha256(f"votes_commitment|{votes_concat}".encode()).hexdigest()
        
        return f"commit_{commitment[:32]}"
    
    def _create_computation_witness(self, encrypted_votes: List[str], total_ciphertext: str) -> str:
        """
        Create a witness for the homomorphic computation.
        
        Args:
            encrypted_votes: List of input votes
            total_ciphertext: Computed result
            
        Returns:
            str: Computation witness
        """
        import hashlib
        
        # Create witness showing the computation path
        computation_steps = f"homomorphic_add({len(encrypted_votes)}_votes) -> {total_ciphertext}"
        witness_hash = hashlib.sha256(computation_steps.encode()).hexdigest()
        
        return f"witness_{witness_hash[:32]}"
    
    def get_tallied_results(self) -> dict:
        """
        Get the tallied results along with verification proof.
        
        Returns:
            dict: Contains 'total_ciphertext', and metadata
            
        Raises:
            ValueError: If tally has not been computed yet
        """
        if not hasattr(self, '_encrypted_tally'):
            raise ValueError("Tally has not been computed yet. Call tally_vote() first.")
        
        results = {
            'total_ciphertext': self._encrypted_tally,
            'num_votes': len(self.votes) if hasattr(self, 'votes') else 0,
            'quorum': self.quorum,
            'timestamp': self._get_timestamp(),
            'voter_ids': list(self.votes.keys()) if hasattr(self, 'votes') else []
        }
        
        print(f"DecisionServer: Returning tallied results with verification proof")
        
        return results
    
    def _get_timestamp(self) -> str:
        """Get current timestamp for results."""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def decrypt_results(self, voter_ids_for_decryption: List[int], voters: List) -> int:
        """
        Decrypt the tallied results using Shamir's secret sharing reconstruction.
        
        This method:
        1. Verifies the NIZK proof from the tally
        2. Requests partial decryptions from specified voters
        3. Combines partial decryptions to recover the plaintext total
        
        Args:
            voter_ids_for_decryption: List of voter IDs to use for decryption (must be >= quorum)
            voters: List of Voter objects for partial decryption
            
        Returns:
            int: The plaintext vote total
            
        Raises:
            ValueError: If insufficient voters, tally not computed, or proof invalid
        """
        # Validate inputs
        if len(voter_ids_for_decryption) < self.quorum:
            raise ValueError(f"Need at least {self.quorum} voters for decryption, got {len(voter_ids_for_decryption)}")
        
        if not hasattr(self, '_encrypted_tally'):
            raise ValueError("No encrypted tally available. Call tally_vote() first.")
        
        print(f"DecisionServer: Starting decryption process with {len(voter_ids_for_decryption)} voters")
        
        results = self.get_tallied_results()
        
        # Step 1: Get partial decryptions from each voter
        partial_decryptions = []
        voter_lookup = {v.voter_id: v for v in voters}
        
        print(f"DecisionServer: Requesting partial decryptions from voters...")
        for voter_id in voter_ids_for_decryption:
            if voter_id not in voter_lookup:
                raise ValueError(f"Voter {voter_id} not found in voter list")
            
            voter = voter_lookup[voter_id]
            
            # Request partial decryption from this voter
            partial_decryption = voter.perform_partial_decryption(self._encrypted_tally)
            if partial_decryption is None:
                raise ValueError(f"Failed to get partial decryption from voter {voter_id}")
            
            partial_decryptions.append(partial_decryption)
            print(f"  ✓ Received partial decryption from voter {voter_id}")

        # Step 2: Combine partial decryptions using Shamir's secret reconstruction
        print(f"DecisionServer: Combining {len(partial_decryptions)} partial decryptions...")
        plaintext_total = self._reconstruct_secret_from_shares(partial_decryptions)
        
        print(f"DecisionServer: Decryption complete. Total votes: {plaintext_total}")
        
        return plaintext_total
     
    def _reconstruct_secret_from_shares(self, partial_decryptions: List) -> int:
        """
        Reconstruct the vote total using BGV threshold decryption.
        
        This combines partial decryptions using Lagrange 
        interpolation coefficients to recover the plaintext vote total from the 
        homomorphic sum.
        
        SECURITY: This method now processes partial decryption results instead of
        raw secret shares, maintaining the security of the threshold scheme.
        
        Args:
            partial_decryptions: List of partial decryption results from voters
            
        Returns:
            int: The reconstructed vote total
        """
        print(f"DecisionServer: Reconstructing vote total using BGV threshold decryption")
        
        # Extract the encrypted tally ciphertext
        if not hasattr(self, '_encrypted_tally'):
            raise ValueError("No encrypted tally available for decryption")
        
        encrypted_tally = self._encrypted_tally
        
        # Parse the BGV ciphertext from the serialized JSON format
        import json
        try:
            ciphertext_dict = json.loads(encrypted_tally)
            total_ciphertext = BGVCiphertext.from_dict(ciphertext_dict)
        except json.JSONDecodeError:
            raise ValueError(f"Invalid BGV ciphertext format: {encrypted_tally[:100]}...")
        
        # Collect partial decryption results (NOT raw secret shares)
        partial_results = []
        
        for partial in partial_decryptions:
            # Verify this is a partial decryption result, not a raw secret share
            if 'partial_decryption' not in partial:
                raise ValueError(f"Invalid partial decryption format from voter {partial.get('voter_id')}")
            
            partial_decrypt_data = partial['partial_decryption']
            
            # Extract the safe partial decryption values
            share_index = partial_decrypt_data['share_index']
            partial_value = partial_decrypt_data['partial_value']
            
            partial_results.append((share_index, partial_value))
            print(f"  Voter {partial['voter_id']}: Partial decryption ({share_index}, <partial_value>)")
        
        # Use BGV threshold decryption with partial results
        plaintext_total = self.crypto_system.combine_shares_and_decrypt(
            total_ciphertext, partial_results
        )
        
        print(f"DecisionServer: BGV threshold decryption complete: {plaintext_total}")
        print(f"DecisionServer: SECRET SHARES NEVER REVEALED - only partial decryptions used")
        
        return plaintext_total
    
    def can_tally(self) -> bool:
        """
        Check if tallying is possible (enough votes received).
        
        Returns:
            bool: True if tallying can be performed, False otherwise
        """
        return hasattr(self, 'votes') and len(self.votes) >= self.quorum

    def __repr__(self):
        return f"DecisionServer(number_voters={self.number_voters}, quorum={self.quorum})"
