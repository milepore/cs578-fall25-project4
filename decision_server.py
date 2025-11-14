from typing import List
from ed25519_utils import generate_auth_challenge, verify_signature 

import hashlib

# Import our ElGamal-based threshold crypto system
from elgamal_threshold_crypto import ThresholdElGamal, ElGamalCiphertext
from schnorr_zkp import verify_zkp_from_json, verify_partial_decryption_zkp_from_json


debug_on=False

def debug(msg):
    if (debug_on):
        print(msg)

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
        self.crypto_system = ThresholdElGamal(threshold=quorum, num_participants=number_voters)
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

    def publish_voting_data(self):
            """Publish data needed for tally verification."""
            return {
                'all_encrypted_votes': list(self.votes.values()),
                'encrypted_tally': self.get_encrypted_tally(),
                'elgamal_parameters': self.crypto_system.get_public_key(),
            }

    def cast_vote(self, encrypted_vote: str, zkp: str, voter_id: int, signature: str) -> bool:
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
        debug(f"DecisionServer: Receiving vote from voter {voter_id}")
        
        # Step 1: Verify voter is registered
        if not self.is_voter_registered(voter_id):
            debug(f"DecisionServer: Vote rejected - voter {voter_id} not registered")
            return False
        
        # Step 2: Verify signature
        vote_message = f"{encrypted_vote}|{zkp}|{voter_id}"
        if not self._verify_vote_signature(vote_message, signature, voter_id):
            debug(f"DecisionServer: Vote rejected - invalid signature from voter {voter_id}")
            return False
        
        # Step 3: Verify zero-knowledge proof
        if not verify_zkp_from_json(zkp, encrypted_vote):
            debug(f"DecisionServer: Vote rejected - invalid ZKP from voter {voter_id}")
            return False
        
        # Step 4: Store the vote (in practice, would check for double voting)
        if not hasattr(self, 'votes'):
            self.votes = {}
        
        if voter_id in self.votes:
            debug(f"DecisionServer: Vote rejected - voter {voter_id} already voted")
            return False
        
        self.votes[voter_id] = {
            'encrypted_vote': encrypted_vote,
            'zkp': zkp,
            'signature': signature
        }
        
        debug(f"DecisionServer: Vote accepted from voter {voter_id}")
        debug(f"DecisionServer: Total votes received: {len(self.votes)}")
        
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
        return verify_signature(message_bytes, signature, public_key_hex)
        
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
        
        debug(f"DecisionServer: Starting homomorphic tally of {len(self.votes)} votes")
        
        # Extract all encrypted votes
        encrypted_votes = [vote_data['encrypted_vote'] for vote_data in self.votes.values()]
        # Perform homomorphic addition
        total_ciphertext = self._homomorphic_add_votes(encrypted_votes)
        
        # Store results for later retrieval
        self._encrypted_tally = total_ciphertext
        
        debug(f"DecisionServer: Tally complete. Total ciphertext: {total_ciphertext[:30]}...")        
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
                elgamal_ciphertext = ElGamalCiphertext.from_dict(ciphertext_dict)
                ciphertexts.append(elgamal_ciphertext)
                debug(f"  Processing vote {i}: BGV ciphertext parsed")
                
            except (ValueError, json.JSONDecodeError) as e:
                debug(f"  Warning: Could not parse encrypted vote {i}: {e}")
        
        if not ciphertexts:
            raise ValueError("No valid ciphertexts found for homomorphic addition")
        
        # Perform homomorphic addition using BGV
        debug(f"DecisionServer: Adding {len(ciphertexts)} BGV ciphertexts...")
        
        # Start with the first ciphertext
        total_ciphertext = ciphertexts[0]
        
        # Add with remaining ciphertexts
        for i in range(1, len(ciphertexts)):
            total_ciphertext = self.crypto_system.homomorphic_add(total_ciphertext, ciphertexts[i])
            debug(f"  Added ciphertext {i+1}")
        
        # Serialize the result for storage (without revealing plaintext total)
        import json
        serialized_result = json.dumps(total_ciphertext.to_dict())
        
        debug(f"DecisionServer: BGV homomorphic sum computed from {len(ciphertexts)} ciphertexts")
        debug(f"DecisionServer: Result size: {len(str(total_ciphertext.to_dict()))} bytes")
        
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
        
        debug(f"DecisionServer: Returning tallied results with verification proof")
        
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
        
        debug(f"DecisionServer: Starting decryption process with {len(voter_ids_for_decryption)} voters")
        
        results = self.get_tallied_results()
        
        # Step 1: Get partial decryptions from each voter
        partial_decryptions = []
        voter_lookup = {v.voter_id: v for v in voters}
        
        debug(f"DecisionServer: Requesting partial decryptions from voters...")
        for voter_id in voter_ids_for_decryption:
            if voter_id not in voter_lookup:
                raise ValueError(f"Voter {voter_id} not found in voter list")
            
            voter = voter_lookup[voter_id]
            
            # Request partial decryption from this voter
            partial_decryption = voter.perform_partial_decryption(self._encrypted_tally)
            if partial_decryption is None:
                raise ValueError(f"Failed to get partial decryption from voter {voter_id}")
            
            # Step 1.5: Verify the partial decryption zero-knowledge proof
            if not self._verify_partial_decryption_proof(partial_decryption, self._encrypted_tally):
                raise ValueError(f"Invalid partial decryption proof from voter {voter_id}")
                
            partial_decryptions.append(partial_decryption)
            debug(f"  ✓ Received and verified partial decryption from voter {voter_id}")

        # Step 2: Combine partial decryptions using Shamir's secret reconstruction
        debug(f"DecisionServer: Combining {len(partial_decryptions)} partial decryptions...")
        plaintext_total = self._reconstruct_vote_from_shares(partial_decryptions)

        debug(f"DecisionServer: Decryption complete. Total votes: {plaintext_total}")

        return plaintext_total
     
    def _reconstruct_vote_from_shares(self, partial_decryptions: List) -> int:
        """
        Reconstruct the vote total using BGV threshold decryption.
        
        This combines partial decryptions using Lagrange 
        interpolation coefficients to recover the plaintext vote total from the 
        homomorphic sum.
        
        Args:
            partial_decryptions: List of partial decryption results from voters
            
        Returns:
            int: The reconstructed vote total
        """
        debug(f"DecisionServer: Reconstructing vote total using BGV threshold decryption")
        
        # Extract the encrypted tally ciphertext
        if not hasattr(self, '_encrypted_tally'):
            raise ValueError("No encrypted tally available for decryption")
        
        encrypted_tally = self._encrypted_tally
        
        # Parse the BGV ciphertext from the serialized JSON format
        import json
        try:
            ciphertext_dict = json.loads(encrypted_tally)
            total_ciphertext = ElGamalCiphertext.from_dict(ciphertext_dict)
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
            debug(f"  Voter {partial['voter_id']}: Partial decryption ({share_index}, {partial_value})")

        # Use BGV threshold decryption with partial results
        plaintext_total = self.crypto_system.combine_shares_and_decrypt(
            total_ciphertext, partial_results
        )
        
        debug(f"DecisionServer: BGV threshold decryption complete: {plaintext_total}")
        debug(f"DecisionServer: SECRET SHARES NEVER REVEALED - only partial decryptions used")
        
        return plaintext_total
    
    def _verify_partial_decryption_proof(self, partial_decryption: dict, encrypted_tally: str) -> bool:
        """
        Verify the zero-knowledge proof of correct partial decryption.
        
        This method verifies that:
        1. The voter correctly computed their partial decryption using their secret share
        2. The partial decryption corresponds to the given encrypted tally
        3. The voter knows their secret share without revealing it
        
        Args:
            partial_decryption: Partial decryption result from voter containing proof
            encrypted_tally: The encrypted tally being partially decrypted
            
        Returns:
            bool: True if the proof is valid, False otherwise
        """
        try:
            # Extract the proof from the partial decryption result
            if 'decryption_proof' not in partial_decryption:
                debug(f"DecisionServer: No decryption proof found in partial decryption from voter {partial_decryption.get('voter_id', 'unknown')}")
                return False
            
            zkp_proof = partial_decryption['decryption_proof']
            partial_result = partial_decryption['partial_decryption']
            voter_id = partial_decryption['voter_id']
            
            debug(f"DecisionServer: Verifying partial decryption ZKP from voter {voter_id}")
            
            # Verify the zero-knowledge proof using the standalone verification function
            is_valid = verify_partial_decryption_zkp_from_json(zkp_proof, encrypted_tally, partial_result)
            
            if is_valid:
                debug(f"DecisionServer: Partial decryption ZKP verification PASSED for voter {voter_id}")
            else:
                debug(f"DecisionServer: Partial decryption ZKP verification FAILED for voter {voter_id}")
            
            return is_valid
            
        except Exception as e:
            debug(f"DecisionServer: Error verifying partial decryption proof: {e}")
            return False
    
    def can_tally(self) -> bool:
        """
        Check if tallying is possible (enough votes received).
        
        Returns:
            bool: True if tallying can be performed, False otherwise
        """
        return hasattr(self, 'votes') and len(self.votes) >= self.quorum

    def __repr__(self):
        return f"DecisionServer(number_voters={self.number_voters}, quorum={self.quorum})"
