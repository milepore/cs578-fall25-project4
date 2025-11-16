from decision_server import DecisionServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import hashlib
import secrets
import json

# Import our BGV threshold crypto implementation
from bgv_threshold_crypto import BGVThresholdCrypto, BGVCiphertext

# Import the Schnorr-based zero-knowledge proof system
from schnorr_zkp import SchnorrDisjunctiveProof, verify_zkp_from_json, SchnorrPartialDecryptionProof

debug_on=False

def debug(msg):
    if (debug_on):
        print(msg)

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

        # Generate Ed25519 key pair for authentication and signing
        self.public_key_hex, self.private_key_obj = create_key_pair(self.voter_id)
        DecisionServer.register_voter(self.decision_server, self.voter_id, self.public_key_hex)

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
        debug(f"Voter {self.voter_id} received key share: ({share[0]}, {str(share[1])[:10]}...) and public key: {public_key[:20]}...")
    
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
        Sign an authentication challenge using Ed25519 private key.
        
        Args:
            challenge: The challenge bytes to sign
            
        Returns:
            str: The Ed25519 signature as hex string
        """
        # Sign the challenge using Ed25519
        signature_bytes = self.private_key_obj.sign(challenge)
        signature_hex = signature_bytes.hex()
        
        debug(f"Voter {self.voter_id} signed challenge with Ed25519")
        return signature_hex
    
    def cast_vote(self, vote: int) -> bool:
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
        
        debug(f"Voter {self.voter_id} casting vote: {vote}")
        
        # Step 1: Encrypt the vote using the shared public key
        if not isinstance(self.shared_public_key, bytes):
            raise ValueError("Public key must be bytes for BGV encryption")
        encrypted_vote = self._encrypt_vote(vote, self.shared_public_key)
        debug(f"Voter {self.voter_id} encrypted vote: {encrypted_vote[:20]}...")
        
        # Step 2: Create a zero-knowledge proof that the vote is 0 or 1
        zkp = self._create_vote_zkp(vote, encrypted_vote)
        debug(f"Voter {self.voter_id} created ZKP: {zkp[:30]}...")
        
        # Step 3: Create message to sign (vote data + voter identity)
        election_id = self.decision_server.get_election_id()
        vote_message = f"{encrypted_vote}|{zkp}|{election_id}|{self.voter_id}"
        vote_signature = self._sign_vote_message(vote_message)
        
        # Step 4: Send to DecisionServer
        try:
            result = self.decision_server.cast_vote(
                encrypted_vote=encrypted_vote,
                zkp=zkp,
                voter_id=self.voter_id,
                signature=vote_signature
            )
            
            if result:
                debug(f"Voter {self.voter_id} successfully cast vote")
            else:
                debug(f"Voter {self.voter_id} failed to cast vote")

            return result
            
        except Exception as e:
            debug(f"Voter {self.voter_id} vote casting failed: {e}")
            return False
    
    def _encrypt_vote(self, vote: int, public_context: bytes) -> str:
        """
        Encrypt a vote using BGV homomorphic encryption.
        
        Args:
            vote: The vote to encrypt (0 or 1)
            public_context: The BGV public context for encryption
            
        Returns:
            str: The encrypted vote (BGV ciphertext serialized as JSON)
        """
        import json
        
        try:
            # Create a temporary BGV crypto instance with public context
            import tenseal as ts
            context = ts.context_from(public_context)
            
            # Encrypt the vote using BFV
            encrypted_vote = ts.bfv_vector(context, [vote])
            
            # Create BGV ciphertext object
            bgv_ciphertext = BGVCiphertext(
                serialized_data=encrypted_vote.serialize(),
                context_data={
                    'scheme': 'BFV',
                    'voter_id': self.voter_id,
                    'encrypted_at': 'timestamp_placeholder'
                }
            )
            
            # Serialize to JSON
            encrypted_vote_json = json.dumps(bgv_ciphertext.to_dict())

            debug(f"Voter {self.voter_id}: Encrypted vote using BGV/BFV")

            return encrypted_vote_json
            
        except Exception as e:
            debug(f"Voter {self.voter_id}: BGV encryption failed: {e}")
            raise e
    
    def _create_vote_zkp(self, vote: int, encrypted_vote: str) -> str:
        """
        Create a Non-Interactive Zero-Knowledge Proof that the vote is 0 or 1.
        
        Uses Schnorr-based disjunctive proof to demonstrate:
        1. The prover knows the plaintext of the encrypted vote
        2. The plaintext is either 0 or 1
        3. The proof is bound to the specific encrypted vote
        
        The proof uses:
        - Schnorr proofs for discrete log knowledge
        - Sigma protocols for OR statements (disjunctive proof)
        - Fiat-Shamir heuristic for non-interactivity
        - Elliptic curve cryptography (secp256r1)
        
        Args:
            vote: The actual vote value (0 or 1)
            encrypted_vote: The encrypted vote (JSON string)
            
        Returns:
            str: The zero-knowledge proof as JSON string
            
        Raises:
            ValueError: If vote is not 0 or 1
        """
        if vote not in [0, 1]:
            raise ValueError("Vote must be 0 or 1")

        debug(f"Voter {self.voter_id}: Creating Schnorr disjunctive ZKP for vote {vote}")

        # Create the Schnorr disjunctive proof system
        proof_system = SchnorrDisjunctiveProof()
        
        # Generate the proof
        proof_dict = proof_system.create_proof(vote, encrypted_vote, self.voter_id)
        
        # Serialize proof to JSON
        zkp_json = json.dumps(proof_dict, sort_keys=True)

        debug(f"Voter {self.voter_id}: Successfully created Schnorr ZKP")
        debug(f"Voter {self.voter_id}: Proof type: {proof_dict['type']}")
        debug(f"Voter {self.voter_id}: Challenge: {proof_dict['challenge'][:16]}...")

        return zkp_json
    
    def _sign_vote_message(self, message: str) -> str:
        """
        Sign a vote message using Ed25519 private key.
        
        Args:
            message: The message to sign
            
        Returns:
            str: The Ed25519 signature as hex string
        """
        message_bytes = message.encode()
        # Sign the message using Ed25519
        signature_bytes = self.private_key_obj.sign(message_bytes)
        signature_hex = signature_bytes.hex()
        
        return signature_hex
    
    def perform_partial_decryption(self, encrypted_tally: str) -> dict:
        """
        Perform partial decryption of the encrypted tally using this voter's key share.
        
        SECURITY: This method computes a partial decryption using the voter's secret share
        but NEVER reveals the secret share itself. Only the partial decryption result
        is returned to the server.

        Args:
            encrypted_tally: The encrypted tally to partially decrypt
            
        Returns:
            dict: Contains 'voter_id', 'partial_decryption', and 'proof' of correct decryption
            
        Raises:
            ValueError: If voter doesn't have a key share or shared public key
        """
        # Validate preconditions
        if self.key_share is None:
            raise ValueError(f"Voter {self.voter_id} key share is None")
        
        if self.shared_public_key is None:
            raise ValueError(f"Voter {self.voter_id} shared public key is None")
        
        debug(f"Voter {self.voter_id}: Computing partial decryption of tally")
        
        # Parse the BGV ciphertext from the encrypted tally
        try:
            import json
            ciphertext_dict = json.loads(encrypted_tally)
            from bgv_threshold_crypto import BGVCiphertext
            bgv_ciphertext = BGVCiphertext.from_dict(ciphertext_dict)
        except (json.JSONDecodeError, Exception) as e:
            raise ValueError(f"Invalid encrypted tally format: {e}")
        
        # Compute partial decryption using BGV threshold crypto
        partial_decryption_result = self._compute_partial_decryption(bgv_ciphertext)
        
        # Create proof of correct partial decryption
        decryption_proof = self._create_partial_decryption_proof(
            encrypted_tally, 
            partial_decryption_result
        )
        
        partial_result = {
            'voter_id': self.voter_id,
            'partial_decryption': partial_decryption_result,
            'tally_hash': self._hash_tally(encrypted_tally),
            'decryption_proof': decryption_proof
        }

        debug(f"Voter {self.voter_id}: Partial decryption complete (secret share kept private)")

        return partial_result
    
    def _hash_tally(self, encrypted_tally: str) -> str:
        """
        Create a hash of the encrypted tally for verification.
        
        Args:
            encrypted_tally: The encrypted tally
            
        Returns:
            str: Hash of the tally
        """
        return hashlib.sha256(encrypted_tally.encode()).hexdigest()[:16]
    
    def _compute_partial_decryption(self, bgv_ciphertext) -> dict:
        """
        Compute the actual partial decryption using this voter's secret share.
        
        This method uses the BGV threshold crypto system to compute a partial
        decryption that can be combined with other partial decryptions to 
        recover the plaintext, without revealing the secret share.
        
        Args:
            bgv_ciphertext: The BGV ciphertext to partially decrypt
            
        Returns:
            dict: Partial decryption result that can be safely shared
        """
        from bgv_threshold_crypto import BGVThresholdCrypto
        
        # Create a temporary crypto system to perform partial decryption
        # Note: In a real implementation, this would be more sophisticated
        temp_crypto = BGVThresholdCrypto(
            threshold=self.decision_server.quorum,
            num_participants=self.decision_server.number_voters
        )
        
        # Ensure we have a key share
        if not hasattr(self, 'key_share') or self.key_share is None:
            raise ValueError(f"Voter {self.voter_id} does not have a key share")
        
        # Perform partial decryption using our secret share
        # This returns a partial decryption result, NOT the raw secret share
        partial_x, partial_y = temp_crypto.partial_decrypt(bgv_ciphertext, self.voter_id, self.key_share)
        
        # Return the partial decryption result (safe to share)
        return {
            'share_index': partial_x,  # Index of this share (x-coordinate)
            'partial_value': partial_y,  # Partial decryption result (NOT raw secret)
            'computation_metadata': {
                'voter_id': self.voter_id,
                'decryption_type': 'bgv_threshold_partial'
            }
        }

    def _create_partial_decryption_proof(self, encrypted_tally: str, partial_decryption_result: dict) -> str:
        """
        Create a real zero-knowledge proof of correct partial decryption.
        
        Uses Schnorr-based proof to demonstrate:
        1. The partial decryption was computed correctly using the voter's secret share
        2. The voter knows their secret share without revealing it
        3. The partial decryption corresponds to the given encrypted tally
        
        The proof uses:
        - Schnorr proofs for discrete log knowledge
        - Fiat-Shamir heuristic for non-interactivity
        - Elliptic curve cryptography (secp256r1)
        - Binding to both encrypted tally and partial decryption result
        
        Args:
            encrypted_tally: The encrypted tally being decrypted
            partial_decryption_result: The computed partial decryption result
            
        Returns:
            str: The zero-knowledge proof as JSON string
            
        Raises:
            ValueError: If key share is not available
        """
        if self.key_share is None:
            raise ValueError("Cannot create partial decryption proof: key share not available")

        debug(f"Voter {self.voter_id}: Creating Schnorr partial decryption ZKP")

        # Create the Schnorr partial decryption proof system
        proof_system = SchnorrPartialDecryptionProof()
        
        # Generate the proof using our secret share
        proof_dict = proof_system.create_proof(
            secret_share=self.key_share,
            encrypted_tally=encrypted_tally,
            partial_decryption_result=partial_decryption_result,
            voter_id=self.voter_id
        )
        
        # Serialize proof to JSON
        zkp_json = json.dumps(proof_dict, sort_keys=True)

        debug(f"Voter {self.voter_id}: Successfully created Schnorr partial decryption ZKP")
        debug(f"Voter {self.voter_id}: Proof type: {proof_dict['type']}")
        debug(f"Voter {self.voter_id}: Share index: {proof_dict['share_index']}")
        debug(f"Voter {self.voter_id}: Challenge: {proof_dict['challenge'][:16]}...")

        return zkp_json

    def __repr__(self):
        return f"Voter(voter_id={self.voter_id}, decision_server={self.decision_server})"
    

def create_key_pair(voter_id):
    """
    Create an Ed25519 public/private key pair for the voter.
    
    Args:
        voter_id (int): Unique identifier for the voter

    Returns:
        tuple: A tuple containing (public_key_hex, private_key_object)
    """
    # Generate Ed25519 key pair
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Serialize public key to hex for easy storage/transmission
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return public_key_bytes.hex(), private_key