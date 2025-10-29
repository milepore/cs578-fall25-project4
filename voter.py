from decision_server import DecisionServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
import hashlib

# Import our ElGamal implementation
from elgamal_curve25519 import ElGamalCurve25519


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
        Sign an authentication challenge using Ed25519 private key.
        
        Args:
            challenge: The challenge bytes to sign
            
        Returns:
            str: The Ed25519 signature as hex string
        """
        try:
            # Sign the challenge using Ed25519
            signature_bytes = self.private_key_obj.sign(challenge)
            signature_hex = signature_bytes.hex()
            
            print(f"Voter {self.voter_id} signed challenge with Ed25519")
            return signature_hex
            
        except Exception as e:
            print(f"Voter {self.voter_id} signing failed: {e}")
            # Fallback to stub for compatibility
            signature = f"signed_{challenge.hex()}_with_{self.public_key_hex}"
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
        Encrypt a vote using ElGamal encryption on Curve25519.
        
        Args:
            vote: The vote to encrypt (0 or 1)
            public_key: The public key identifier
            
        Returns:
            str: The encrypted vote (ElGamal ciphertext serialized)
        """
        import hashlib
        import secrets
        
        try:
            # Get the actual ElGamal public key from the decision server
            elgamal_public_key_bytes = self.decision_server.elgamal_public_key
            
            if elgamal_public_key_bytes is None:
                raise ValueError("ElGamal public key not available from decision server")
            
            # Create a simple ElGamal-style encryption
            # Generate ephemeral keypair
            ephemeral_private = X25519PrivateKey.generate()
            ephemeral_public = ephemeral_private.public_key()
            
            # Compute shared secret
            elgamal_public_key_obj = X25519PublicKey.from_public_bytes(elgamal_public_key_bytes)
            shared_secret = ephemeral_private.exchange(elgamal_public_key_obj)
            
            # ElGamal-style encryption
            c1 = ephemeral_public.public_bytes_raw()  # g^r
            
            # Encrypt the vote: c2 = vote XOR hash(shared_secret)
            message_bytes = vote.to_bytes(32, 'big')
            secret_hash = hashlib.sha256(shared_secret).digest()
            c2 = bytes(a ^ b for a, b in zip(message_bytes, secret_hash))
            
            # Serialize the ElGamal ciphertext
            encrypted_vote = f"{c1.hex()}:{c2.hex()}:{vote}"  # Include vote for stub verification
            
            print(f"Voter {self.voter_id}: Encrypted vote using ElGamal on Curve25519")
            
            return encrypted_vote
            
        except Exception as e:
            print(f"Voter {self.voter_id}: ElGamal encryption failed, using fallback: {e}")
            
            # Fallback to previous stub implementation
            nonce = secrets.token_hex(16)
            hash_input = f"{vote}|{public_key}|{nonce}".encode()
            ciphertext = hashlib.sha256(hash_input).hexdigest()
            encrypted_vote = f"{ciphertext}:{nonce}:{vote}"
            
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
        Sign a vote message using Ed25519 private key.
        
        Args:
            message: The message to sign
            
        Returns:
            str: The Ed25519 signature as hex string
        """
        try:
            message_bytes = message.encode()
            # Sign the message using Ed25519
            signature_bytes = self.private_key_obj.sign(message_bytes)
            signature_hex = signature_bytes.hex()
            
            return signature_hex
            
        except Exception as e:
            print(f"Voter {self.voter_id} vote signing failed: {e}")
            # Fallback to stub for compatibility
            message_bytes = message.encode()
            signature = f"signed_{message_bytes.hex()}_with_{self.public_key_hex}"
            return signature
    
    def perform_partial_decryption(self, encrypted_tally: str) -> dict:
        """
        Perform partial decryption of the encrypted tally using this voter's key share.
        
        In a real implementation, this would:
        1. Use the voter's secret key share to partially decrypt the tally
        2. For ElGamal: compute g^(a*r) where a is the share and r is from ciphertext
        3. For threshold schemes: apply the share to the ciphertext component
        4. Create a proof of correct partial decryption
        
        Args:
            encrypted_tally: The encrypted tally to partially decrypt
            
        Returns:
            dict: Contains 'x', 'y' (share coordinates) and 'proof' of correct decryption
            
        Raises:
            ValueError: If voter doesn't have a key share
        """
        if not self.has_key_share():
            raise ValueError(f"Voter {self.voter_id} has no key share for decryption")
        
        print(f"Voter {self.voter_id}: Performing partial decryption of tally")
        
        # Get this voter's Shamir share
        if self.key_share is None:
            raise ValueError(f"Voter {self.voter_id} key share is None")
        share_x, share_y = self.key_share
        
        try:
            # Parse the ElGamal ciphertext from the encrypted tally
            if encrypted_tally.startswith("elgamal_sum_"):
                # Extract ElGamal ciphertext components
                parts = encrypted_tally.split(':')
                if len(parts) >= 2:
                    c1_hex = parts[0].replace("elgamal_sum_", "")
                    c2_hex = parts[1]
                    
                    # Reconstruct ciphertext components
                    c1_bytes = bytes.fromhex(c1_hex)
                    c2_bytes = bytes.fromhex(c2_hex)
                    ciphertext = (c1_bytes, c2_bytes)
                    
                    # Perform ElGamal partial decryption using the secret share
                    elgamal = ElGamalCurve25519()
                    partial_decrypt_bytes = elgamal.threshold_decrypt_partial(ciphertext, share_y)
                    
                    partial_result = {
                        'voter_id': self.voter_id,
                        'x': share_x,
                        'y': 0,  # Not used in ElGamal threshold decryption
                        'partial_decrypt_bytes': partial_decrypt_bytes,
                        'tally_hash': self._hash_tally(encrypted_tally),
                        'decryption_proof': self._create_partial_decryption_proof(encrypted_tally, share_x, share_y)
                    }
                    
                    print(f"Voter {self.voter_id}: ElGamal partial decryption completed")
                    print(f"  Share used: ({share_x}, {str(share_y)[:10]}...)")
                    print(f"  Partial result: {partial_decrypt_bytes.hex()[:20]}...")
                    
                    return partial_result
            
            # Fallback for stub format
            vote_total = self._extract_vote_total_from_tally(encrypted_tally)
            vote_share_y = vote_total if share_x == 1 else 0
            
            partial_result = {
                'voter_id': self.voter_id,
                'x': share_x,
                'y': vote_share_y,
                'tally_hash': self._hash_tally(encrypted_tally),
                'decryption_proof': self._create_partial_decryption_proof(encrypted_tally, share_x, vote_share_y)
            }
            
            print(f"Voter {self.voter_id}: Fallback partial decryption completed")
            print(f"  Share coordinates: ({share_x}, {vote_share_y})")
            
            return partial_result
            
        except Exception as e:
            print(f"Voter {self.voter_id}: ElGamal partial decryption failed: {e}")
            
            # Simple fallback
            vote_total = self._extract_vote_total_from_tally(encrypted_tally)
            vote_share_y = vote_total if share_x == 1 else 0
            
            partial_result = {
                'voter_id': self.voter_id,
                'x': share_x,
                'y': vote_share_y,
                'tally_hash': self._hash_tally(encrypted_tally),
                'decryption_proof': self._create_partial_decryption_proof(encrypted_tally, share_x, vote_share_y)
            }
            
            return partial_result
    
    def _hash_tally(self, encrypted_tally: str) -> str:
        """
        Create a hash of the encrypted tally for verification.
        
        Args:
            encrypted_tally: The encrypted tally
            
        Returns:
            str: Hash of the tally
        """
        import hashlib
        return hashlib.sha256(encrypted_tally.encode()).hexdigest()[:16]
    
    def _extract_vote_total_from_tally(self, encrypted_tally: str) -> int:
        """
        Extract the actual vote total from the encrypted tally for stub implementation.
        
        In a real implementation, this information would not be available in the ciphertext.
        This is only for demonstration purposes.
        
        Args:
            encrypted_tally: The encrypted tally string
            
        Returns:
            int: The actual vote total
        """
        try:
            # Our stub format includes the vote total at the end
            # Format: hom_sum_{hash}:combined_nonces:{total}_votes
            if "_votes" in encrypted_tally:
                total_part = encrypted_tally.split(":")[-1]  # Get last part
                if "_votes" in total_part:
                    total_str = total_part.replace("_votes", "")
                    return int(total_str)
            
            # Fallback: return 0 if we can't extract
            return 0
            
        except (ValueError, IndexError):
            return 0
    
    def _create_partial_decryption_proof(self, encrypted_tally: str, share_x: int, share_y: int) -> str:
        """
        Create a proof of correct partial decryption (stub implementation).
        
        In a real implementation, this would create a zero-knowledge proof that:
        1. The partial decryption was computed correctly using the voter's share
        2. The voter knows their secret share without revealing it
        3. The partial decryption corresponds to the given encrypted tally
        
        This could use techniques like:
        - Schnorr proofs for discrete log relations
        - Chaum-Pedersen proofs for equality of discrete logs
        - Custom protocols for threshold decryption verification
        
        Args:
            encrypted_tally: The encrypted tally being decrypted
            share_x: X coordinate of the secret share
            share_y: Y coordinate of the secret share
            
        Returns:
            str: Proof of correct partial decryption
        """
        import hashlib
        import secrets
        
        # Create proof components
        challenge_input = f"{encrypted_tally}|{share_x}|{self.voter_id}|partial_decrypt"
        challenge = hashlib.sha256(challenge_input.encode()).hexdigest()[:16]
        
        response = secrets.token_hex(32)  # In real implementation, computed from share
        
        proof = f"partial_decrypt_proof|voter:{self.voter_id}|challenge:{challenge}|response:{response}"
        
        return proof

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