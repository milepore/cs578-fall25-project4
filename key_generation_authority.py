import hashlib
import secrets
from typing import List, Tuple
from ed25519_utils import generate_auth_challenge, verify_signature 
from elgamal_threshold_crypto import create_elgamal_secret_shares

debug_on=False

def debug(msg):
    if (debug_on):
        print(msg)


class KeyGenerationAuthority:
    """
    A trusted authority that will create a secret and public key and distribute it
    using Shamir's secret sharing scheme to a set of voters.
    
    Security Note: The KGA generates the master secret, creates shares, distributes them,
    and then securely deletes the master secret to prevent single-point-of-failure.
    """

    def __init__(self, decision_server):
        """
        Initialize Key Generation Authority with reference to DecisionServer.
        
        Args:
            decision_server: The DecisionServer instance to work with
        """
        self.decision_server = decision_server
        self.master_secret = None  # Will be created and then securely deleted
        self.secret_shares = None  # Will be created and then cleared after distribution

    def generate_and_distribute_key(self, voters) -> bytes:
        """
        Create a secret key using Shamir's secret sharing scheme and distribute 
        shares to all registered voters after authentication challenge.
        
        This method:
        1. Generates master secret (ONLY in KGA)
        2. Creates Shamir secret shares
        3. Distributes shares to authenticated voters
        4. SECURELY DELETES master secret and shares from KGA memory
        5. Returns public context for DecisionServer
        
        Args:
            voters: List of Voter objects to distribute key shares to
            
        Returns:
            bytes: The public context for BGV encryption (no secret material)
            
        Raises:
            ValueError: If not enough voters are registered or provided
            Exception: If authentication challenge fails for any voter
        """
        threshold = self.decision_server.quorum
        num_participants = len(voters)
        
        if num_participants < threshold:
            raise ValueError(f"Need at least {threshold} voters, got {num_participants}")
        
        # Step 1: Authenticate all voters using public key signature challenge
        debug("KGA: Starting authentication challenge for all voters...")
        for voter in voters:
            if not self._authenticate_voter(voter):
                raise Exception(f"Authentication failed for voter {voter.voter_id}")
        debug("KGA: All voters authenticated successfully!")
        
        # Step 2: Generate master secret and create shares (CRITICAL SECURITY STEP)
        debug("KGA: Generating master secret and creating Shamir shares...")
        # Generate a random master secret for ElGamal
        import secrets
        from elgamal_threshold_crypto import Q
        self.master_secret = secrets.randbits(256) % Q
        self.secret_shares = create_elgamal_secret_shares(
            self.master_secret,
            threshold, 
            num_participants
        )
        debug(f"KGA: Created {len(self.secret_shares)} secret shares with threshold {threshold}")
        
        # Step 3: Get public key for ElGamal encryption
        public_context = self.decision_server.crypto_system.get_public_key()
        
        # Create a derived public key identifier for voters
        public_key = f"elgamal_threshold_pk_{hashlib.sha256(public_context).hexdigest()[:32]}"
        debug(f"KGA: Generated ElGamal public key: {public_key[:20]}...")
        
        # Step 4: Distribute ElGamal secret shares and public key to authenticated voters
        debug("KGA: Distributing secret shares to voters...")
        for i, voter in enumerate(voters):
            secret_share = self.secret_shares[i] 
            voter.receive_key_share_and_public_key(secret_share, public_context)
            debug(f"KGA: Distributed share to voter {voter.voter_id}")

        # Step 5: CRITICAL SECURITY - Securely delete master secret and shares
        debug("KGA: SECURELY DELETING master secret and shares from KGA memory...")
        self._secure_delete_secrets()
        
        debug("KGA: Key generation and distribution completed successfully")
        return public_context
    

    def _authenticate_voter(self, voter) -> bool:
        """
        Authenticate a voter using public key signature challenge
        1. Generate a random challenge message
        2. Send challenge to voter
        3. Voter signs challenge with their private key
        4. Server verifies signature using voter's registered public key
        
        Args:
            voter: The Voter object to authenticate
            
        Returns:
            bool: True if authentication succeeds, False otherwise
        """
        # Generate challenge with security-level appropriate size
        challenge = generate_auth_challenge()
        debug(f"Sending authentication challenge to voter {voter.voter_id}")
        
        # Get voter's signature response
        signature = voter.sign_challenge(challenge)
        
        # Verify signature using registered public key
        registered_public_key = self.decision_server.get_voter_public_key(voter.voter_id)
        if registered_public_key is None:
            debug(f"Authentication failed: No public key found for voter {voter.voter_id}")
            return False
        
        is_valid = verify_signature(challenge, signature, registered_public_key)
        
        if is_valid:
            debug(f"Voter {voter.voter_id} authentication successful")
        else:
            debug(f"Voter {voter.voter_id} authentication failed - invalid signature")

        return is_valid

    def _secure_delete_secrets(self):
        """
        Securely delete master secret and shares from memory.
        
        This is a critical security operation that ensures the KGA cannot
        be used to decrypt individual votes after key distribution.
        
        Note: In a production system, this would use secure memory clearing
        techniques to overwrite memory locations.
        """
        if self.master_secret is not None:
            # In Python, we can't truly "secure delete" from memory due to
            # garbage collection, but we can overwrite with zeros and None
            self.master_secret = 0
            self.master_secret = None
            debug("KGA: Master secret securely deleted")
            
        if self.secret_shares is not None:
            # Overwrite all shares with zeros then clear the list
            for i in range(len(self.secret_shares)):
                if self.secret_shares[i] is not None:
                    self.secret_shares[i] = (0, 0)
            self.secret_shares.clear()
            self.secret_shares = None
            debug("KGA: Secret shares securely deleted")
        
        debug("🔒 KGA: All secret material has been securely deleted - KGA is now safe")
