import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519


debug_on=False

def debug(msg):
    if (debug_on):
        print(msg)

def generate_auth_challenge() -> bytes:
    """
    Generate authentication challenge with security-level appropriate size.
    
    Returns:
        bytes: Random challenge bytes
    """
    # For 128-bit security, 16 bytes is 
    challenge_bytes = 16  # At least 16 bytes
    
    return secrets.token_bytes(challenge_bytes)

def verify_signature(message: bytes, signature: str, public_key_hex: str) -> bool:
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
        debug(f"DecisionServer: Signature verification error: {e}")
        return False

__all__ = ["generate_auth_challenge", "verify_signature"]
