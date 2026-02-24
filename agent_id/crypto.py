"""Low-level Ed25519 cryptography and encoding utilities.

Uses PyNaCl (nacl.signing) for Ed25519 operations.
"""

from __future__ import annotations

import base64
import hashlib
import os

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        Tuple of (private_key_seed, public_key) where private_key_seed
        is the 32-byte seed and public_key is the 32-byte raw public key.
    """
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def ed25519_sign(private_key: bytes, data: bytes) -> bytes:
    """Sign data with an Ed25519 private key.

    Args:
        private_key: 32-byte seed or 64-byte (seed || public).
        data: The bytes to sign.

    Returns:
        64-byte Ed25519 signature.
    """
    seed = private_key[:32]
    signing_key = SigningKey(seed)
    signed = signing_key.sign(data)
    return signed.signature


def ed25519_verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        public_key: 32-byte raw public key.
        data: The bytes that were signed.
        signature: 64-byte Ed25519 signature.

    Returns:
        True if valid, False otherwise.
    """
    try:
        verify_key = VerifyKey(public_key)
        verify_key.verify(data, signature)
        return True
    except (BadSignatureError, Exception):
        return False


def sha256(data: bytes) -> str:
    """Return the SHA-256 hex digest of data (lowercase)."""
    return hashlib.sha256(data).hexdigest()


def generate_nonce() -> str:
    """Generate a random 16-byte hex nonce."""
    return os.urandom(16).hex()


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url with no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)
