"""Ed25519 cryptography and encoding utilities."""

from __future__ import annotations

import base64
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import serialization


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate an Ed25519 keypair.

    Returns:
        Tuple of (private_key_bytes, public_key_bytes) where private_key_bytes
        is the 64-byte raw private key (seed + public) and public_key_bytes
        is the 32-byte raw public key.
    """
    private_key = Ed25519PrivateKey.generate()
    raw_private = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    raw_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    # Return 64-byte private key (seed || public) as used by the spec
    return raw_private + raw_public, raw_public


def sign(payload: bytes, private_key: bytes) -> bytes:
    """Sign a payload with an Ed25519 private key.

    Args:
        payload: The bytes to sign.
        private_key: 64-byte raw private key (seed || public) or 32-byte seed.

    Returns:
        64-byte Ed25519 signature.
    """
    seed = private_key[:32]
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.sign(payload)


def verify(payload: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature.

    Args:
        payload: The bytes that were signed.
        signature: 64-byte Ed25519 signature.
        public_key: 32-byte raw public key.

    Returns:
        True if valid, False otherwise.
    """
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(signature, payload)
        return True
    except Exception:
        return False


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()


def generate_nonce() -> str:
    """Generate a random 16-byte hex nonce."""
    return os.urandom(16).hex()


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url with no padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(s: str) -> bytes:
    """Decode a base64url string (with or without padding) to bytes."""
    # Add back padding
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)
