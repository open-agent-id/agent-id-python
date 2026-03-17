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


# ---------------------------------------------------------------------------
# End-to-end encryption (NaCl box: X25519-XSalsa20-Poly1305)
# ---------------------------------------------------------------------------


def ed25519_to_x25519_public(ed25519_pub: bytes) -> bytes:
    """Convert an Ed25519 public key to an X25519 public key for encryption."""
    from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519

    return crypto_sign_ed25519_pk_to_curve25519(ed25519_pub)


def ed25519_to_x25519_private(ed25519_priv: bytes) -> bytes:
    """Convert an Ed25519 private key (32-byte seed) to an X25519 private key.

    PyNaCl requires the full 64-byte secret key, so we reconstruct it from the
    seed via ``SigningKey``.
    """
    from nacl.bindings import crypto_sign_ed25519_sk_to_curve25519

    sk = SigningKey(ed25519_priv[:32])
    return crypto_sign_ed25519_sk_to_curve25519(sk._signing_key)


def encrypt_for(
    plaintext: bytes,
    recipient_ed25519_pub: bytes,
    sender_ed25519_priv: bytes,
) -> bytes:
    """Encrypt *plaintext* for *recipient* using NaCl box.

    The returned bytes are ``[24-byte nonce][ciphertext + 16-byte MAC]``,
    which is the standard NaCl box format compatible with the JS and Rust SDKs.
    """
    from nacl.public import Box, PrivateKey, PublicKey

    sender_x25519 = PrivateKey(ed25519_to_x25519_private(sender_ed25519_priv))
    recipient_x25519 = PublicKey(ed25519_to_x25519_public(recipient_ed25519_pub))
    box = Box(sender_x25519, recipient_x25519)
    return bytes(box.encrypt(plaintext))  # nonce is prepended by default


def decrypt_from(
    ciphertext: bytes,
    sender_ed25519_pub: bytes,
    recipient_ed25519_priv: bytes,
) -> bytes:
    """Decrypt *ciphertext* that was encrypted by *sender*.

    *ciphertext* must include the 24-byte nonce prefix (standard NaCl box
    format).
    """
    from nacl.public import Box, PrivateKey, PublicKey

    recipient_x25519 = PrivateKey(ed25519_to_x25519_private(recipient_ed25519_priv))
    sender_x25519 = PublicKey(ed25519_to_x25519_public(sender_ed25519_pub))
    box = Box(recipient_x25519, sender_x25519)
    return box.decrypt(ciphertext)
