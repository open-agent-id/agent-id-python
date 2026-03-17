"""Tests for the crypto module (V2, using PyNaCl)."""

import pytest

from agent_id.crypto import (
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    sha256,
    base64url_encode,
    base64url_decode,
    generate_nonce,
    ed25519_to_x25519_public,
    ed25519_to_x25519_private,
    encrypt_for,
    decrypt_from,
)


def test_generate_keypair_sizes() -> None:
    priv, pub = generate_ed25519_keypair()
    assert len(priv) == 32  # seed only
    assert len(pub) == 32


def test_sign_verify_roundtrip() -> None:
    priv, pub = generate_ed25519_keypair()
    message = b"hello world"
    sig = ed25519_sign(priv, message)
    assert len(sig) == 64
    assert ed25519_verify(pub, message, sig) is True


def test_verify_wrong_message() -> None:
    priv, pub = generate_ed25519_keypair()
    sig = ed25519_sign(priv, b"hello")
    assert ed25519_verify(pub, b"world", sig) is False


def test_verify_wrong_key() -> None:
    priv1, _ = generate_ed25519_keypair()
    _, pub2 = generate_ed25519_keypair()
    sig = ed25519_sign(priv1, b"hello")
    assert ed25519_verify(pub2, b"hello", sig) is False


def test_sha256_empty() -> None:
    assert sha256(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_nonempty() -> None:
    assert sha256(b"test") == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def test_base64url_roundtrip() -> None:
    data = b"\x00\xff\x80\x01"
    encoded = base64url_encode(data)
    assert "+" not in encoded
    assert "/" not in encoded
    assert "=" not in encoded
    assert base64url_decode(encoded) == data


def test_base64url_empty() -> None:
    assert base64url_encode(b"") == ""
    assert base64url_decode("") == b""


def test_generate_nonce_length() -> None:
    nonce = generate_nonce()
    assert len(nonce) == 32  # 16 bytes = 32 hex chars
    int(nonce, 16)  # should be valid hex


# ---------------------------------------------------------------------------
# E2E encryption tests
# ---------------------------------------------------------------------------


def test_key_conversion_deterministic() -> None:
    priv, pub = generate_ed25519_keypair()
    assert ed25519_to_x25519_public(pub) == ed25519_to_x25519_public(pub)
    assert ed25519_to_x25519_private(priv) == ed25519_to_x25519_private(priv)
    assert len(ed25519_to_x25519_public(pub)) == 32
    assert len(ed25519_to_x25519_private(priv)) == 32


def test_encrypt_decrypt_roundtrip() -> None:
    sender_priv, sender_pub = generate_ed25519_keypair()
    recipient_priv, recipient_pub = generate_ed25519_keypair()

    plaintext = b"hello agent world"
    ciphertext = encrypt_for(plaintext, recipient_pub, sender_priv)

    # Ciphertext should be nonce (24) + MAC (16) + plaintext length
    assert len(ciphertext) == 24 + 16 + len(plaintext)

    decrypted = decrypt_from(ciphertext, sender_pub, recipient_priv)
    assert decrypted == plaintext


def test_decrypt_with_wrong_key_fails() -> None:
    sender_priv, sender_pub = generate_ed25519_keypair()
    _, recipient_pub = generate_ed25519_keypair()
    wrong_priv, _ = generate_ed25519_keypair()

    plaintext = b"secret message"
    ciphertext = encrypt_for(plaintext, recipient_pub, sender_priv)

    from nacl.exceptions import CryptoError

    with pytest.raises(CryptoError):
        decrypt_from(ciphertext, sender_pub, wrong_priv)


def test_encrypt_empty_message() -> None:
    sender_priv, sender_pub = generate_ed25519_keypair()
    recipient_priv, recipient_pub = generate_ed25519_keypair()

    ciphertext = encrypt_for(b"", recipient_pub, sender_priv)
    decrypted = decrypt_from(ciphertext, sender_pub, recipient_priv)
    assert decrypted == b""
