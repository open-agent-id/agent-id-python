"""Tests for the crypto module."""

from agent_id.crypto import (
    generate_keypair,
    sign,
    verify,
    sha256_hex,
    base64url_encode,
    base64url_decode,
    generate_nonce,
)


def test_generate_keypair_sizes() -> None:
    priv, pub = generate_keypair()
    assert len(priv) == 64  # seed (32) + public (32)
    assert len(pub) == 32


def test_sign_verify_roundtrip() -> None:
    priv, pub = generate_keypair()
    message = b"hello world"
    sig = sign(message, priv)
    assert len(sig) == 64
    assert verify(message, sig, pub) is True


def test_verify_wrong_message() -> None:
    priv, pub = generate_keypair()
    sig = sign(b"hello", priv)
    assert verify(b"world", sig, pub) is False


def test_verify_wrong_key() -> None:
    priv1, _ = generate_keypair()
    _, pub2 = generate_keypair()
    sig = sign(b"hello", priv1)
    assert verify(b"hello", sig, pub2) is False


def test_sha256_hex_empty() -> None:
    # SHA-256 of empty string is a well-known constant
    assert sha256_hex(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_sha256_hex_nonempty() -> None:
    # Known SHA-256 value for a simple string
    assert sha256_hex(b"test") == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


def test_base64url_roundtrip() -> None:
    data = b"\x00\xff\x80\x01"
    encoded = base64url_encode(data)
    assert "+" not in encoded
    assert "/" not in encoded
    assert "=" not in encoded
    assert base64url_decode(encoded) == data


def test_generate_nonce_length() -> None:
    nonce = generate_nonce()
    assert len(nonce) == 32  # 16 bytes = 32 hex chars
    int(nonce, 16)  # should be valid hex
