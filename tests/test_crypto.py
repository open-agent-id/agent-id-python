"""Tests for the crypto module (V2, using PyNaCl)."""

from agent_id.crypto import (
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    sha256,
    base64url_encode,
    base64url_decode,
    generate_nonce,
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
