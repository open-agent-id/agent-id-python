"""Tests for the AgentIdentity class."""

import pytest

from agent_id.identity import AgentIdentity
from agent_id.crypto import generate_keypair, base64url_encode, verify, base64url_decode


def _make_identity() -> AgentIdentity:
    """Create a test identity with a fresh keypair."""
    priv, pub = generate_keypair()
    return AgentIdentity(
        did="did:agent:testplatform:agt_a1B2c3D4e5",
        private_key=priv,
        public_key=pub,
    )


def test_constructor_validates_did() -> None:
    _, pub = generate_keypair()
    with pytest.raises(ValueError):
        AgentIdentity(did="bad-did", private_key=None, public_key=pub)


def test_did_property() -> None:
    ident = _make_identity()
    assert ident.did == "did:agent:testplatform:agt_a1B2c3D4e5"


def test_public_key_base64url() -> None:
    priv, pub = generate_keypair()
    ident = AgentIdentity(
        did="did:agent:test:agt_a1B2c3D4e5",
        private_key=priv,
        public_key=pub,
    )
    encoded = ident.public_key_base64url
    assert base64url_decode(encoded) == pub


def test_sign_produces_valid_signature() -> None:
    ident = _make_identity()
    payload = "test payload"
    sig_b64 = ident.sign(payload)
    sig_bytes = base64url_decode(sig_b64)
    assert len(sig_bytes) == 64
    # Verify with raw public key
    assert verify(payload.encode("utf-8"), sig_bytes, base64url_decode(ident.public_key_base64url))


def test_sign_without_private_key_raises() -> None:
    _, pub = generate_keypair()
    ident = AgentIdentity(
        did="did:agent:test:agt_a1B2c3D4e5",
        private_key=None,
        public_key=pub,
    )
    with pytest.raises(RuntimeError, match="no private key"):
        ident.sign("anything")


def test_sign_request_returns_required_headers() -> None:
    ident = _make_identity()
    headers = ident.sign_request("POST", "https://example.com/api", '{"key":"val"}')
    assert headers["X-Agent-DID"] == ident.did
    assert "X-Agent-Timestamp" in headers
    assert "X-Agent-Nonce" in headers
    assert "X-Agent-Signature" in headers
    # Timestamp should be a numeric string
    int(headers["X-Agent-Timestamp"])
    # Nonce should be hex
    int(headers["X-Agent-Nonce"], 16)


def test_sign_request_signature_verifiable() -> None:
    """Verify that the signature in the headers actually validates."""
    priv, pub = generate_keypair()
    ident = AgentIdentity(
        did="did:agent:test:agt_a1B2c3D4e5",
        private_key=priv,
        public_key=pub,
    )
    body = '{"task":"search"}'
    headers = ident.sign_request("POST", "https://api.example.com/v1/tasks", body)

    # Reconstruct canonical payload
    from agent_id.crypto import sha256_hex
    body_hash = sha256_hex(body.encode("utf-8"))
    canonical = (
        f"POST\nhttps://api.example.com/v1/tasks\n{body_hash}\n"
        f"{headers['X-Agent-Timestamp']}\n{headers['X-Agent-Nonce']}"
    )
    sig_bytes = base64url_decode(headers["X-Agent-Signature"])
    assert verify(canonical.encode("utf-8"), sig_bytes, pub)


def test_load_from_base64url_key() -> None:
    priv, pub = generate_keypair()
    did = "did:agent:test:agt_a1B2c3D4e5"
    priv_b64 = base64url_encode(priv)

    loaded = AgentIdentity.load(did, priv_b64)
    assert loaded.did == did
    assert loaded.public_key_base64url == base64url_encode(pub)

    # Should be able to sign
    sig_b64 = loaded.sign("hello")
    sig_bytes = base64url_decode(sig_b64)
    assert verify(b"hello", sig_bytes, pub)
