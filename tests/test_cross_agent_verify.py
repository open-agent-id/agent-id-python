"""Cross-agent verification tests.

Two independent agents register, sign messages, and verify each other's
signatures.  All network calls are mocked so the tests run fully offline.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from agent_id.identity import AgentIdentity, _key_cache
from agent_id.crypto import (
    base64url_decode,
    base64url_encode,
    generate_keypair,
    sha256_hex,
    verify,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_agent(platform: str, suffix: str) -> AgentIdentity:
    """Create a test agent with a fresh keypair and a unique DID."""
    priv, pub = generate_keypair()
    did = f"did:agent:{platform}:agt_{suffix}"
    return AgentIdentity(did=did, private_key=priv, public_key=pub)


def _mock_get_agent(agent: AgentIdentity) -> dict:
    """Return a registry-style dict for the given agent."""
    return {
        "did": agent.did,
        "public_key": agent.public_key_base64url,
        "name": "test-agent",
        "status": "active",
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _clear_key_cache() -> None:
    """Clear the module-level public key cache before each test so that
    cached keys from prior tests never interfere."""
    _key_cache.clear()


@pytest.fixture()
def agent_a() -> AgentIdentity:
    return _make_agent("alpha", "a1B2c3D4e5")


@pytest.fixture()
def agent_b() -> AgentIdentity:
    return _make_agent("beta", "f6G7h8I9j0")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestCrossAgentVerification:
    """Prove that two independently created agents can verify each other."""

    def test_two_agents_register_different_dids(
        self, agent_a: AgentIdentity, agent_b: AgentIdentity
    ) -> None:
        """Agent A and Agent B must have distinct DIDs and distinct keys."""
        assert agent_a.did != agent_b.did
        assert agent_a.public_key_base64url != agent_b.public_key_base64url

        # Both DIDs must be well-formed
        assert agent_a.did.startswith("did:agent:")
        assert agent_b.did.startswith("did:agent:")

        # Public keys must be 32-byte Ed25519 keys
        pub_a = base64url_decode(agent_a.public_key_base64url)
        pub_b = base64url_decode(agent_b.public_key_base64url)
        assert len(pub_a) == 32
        assert len(pub_b) == 32

    @pytest.mark.asyncio
    async def test_agent_b_verifies_agent_a_signature(
        self, agent_a: AgentIdentity, agent_b: AgentIdentity
    ) -> None:
        """Agent A signs a payload; Agent B resolves A's key and verifies."""
        payload = "hello from agent A"
        signature = agent_a.sign(payload)

        # Mock the registry lookup so AgentIdentity.verify resolves A's key
        with patch("agent_id.identity.client.get_agent", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_get_agent(agent_a)
            valid = await AgentIdentity.verify(
                did=agent_a.did,
                payload=payload,
                signature=signature,
            )

        assert valid is True
        mock_get.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_agent_a_verifies_agent_b_signature(
        self, agent_a: AgentIdentity, agent_b: AgentIdentity
    ) -> None:
        """Agent B signs a payload; Agent A resolves B's key and verifies."""
        payload = "hello from agent B"
        signature = agent_b.sign(payload)

        with patch("agent_id.identity.client.get_agent", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_get_agent(agent_b)
            valid = await AgentIdentity.verify(
                did=agent_b.did,
                payload=payload,
                signature=signature,
            )

        assert valid is True
        mock_get.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cross_verify_http_request(
        self, agent_a: AgentIdentity, agent_b: AgentIdentity
    ) -> None:
        """Agent A signs an HTTP request; Agent B reconstructs the canonical
        payload from the headers and verifies the signature offline."""
        method = "POST"
        url = "https://api.example.com/v1/tasks"
        body = '{"task":"summarise","input":"some document"}'

        # Agent A produces signed headers
        headers = agent_a.sign_request(method, url, body)

        # Agent B reconstructs the canonical payload from the headers
        body_hash = sha256_hex(body.encode("utf-8"))
        canonical = (
            f"{method}\n{url}\n{body_hash}\n"
            f"{headers['X-Agent-Timestamp']}\n{headers['X-Agent-Nonce']}"
        )

        # Agent B resolves Agent A's public key via the registry and verifies
        with patch("agent_id.identity.client.get_agent", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_get_agent(agent_a)
            valid = await AgentIdentity.verify(
                did=headers["X-Agent-DID"],
                payload=canonical,
                signature=headers["X-Agent-Signature"],
            )

        assert valid is True
        # The DID in the headers should be Agent A's DID
        assert headers["X-Agent-DID"] == agent_a.did

    @pytest.mark.asyncio
    async def test_tampered_signature_rejected(
        self, agent_a: AgentIdentity, agent_b: AgentIdentity
    ) -> None:
        """Flipping a byte in the signature must cause verification to fail."""
        payload = "important message"
        signature = agent_a.sign(payload)

        # Tamper: flip the first byte of the decoded signature
        sig_bytes = bytearray(base64url_decode(signature))
        sig_bytes[0] ^= 0xFF
        tampered_sig = base64url_encode(bytes(sig_bytes))

        with patch("agent_id.identity.client.get_agent", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = _mock_get_agent(agent_a)
            valid = await AgentIdentity.verify(
                did=agent_a.did,
                payload=payload,
                signature=tampered_sig,
            )

        assert valid is False
