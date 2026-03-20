"""Tests for the RegistryClient (async HTTP client)."""

from __future__ import annotations

import httpx
import pytest

from agent_id.client import RegistryClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_transport(handler):
    """Create an httpx.MockTransport from an async handler function."""
    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# get_credit
# ---------------------------------------------------------------------------


class TestGetCredit:
    @pytest.mark.asyncio
    async def test_calls_correct_url(self) -> None:
        """get_credit should GET /v1/credit/{did}."""
        captured_request = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_request["url"] = str(request.url)
            captured_request["method"] = request.method
            return httpx.Response(200, json={"score": 85, "did": "did:oaid:base:0xabc"})

        transport = _mock_transport(handler)
        async with RegistryClient(
            base_url="https://api.test.local",
            client=httpx.AsyncClient(transport=transport),
        ) as client:
            result = await client.get_credit("did:oaid:base:0xabc")

        assert captured_request["method"] == "GET"
        assert captured_request["url"] == "https://api.test.local/v1/credit/did:oaid:base:0xabc"
        assert result == {"score": 85, "did": "did:oaid:base:0xabc"}

    @pytest.mark.asyncio
    async def test_raises_on_http_error(self) -> None:
        """get_credit should raise on non-2xx status."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, json={"error": "not found"})

        transport = _mock_transport(handler)
        async with RegistryClient(
            base_url="https://api.test.local",
            client=httpx.AsyncClient(transport=transport),
        ) as client:
            with pytest.raises(httpx.HTTPStatusError):
                await client.get_credit("did:oaid:base:0xnonexistent")


# ---------------------------------------------------------------------------
# list_agents
# ---------------------------------------------------------------------------


class TestListAgents:
    @pytest.mark.asyncio
    async def test_sends_auth_token_header(self) -> None:
        """list_agents should send Authorization: Bearer <token>."""
        captured_headers = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_headers.update(dict(request.headers))
            return httpx.Response(200, json={"agents": [], "next_cursor": None})

        transport = _mock_transport(handler)
        async with RegistryClient(
            base_url="https://api.test.local",
            client=httpx.AsyncClient(transport=transport),
        ) as client:
            await client.list_agents("oaid_test_token_123")

        assert captured_headers["authorization"] == "Bearer oaid_test_token_123"

    @pytest.mark.asyncio
    async def test_sends_query_params(self) -> None:
        """list_agents should send limit and cursor as query params."""
        captured_url = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured_url["url"] = str(request.url)
            return httpx.Response(200, json={"agents": [], "next_cursor": None})

        transport = _mock_transport(handler)
        async with RegistryClient(
            base_url="https://api.test.local",
            client=httpx.AsyncClient(transport=transport),
        ) as client:
            await client.list_agents("oaid_tok", limit=5, cursor="abc123")

        url = captured_url["url"]
        assert "limit=5" in url
        assert "cursor=abc123" in url

    @pytest.mark.asyncio
    async def test_calls_correct_endpoint(self) -> None:
        """list_agents should GET /v1/agents."""
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["method"] = request.method
            captured["path"] = request.url.path
            return httpx.Response(200, json={"agents": [], "next_cursor": None})

        transport = _mock_transport(handler)
        async with RegistryClient(
            base_url="https://api.test.local",
            client=httpx.AsyncClient(transport=transport),
        ) as client:
            await client.list_agents("oaid_tok")

        assert captured["method"] == "GET"
        assert captured["path"] == "/v1/agents"


# ---------------------------------------------------------------------------
# close() and context manager
# ---------------------------------------------------------------------------


class TestCloseAndContextManager:
    @pytest.mark.asyncio
    async def test_close_owned_client(self) -> None:
        """close() should close the internal client when we own it."""
        client = RegistryClient(base_url="https://api.test.local")
        assert client._owns_client is True
        await client.close()
        # After close, the underlying httpx client should be closed
        assert client._client.is_closed

    @pytest.mark.asyncio
    async def test_close_does_not_close_external_client(self) -> None:
        """close() should NOT close a client passed from outside."""
        external = httpx.AsyncClient()
        try:
            client = RegistryClient(
                base_url="https://api.test.local",
                client=external,
            )
            assert client._owns_client is False
            await client.close()
            # External client should still be open
            assert not external.is_closed
        finally:
            await external.aclose()

    @pytest.mark.asyncio
    async def test_context_manager_closes_on_exit(self) -> None:
        """async with RegistryClient() should close the client on exit."""
        client = RegistryClient(base_url="https://api.test.local")
        async with client:
            assert not client._client.is_closed
        assert client._client.is_closed

    @pytest.mark.asyncio
    async def test_context_manager_returns_self(self) -> None:
        """async with RegistryClient() as c should return the client."""
        original = RegistryClient(base_url="https://api.test.local")
        async with original as c:
            assert c is original

    @pytest.mark.asyncio
    async def test_context_manager_with_external_client(self) -> None:
        """Context manager should not close an externally-provided client."""
        external = httpx.AsyncClient()
        try:
            async with RegistryClient(
                base_url="https://api.test.local",
                client=external,
            ):
                pass
            # external client should still be usable
            assert not external.is_closed
        finally:
            await external.aclose()
