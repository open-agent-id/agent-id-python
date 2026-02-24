"""High-level Agent class for Open Agent ID V2.

Provides a convenient interface for agents to sign HTTP requests,
send messages, and interact with the registry.
"""

from __future__ import annotations

import uuid
import time
from typing import Any

import httpx

from .signer import Signer
from .signing import (
    sign_http_request_async,
    canonical_json,
    DEFAULT_EXPIRE_SECONDS,
)
from .client import RegistryClient
from . import crypto


class _HttpNamespace:
    """Namespace for HTTP methods on Agent, providing auto-signed requests."""

    def __init__(self, agent: "Agent") -> None:
        self._agent = agent

    async def get(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send an auto-signed HTTP GET request.

        Args:
            url: The URL to request.
            **kwargs: Additional keyword arguments passed to httpx.

        Returns:
            httpx.Response object.
        """
        headers = await self._agent._sign_http("GET", url, None)
        merged_headers = {**headers, **kwargs.pop("headers", {})}
        async with httpx.AsyncClient() as client:
            return await client.get(url, headers=merged_headers, **kwargs)

    async def post(
        self,
        url: str,
        body: dict | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an auto-signed HTTP POST request.

        Args:
            url: The URL to request.
            body: Optional JSON body dict.
            **kwargs: Additional keyword arguments passed to httpx.

        Returns:
            httpx.Response object.
        """
        body_bytes = canonical_json(body) if body is not None else None
        headers = await self._agent._sign_http("POST", url, body_bytes)
        merged_headers = {**headers, **kwargs.pop("headers", {})}
        async with httpx.AsyncClient() as client:
            if body is not None:
                merged_headers["Content-Type"] = "application/json"
                return await client.post(
                    url, content=body_bytes, headers=merged_headers, **kwargs
                )
            else:
                return await client.post(url, headers=merged_headers, **kwargs)

    async def put(
        self,
        url: str,
        body: dict | None = None,
        **kwargs: Any,
    ) -> httpx.Response:
        """Send an auto-signed HTTP PUT request.

        Args:
            url: The URL to request.
            body: Optional JSON body dict.
            **kwargs: Additional keyword arguments passed to httpx.

        Returns:
            httpx.Response object.
        """
        body_bytes = canonical_json(body) if body is not None else None
        headers = await self._agent._sign_http("PUT", url, body_bytes)
        merged_headers = {**headers, **kwargs.pop("headers", {})}
        async with httpx.AsyncClient() as client:
            if body is not None:
                merged_headers["Content-Type"] = "application/json"
                return await client.put(
                    url, content=body_bytes, headers=merged_headers, **kwargs
                )
            else:
                return await client.put(url, headers=merged_headers, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> httpx.Response:
        """Send an auto-signed HTTP DELETE request.

        Args:
            url: The URL to request.
            **kwargs: Additional keyword arguments passed to httpx.

        Returns:
            httpx.Response object.
        """
        headers = await self._agent._sign_http("DELETE", url, None)
        merged_headers = {**headers, **kwargs.pop("headers", {})}
        async with httpx.AsyncClient() as client:
            return await client.delete(url, headers=merged_headers, **kwargs)


class Agent:
    """High-level agent interface for Open Agent ID V2.

    Wraps a Signer connection and provides convenient methods for
    signing HTTP requests, sending messages, and interacting with
    the registry.
    """

    def __init__(
        self,
        did: str,
        key_id: str,
        signer: Signer,
        registry_url: str = "https://api.openagentid.org",
    ) -> None:
        self._did = did
        self._key_id = key_id
        self._signer = signer
        self._registry = RegistryClient(registry_url)
        self.http = _HttpNamespace(self)

    @property
    def did(self) -> str:
        """The agent's DID string."""
        return self._did

    async def _sign_http(
        self,
        method: str,
        url: str,
        body: bytes | None,
    ) -> dict[str, str]:
        """Sign an HTTP request and return headers including X-Agent-DID."""
        headers = await sign_http_request_async(
            self._signer, method, url, body, key_id=self._key_id,
        )
        headers["X-Agent-DID"] = self._did
        return headers

    async def send(self, to: str | list[str], message: dict) -> dict:
        """Send a signed message to another agent or agents.

        Args:
            to: Recipient DID or list of recipient DIDs.
            message: Message body dict.

        Returns:
            Dict with message envelope including signature.
        """
        if isinstance(to, str):
            to_dids = [to]
        else:
            to_dids = to

        msg_id = str(uuid.uuid4())
        timestamp = int(time.time())
        expires_at = timestamp + DEFAULT_EXPIRE_SECONDS

        from .signing import _build_message_payload
        payload = _build_message_payload(
            msg_type="message",
            msg_id=msg_id,
            from_did=self._did,
            to_dids=to_dids,
            ref=None,
            timestamp=timestamp,
            expires_at=expires_at,
            body=message,
        )

        signature = await self._signer.sign(self._key_id, "message", payload)

        return {
            "type": "message",
            "id": msg_id,
            "from": self._did,
            "to": to_dids,
            "ref": None,
            "timestamp": timestamp,
            "expires_at": expires_at,
            "body": message,
            "signature": crypto.base64url_encode(signature),
        }

    async def sign(self, data: bytes) -> bytes:
        """Sign arbitrary data via the oaid-signer.

        Args:
            data: Bytes to sign.

        Returns:
            64-byte Ed25519 signature.
        """
        return await self._signer.sign(self._key_id, "raw", data)
