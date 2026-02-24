"""Async HTTP client for the Open Agent ID Registry API (V2).

Supports two authentication methods:
1. Wallet auth: Authorization: Bearer oaid_...
2. Agent signature: X-Agent-DID + X-Agent-Timestamp + X-Agent-Nonce + X-Agent-Signature
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from .signer import Signer


class RegistryClient:
    """Client for the Open Agent ID Registry API.

    Provides methods for wallet authentication, agent management,
    and signature verification.
    """

    def __init__(self, base_url: str = "https://api.openagentid.org") -> None:
        self._base_url = base_url.rstrip("/")

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    async def request_challenge(self, wallet_address: str) -> dict:
        """Request a wallet authentication challenge.

        Args:
            wallet_address: Ethereum wallet address (0x...).

        Returns:
            Dict with challenge_id and message to sign.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/v1/auth/challenge",
                json={"wallet_address": wallet_address},
            )
            resp.raise_for_status()
            return resp.json()

    async def verify_wallet(
        self,
        wallet_address: str,
        challenge_id: str,
        signature: str,
    ) -> str:
        """Verify a wallet challenge and get a bearer token.

        Args:
            wallet_address: Ethereum wallet address.
            challenge_id: Challenge ID from request_challenge.
            signature: Wallet signature of the challenge message.

        Returns:
            Bearer token string (oaid_...).
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/v1/auth/verify",
                json={
                    "wallet_address": wallet_address,
                    "challenge_id": challenge_id,
                    "signature": signature,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data["token"]

    # ------------------------------------------------------------------
    # Agent management
    # ------------------------------------------------------------------

    async def register_agent(
        self,
        token: str,
        name: str,
        capabilities: list[str] | None = None,
        public_key: str | None = None,
    ) -> dict:
        """Register a new agent.

        Args:
            token: Bearer token from wallet auth (oaid_...).
            name: Agent name (max 100 characters).
            capabilities: Optional list of capability strings.
            public_key: Base64url-encoded Ed25519 public key.

        Returns:
            Dict with agent info including did, public_key, etc.
        """
        body: dict = {"name": name}
        if capabilities is not None:
            body["capabilities"] = capabilities
        if public_key is not None:
            body["public_key"] = public_key

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/v1/agents",
                json=body,
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()
            return resp.json()

    async def get_agent(self, did: str) -> dict:
        """Look up an agent by DID.

        Args:
            did: The agent DID string.

        Returns:
            Dict with agent info.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(f"{self._base_url}/v1/agents/{did}")
            resp.raise_for_status()
            return resp.json()

    async def list_agents(
        self,
        owner: str,
        limit: int = 20,
        cursor: str | None = None,
    ) -> dict:
        """List agents owned by a wallet address.

        Args:
            owner: Wallet address of the owner.
            limit: Maximum number of results (default 20).
            cursor: Pagination cursor.

        Returns:
            Dict with agents list and next_cursor.
        """
        params: dict = {"owner": owner, "limit": limit}
        if cursor is not None:
            params["cursor"] = cursor

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self._base_url}/v1/agents",
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    async def update_agent(
        self,
        did: str,
        token: str | None = None,
        agent_signer: tuple | None = None,
        **updates: object,
    ) -> dict:
        """Update an agent's properties.

        Auth can be provided either via bearer token or agent signature.

        Args:
            did: The agent DID to update.
            token: Bearer token for wallet auth.
            agent_signer: Tuple of (signer_or_key, key_id) for agent signature auth.
                When provided, the request is signed with agent headers instead.
            **updates: Fields to update (name, capabilities, etc.).

        Returns:
            Updated agent info dict.
        """
        headers: dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"

        if agent_signer is not None:
            from .signing import sign_http_request
            from . import crypto

            signer_or_key, key_id = agent_signer
            body_bytes = crypto.canonical_json(dict(updates)) if updates else b"{}"
            url = f"{self._base_url}/v1/agents/{did}"
            sig_headers = sign_http_request(
                signer_or_key, "PATCH", url, body_bytes,
            )
            headers.update(sig_headers)
            headers["X-Agent-DID"] = did

        async with httpx.AsyncClient() as client:
            resp = await client.patch(
                f"{self._base_url}/v1/agents/{did}",
                json=dict(updates) if updates else {},
                headers=headers,
            )
            resp.raise_for_status()
            return resp.json()

    async def revoke_agent(self, did: str, token: str) -> None:
        """Revoke an agent.

        Args:
            did: The agent DID to revoke.
            token: Bearer token for wallet auth.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self._base_url}/v1/agents/{did}",
                headers={"Authorization": f"Bearer {token}"},
            )
            resp.raise_for_status()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    async def verify_signature(
        self,
        did: str,
        domain: str,
        payload: str,
        signature: str,
    ) -> bool:
        """Verify a signature using the registry API.

        Args:
            did: The signer's DID.
            domain: Signing domain ("http" or "message").
            payload: The canonical payload that was signed.
            signature: Base64url-encoded Ed25519 signature.

        Returns:
            True if valid, False otherwise.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self._base_url}/v1/verify",
                json={
                    "did": did,
                    "domain": domain,
                    "payload": payload,
                    "signature": signature,
                },
            )
            resp.raise_for_status()
            return resp.json().get("valid", False)
