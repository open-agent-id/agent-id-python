"""Async HTTP client for the Open Agent ID Registry API."""

from __future__ import annotations

import httpx


async def register_agent(
    name: str,
    capabilities: list[str] | None = None,
    api_url: str = "https://api.openagentid.org",
    api_key: str | None = None,
    user_token: str | None = None,
    public_key: str | None = None,
    owner_id: str | None = None,
) -> dict:
    """Register a new agent identity.

    Args:
        name: Agent name (max 100 characters).
        capabilities: Optional list of capability strings.
        api_url: Base URL for the registry API.
        api_key: Platform API key for authentication.
        user_token: Bearer token from wallet auth (alternative to api_key).
        public_key: Base64url-encoded Ed25519 public key (BYOK mode).
            If provided, the server will not generate a keypair.
        owner_id: Owner wallet address (for platform-key auth).

    Returns:
        Dict with keys: did, public_key, chain_status, created_at.
        Also includes private_key if public_key was not provided (legacy mode).

    Raises:
        httpx.HTTPStatusError: On non-2xx responses.
    """
    headers: dict[str, str] = {}
    if api_key:
        headers["X-Platform-Key"] = api_key
    elif user_token:
        headers["Authorization"] = f"Bearer {user_token}"

    body: dict = {"name": name}
    if capabilities is not None:
        body["capabilities"] = capabilities
    if public_key is not None:
        body["public_key"] = public_key
    if owner_id is not None:
        body["owner_id"] = owner_id

    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{api_url}/v1/agents",
            json=body,
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()


async def get_agent(did: str, api_url: str = "https://api.openagentid.org") -> dict:
    """Look up an agent by DID.

    Args:
        did: The agent DID string.
        api_url: Base URL for the registry API.

    Returns:
        Dict with agent info (did, name, public_key, capabilities, status, etc.).

    Raises:
        httpx.HTTPStatusError: On non-2xx responses.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{api_url}/v1/agents/{did}")
        resp.raise_for_status()
        return resp.json()


async def verify_signature(
    did: str,
    payload: str,
    signature: str,
    api_url: str = "https://api.openagentid.org",
) -> bool:
    """Verify a signature using the remote registry API.

    This is a convenience for when local verification is not possible.
    Prefer local verification via the SDK for better performance.

    Args:
        did: The signer's DID.
        payload: The canonical payload that was signed.
        signature: Base64url-encoded Ed25519 signature.
        api_url: Base URL for the registry API.

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        httpx.HTTPStatusError: On non-2xx responses.
    """
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{api_url}/v1/verify",
            json={
                "did": did,
                "payload": payload,
                "signature": signature,
            },
        )
        resp.raise_for_status()
        return resp.json().get("valid", False)
