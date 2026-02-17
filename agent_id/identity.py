"""Main AgentIdentity class for the Open Agent ID SDK."""

from __future__ import annotations

import time

from . import crypto, client, did as did_module
from .cache import PublicKeyCache

# Module-level cache shared across all lookups
_key_cache = PublicKeyCache()


class AgentIdentity:
    """Represents an AI agent's identity.

    An AgentIdentity holds a DID, a public key, and optionally a private key.
    When the private key is present the identity can sign payloads and HTTP
    requests.  Verification and lookup are available as static methods.
    """

    def __init__(
        self,
        did: str,
        private_key: bytes | None,
        public_key: bytes,
    ) -> None:
        if not did_module.validate_did(did):
            raise ValueError(f"Invalid DID: {did!r}")
        self._did = did
        self._private_key = private_key
        self._public_key = public_key

    # ------------------------------------------------------------------
    # Constructors
    # ------------------------------------------------------------------

    @classmethod
    async def register(
        cls,
        name: str,
        capabilities: list[str] | None = None,
        api_url: str = "https://api.openagentid.org",
        api_key: str | None = None,
    ) -> "AgentIdentity":
        """Register a new agent identity with the registry.

        The registry generates the keypair server-side.  The private key is
        returned only once in the registration response -- store it securely.

        Args:
            name: Human-readable agent name (max 100 chars).
            capabilities: Optional list of capability strings.
            api_url: Registry API base URL.
            api_key: Platform API key for authentication.

        Returns:
            An AgentIdentity with the private key populated.
        """
        data = await client.register_agent(
            name=name,
            capabilities=capabilities,
            api_url=api_url,
            api_key=api_key,
        )
        priv = crypto.base64url_decode(data["private_key"])
        pub = crypto.base64url_decode(data["public_key"])
        return cls(did=data["did"], private_key=priv, public_key=pub)

    @classmethod
    def load(cls, did: str, private_key: str) -> "AgentIdentity":
        """Load an existing identity from a DID and base64url-encoded private key.

        Args:
            did: The agent's DID string.
            private_key: Base64url-encoded Ed25519 private key (seed or seed||pub).

        Returns:
            An AgentIdentity with the private key populated.
        """
        priv_bytes = crypto.base64url_decode(private_key)
        # Derive the public key from the seed (first 32 bytes)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization

        key = Ed25519PrivateKey.from_private_bytes(priv_bytes[:32])
        pub_bytes = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        # Store full 64-byte private key (seed || public)
        full_priv = priv_bytes[:32] + pub_bytes
        return cls(did=did, private_key=full_priv, public_key=pub_bytes)

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def did(self) -> str:
        """The agent's DID string."""
        return self._did

    @property
    def public_key_base64url(self) -> str:
        """The agent's public key encoded as base64url (no padding)."""
        return crypto.base64url_encode(self._public_key)

    # ------------------------------------------------------------------
    # Signing
    # ------------------------------------------------------------------

    def sign(self, payload: str) -> str:
        """Sign a payload string with this identity's private key.

        Args:
            payload: Arbitrary string to sign.

        Returns:
            Base64url-encoded Ed25519 signature.

        Raises:
            RuntimeError: If this identity has no private key.
        """
        if self._private_key is None:
            raise RuntimeError("Cannot sign: no private key available")
        sig = crypto.sign(payload.encode("utf-8"), self._private_key)
        return crypto.base64url_encode(sig)

    def sign_request(
        self,
        method: str,
        url: str,
        body: str = "",
    ) -> dict[str, str]:
        """Sign an HTTP request and return the headers to attach.

        Constructs the canonical payload per the signing spec:
            {METHOD}\\n{url}\\n{body_sha256}\\n{timestamp}\\n{nonce}

        Args:
            method: HTTP method (will be upper-cased).
            url: Full request URL including query parameters.
            body: Request body string (empty string for GET, etc.).

        Returns:
            Dict of HTTP headers to add to the request:
                X-Agent-DID, X-Agent-Timestamp, X-Agent-Nonce, X-Agent-Signature.
        """
        timestamp = str(int(time.time()))
        nonce = crypto.generate_nonce()
        body_hash = crypto.sha256_hex(body.encode("utf-8"))
        canonical = f"{method.upper()}\n{url}\n{body_hash}\n{timestamp}\n{nonce}"
        signature = self.sign(canonical)
        return {
            "X-Agent-DID": self._did,
            "X-Agent-Timestamp": timestamp,
            "X-Agent-Nonce": nonce,
            "X-Agent-Signature": signature,
        }

    # ------------------------------------------------------------------
    # Verification & lookup (static / async)
    # ------------------------------------------------------------------

    @staticmethod
    async def verify(
        did: str,
        payload: str,
        signature: str,
        api_url: str = "https://api.openagentid.org",
    ) -> bool:
        """Verify a signature from another agent.

        Resolves the public key from cache or the registry API, then verifies
        the Ed25519 signature locally.

        Args:
            did: The signer's DID.
            payload: The canonical payload that was signed.
            signature: Base64url-encoded Ed25519 signature.
            api_url: Registry API base URL.

        Returns:
            True if the signature is valid, False otherwise.
        """
        # Resolve public key: cache first, then API
        pub_bytes = _key_cache.get(did)
        if pub_bytes is None:
            info = await client.get_agent(did, api_url=api_url)
            pub_bytes = crypto.base64url_decode(info["public_key"])
            _key_cache.set(did, pub_bytes)

        sig_bytes = crypto.base64url_decode(signature)
        return crypto.verify(
            payload.encode("utf-8"),
            sig_bytes,
            pub_bytes,
        )

    @staticmethod
    async def lookup(
        did: str,
        api_url: str = "https://api.openagentid.org",
    ) -> dict:
        """Look up agent info by DID.

        Args:
            did: The agent's DID string.
            api_url: Registry API base URL.

        Returns:
            Dict with agent info from the registry.
        """
        return await client.get_agent(did, api_url=api_url)
