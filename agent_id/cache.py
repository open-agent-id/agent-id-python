"""Simple in-memory TTL cache for public keys."""

from __future__ import annotations

import time


class PublicKeyCache:
    """Thread-safe in-memory cache with time-to-live for public keys."""

    def __init__(self, ttl: int = 3600) -> None:
        self._ttl = ttl
        self._store: dict[str, tuple[bytes, float]] = {}

    def get(self, did: str) -> bytes | None:
        """Get a cached public key for a DID.

        Returns the public key bytes, or None if not found or expired.
        """
        entry = self._store.get(did)
        if entry is None:
            return None
        public_key, stored_at = entry
        if time.time() - stored_at > self._ttl:
            del self._store[did]
            return None
        return public_key

    def set(self, did: str, public_key: bytes) -> None:
        """Cache a public key for a DID."""
        self._store[did] = (public_key, time.time())

    def invalidate(self, did: str) -> None:
        """Remove a DID from the cache."""
        self._store.pop(did, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        self._store.clear()
