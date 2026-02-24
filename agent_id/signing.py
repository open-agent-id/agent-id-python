"""Signature construction and verification for Open Agent ID V2.

Two signing domains:
- oaid-http/v1: HTTP request signing
- oaid-msg/v1: Agent-to-agent message signing
"""

from __future__ import annotations

import json
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from . import crypto

if TYPE_CHECKING:
    from .signer import Signer

# Constants
DEFAULT_EXPIRE_SECONDS = 300
HTTP_TIMESTAMP_TOLERANCE = 300
DEDUP_CACHE_TTL = 600


def canonical_url(url: str) -> str:
    """Normalize URL: lowercase host, sort query params, strip fragment.

    Args:
        url: The URL to canonicalize.

    Returns:
        Normalized URL string.
    """
    parsed = urlparse(url)
    # Lowercase the scheme and host
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    # Sort query parameters
    params = parse_qs(parsed.query, keep_blank_values=True)
    sorted_params = sorted(params.items())
    # Flatten: each key may have multiple values, sort those too
    flat_params: list[tuple[str, str]] = []
    for key, values in sorted_params:
        for v in sorted(values):
            flat_params.append((key, v))
    query = urlencode(flat_params)
    # No fragment
    return urlunparse((scheme, netloc, path, parsed.params, query, ""))


def canonical_json(obj: dict) -> bytes:
    """Serialize dict to canonical JSON: sorted keys, no whitespace, UTF-8.

    Args:
        obj: Dictionary to serialize.

    Returns:
        UTF-8 encoded canonical JSON bytes.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _build_http_payload(
    method: str,
    url: str,
    body: bytes | None,
    timestamp: int,
    nonce: str,
) -> bytes:
    """Build the oaid-http/v1 signing payload."""
    body_hash = crypto.sha256(body if body is not None else b"")
    canon_url = canonical_url(url)
    payload = f"oaid-http/v1\n{method.upper()}\n{canon_url}\n{body_hash}\n{timestamp}\n{nonce}"
    return payload.encode("utf-8")


def sign_http_request(
    private_key_or_signer: bytes | "Signer",
    method: str,
    url: str,
    body: bytes | None,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    """Construct oaid-http/v1 payload, sign, and return headers dict.

    Args:
        private_key_or_signer: 32 or 64-byte Ed25519 private key bytes.
            Signer objects are not supported in sync mode; use
            sign_http_request_async for Signer support.
        method: HTTP method (GET, POST, etc.).
        url: Full request URL.
        body: Request body bytes, or None for GET requests.
        timestamp: Unix timestamp. Auto-generated if None.
        nonce: Hex nonce. Auto-generated if None.

    Returns:
        Dict of HTTP headers: X-Agent-Timestamp, X-Agent-Nonce, X-Agent-Signature.
    """
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = crypto.generate_nonce()

    payload = _build_http_payload(method, url, body, timestamp, nonce)

    if isinstance(private_key_or_signer, bytes):
        signature = crypto.ed25519_sign(private_key_or_signer, payload)
    else:
        raise TypeError("Use sign_http_request_async for Signer objects")

    return {
        "X-Agent-Timestamp": str(timestamp),
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": crypto.base64url_encode(signature),
    }


async def sign_http_request_async(
    private_key_or_signer: bytes | "Signer",
    method: str,
    url: str,
    body: bytes | None,
    timestamp: int | None = None,
    nonce: str | None = None,
    key_id: str | None = None,
) -> dict[str, str]:
    """Async version of sign_http_request supporting Signer objects.

    Args:
        private_key_or_signer: Ed25519 private key bytes or Signer instance.
        method: HTTP method.
        url: Full request URL.
        body: Request body bytes, or None.
        timestamp: Unix timestamp. Auto-generated if None.
        nonce: Hex nonce. Auto-generated if None.
        key_id: Key identifier for Signer. Required when using Signer.

    Returns:
        Dict of HTTP headers.
    """
    from .signer import Signer

    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = crypto.generate_nonce()

    payload = _build_http_payload(method, url, body, timestamp, nonce)

    if isinstance(private_key_or_signer, Signer):
        if key_id is None:
            raise ValueError("key_id is required when using Signer")
        signature = await private_key_or_signer.sign(key_id, "http", payload)
    else:
        signature = crypto.ed25519_sign(private_key_or_signer, payload)

    return {
        "X-Agent-Timestamp": str(timestamp),
        "X-Agent-Nonce": nonce,
        "X-Agent-Signature": crypto.base64url_encode(signature),
    }


def verify_http_signature(
    public_key: bytes,
    method: str,
    url: str,
    body: bytes | None,
    timestamp: int,
    nonce: str,
    signature: bytes,
) -> bool:
    """Verify an oaid-http/v1 signature.

    Args:
        public_key: 32-byte Ed25519 public key.
        method: HTTP method.
        url: Full request URL.
        body: Request body bytes, or None.
        timestamp: Unix timestamp from the request.
        nonce: Hex nonce from the request.
        signature: 64-byte Ed25519 signature.

    Returns:
        True if valid, False otherwise.
    """
    payload = _build_http_payload(method, url, body, timestamp, nonce)
    return crypto.ed25519_verify(public_key, payload, signature)


def _build_message_payload(
    msg_type: str,
    msg_id: str,
    from_did: str,
    to_dids: list[str],
    ref: str | None,
    timestamp: int,
    expires_at: int | None,
    body: dict,
) -> bytes:
    """Build the oaid-msg/v1 signing payload."""
    sorted_to = ",".join(sorted(to_dids))
    ref_str = ref if ref is not None else ""
    expires_str = str(expires_at) if expires_at is not None else ""
    body_hash = crypto.sha256(canonical_json(body))
    payload = (
        f"oaid-msg/v1\n{msg_type}\n{msg_id}\n{from_did}\n{sorted_to}\n"
        f"{ref_str}\n{timestamp}\n{expires_str}\n{body_hash}"
    )
    return payload.encode("utf-8")


def sign_message(
    private_key_or_signer: bytes | "Signer",
    msg_type: str,
    msg_id: str,
    from_did: str,
    to_dids: list[str],
    ref: str | None,
    timestamp: int | None,
    expires_at: int | None,
    body: dict,
) -> bytes:
    """Construct oaid-msg/v1 payload and sign.

    Args:
        private_key_or_signer: Ed25519 private key bytes.
        msg_type: Message type string.
        msg_id: Message identifier.
        from_did: Sender DID.
        to_dids: List of recipient DIDs.
        ref: Optional reference to a previous message.
        timestamp: Unix timestamp. Auto-generated if None.
        expires_at: Optional expiration timestamp.
        body: Message body dict.

    Returns:
        64-byte Ed25519 signature.
    """
    if timestamp is None:
        timestamp = int(time.time())

    payload = _build_message_payload(
        msg_type, msg_id, from_did, to_dids, ref, timestamp, expires_at, body
    )

    if isinstance(private_key_or_signer, bytes):
        return crypto.ed25519_sign(private_key_or_signer, payload)
    else:
        raise TypeError("Use sign_message_async for Signer objects")


def verify_message_signature(
    public_key: bytes,
    msg_type: str,
    msg_id: str,
    from_did: str,
    to_dids: list[str],
    ref: str | None,
    timestamp: int,
    expires_at: int | None,
    body: dict,
    signature: bytes,
) -> bool:
    """Verify an oaid-msg/v1 signature.

    Args:
        public_key: 32-byte Ed25519 public key.
        msg_type: Message type string.
        msg_id: Message identifier.
        from_did: Sender DID.
        to_dids: List of recipient DIDs.
        ref: Optional reference to a previous message.
        timestamp: Unix timestamp.
        expires_at: Optional expiration timestamp.
        body: Message body dict.
        signature: 64-byte Ed25519 signature.

    Returns:
        True if valid, False otherwise.
    """
    payload = _build_message_payload(
        msg_type, msg_id, from_did, to_dids, ref, timestamp, expires_at, body
    )
    return crypto.ed25519_verify(public_key, payload, signature)
