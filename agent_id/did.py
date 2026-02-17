"""DID parsing and validation for the Open Agent ID format.

DID format: did:agent:{platform}:{unique_id}

- platform: 3-20 lowercase alphanumeric characters [a-z0-9]
- unique_id: 'agt_' followed by exactly 10 base62 characters [0-9A-Za-z]
- Total DID length must not exceed 60 characters.
"""

from __future__ import annotations

import re
import secrets
import string

# Base62 character set: 0-9, A-Z, a-z
BASE62_CHARS = string.digits + string.ascii_uppercase + string.ascii_lowercase

# Pre-compiled regex for the full DID format
_DID_RE = re.compile(
    r"^did:agent:([a-z0-9]{3,20}):(agt_[0-9A-Za-z]{10})$"
)


def validate_did(did: str) -> bool:
    """Validate a DID string against the Open Agent ID format spec.

    Returns True if valid, False otherwise.
    """
    if not did or len(did) > 60:
        return False
    return _DID_RE.match(did) is not None


def parse_did(did: str) -> dict:
    """Parse a DID string and extract components.

    Returns:
        Dict with keys: 'method', 'platform', 'unique_id'.

    Raises:
        ValueError: If the DID is not valid.
    """
    if not validate_did(did):
        raise ValueError(f"Invalid DID: {did!r}")
    m = _DID_RE.match(did)
    assert m is not None
    return {
        "method": "agent",
        "platform": m.group(1),
        "unique_id": m.group(2),
    }


def generate_unique_id() -> str:
    """Generate a random unique ID in the format agt_ + 10 base62 chars."""
    suffix = "".join(secrets.choice(BASE62_CHARS) for _ in range(10))
    return f"agt_{suffix}"
