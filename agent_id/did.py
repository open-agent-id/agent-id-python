"""DID parsing and validation for Open Agent ID V2.

DID format: did:oaid:{chain}:{agent_address}

- chain: lowercase alphanumeric chain identifier (e.g., "base")
- agent_address: 0x + 40 hex characters (all lowercase)
"""

from __future__ import annotations

import re

# Pre-compiled regex for the V2 DID format
# did:oaid:{chain}:{agent_address}
# chain: 1-20 lowercase alphanumeric chars
# agent_address: 0x + exactly 40 lowercase hex chars
_DID_RE = re.compile(
    r"^did:oaid:([a-z0-9]{1,20}):(0x[0-9a-f]{40})$"
)


def validate_did(did: str) -> bool:
    """Validate a DID string against the Open Agent ID V2 format spec.

    Returns True if valid, False otherwise.
    """
    if not did:
        return False
    return _DID_RE.match(did) is not None


def parse_did(did: str) -> tuple[str, str, str]:
    """Parse a DID string and extract components.

    Args:
        did: A DID string like "did:oaid:base:0x1234abcd..."

    Returns:
        Tuple of (method, chain, agent_address).

    Raises:
        ValueError: If the DID is not valid.
    """
    if not validate_did(did):
        raise ValueError(f"Invalid DID: {did!r}")
    m = _DID_RE.match(did)
    assert m is not None
    return ("oaid", m.group(1), m.group(2))


def format_did(chain: str, agent_address: str) -> str:
    """Format components into a DID string.

    Both chain and agent_address are lowercased automatically.

    Args:
        chain: Chain identifier (e.g., "base").
        agent_address: Agent address (e.g., "0x1234...").

    Returns:
        DID string like "did:oaid:base:0x1234..."

    Raises:
        ValueError: If the resulting DID would be invalid.
    """
    did = f"did:oaid:{chain.lower()}:{agent_address.lower()}"
    if not validate_did(did):
        raise ValueError(f"Invalid DID components: chain={chain!r}, address={agent_address!r}")
    return did
