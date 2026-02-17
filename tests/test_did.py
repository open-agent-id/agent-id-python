"""Tests for DID validation and parsing."""

import pytest

from agent_id.did import validate_did, parse_did, generate_unique_id


# ---------------------------------------------------------------------------
# Validation — valid DIDs (from test vectors)
# ---------------------------------------------------------------------------

VALID_DIDS = [
    "did:agent:tokli:agt_a1B2c3D4e5",
    "did:agent:openai:agt_X9yZ8wV7u6",
    "did:agent:langchain:agt_Q3rS4tU5v6",
    "did:agent:abc:agt_0000000000",
]


@pytest.mark.parametrize("did", VALID_DIDS)
def test_validate_valid(did: str) -> None:
    assert validate_did(did) is True


# ---------------------------------------------------------------------------
# Validation — invalid DIDs (from test vectors)
# ---------------------------------------------------------------------------

INVALID_DIDS = [
    "did:agent:AB:agt_a1B2c3D4e5",                    # platform too short (2 chars) and uppercase
    "did:agent:toolongplatformnamehere:agt_a1B2c3D4e5", # platform > 20 chars
    "did:agent:tokli:a1B2c3D4e5",                      # missing agt_ prefix
    "did:agent:tokli:agt_short",                       # unique_id too short
    "did:agent:tokli:agt_a1B2c3D4e5!",                 # invalid character
    "did:other:tokli:agt_a1B2c3D4e5",                  # wrong method
    "did:agent:UPPER:agt_a1B2c3D4e5",                  # uppercase platform
    "",                                                 # empty string
]


@pytest.mark.parametrize("did", INVALID_DIDS)
def test_validate_invalid(did: str) -> None:
    assert validate_did(did) is False


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_parse_did_valid() -> None:
    result = parse_did("did:agent:tokli:agt_a1B2c3D4e5")
    assert result == {
        "method": "agent",
        "platform": "tokli",
        "unique_id": "agt_a1B2c3D4e5",
    }


def test_parse_did_invalid_raises() -> None:
    with pytest.raises(ValueError):
        parse_did("did:other:tokli:agt_a1B2c3D4e5")


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def test_generate_unique_id_format() -> None:
    uid = generate_unique_id()
    assert uid.startswith("agt_")
    assert len(uid) == 14  # 'agt_' (4) + 10 base62 chars
    # Should be valid when used in a DID
    assert validate_did(f"did:agent:test:{uid}") is True


def test_generate_unique_id_randomness() -> None:
    ids = {generate_unique_id() for _ in range(100)}
    # Extremely unlikely to have collisions
    assert len(ids) == 100
