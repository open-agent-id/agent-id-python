"""Tests for DID validation, parsing, and formatting (V2)."""

import pytest

from agent_id.did import validate_did, parse_did, format_did


# ---------------------------------------------------------------------------
# Validation -- valid DIDs
# ---------------------------------------------------------------------------

VALID_DIDS = [
    "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
    "did:oaid:ethereum:0x0000000000000000000000000000000000000000",
    "did:oaid:base:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    "did:oaid:a:0xffffffffffffffffffffffffffffffffffffffff",
]


@pytest.mark.parametrize("did", VALID_DIDS)
def test_validate_valid(did: str) -> None:
    assert validate_did(did) is True


# ---------------------------------------------------------------------------
# Validation -- invalid DIDs
# ---------------------------------------------------------------------------

INVALID_DIDS = [
    "",                                                                     # empty
    "did:agent:tokli:agt_a1B2c3D4e5",                                      # V1 format
    "did:oaid:base:0x1234",                                                 # address too short
    "did:oaid:base:0x1234567890abcdef1234567890abcdef1234567890",            # address too long (42 hex)
    "did:oaid:base:1234567890abcdef1234567890abcdef12345678",               # missing 0x prefix
    "did:oaid:BASE:0x1234567890abcdef1234567890abcdef12345678",             # uppercase chain
    "did:oaid:base:0x1234567890ABCDEF1234567890abcdef12345678",             # uppercase hex in address
    "did:oaid:base:0xgggggggggggggggggggggggggggggggggggggggg",             # invalid hex chars
    "did:other:base:0x1234567890abcdef1234567890abcdef12345678",            # wrong method
    "did:oaid::0x1234567890abcdef1234567890abcdef12345678",                 # empty chain
]


@pytest.mark.parametrize("did", INVALID_DIDS)
def test_validate_invalid(did: str) -> None:
    assert validate_did(did) is False


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_parse_did_valid() -> None:
    method, chain, address = parse_did(
        "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678"
    )
    assert method == "oaid"
    assert chain == "base"
    assert address == "0x1234567890abcdef1234567890abcdef12345678"


def test_parse_did_invalid_raises() -> None:
    with pytest.raises(ValueError):
        parse_did("did:agent:tokli:agt_a1B2c3D4e5")


def test_parse_did_returns_tuple() -> None:
    result = parse_did("did:oaid:ethereum:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
    assert isinstance(result, tuple)
    assert len(result) == 3


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

def test_format_did() -> None:
    did = format_did("base", "0x1234567890abcdef1234567890abcdef12345678")
    assert did == "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678"


def test_format_did_lowercases() -> None:
    did = format_did("Base", "0x1234567890ABCDEF1234567890abcdef12345678")
    assert did == "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678"


def test_format_did_invalid_raises() -> None:
    with pytest.raises(ValueError):
        format_did("base", "not-an-address")
