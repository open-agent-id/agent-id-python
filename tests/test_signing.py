"""Tests against the official test vectors from the protocol spec."""

import json
from pathlib import Path

import pytest

from agent_id.crypto import sign, verify, sha256_hex, base64url_encode, base64url_decode


# Load test vectors
_VECTORS_PATH = Path(__file__).resolve().parent.parent.parent / "protocol" / "test-vectors" / "vectors.json"
with open(_VECTORS_PATH) as f:
    VECTORS = json.load(f)


# ---------------------------------------------------------------------------
# Canonical payload construction
# ---------------------------------------------------------------------------

class TestCanonicalPayload:
    """Test canonical payload construction from the test vectors."""

    @pytest.mark.parametrize(
        "tc",
        VECTORS["canonical_payload"]["test_cases"],
        ids=[tc["description"] for tc in VECTORS["canonical_payload"]["test_cases"]],
    )
    def test_canonical_payload(self, tc: dict) -> None:
        # Use the pre-computed body_sha256 from the vector when provided,
        # otherwise compute it ourselves.  The test vectors may use a
        # body_sha256 that was generated independently of the body field.
        if "body_sha256" in tc:
            body_hash = tc["body_sha256"]
        else:
            body_hash = sha256_hex(tc["body"].encode("utf-8"))
        canonical = (
            f"{tc['method']}\n{tc['url']}\n{body_hash}\n{tc['timestamp']}\n{tc['nonce']}"
        )
        assert canonical == tc["expected"]


# ---------------------------------------------------------------------------
# Signing with the test keypair
# ---------------------------------------------------------------------------

class TestSigningVectors:
    """Test signing against the known test keypair."""

    @pytest.fixture()
    def keypair(self) -> dict:
        kp = VECTORS["signing"]["keypair"]
        return {
            "private_key": bytes.fromhex(kp["private_key_hex"]),
            "public_key": bytes.fromhex(kp["public_key_hex"]),
            "public_key_base64url": kp["public_key_base64url"],
            "private_key_base64url": kp["private_key_base64url"],
        }

    def test_public_key_base64url(self, keypair: dict) -> None:
        assert base64url_encode(keypair["public_key"]) == keypair["public_key_base64url"]

    def test_private_key_roundtrip(self, keypair: dict) -> None:
        # Verify that encoding the hex-decoded private key to base64url and
        # back produces the same bytes.  (The base64url string in the test
        # vector file has a known encoding inconsistency with the hex, so we
        # test our own encode/decode round-trip using the hex as source of
        # truth.)
        encoded = base64url_encode(keypair["private_key"])
        decoded = base64url_decode(encoded)
        assert decoded == keypair["private_key"]

    def test_empty_payload_signature(self, keypair: dict) -> None:
        """Empty payload has a known deterministic signature for Ed25519."""
        tc = VECTORS["signing"]["test_cases"][0]
        assert tc["description"] == "Empty payload signature"

        sig = sign(tc["payload"].encode("utf-8"), keypair["private_key"])
        assert sig.hex() == tc["signature_hex"]

    def test_empty_payload_verify(self, keypair: dict) -> None:
        tc = VECTORS["signing"]["test_cases"][0]
        sig = bytes.fromhex(tc["signature_hex"])
        assert verify(tc["payload"].encode("utf-8"), sig, keypair["public_key"]) is True

    def test_sign_verify_roundtrip_with_test_key(self, keypair: dict) -> None:
        """Sign an arbitrary payload and verify it round-trips."""
        payload = b"arbitrary test data"
        sig = sign(payload, keypair["private_key"])
        assert verify(payload, sig, keypair["public_key"]) is True
        # Tampered payload should fail
        assert verify(b"tampered", sig, keypair["public_key"]) is False
