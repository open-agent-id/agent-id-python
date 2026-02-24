"""Tests for signing and verification (V2).

Tests the oaid-http/v1 and oaid-msg/v1 signing domains,
as well as canonical_url and canonical_json utilities.
"""

import json
import time

import pytest

from agent_id.crypto import generate_ed25519_keypair, base64url_decode
from agent_id.signing import (
    sign_http_request,
    verify_http_signature,
    sign_message,
    verify_message_signature,
    canonical_url,
    canonical_json,
    _build_http_payload,
    _build_message_payload,
)


# ---------------------------------------------------------------------------
# canonical_url
# ---------------------------------------------------------------------------

class TestCanonicalUrl:
    def test_basic(self) -> None:
        assert canonical_url("https://api.example.com/v1/agents") == "https://api.example.com/v1/agents"

    def test_lowercase_host(self) -> None:
        assert canonical_url("https://API.Example.COM/v1/agents") == "https://api.example.com/v1/agents"

    def test_sort_query_params(self) -> None:
        result = canonical_url("https://api.example.com/search?z=1&a=2&m=3")
        assert result == "https://api.example.com/search?a=2&m=3&z=1"

    def test_strip_fragment(self) -> None:
        result = canonical_url("https://api.example.com/path#section")
        assert result == "https://api.example.com/path"

    def test_preserves_path(self) -> None:
        result = canonical_url("https://api.example.com/V1/Agents/did:oaid:base:0x1234")
        assert "/V1/Agents/did:oaid:base:0x1234" in result

    def test_empty_query(self) -> None:
        result = canonical_url("https://api.example.com/path")
        assert result == "https://api.example.com/path"

    def test_duplicate_query_keys(self) -> None:
        result = canonical_url("https://api.example.com/search?b=2&a=3&a=1")
        # Both 'a' values preserved, sorted
        assert "a=1" in result and "a=3" in result and "b=2" in result

    def test_lowercase_scheme(self) -> None:
        result = canonical_url("HTTPS://api.example.com/path")
        assert result.startswith("https://")


# ---------------------------------------------------------------------------
# canonical_json
# ---------------------------------------------------------------------------

class TestCanonicalJson:
    def test_sorted_keys(self) -> None:
        result = canonical_json({"z": 1, "a": 2, "m": 3})
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_no_whitespace(self) -> None:
        result = canonical_json({"key": "value", "nested": {"a": 1}})
        assert b" " not in result
        assert b"\n" not in result

    def test_utf8_encoding(self) -> None:
        result = canonical_json({"msg": "hello"})
        assert isinstance(result, bytes)
        assert result.decode("utf-8") == '{"msg":"hello"}'

    def test_empty_dict(self) -> None:
        assert canonical_json({}) == b"{}"

    def test_nested_sorting(self) -> None:
        result = canonical_json({"b": {"z": 1, "a": 2}, "a": 1})
        parsed = json.loads(result)
        assert list(parsed.keys()) == ["a", "b"]


# ---------------------------------------------------------------------------
# HTTP signing (oaid-http/v1)
# ---------------------------------------------------------------------------

class TestHttpSigning:
    def test_sign_returns_required_headers(self) -> None:
        priv, pub = generate_ed25519_keypair()
        headers = sign_http_request(priv, "POST", "https://api.example.com/v1/agents", b'{"name":"test"}')
        assert "X-Agent-Timestamp" in headers
        assert "X-Agent-Nonce" in headers
        assert "X-Agent-Signature" in headers
        # Timestamp is numeric
        int(headers["X-Agent-Timestamp"])
        # Nonce is hex
        int(headers["X-Agent-Nonce"], 16)

    def test_sign_verify_roundtrip(self) -> None:
        priv, pub = generate_ed25519_keypair()
        body = b'{"task":"search"}'
        ts = int(time.time())
        nonce = "abcdef1234567890abcdef1234567890"

        headers = sign_http_request(priv, "POST", "https://api.example.com/v1/tasks", body, timestamp=ts, nonce=nonce)
        sig = base64url_decode(headers["X-Agent-Signature"])

        assert verify_http_signature(
            pub, "POST", "https://api.example.com/v1/tasks", body, ts, nonce, sig
        ) is True

    def test_verify_fails_with_wrong_body(self) -> None:
        priv, pub = generate_ed25519_keypair()
        body = b'{"task":"search"}'
        ts = int(time.time())
        nonce = "abcdef1234567890abcdef1234567890"

        headers = sign_http_request(priv, "POST", "https://api.example.com/v1/tasks", body, timestamp=ts, nonce=nonce)
        sig = base64url_decode(headers["X-Agent-Signature"])

        # Different body should fail
        assert verify_http_signature(
            pub, "POST", "https://api.example.com/v1/tasks", b'{"task":"tampered"}', ts, nonce, sig
        ) is False

    def test_verify_fails_with_wrong_key(self) -> None:
        priv1, _ = generate_ed25519_keypair()
        _, pub2 = generate_ed25519_keypair()
        body = b'{"task":"search"}'
        ts = int(time.time())
        nonce = "abcdef1234567890abcdef1234567890"

        headers = sign_http_request(priv1, "POST", "https://api.example.com/v1/tasks", body, timestamp=ts, nonce=nonce)
        sig = base64url_decode(headers["X-Agent-Signature"])

        assert verify_http_signature(
            pub2, "POST", "https://api.example.com/v1/tasks", body, ts, nonce, sig
        ) is False

    def test_sign_none_body(self) -> None:
        priv, pub = generate_ed25519_keypair()
        ts = int(time.time())
        nonce = "abcdef1234567890abcdef1234567890"

        headers = sign_http_request(priv, "GET", "https://api.example.com/v1/agents", None, timestamp=ts, nonce=nonce)
        sig = base64url_decode(headers["X-Agent-Signature"])

        assert verify_http_signature(
            pub, "GET", "https://api.example.com/v1/agents", None, ts, nonce, sig
        ) is True

    def test_payload_has_domain_prefix(self) -> None:
        payload = _build_http_payload("GET", "https://example.com", None, 1000, "abc123")
        assert payload.startswith(b"oaid-http/v1\n")

    def test_payload_contains_method(self) -> None:
        payload = _build_http_payload("POST", "https://example.com", b"body", 1000, "abc123")
        lines = payload.decode("utf-8").split("\n")
        assert lines[0] == "oaid-http/v1"
        assert lines[1] == "POST"

    def test_url_is_canonicalized_in_payload(self) -> None:
        payload = _build_http_payload("GET", "https://API.Example.COM/path?b=2&a=1", None, 1000, "abc123")
        text = payload.decode("utf-8")
        assert "api.example.com" in text
        assert "a=1" in text


# ---------------------------------------------------------------------------
# Message signing (oaid-msg/v1)
# ---------------------------------------------------------------------------

class TestMessageSigning:
    def test_sign_verify_roundtrip(self) -> None:
        priv, pub = generate_ed25519_keypair()
        from_did = "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678"
        to_dids = ["did:oaid:base:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"]
        body = {"text": "hello agent"}
        ts = int(time.time())

        sig = sign_message(priv, "message", "msg-001", from_did, to_dids, None, ts, None, body)
        assert len(sig) == 64

        assert verify_message_signature(
            pub, "message", "msg-001", from_did, to_dids, None, ts, None, body, sig
        ) is True

    def test_verify_fails_with_different_body(self) -> None:
        priv, pub = generate_ed25519_keypair()
        from_did = "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678"
        to_dids = ["did:oaid:base:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"]
        body = {"text": "hello agent"}
        ts = int(time.time())

        sig = sign_message(priv, "message", "msg-001", from_did, to_dids, None, ts, None, body)

        assert verify_message_signature(
            pub, "message", "msg-001", from_did, to_dids, None, ts, None, {"text": "tampered"}, sig
        ) is False

    def test_to_dids_are_sorted(self) -> None:
        """The order of to_dids should not matter -- they are sorted in the payload."""
        priv, pub = generate_ed25519_keypair()
        from_did = "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678"
        to_a = "did:oaid:base:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        to_b = "did:oaid:base:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        body = {"text": "multi-recipient"}
        ts = int(time.time())

        sig = sign_message(priv, "message", "msg-002", from_did, [to_b, to_a], None, ts, None, body)

        # Verify with reversed order should also work (both get sorted)
        assert verify_message_signature(
            pub, "message", "msg-002", from_did, [to_a, to_b], None, ts, None, body, sig
        ) is True

    def test_with_ref_and_expires(self) -> None:
        priv, pub = generate_ed25519_keypair()
        from_did = "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678"
        to_dids = ["did:oaid:base:0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"]
        body = {"text": "reply"}
        ts = int(time.time())
        expires = ts + 300

        sig = sign_message(
            priv, "reply", "msg-003", from_did, to_dids,
            "msg-001", ts, expires, body,
        )

        assert verify_message_signature(
            pub, "reply", "msg-003", from_did, to_dids,
            "msg-001", ts, expires, body, sig,
        ) is True

    def test_payload_has_domain_prefix(self) -> None:
        payload = _build_message_payload(
            "message", "id", "from", ["to"], None, 1000, None, {},
        )
        assert payload.startswith(b"oaid-msg/v1\n")

    def test_empty_ref_is_empty_string(self) -> None:
        payload = _build_message_payload(
            "message", "id", "from", ["to"], None, 1000, None, {},
        )
        lines = payload.decode("utf-8").split("\n")
        # ref is at index 5 (0: domain, 1: type, 2: id, 3: from, 4: sorted_to, 5: ref)
        assert lines[5] == ""

    def test_expires_at_none_is_empty_string(self) -> None:
        payload = _build_message_payload(
            "message", "id", "from", ["to"], None, 1000, None, {},
        )
        lines = payload.decode("utf-8").split("\n")
        # expires_at is at index 7
        assert lines[7] == ""
