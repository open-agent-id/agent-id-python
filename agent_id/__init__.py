"""Open Agent ID Python SDK (V2).

Register, sign, and verify AI agent identities using the Open Agent ID protocol.
"""

from .agent import Agent
from .signer import Signer
from .client import RegistryClient
from .did import parse_did, validate_did, format_did
from .signing import (
    sign_agent_auth,
    verify_agent_auth,
    sign_http_request,
    sign_http_request_async,
    verify_http_signature,
    sign_message,
    sign_message_async,
    verify_message_signature,
    canonical_url,
    canonical_json,
)
from .crypto import (
    generate_ed25519_keypair,
    ed25519_sign,
    ed25519_verify,
    base64url_encode,
    base64url_decode,
    sha256,
    ed25519_to_x25519_public,
    ed25519_to_x25519_private,
    encrypt_for,
    decrypt_from,
)

__all__ = [
    "Agent",
    "Signer",
    "RegistryClient",
    "parse_did",
    "validate_did",
    "format_did",
    "sign_agent_auth",
    "verify_agent_auth",
    "sign_http_request",
    "sign_http_request_async",
    "verify_http_signature",
    "sign_message",
    "sign_message_async",
    "verify_message_signature",
    "canonical_url",
    "canonical_json",
    "generate_ed25519_keypair",
    "ed25519_sign",
    "ed25519_verify",
    "base64url_encode",
    "base64url_decode",
    "sha256",
    "ed25519_to_x25519_public",
    "ed25519_to_x25519_private",
    "encrypt_for",
    "decrypt_from",
]
__version__ = "0.2.0"
