"""Integration with the oaid-signer daemon.

The oaid-signer is a local daemon that manages agent private keys.
Agent processes never hold private keys directly; instead they request
signatures from the signer daemon via a Unix socket.

Protocol: 4-byte big-endian length prefix + JSON payload.
"""

from __future__ import annotations

import asyncio
import json
import struct
import warnings


class SignerConnectionError(Exception):
    """Raised when connection to oaid-signer daemon fails."""


class SignerError(Exception):
    """Raised when oaid-signer returns an error."""


class Signer:
    """Client for the oaid-signer daemon.

    The signer communicates over a Unix socket using a simple
    length-prefixed JSON protocol.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        socket_path: str,
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._socket_path = socket_path

    @classmethod
    async def connect(
        cls,
        socket_path: str = "/tmp/oaid-signer.sock",
    ) -> "Signer":
        """Connect to local oaid-signer daemon via Unix socket.

        Args:
            socket_path: Path to the Unix domain socket.

        Returns:
            A connected Signer instance.

        Raises:
            SignerConnectionError: If the daemon is not running or the
                socket is not available.
        """
        try:
            reader, writer = await asyncio.open_unix_connection(socket_path)
            return cls(reader, writer, socket_path)
        except (ConnectionRefusedError, FileNotFoundError, OSError) as exc:
            raise SignerConnectionError(
                f"Cannot connect to oaid-signer at {socket_path}: {exc}"
            ) from exc

    async def _send_request(self, request: dict) -> dict:
        """Send a JSON request and read the JSON response.

        Protocol: 4-byte big-endian length prefix + JSON bytes.
        """
        data = json.dumps(request).encode("utf-8")
        # Write length-prefixed message
        self._writer.write(struct.pack(">I", len(data)) + data)
        await self._writer.drain()

        # Read length-prefixed response
        length_bytes = await self._reader.readexactly(4)
        length = struct.unpack(">I", length_bytes)[0]
        response_bytes = await self._reader.readexactly(length)
        response = json.loads(response_bytes)

        if "error" in response:
            raise SignerError(response["error"])

        return response

    async def sign(self, key_id: str, operation: str, data: bytes) -> bytes:
        """Request a signature from the daemon.

        Args:
            key_id: Key identifier for the signing key.
            operation: Operation type (e.g., "http", "message").
            data: The bytes to sign.

        Returns:
            64-byte Ed25519 signature.
        """
        from . import crypto

        response = await self._send_request({
            "action": "sign",
            "key_id": key_id,
            "operation": operation,
            "data": crypto.base64url_encode(data),
        })
        return crypto.base64url_decode(response["signature"])

    async def get_public_key(self, key_id: str) -> bytes:
        """Get the public key for a key_id.

        Args:
            key_id: Key identifier.

        Returns:
            32-byte Ed25519 public key.
        """
        from . import crypto

        response = await self._send_request({
            "action": "get_public_key",
            "key_id": key_id,
        })
        return crypto.base64url_decode(response["public_key"])

    async def close(self) -> None:
        """Close the connection to the signer daemon."""
        self._writer.close()
        await self._writer.wait_closed()

    async def __aenter__(self) -> "Signer":
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.close()
