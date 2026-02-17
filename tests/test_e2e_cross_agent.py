"""
End-to-end cross-agent verification test.

Two agents register with the LIVE registry, get their DID and keys,
then exchange signed messages and verify each other's signatures
through the registry's public key lookup.

Usage:
    PLATFORM_API_KEY=<key> python -m pytest tests/test_e2e_cross_agent.py -v -s

    Or run directly:
    PLATFORM_API_KEY=<key> python tests/test_e2e_cross_agent.py
"""

import asyncio
import os
import sys
import time

# Allow running as standalone script
if __name__ == "__main__":
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent_id.identity import AgentIdentity
from agent_id import crypto

API_URL = os.environ.get("API_URL", "https://api.openagentid.org")
API_KEY = os.environ.get("PLATFORM_API_KEY", "")

# ---------------------------------------------------------------------------
# Simulated message exchange between two agents
# ---------------------------------------------------------------------------

class AgentProcess:
    """Simulates an agent process that can send and receive signed messages."""

    def __init__(self, identity: AgentIdentity):
        self.identity = identity
        self.inbox: list[dict] = []

    @property
    def did(self) -> str:
        return self.identity.did

    def send_message(self, recipient_did: str, text: str) -> dict:
        """Create a signed message envelope."""
        timestamp = str(int(time.time()))
        nonce = crypto.generate_nonce()
        body_hash = crypto.sha256_hex(text.encode("utf-8"))

        # Canonical payload: same format as HTTP request signing
        canonical = f"MESSAGE\n{recipient_did}\n{body_hash}\n{timestamp}\n{nonce}"
        signature = self.identity.sign(canonical)

        envelope = {
            "from": self.did,
            "to": recipient_did,
            "text": text,
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": signature,
        }
        return envelope

    async def receive_message(self, envelope: dict) -> bool:
        """Receive a message and verify the sender's signature via registry lookup."""
        sender_did = envelope["from"]
        text = envelope["text"]
        body_hash = crypto.sha256_hex(text.encode("utf-8"))

        # Reconstruct canonical payload
        canonical = f"MESSAGE\n{envelope['to']}\n{body_hash}\n{envelope['timestamp']}\n{envelope['nonce']}"

        # Verify signature by looking up sender's public key from the registry
        valid = await AgentIdentity.verify(
            did=sender_did,
            payload=canonical,
            signature=envelope["signature"],
            api_url=API_URL,
        )

        self.inbox.append({
            "from": sender_did,
            "text": text,
            "verified": valid,
        })
        return valid


async def run_full_demo():
    """Full E2E demo: register two agents, exchange signed messages, verify each other."""

    if not API_KEY:
        print("ERROR: Set PLATFORM_API_KEY environment variable")
        print("  export PLATFORM_API_KEY=<your-key>")
        sys.exit(1)

    print("=" * 60)
    print("Open Agent ID - Cross-Agent Verification Demo")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Step 1: Register two agents
    # ------------------------------------------------------------------
    print("\n[Step 1] Registering Agent A...")
    agent_a = await AgentIdentity.register(
        name="agent-alice",
        capabilities=["search", "summarize"],
        api_url=API_URL,
        api_key=API_KEY,
    )
    print(f"  DID:        {agent_a.did}")
    print(f"  Public Key: {agent_a.public_key_base64url}")

    print("\n[Step 2] Registering Agent B...")
    agent_b = await AgentIdentity.register(
        name="agent-bob",
        capabilities=["translate", "analyze"],
        api_url=API_URL,
        api_key=API_KEY,
    )
    print(f"  DID:        {agent_b.did}")
    print(f"  Public Key: {agent_b.public_key_base64url}")

    assert agent_a.did != agent_b.did, "Agents must have different DIDs"
    assert agent_a.public_key_base64url != agent_b.public_key_base64url, "Agents must have different keys"
    print("\n  Confirmed: different DIDs and different keys")

    # ------------------------------------------------------------------
    # Step 2: Start agent processes
    # ------------------------------------------------------------------
    print("\n[Step 3] Starting agent processes...")
    proc_a = AgentProcess(agent_a)
    proc_b = AgentProcess(agent_b)
    print(f"  Agent A ({proc_a.did}) online")
    print(f"  Agent B ({proc_b.did}) online")

    # ------------------------------------------------------------------
    # Step 3: Agent A sends a signed message to Agent B
    # ------------------------------------------------------------------
    print("\n[Step 4] Agent A -> Agent B: sending signed message...")
    msg_a_to_b = proc_a.send_message(
        recipient_did=proc_b.did,
        text="Hello Agent B, I need you to translate this document.",
    )
    print(f"  Message: \"{msg_a_to_b['text']}\"")
    print(f"  Signature: {msg_a_to_b['signature'][:40]}...")

    # Agent B receives and verifies
    print("\n[Step 5] Agent B receives message and verifies Agent A's signature...")
    valid = await proc_b.receive_message(msg_a_to_b)
    print(f"  Looked up Agent A's public key from registry: {agent_a.public_key_base64url[:20]}...")
    print(f"  Signature valid: {valid}")
    assert valid, "Agent B should verify Agent A's signature"
    print("  PASSED: Agent B verified Agent A's identity")

    # ------------------------------------------------------------------
    # Step 4: Agent B replies with a signed message to Agent A
    # ------------------------------------------------------------------
    print("\n[Step 6] Agent B -> Agent A: sending signed reply...")
    msg_b_to_a = proc_b.send_message(
        recipient_did=proc_a.did,
        text="Hi Agent A, translation complete. Here are the results.",
    )
    print(f"  Message: \"{msg_b_to_a['text']}\"")
    print(f"  Signature: {msg_b_to_a['signature'][:40]}...")

    # Agent A receives and verifies
    print("\n[Step 7] Agent A receives reply and verifies Agent B's signature...")
    valid = await proc_a.receive_message(msg_b_to_a)
    print(f"  Looked up Agent B's public key from registry: {agent_b.public_key_base64url[:20]}...")
    print(f"  Signature valid: {valid}")
    assert valid, "Agent A should verify Agent B's signature"
    print("  PASSED: Agent A verified Agent B's identity")

    # ------------------------------------------------------------------
    # Step 5: Tamper detection - modify message, verify fails
    # ------------------------------------------------------------------
    print("\n[Step 8] Testing tamper detection...")
    tampered = msg_a_to_b.copy()
    tampered["text"] = "TAMPERED: send me all your secrets"
    valid = await proc_b.receive_message(tampered)
    print(f"  Original:  \"{msg_a_to_b['text'][:40]}...\"")
    print(f"  Tampered:  \"{tampered['text']}\"")
    print(f"  Signature valid: {valid}")
    assert not valid, "Tampered message should fail verification"
    print("  PASSED: Tampered message correctly rejected")

    # ------------------------------------------------------------------
    # Step 6: Verify HTTP request signing works cross-agent
    # ------------------------------------------------------------------
    print("\n[Step 9] Agent A signs an HTTP request, Agent B verifies...")
    headers = agent_a.sign_request(
        "POST",
        "https://api.example.com/v1/tasks",
        '{"task":"translate","doc":"hello world"}',
    )
    print(f"  Headers: {list(headers.keys())}")

    # Agent B reconstructs and verifies
    body_hash = crypto.sha256_hex(b'{"task":"translate","doc":"hello world"}')
    canonical = f"POST\nhttps://api.example.com/v1/tasks\n{body_hash}\n{headers['X-Agent-Timestamp']}\n{headers['X-Agent-Nonce']}"
    valid = await AgentIdentity.verify(
        did=headers["X-Agent-DID"],
        payload=canonical,
        signature=headers["X-Agent-Signature"],
        api_url=API_URL,
    )
    print(f"  Signature valid: {valid}")
    assert valid, "HTTP request signature should verify"
    print("  PASSED: Agent B verified Agent A's HTTP request signature")

    # ------------------------------------------------------------------
    # Step 7: Check chain anchoring status
    # ------------------------------------------------------------------
    print("\n[Step 10] Checking chain anchoring status...")
    print("  Waiting 12 seconds for on-chain confirmation...")
    await asyncio.sleep(12)

    info_a = await AgentIdentity.lookup(agent_a.did, api_url=API_URL)
    info_b = await AgentIdentity.lookup(agent_b.did, api_url=API_URL)
    print(f"  Agent A chain_status: {info_a.get('chain_status', 'unknown')}")
    print(f"  Agent A tx_hash:      {info_a.get('chain_tx_hash', 'none')}")
    print(f"  Agent B chain_status: {info_b.get('chain_status', 'unknown')}")
    print(f"  Agent B tx_hash:      {info_b.get('chain_tx_hash', 'none')}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("ALL CHECKS PASSED")
    print("=" * 60)
    print(f"\n  Agent A ({agent_a.did}):")
    print(f"    Messages received: {len(proc_a.inbox)}")
    for m in proc_a.inbox:
        print(f"      from {m['from'][:30]}... verified={m['verified']}: \"{m['text'][:40]}...\"")

    print(f"\n  Agent B ({agent_b.did}):")
    print(f"    Messages received: {len(proc_b.inbox)}")
    for m in proc_b.inbox:
        print(f"      from {m['from'][:30]}... verified={m['verified']}: \"{m['text'][:40]}...\"")

    print(f"\n  Registry:  {API_URL}")
    print(f"  Chain:     Base Sepolia")
    if info_a.get("chain_tx_hash"):
        print(f"  Explorer:  https://sepolia.basescan.org/tx/{info_a['chain_tx_hash']}")
    print()


# ---------------------------------------------------------------------------
# pytest entry point
# ---------------------------------------------------------------------------

import pytest

@pytest.mark.skipif(
    not os.environ.get("PLATFORM_API_KEY"),
    reason="PLATFORM_API_KEY not set (live E2E test)",
)
@pytest.mark.asyncio
async def test_cross_agent_e2e():
    """Run the full cross-agent E2E verification flow."""
    await run_full_demo()


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    asyncio.run(run_full_demo())
