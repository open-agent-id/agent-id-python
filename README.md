# open-agent-id

Python SDK for [Open Agent ID](https://openagentid.org) -- sign and verify AI agent identities using the V2 protocol.

## Installation

```bash
pip install open-agent-id
```

Or for development:

```bash
pip install -e ".[dev]"
```

## Quick Start

The most common use case is adding agent authentication headers to outbound requests:

```python
from agent_id import sign_agent_auth

headers = sign_agent_auth(
    "did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
    private_key,  # 32-byte Ed25519 seed
)
# Returns dict with:
#   "X-Agent-DID":       "did:oaid:base:0x1234..."
#   "X-Agent-Timestamp": "1708123456"
#   "X-Agent-Nonce":     "a3f1b2c4d5e6f7089012abcd"
#   "X-Agent-Signature": "<base64url signature>"

import httpx
resp = httpx.post("https://api.example.com/v1/tasks", headers=headers, json={"task": "search"})
```

## Registry Client

```python
from agent_id import RegistryClient

client = RegistryClient()  # defaults to https://api.openagentid.org
```

### All methods

| Method | Auth required | Description |
|---|---|---|
| `client.request_challenge(wallet_address)` | No | Request a wallet auth challenge |
| `client.verify_wallet(wallet_address, challenge_id, signature)` | No | Verify wallet signature, returns auth token |
| `client.register_agent(token, name, public_key, capabilities=None)` | Yes | Register a new agent |
| `client.get_agent(did)` | No | Look up an agent by DID |
| `client.list_agents(token, limit=20, cursor=None)` | Yes | List agents owned by the authenticated wallet |
| `client.update_agent(did, token=None, agent_signer=None, **updates)` | Yes | Update agent metadata |
| `client.revoke_agent(did, token)` | Yes | Revoke an agent identity |
| `client.rotate_key(did, token, public_key)` | Yes | Rotate an agent's public key |
| `client.deploy_wallet(did, token)` | Yes | Deploy an on-chain smart wallet for an agent |
| `client.get_credit(did)` | No | Look up an agent's credit score |
| `client.verify_signature(did, domain, payload, signature)` | No | Verify a signature against the agent's registered key |

### Wallet auth flow

```python
# 1. Request challenge
challenge = await client.request_challenge(wallet_address)

# 2. Sign the challenge text with your wallet (e.g. via web3.py)
# wallet_signature = ...

# 3. Verify and get auth token
token = await client.verify_wallet(wallet_address, challenge["challenge_id"], wallet_signature)
```

### Register an agent

```python
agent = await client.register_agent(
    token,
    name="my-agent",
    public_key=base64url_public_key,
    capabilities=["search", "summarize"],
)
```

### Look up and list agents

```python
info = await client.get_agent("did:oaid:base:0x1234...")
agents = await client.list_agents(token)
```

### Manage agents

```python
await client.update_agent(did, token=token, name="new-name")
await client.rotate_key(did, token, new_public_key)
await client.revoke_agent(did, token)
await client.deploy_wallet(did, token)
```

## Credit Score

```python
credit = await client.get_credit("did:oaid:base:0x1234567890abcdef1234567890abcdef12345678")
print(credit["credit_score"])  # 300
print(credit["level"])         # "verified"
```

## HTTP Signing

### Sign an HTTP request

```python
from agent_id import sign_http_request, verify_http_signature

headers = sign_http_request(
    private_key,
    method="POST",
    url="https://api.example.com/v1/tasks",
    body=b'{"task":"search"}',
)
# headers: X-Agent-Timestamp, X-Agent-Nonce, X-Agent-Signature
```

### Verify an HTTP signature

```python
valid = verify_http_signature(
    public_key, method="POST", url=url, body=body,
    timestamp=timestamp, nonce=nonce, signature=signature,
)
```

### Async signing with the Signer daemon

```python
from agent_id import sign_http_request_async, Signer

signer = Signer(socket_path="/tmp/oaid-signer.sock")
headers = await sign_http_request_async(
    signer, method="GET", url="https://api.example.com/data", body=None, key_id="key-1"
)
```

## Message Signing

### Sign a P2P message

```python
from agent_id import sign_message, verify_message_signature

signature = sign_message(
    private_key,
    msg_type="request",
    msg_id="msg-001",
    from_did="did:oaid:base:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    to_dids=["did:oaid:base:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    ref=None,
    timestamp=None,  # auto-generated
    expires_at=None,
    body={"task": "summarize", "url": "https://example.com"},
)
```

### Async message signing

```python
from agent_id import sign_message_async

sig = await sign_message_async(
    signer, msg_type="request", msg_id="msg-002",
    from_did="did:oaid:base:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    to_dids=["did:oaid:base:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    ref=None, timestamp=None, expires_at=None, body={"hello": "world"}, key_id="key-1",
)
```

## E2E Encryption

```python
from agent_id import encrypt_for, decrypt_from

# Encrypt a message for another agent (NaCl box: X25519-XSalsa20-Poly1305)
ciphertext = encrypt_for(
    b"secret message",
    recipient_public_key,  # 32-byte Ed25519 public key
    sender_private_key,    # 32-byte Ed25519 seed
)

# Recipient decrypts
plaintext = decrypt_from(ciphertext, sender_public_key, recipient_private_key)
```

## DID Utilities

```python
from agent_id import validate_did, parse_did, format_did

validate_did("did:oaid:base-sepolia:0x1234567890abcdef1234567890abcdef12345678")  # True

method, chain, address = parse_did("did:oaid:base:0x1234567890abcdef1234567890abcdef12345678")
# ("oaid", "base", "0x1234...")

did = format_did("base", "0x1234567890abcdef1234567890abcdef12345678")
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache-2.0 -- see [LICENSE](LICENSE).
