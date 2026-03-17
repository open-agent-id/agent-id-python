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

## Quick start

### Create an Agent and sign an HTTP request

```python
from agent_id import Agent, sign_http_request, verify_http_signature

# Load an agent from a private key
agent = Agent(
    did="did:oaid:base:0x1234567890abcdef1234567890abcdef12345678",
    private_key=b"...",  # 32-byte Ed25519 seed
)

# Sign an HTTP request (oaid-http/v1 domain)
headers = sign_http_request(
    agent.private_key,
    method="POST",
    url="https://api.example.com/v1/tasks",
    body=b'{"task":"search"}',
)
# headers: X-Agent-Timestamp, X-Agent-Nonce, X-Agent-Signature
```

### Sign a message (agent-to-agent)

```python
from agent_id import sign_message, verify_message_signature

# Sign a P2P message (oaid-msg/v1 domain)
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

### Async signing with the Signer daemon

```python
from agent_id import sign_http_request_async, sign_message_async, Signer

signer = Signer(socket_path="/tmp/oaid-signer.sock")

# Async HTTP request signing
headers = await sign_http_request_async(
    signer, method="GET", url="https://api.example.com/data", body=None, key_id="key-1"
)

# Async message signing
sig = await sign_message_async(
    signer, msg_type="request", msg_id="msg-002",
    from_did="did:oaid:base:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    to_dids=["did:oaid:base:0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],
    ref=None, timestamp=None, expires_at=None, body={"hello": "world"}, key_id="key-1",
)
```

### DID utilities

```python
from agent_id import validate_did, parse_did, format_did

validate_did("did:oaid:base-sepolia:0x1234567890abcdef1234567890abcdef12345678")  # True

method, chain, address = parse_did("did:oaid:base:0x1234567890abcdef1234567890abcdef12345678")
# ("oaid", "base", "0x1234...")

did = format_did("base", "0x1234567890abcdef1234567890abcdef12345678")
```

### Registry client

```python
from agent_id import RegistryClient

client = RegistryClient()  # defaults to https://api.openagentid.org
```

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache 2.0 -- see [LICENSE](LICENSE).
