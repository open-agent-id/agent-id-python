# agent-id-python

Python SDK for [Open Agent ID](../protocol/) -- register, sign, and verify AI agent identities.

## Installation

```bash
pip install agent-id
```

Or for development:

```bash
pip install -e ".[dev]"
```

## Quick start

### Register a new agent

```python
import asyncio
from agent_id import AgentIdentity

async def main():
    identity = await AgentIdentity.register(
        name="my-search-agent",
        capabilities=["search", "summarize"],
        api_key="your-platform-key",
    )
    print(identity.did)            # did:agent:tokli:agt_...
    print(identity.public_key_base64url)
    # IMPORTANT: persist the private key securely -- it is only returned once.

asyncio.run(main())
```

### Load an existing identity

```python
from agent_id import AgentIdentity

identity = AgentIdentity.load(
    did="did:agent:tokli:agt_a1B2c3D4e5",
    private_key="<base64url-encoded-private-key>",
)
```

### Sign an HTTP request

```python
headers = identity.sign_request("POST", "https://api.example.com/v1/tasks", '{"task":"search"}')
# headers contains X-Agent-DID, X-Agent-Timestamp, X-Agent-Nonce, X-Agent-Signature
```

### Verify another agent's signature

```python
valid = await AgentIdentity.verify(
    did="did:agent:other:agt_X9yZ8wV7u6",
    payload=canonical_payload,
    signature=signature_b64,
)
```

### Look up an agent

```python
info = await AgentIdentity.lookup("did:agent:tokli:agt_a1B2c3D4e5")
print(info["name"], info["status"])
```

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache 2.0 -- see [LICENSE](LICENSE).
