# Post-Quantum Cryptographic Tokens (PQT)

A JWT-like token format using post-quantum digital signatures for authentication and authorization.

## Overview

PQC Tokens provide a quantum-resistant alternative to traditional JWTs:

- **Token Format**: `<header>.<payload>.<signature>` (base64url encoded)
- **Standard Claims**: Compatible with JWT registered claims (iss, sub, aud, exp, nbf, iat, jti)
- **Post-Quantum Signatures**: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)

### Comparison with JWT

| Feature | JWT | PQT |
|---------|-----|-----|
| Format | `header.payload.signature` | `header.payload.signature` |
| Encoding | Base64url | Base64url |
| Algorithm Header | `alg: RS256, ES256, etc.` | `alg: MLDSA44, MLDSA65, etc.` |
| Type Header | `typ: JWT` | `typ: PQT` |
| Quantum Resistant | No | Yes |

### Algorithm Recommendations

| Use Case | Algorithm | Rationale |
|----------|-----------|-----------|
| Short-lived tokens | **ML-DSA-44** | Smallest signatures, fastest |
| Standard auth tokens | **ML-DSA-65** | Balanced security/size |
| High-security tokens | **ML-DSA-87** | Maximum security |

### Token Size Comparison

| Algorithm | Signature Size | Token Overhead |
|-----------|---------------|----------------|
| RS256 | ~256 bytes | ~350 bytes |
| ES256 | 64 bytes | ~90 bytes |
| ML-DSA-44 | 2,420 bytes | ~3,230 bytes |
| ML-DSA-65 | 3,309 bytes | ~4,415 bytes |
| ML-DSA-87 | 4,627 bytes | ~6,170 bytes |

## Quick Start (Docker)

### 1. Generate Token Keys

```bash
# From project root
make keygen-cpp ALG=mldsa65 OUT=pqc-token CN="Token Signing Key"
```

### 2. Create a Token

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  dsa-py python examples/use-cases/pqc-token/pqc_token.py create \
    --key /keys/pqc-token_secret.key \
    --payload '{"sub": "user123", "role": "admin"}' \
    --expires 3600
```

Output:
```
eyJhbGciOiJNTERTQTY1IiwidHlwIjoiUFFUIn0.eyJzdWIiOiJ1c2VyMTIzIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzA1MzE4MDAwLCJleHAiOjE3MDUzMjE2MDB9.ABCD...
```

### 3. Verify a Token

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  dsa-py python examples/use-cases/pqc-token/pqc_token.py verify \
    --key /keys/pqc-token_public.key \
    --token "eyJhbGciOiJNTERTQTY1..."
```

Output:
```
==================================================
  Token Verification Result
==================================================

Algorithm:  MLDSA65
Type:       PQT

Claims:
  sub: user123
  role: admin
  iat: 1705318000 (2024-01-15T10:00:00+00:00)
  exp: 1705321600 (2024-01-15T11:00:00+00:00)

Status: VALID
==================================================
```

## Library Usage

### Python - Creating Tokens

```python
from pqc_token import PQCToken

# Create a simple token
token = PQCToken.create(
    payload={"sub": "user123", "role": "admin"},
    secret_key_path="keys/token_secret.key",
    expires_in=3600,  # 1 hour
)

# Create token with all standard claims
token = PQCToken.create(
    payload={"scope": "read write", "permissions": ["users:read", "orders:write"]},
    secret_key_path="keys/token_secret.key",
    expires_in=86400,        # 24 hours
    issuer="auth.example.com",
    subject="user@example.com",
    audience="api.example.com",
    token_id="unique-token-id-123",
)
```

### Python - Verifying Tokens

```python
from pqc_token import PQCToken

# Basic verification
result = PQCToken.verify(
    token=token_string,
    public_key_path="keys/token_public.key",
)

if result.valid:
    print(f"Token valid! Subject: {result.payload['sub']}")
else:
    print(f"Token invalid: {result.error}")

# Verification with options
result = PQCToken.verify(
    token=token_string,
    public_key_path="keys/token_public.key",
    verify_exp=True,      # Check expiration
    verify_nbf=True,      # Check not-before
    leeway=60,            # 60 second clock skew allowance
)
```

### Python - Decoding Without Verification

```python
from pqc_token import PQCToken

# Decode token to inspect claims (without verification)
result = PQCToken.decode(token_string)
print(f"Algorithm: {result.header['alg']}")
print(f"Subject: {result.payload.get('sub')}")
print(f"Expires: {result.payload.get('exp')}")

# Get specific claim
subject = PQCToken.get_claim(token_string, "sub")
```

## Token Format

### Header

```json
{
  "alg": "MLDSA65",
  "typ": "PQT"
}
```

### Payload (Claims)

```json
{
  "iss": "auth.example.com",
  "sub": "user@example.com",
  "aud": "api.example.com",
  "exp": 1705321600,
  "nbf": 1705318000,
  "iat": 1705318000,
  "jti": "unique-token-id",
  "role": "admin",
  "permissions": ["users:read", "orders:write"]
}
```

### Registered Claims

| Claim | Name | Description |
|-------|------|-------------|
| `iss` | Issuer | Token issuer identifier |
| `sub` | Subject | Token subject (user ID) |
| `aud` | Audience | Intended recipient |
| `exp` | Expiration | Expiration time (Unix timestamp) |
| `nbf` | Not Before | Token not valid before (Unix timestamp) |
| `iat` | Issued At | Token creation time |
| `jti` | JWT ID | Unique token identifier |

## Integration Examples

### FastAPI Middleware

```python
from fastapi import FastAPI, Request, HTTPException, Depends
from pqc_token import PQCToken, TokenResult

app = FastAPI()

async def verify_token(request: Request) -> TokenResult:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")

    token = auth_header[7:]  # Remove "Bearer " prefix

    result = PQCToken.verify(
        token=token,
        public_key_path="keys/token_public.key",
    )

    if not result.valid:
        raise HTTPException(status_code=401, detail=result.error)

    return result

@app.get("/api/protected")
async def protected_route(token_result: TokenResult = Depends(verify_token)):
    return {
        "message": "Access granted",
        "user": token_result.payload.get("sub"),
    }
```

### Flask Decorator

```python
from functools import wraps
from flask import Flask, request, jsonify, g
from pqc_token import PQCToken

app = Flask(__name__)

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing token"}), 401

        token = auth_header[7:]
        result = PQCToken.verify(
            token=token,
            public_key_path="keys/token_public.key",
        )

        if not result.valid:
            return jsonify({"error": result.error}), 401

        g.token_payload = result.payload
        return f(*args, **kwargs)

    return decorated

@app.route("/api/user")
@require_token
def get_user():
    return jsonify({
        "user": g.token_payload.get("sub"),
        "role": g.token_payload.get("role"),
    })
```

### Client SDK

```python
import requests
from pqc_token import PQCToken

class PQTClient:
    def __init__(self, base_url: str, secret_key_path: str):
        self.base_url = base_url
        self.secret_key_path = secret_key_path
        self._token = None
        self._token_exp = 0

    def _get_token(self):
        import time
        if self._token and time.time() < self._token_exp - 60:
            return self._token

        self._token = PQCToken.create(
            payload={"client": "my-service"},
            secret_key_path=self.secret_key_path,
            expires_in=3600,
        )
        self._token_exp = time.time() + 3600
        return self._token

    def request(self, method: str, path: str, **kwargs):
        headers = kwargs.pop("headers", {})
        headers["Authorization"] = f"Bearer {self._get_token()}"

        return requests.request(
            method,
            f"{self.base_url}{path}",
            headers=headers,
            **kwargs
        )

# Usage
client = PQTClient(
    base_url="https://api.example.com",
    secret_key_path="keys/client_secret.key",
)

response = client.request("GET", "/api/users")
```

## Security Considerations

### Token Expiration

Always set reasonable expiration times:

```python
# Short-lived tokens for API access (15 minutes)
token = PQCToken.create(
    payload={"sub": "user123"},
    secret_key_path="keys/token_secret.key",
    expires_in=900,
)

# Refresh tokens (7 days) - store securely
refresh_token = PQCToken.create(
    payload={"sub": "user123", "type": "refresh"},
    secret_key_path="keys/refresh_secret.key",
    expires_in=604800,
)
```

### Key Rotation

Support multiple signing keys:

```python
# Server maintains multiple public keys
PUBLIC_KEYS = {
    "key-v1": load_key("keys/token_v1_public.key"),
    "key-v2": load_key("keys/token_v2_public.key"),
}

def verify_with_key_id(token: str, key_id: str):
    if key_id not in PUBLIC_KEYS:
        return {"error": "Unknown key ID"}

    return PQCToken.verify(
        token=token,
        public_key=PUBLIC_KEYS[key_id],
    )
```

### Token Storage

- **Access tokens**: Store in memory only, never in localStorage
- **Refresh tokens**: Store in HTTP-only, secure cookies
- **Server-side**: Consider token blacklisting for logout

### Clock Skew

Allow for clock differences between servers:

```python
result = PQCToken.verify(
    token=token_string,
    public_key_path="keys/token_public.key",
    leeway=60,  # 60 seconds tolerance
)
```

## CLI Reference

### Create Token

```bash
pqc_token.py create [OPTIONS]

Required:
  -k, --key FILE          Secret key file
  -p, --payload JSON      Token payload

Options:
  -a, --algorithm ALG     Signing algorithm
  --expires SECONDS       Expiration time
  --issuer STRING         Issuer claim
  --subject STRING        Subject claim
  --audience STRING       Audience claim
  --token-id STRING       Token ID claim
  --json                  JSON output
```

### Verify Token

```bash
pqc_token.py verify [OPTIONS]

Required:
  -k, --key FILE          Public key file
  -t, --token STRING      Token to verify

Options:
  -a, --algorithm ALG     Expected algorithm
  --no-exp                Skip expiration check
  --no-nbf                Skip not-before check
  --leeway SECONDS        Clock skew allowance
  --json                  JSON output
  -q, --quiet             Exit code only
```

### Decode Token

```bash
pqc_token.py decode [OPTIONS]

Required:
  -t, --token STRING      Token to decode

Options:
  --json                  JSON output
```

## Testing

Run the test suite:

```bash
make test-examples-pqc-token
```

## Related Examples

- [API Signing](../api-signing/) - Sign API requests
- [Code Signing](../code-signing/) - Sign software releases
- [Document Signing](../document-signing/) - Sign documents
