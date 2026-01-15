# Post-Quantum API Request Signing

Sign and verify HTTP API requests using post-quantum cryptographic signatures for authentication.

## Overview

This example demonstrates API request signing similar to AWS Signature Version 4, but using post-quantum algorithms:

- **Request Signing**: Sign HTTP method, path, headers, and body
- **Replay Protection**: Timestamp-based request expiration
- **Content Integrity**: SHA-256 hash of request body
- **Key Rotation**: Support for key identifiers

### Features

| Feature | Description |
|---------|-------------|
| Post-Quantum Signatures | ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) |
| Canonical Request | Deterministic request serialization |
| Timestamp Validation | 5-minute request window (configurable) |
| Content Hash | SHA-256 body hash included in signature |
| Key Rotation | Key ID support for seamless rotation |

### Algorithm Recommendations

| Use Case | Algorithm | Rationale |
|----------|-----------|-----------|
| High-traffic APIs | **ML-DSA-44** | Fastest, smallest signatures |
| Standard APIs | **ML-DSA-65** | Balanced security/performance |
| Sensitive APIs | **ML-DSA-87** | Maximum security |

## Quick Start (Docker)

### 1. Generate API Keys

```bash
# From project root
make keygen-cpp ALG=mldsa65 OUT=api-signing CN="API Signing Key"
```

### 2. Sign a Request

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  dsa-py python examples/use-cases/api-signing/sign_request.py \
    --key /keys/api-signing_secret.key \
    --method POST \
    --path /api/v1/orders \
    --header "Content-Type: application/json" \
    --body '{"item": "widget", "quantity": 10}'
```

Output:
```
Signed Headers:
----------------------------------------
X-PQC-Date: 20240115T103000Z
X-PQC-Content-SHA256: abc123...
X-PQC-Algorithm: mldsa65
Authorization: PQC-MLDSA65 KeyId=default, SignedHeaders=..., Signature=...
```

### 3. Verify a Request

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  dsa-py python examples/use-cases/api-signing/verify_request.py \
    --key /keys/api-signing_public.key \
    --method POST \
    --path /api/v1/orders \
    --header "Content-Type: application/json" \
    --header "X-PQC-Date: 20240115T103000Z" \
    --header "X-PQC-Content-SHA256: abc123..." \
    --header "Authorization: PQC-MLDSA65 KeyId=default, ..." \
    --body '{"item": "widget", "quantity": 10}'
```

## Library Usage

### Python - Signing Requests

```python
from sign_request import RequestSigner

# Initialize signer
signer = RequestSigner(
    secret_key_path="keys/api_secret.key",
    key_id="my-service-v1",
)

# Sign a request
signed_headers = signer.sign_request(
    method="POST",
    path="/api/v1/orders",
    headers={"Content-Type": "application/json"},
    body={"item": "widget", "quantity": 10},
    host="api.example.com",
)

# Add signed headers to your HTTP request
requests.post(
    "https://api.example.com/api/v1/orders",
    json={"item": "widget", "quantity": 10},
    headers={**original_headers, **signed_headers},
)
```

### Python - Verifying Requests

```python
from verify_request import RequestVerifier

# Initialize verifier
verifier = RequestVerifier(
    public_key_path="keys/api_public.key",
)

# Verify incoming request (Flask example)
@app.before_request
def verify_signature():
    result = verifier.verify_request(
        method=request.method,
        path=request.path,
        headers=dict(request.headers),
        query_params=request.args.to_dict(),
        body=request.get_json(silent=True),
    )

    if not result.valid:
        return jsonify({"error": "Invalid signature"}), 401
```

## Signature Format

### Authorization Header

```
Authorization: PQC-MLDSA65 KeyId=my-key, SignedHeaders=content-type;host;x-pqc-content-sha256;x-pqc-date, Signature=<hex-encoded-signature>
```

### Required Headers

| Header | Description |
|--------|-------------|
| `Authorization` | Contains algorithm, key ID, signed headers, and signature |
| `X-PQC-Date` | Request timestamp in ISO 8601 basic format |
| `X-PQC-Content-SHA256` | SHA-256 hash of request body |
| `X-PQC-Algorithm` | Algorithm used for signing |

### Canonical Request Format

The signature is computed over a canonical request:

```
<HTTP-Method>
<Canonical-URI>
<Canonical-Query-String>
<Canonical-Headers>

<Signed-Headers>
<Content-SHA256>
```

Example:
```
POST
/api/v1/orders

content-type:application/json
host:api.example.com
x-pqc-content-sha256:abc123...
x-pqc-date:20240115T103000Z

content-type;host;x-pqc-content-sha256;x-pqc-date
abc123...
```

## Integration Examples

### Flask Middleware

```python
from flask import Flask, request, jsonify
from verify_request import RequestVerifier

app = Flask(__name__)
verifier = RequestVerifier(public_key_path="keys/api_public.key")

@app.before_request
def verify_pqc_signature():
    # Skip verification for certain paths
    if request.path in ["/health", "/metrics"]:
        return None

    result = verifier.verify_request(
        method=request.method,
        path=request.path,
        headers=dict(request.headers),
        query_params=request.args.to_dict(),
        body=request.get_data() or None,
    )

    if not result.valid:
        return jsonify({
            "error": "Authentication failed",
            "reason": result.error,
        }), 401

@app.route("/api/v1/orders", methods=["POST"])
def create_order():
    # Request is already verified
    return jsonify({"status": "created"})
```

### FastAPI Dependency

```python
from fastapi import FastAPI, Request, Depends, HTTPException
from verify_request import RequestVerifier

app = FastAPI()
verifier = RequestVerifier(public_key_path="keys/api_public.key")

async def verify_signature(request: Request):
    body = await request.body()

    result = verifier.verify_request(
        method=request.method,
        path=request.url.path,
        headers=dict(request.headers),
        query_params=dict(request.query_params),
        body=body if body else None,
    )

    if not result.valid:
        raise HTTPException(status_code=401, detail=result.error)

    return result

@app.post("/api/v1/orders")
async def create_order(
    verification: dict = Depends(verify_signature)
):
    return {"status": "created", "key_id": verification.key_id}
```

### Client SDK

```python
import requests
from sign_request import RequestSigner

class APIClient:
    def __init__(self, base_url: str, secret_key_path: str):
        self.base_url = base_url
        self.signer = RequestSigner(secret_key_path=secret_key_path)

    def _request(self, method: str, path: str, **kwargs):
        # Extract host from base_url
        from urllib.parse import urlparse
        host = urlparse(self.base_url).netloc

        # Sign the request
        signed_headers = self.signer.sign_request(
            method=method,
            path=path,
            headers=kwargs.get("headers", {}),
            body=kwargs.get("json"),
            host=host,
        )

        # Merge headers
        headers = kwargs.pop("headers", {})
        headers.update(signed_headers)

        return requests.request(
            method, f"{self.base_url}{path}",
            headers=headers, **kwargs
        )

    def get(self, path: str, **kwargs):
        return self._request("GET", path, **kwargs)

    def post(self, path: str, **kwargs):
        return self._request("POST", path, **kwargs)

# Usage
client = APIClient(
    base_url="https://api.example.com",
    secret_key_path="keys/client_secret.key",
)

response = client.post("/api/v1/orders", json={"item": "widget"})
```

## Security Considerations

### Timestamp Validation

Requests older than 5 minutes are rejected to prevent replay attacks:

```python
verifier = RequestVerifier(
    public_key_path="keys/api_public.key",
    max_timestamp_age=timedelta(minutes=5),  # Default
)
```

### Key Rotation

Use key IDs to support seamless key rotation:

```python
# Server maintains multiple public keys
public_keys = {
    "key-v1": load_key("keys/api_v1_public.key"),
    "key-v2": load_key("keys/api_v2_public.key"),
}

def verify_with_key_id(request):
    # Extract key ID from Authorization header
    key_id = extract_key_id(request.headers["Authorization"])
    public_key = public_keys.get(key_id)

    if not public_key:
        return {"error": "Unknown key ID"}

    verifier = RequestVerifier(public_key=public_key)
    return verifier.verify_request(...)
```

### Content Integrity

The `X-PQC-Content-SHA256` header ensures body integrity:

```python
# Server always verifies content hash matches body
if computed_hash != request.headers["X-PQC-Content-SHA256"]:
    return {"error": "Content hash mismatch - body may be tampered"}
```

## Testing

Run the test suite:

```bash
make test-examples-api-signing
```

## Related Examples

- [Code Signing](../code-signing/) - Sign software releases
- [Document Signing](../document-signing/) - Sign documents
- [PQC Tokens](../pqc-token/) - JWT-like tokens with PQC
