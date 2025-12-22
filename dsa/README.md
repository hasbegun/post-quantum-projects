# Post-Quantum Digital Signature Algorithms (DSA)

## What This Project Does

This project provides implementations of two NIST-standardized post-quantum digital signature algorithms in both **Python** and **C++20**:

- **ML-DSA (FIPS 204)** - Module-Lattice-Based Digital Signature Algorithm
- **SLH-DSA (FIPS 205)** - Stateless Hash-Based Digital Signature Algorithm

### What is a Digital Signature?

A digital signature is the electronic equivalent of a handwritten signature. It provides:

1. **Authentication** - Proves who signed the message
2. **Integrity** - Proves the message wasn't altered
3. **Non-repudiation** - The signer cannot deny signing

```
Signing:    Message + Secret Key  →  Signature
Verifying:  Message + Signature + Public Key  →  Valid/Invalid
```

### Why "Post-Quantum"?

Current digital signatures (RSA, ECDSA) can be broken by quantum computers using Shor's algorithm. Post-quantum algorithms are designed to resist attacks from both classical and quantum computers.

| Algorithm | Basis | Quantum-Safe |
|-----------|-------|--------------|
| RSA | Integer factorization | No |
| ECDSA | Elliptic curves | No |
| **ML-DSA** | Lattice problems | **Yes** |
| **SLH-DSA** | Hash functions | **Yes** |

---

## What This Project Demonstrates

### 1. Two Different Security Approaches

**ML-DSA (Lattice-Based)**
- Security based on the hardness of lattice problems (Module-LWE)
- Fast signing and verification
- Smaller signatures (~2.4 KB)
- Larger public keys (~1.3 KB)

**SLH-DSA (Hash-Based)**
- Security based only on hash function properties
- Slower but mathematically simpler
- Larger signatures (~17 KB)
- Tiny public keys (32 bytes)

### 2. Complete NIST Standard Implementation

This project implements the full FIPS 204 and FIPS 205 specifications:

- All parameter sets (ML-DSA-44/65/87, SLH-DSA-128/192/256)
- Deterministic and randomized signing modes
- Context strings for domain separation
- Pre-hash mode for large messages

### 3. Dual Language Support

- **Python**: Reference implementation for educational purposes
- **C++20**: High-performance implementation using modern C++ features

### 4. Side-Channel Resistant Implementation (SLH-DSA C++)

The C++ SLH-DSA implementation demonstrates constant-time programming techniques:

- **Fixed-iteration loops** - WOTS+ chain always executes maximum iterations
- **Branchless selection** - Tree traversal uses bit masking instead of if/else
- **Constant-time comparison** - Signature verification examines all bytes
- **Memory barriers** - Prevents compiler optimization of security-critical code

---

## Quick Start

### Prerequisites

- Docker installed and running
- Make (optional, for convenience commands)

### Run All Tests

```bash
cd ~/dsa

# Run all tests (Python + C++)
make test

# Run only Python tests
make test-py

# Run only C++ tests
make test-cpp
```

---

## Application Examples

### Example 1: API Authentication (ML-DSA)

**Use Case**: Authenticate API requests between services

**Why ML-DSA?** Fast signing, small signatures - ideal for high-frequency requests

```python
from dsa import MLDSA44

# Server generates keypair, shares public key
dsa = MLDSA44()
pk, sk = dsa.keygen()

# Client signs each API request
request_data = b"GET /api/users?id=123"
signature = dsa.sign(sk, request_data)

# Server verifies the request
if dsa.verify(pk, request_data, signature):
    print("Request authenticated")
```

**Run the full example:**
```bash
make demo-api
```

### Example 2: Document Signing (SLH-DSA)

**Use Case**: Sign legal documents, contracts, certificates

**Why SLH-DSA?** Maximum security confidence for long-term validity

```python
from dsa import slh_keygen, slh_sign, slh_verify, SLH_DSA_SHAKE_128f

# Generate signing keys
params = SLH_DSA_SHAKE_128f
sk, pk = slh_keygen(params)

# Sign an important document
document = b"Contract: I agree to pay $1000..."
signature = slh_sign(params, document, sk)

# Anyone can verify with the public key
valid = slh_verify(params, document, signature, pk)
print(f"Signature valid: {valid}")
```

**Run the full example:**
```bash
make demo-document
```

### Example 3: C++ Usage (SLH-DSA)

```cpp
#include "slhdsa/slh_dsa.hpp"

using namespace slhdsa;

int main() {
    // Use SHAKE-128f parameter set (fastest)
    SLHDSA_SHAKE_128f dsa;

    // Generate key pair
    auto [sk, pk] = dsa.keygen();

    // Sign a message
    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    auto signature = dsa.sign(sk, message);

    // Verify signature
    bool valid = dsa.verify(pk, message, signature);
    std::cout << "Valid: " << (valid ? "YES" : "NO") << std::endl;

    return 0;
}
```

### Example 4: Certificate Creation (C++)

Create and verify post-quantum certificates for TLS, code signing, and more.

**ML-DSA Certificate Example:**
```bash
# Build and run ML-DSA certificate demo
make cert-mldsa
```

This demonstrates a complete PKI workflow:
- Root CA creation with ML-DSA-65 (Category 3 security)
- Intermediate CA certificates
- TLS server certificates with ML-DSA-44 (Category 1, faster)
- Certificate chain verification
- TLS handshake signing simulation

Expected output:
```
============================================================
  ML-DSA Certificate Example (FIPS 204)
============================================================

1. Creating Root CA with ML-DSA-65...
   CA created in 45 ms

   Root CA Certificate:
   Subject: Example Root CA
   Algorithm: ML-DSA-65
   Public Key Size: 1952 bytes
   Signature Size: 3309 bytes
   ...
```

**SLH-DSA Certificate Example:**
```bash
# Build and run SLH-DSA certificate demo
make cert-slhdsa
```

This demonstrates hash-based certificates for long-term security:
- Root CA creation with SLH-DSA-SHAKE-128f (30-year validity)
- Code signing certificates
- Document signing certificates
- Firmware signing and verification
- Tamper detection

Expected output:
```
============================================================
  SLH-DSA Certificate Example (FIPS 205)
============================================================

Note: SLH-DSA provides security based only on hash functions.
This is ideal for long-term certificates (Root CAs, code signing).

1. Creating Root CA with SLH-DSA-SHAKE-128f...
   Generating key pair... done (12 ms)
   Signing certificate... done (85 ms)

   Root CA Certificate:
   Subject: Global Root CA
   Algorithm: SLH-DSA-SHAKE-128f
   Public Key Size: 32 bytes
   Signature Size: 17088 bytes
   ...
```

**Running without Make:**
```bash
# Build C++ Docker image
docker build -t dsa-cpp -f Dockerfile.cpp .

# Run ML-DSA certificate example
docker run --rm dsa-cpp ./build/mldsa_cert_example

# Run SLH-DSA certificate example
docker run --rm dsa-cpp ./build/slhdsa_cert_example
```

See [Certificate Guide](docs/CERTIFICATE_GUIDE.md) for complete documentation.

### Example 5: Key Generation with Certificate Parameters

Generate post-quantum key pairs with X.509-like certificate metadata, similar to OpenSSL.

**Quick Start:**
```bash
# Python (reference implementation)
make keygen-mldsa44

# C++ (faster, recommended)
make keygen-cpp-mldsa44
```

**With Certificate Parameters:**
```bash
# Generate keys with certificate metadata (like OpenSSL)
make keygen-cpp ALG=mldsa65 \
    CN=api.example.com \
    ORG="Example Corp" \
    COUNTRY=US \
    STATE=California \
    DAYS=730
```

**Certificate Options:**
| Option | Description | Example |
|--------|-------------|---------|
| `CN` | Common Name | `CN=api.example.com` |
| `ORG` | Organization | `ORG="My Company"` |
| `OU` | Organizational Unit | `OU=Engineering` |
| `COUNTRY` | 2-letter country code | `COUNTRY=US` |
| `STATE` | State or Province | `STATE=California` |
| `LOCALITY` | City | `LOCALITY="San Francisco"` |
| `EMAIL` | Email address | `EMAIL=admin@example.com` |
| `DAYS` | Validity period | `DAYS=365` |
| `SERIAL` | Serial number (hex) | `SERIAL=abc123` |
| `PASSWORD` | Encrypt secret key | `PASSWORD=mysecret` |

**Available Algorithms:**
| Algorithm | Type | Security | Signature Size |
|-----------|------|----------|----------------|
| `mldsa44` | ML-DSA | Category 1 | 2,420 B |
| `mldsa65` | ML-DSA | Category 3 | 3,309 B |
| `mldsa87` | ML-DSA | Category 5 | 4,627 B |
| `slh-shake-128f` | SLH-DSA | Category 1 | 17,088 B |
| `slh-shake-128s` | SLH-DSA | Category 1 | 7,856 B |
| `slh-shake-192f` | SLH-DSA | Category 3 | 35,664 B |
| `slh-shake-256f` | SLH-DSA | Category 5 | 49,856 B |
| `slh-sha2-128f` | SLH-DSA | Category 1 | 17,088 B |
| `slh-sha2-256f` | SLH-DSA | Category 5 | 49,856 B |

**Shortcut Commands:**
```bash
# Python shortcuts:          C++ shortcuts (faster):
make keygen-mldsa44          make keygen-cpp-mldsa44
make keygen-mldsa65          make keygen-cpp-mldsa65
make keygen-mldsa87          make keygen-cpp-mldsa87
make keygen-slhdsa           make keygen-cpp-slhdsa
make keygen-slhdsa-small     make keygen-cpp-slhdsa-small
```

**Output Files:**
```
keys/
├── mldsa65_certificate.json   # Certificate metadata (JSON)
├── mldsa65_public.key         # 1,952 bytes - share this
└── mldsa65_secret.key         # 4,032 bytes - KEEP SECRET!
```

**Certificate JSON Format:**
```bash
cat keys/mldsa65_certificate.json
```
```json
{
  "version": 1,
  "algorithm": "MLDSA65",
  "type": "ML-DSA",
  "standard": "FIPS 204",
  "subject": {
    "commonName": "api.example.com",
    "organization": "Example Corp",
    "country": "US",
    "state": "California",
    "dn": "C=US, ST=California, O=Example Corp, CN=api.example.com"
  },
  "validity": {
    "notBefore": "2025-12-20T10:00:00Z",
    "notAfter": "2027-12-20T10:00:00Z",
    "days": 730
  },
  "serialNumber": "1a2b3c4d5e6f7890",
  "keyInfo": {
    "publicKeySize": 1952,
    "secretKeySize": 4032,
    "signatureSize": 3309
  }
}
```

**Direct Docker Usage:**
```bash
# Using the keygen tool directly
docker run --rm -v $(pwd)/keys:/keys dsa-cpp \
    ./build/keygen mldsa65 /keys \
    --cn "api.example.com" \
    --org "Example Corp" \
    --country "US" \
    --days 730
```

### Password Protection for Secret Keys

Secret keys can be encrypted with a password for secure storage. This uses:
- **PBKDF2-HMAC-SHA256** for key derivation (600,000 iterations per OWASP 2023 recommendations)
- **AES-256-GCM** for authenticated encryption

**Using Make (use `PASSWORD=value` syntax):**
```bash
# Generate password-protected keys
make keygen-cpp ALG=mldsa65 OUT=secure PASSWORD=mysecretpassword

# With certificate metadata
make keygen-cpp ALG=mldsa65 OUT=api \
    CN=api.example.com \
    ORG="Example Corp" \
    PASSWORD=mysecretpassword
```

> **Note:** Use `PASSWORD=value` (Make variable syntax), NOT `--password value`.

**Using keygen binary directly (use `--password value` syntax):**
```bash
# Password provided on command line
./keygen mldsa65 mykey --password "mysecretpassword"

# Interactive password prompt (recommended for security)
./keygen mldsa65 mykey --password-prompt

# Password from stdin (for scripts)
echo "mysecretpassword" | ./keygen mldsa65 mykey --password-stdin
```

**Encrypted Key File Format:**
- Magic header: `PQCRYPT1`
- 32-byte random salt
- 12-byte IV (nonce)
- 16-byte authentication tag
- Encrypted key data

The certificate JSON indicates encryption status:
```json
{
  "encryption": {
    "encrypted": true,
    "cipher": "AES-256-GCM",
    "kdf": "PBKDF2-HMAC-SHA256",
    "kdfIterations": 600000
  }
}
```

### Example 6: Multi-Container Demo App

A complete client/server demo showing how post-quantum signatures work in distributed systems.

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                    CLIENT (Secret Key)                      │
│         Signs messages and sends to servers                 │
└───────────────────────┬─────────────────┬───────────────────┘
                        │                 │
                        ▼                 ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│   SERVER 1 (Public Key)   │   │   SERVER 2 (Public Key)   │
│   Verifies signatures     │   │   Verifies signatures     │
└───────────────────────────┘   └───────────────────────────┘
```

**Run the demo:**
```bash
# Default (ML-DSA-44)
make demo-app

# With specific algorithm
make demo-app ALG=mldsa65
make demo-app ALG=slh-shake-128f
```

**What it demonstrates:**
1. Client generates a key pair
2. Client registers public key with both servers
3. Client signs messages with secret key
4. Servers verify signatures with public key
5. Tampered messages are rejected

See [examples/app/README.md](examples/app/README.md) for details.

### When to Use Each Algorithm

| Scenario | Recommended | Reason |
|----------|-------------|--------|
| API authentication | ML-DSA | Speed, small signatures |
| Real-time messaging | ML-DSA | Low latency |
| Blockchain transactions | ML-DSA | Bandwidth efficiency |
| Root CA certificates | SLH-DSA | Long-term security |
| Legal documents | SLH-DSA | Conservative security |
| Firmware signing | SLH-DSA | Decades of validity |

---

## How to Run Tests

### Run All Tests

```bash
make test
```

**Expected output:**
```
tests/test_mldsa.py::test_keygen_deterministic PASSED
tests/test_mldsa.py::test_sign_verify_basic PASSED
...
tests/test_slhdsa.py::test_keygen_produces_valid_keys PASSED
tests/test_slhdsa.py::test_sign_verify_roundtrip PASSED
...

==================== 40 passed ====================
```

### Run Specific Tests

```bash
# Python ML-DSA tests
make test-mldsa

# Python SLH-DSA tests
make test-slhdsa

# C++ ML-DSA tests
make test-mldsa-cpp

# C++ SLH-DSA tests
make test-slhdsa-cpp
```

### Interactive Python Shell

```bash
make shell
```

Then try:
```python
>>> from dsa import MLDSA44, slh_keygen, SLH_DSA_SHAKE_128f
>>> dsa = MLDSA44()
>>> pk, sk = dsa.keygen()
>>> len(pk)
1312
```

---

## Project Structure

```
dsa/
├── src/
│   ├── py/                      # Python package (dsa)
│   │   ├── __init__.py          # Unified API exports
│   │   ├── mldsa/               # ML-DSA implementation
│   │   │   ├── mldsa.py         # Main MLDSA class
│   │   │   ├── params.py        # Parameter sets (44, 65, 87)
│   │   │   ├── ntt.py           # Number Theoretic Transform
│   │   │   ├── encoding.py      # Bit packing/unpacking
│   │   │   └── sampling.py      # Rejection sampling
│   │   └── slhdsa/              # SLH-DSA implementation
│   │       ├── slh_dsa.py       # Main sign/verify functions
│   │       ├── parameters.py    # All 12 parameter sets
│   │       ├── wots.py          # WOTS+ one-time signatures
│   │       ├── xmss.py          # XMSS Merkle trees
│   │       ├── fors.py          # FORS few-time signatures
│   │       ├── hypertree.py     # Hypertree structure
│   │       └── address.py       # ADRS address scheme
│   └── cpp/                     # C++ implementation
│       ├── main.cpp             # Key generation tool (keygen)
│       ├── mldsa/               # ML-DSA (FIPS 204)
│       │   ├── mldsa.hpp        # Main API
│       │   ├── params.hpp       # Parameter sets
│       │   ├── ntt.hpp          # Number Theoretic Transform
│       │   ├── encoding.hpp     # Bit packing
│       │   ├── sampling.hpp     # Rejection sampling
│       │   └── utils.hpp/cpp    # Utilities
│       └── slhdsa/              # SLH-DSA (FIPS 205)
│           ├── slh_dsa.hpp      # Main API (keygen, sign, verify)
│           ├── params.hpp       # All 12 parameter sets
│           ├── address.hpp      # ADRS address scheme
│           ├── hash_functions.hpp/cpp  # SHAKE256 and SHA2
│           ├── wots.hpp         # WOTS+ signatures (constant-time)
│           ├── xmss.hpp         # XMSS Merkle trees (constant-time)
│           ├── fors.hpp         # FORS signatures (constant-time)
│           ├── hypertree.hpp    # Hypertree structure (constant-time)
│           ├── ct_utils.hpp     # Constant-time utilities
│           └── utils.hpp/cpp    # General utilities
├── tests/
│   ├── py/                      # Python tests
│   │   ├── test_mldsa.py        # 18 ML-DSA tests
│   │   └── test_slhdsa.py       # 22 SLH-DSA tests
│   └── cpp/                     # C++ tests
│       ├── test_mldsa.cpp       # ML-DSA test suite
│       └── test_slhdsa.cpp      # SLH-DSA test suite
├── examples/
│   ├── py/                      # Python examples
│   │   ├── api_authentication.py
│   │   ├── document_signing.py
│   │   ├── comparison.py
│   │   └── generate_keys.py     # Key generation tool
│   ├── cpp/                     # C++ examples
│   │   ├── demo.cpp             # ML-DSA & SLH-DSA demo
│   │   ├── mldsa_certificate.cpp
│   │   └── slhdsa_certificate.cpp
│   └── app/                     # Multi-container demo app
│       ├── client.py            # Signing client (holds secret key)
│       ├── server.py            # Verification server (holds public key)
│       └── docker-compose.yml   # Container orchestration
├── keys/                        # Generated keys (created by keygen)
├── Dockerfile                   # Python Docker image
├── Dockerfile.cpp               # C++ Docker image
├── Makefile
├── docker-compose.yml
└── pyproject.toml
```

---

## Quick Reference

### ML-DSA API (Python)

```python
from dsa import MLDSA44, MLDSA65, MLDSA87

dsa = MLDSA44()  # or MLDSA65(), MLDSA87()

# Key generation
pk, sk = dsa.keygen()
pk, sk = dsa.keygen(seed=bytes(32))  # Deterministic

# Signing
sig = dsa.sign(sk, message)
sig = dsa.sign(sk, message, ctx=b"app-context")
sig = dsa.sign(sk, message, deterministic=True)

# Verification
valid = dsa.verify(pk, message, sig)
valid = dsa.verify(pk, message, sig, ctx=b"app-context")
```

### SLH-DSA API (Python)

```python
from dsa import (
    slh_keygen, slh_sign, slh_verify,
    SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_256f
)

# Key generation
sk, pk = slh_keygen(SLH_DSA_SHAKE_128f)

# Signing
sig = slh_sign(params, message, sk)
sig = slh_sign(params, message, sk, ctx=b"context")
sig = slh_sign(params, message, sk, randomize=False)

# Verification
valid = slh_verify(params, message, sig, pk)
```

### SLH-DSA API (C++)

```cpp
#include "slhdsa/slh_dsa.hpp"
using namespace slhdsa;

// Using convenience class
SLHDSA_SHAKE_128f dsa;
auto [sk, pk] = dsa.keygen();
auto sig = dsa.sign(sk, message);
bool valid = dsa.verify(pk, message, sig);

// Or using free functions
auto [sk, pk] = slh_keygen(SLH_DSA_SHAKE_128f);
auto sig = slh_sign(SLH_DSA_SHAKE_128f, message, sk);
bool valid = slh_verify(SLH_DSA_SHAKE_128f, message, sig, pk);
```

---

## Make Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| **Build** | |
| `make build` | Build all Docker images |
| `make build-py` | Build Python Docker image |
| `make build-cpp` | Build C++ Docker image |
| **Test** | |
| `make test` | Run all tests (Python + C++) |
| `make test-py` | Run all Python tests |
| `make test-cpp` | Run all C++ tests |
| `make test-mldsa` | Run ML-DSA Python tests |
| `make test-slhdsa` | Run SLH-DSA Python tests |
| `make test-mldsa-cpp` | Run ML-DSA C++ tests |
| `make test-slhdsa-cpp` | Run SLH-DSA C++ tests |
| `make test-kat` | Run NIST KAT tests (C++) |
| `make test-kat-mldsa` | Run ML-DSA NIST KAT tests |
| `make test-kat-slhdsa` | Run SLH-DSA NIST KAT tests |
| **Demo** | |
| `make demo-api` | API authentication example (Python) |
| `make demo-document` | Document signing example (Python) |
| `make demo-compare` | Algorithm comparison (Python) |
| `make demo-cpp` | ML-DSA + SLH-DSA demo (C++) |
| `make demo-app [ALG=<alg>]` | Multi-container client/server demo |
| `make cert-mldsa` | ML-DSA certificate example (C++) |
| `make cert-slhdsa` | SLH-DSA certificate example (C++) |
| **Key Generation** | |
| `make keygen ALG=<alg> [options]` | Generate keys with cert params (Python) |
| `make keygen-cpp ALG=<alg> [options]` | Generate keys with cert params (C++, faster) |
| `make keygen-cpp-mldsa44` | Generate ML-DSA-44 keys (C++) |
| `make keygen-cpp-mldsa65` | Generate ML-DSA-65 keys (C++) |
| `make keygen-cpp-slhdsa` | Generate SLH-DSA-SHAKE-128f keys (C++) |
| **Development** | |
| `make dev` | Run tests with mounted source |
| `make shell` | Interactive Python shell |
| `make clean` | Remove Docker resources |

**Key Generation Options:**
```bash
make keygen-cpp ALG=mldsa65 CN=example.com ORG="My Corp" DAYS=730
```
See [Example 5](#example-5-key-generation-with-certificate-parameters) for all certificate options.

---

## Security Notice

This is a **reference implementation** for educational purposes.

### Side-Channel Protection Status

| Implementation | Side-Channel Status | Notes |
|----------------|---------------------|-------|
| SLH-DSA (C++) | **Mitigated** | Constant-time operations implemented |
| ML-DSA (C++) | Unprotected | Reference implementation only |
| SLH-DSA (Python) | Unprotected | Reference implementation only |
| ML-DSA (Python) | Unprotected | Reference implementation only |

### SLH-DSA C++ Constant-Time Features

The C++ SLH-DSA implementation includes protections against timing side-channel attacks:

| Component | Vulnerability | Mitigation |
|-----------|--------------|------------|
| WOTS+ Chain | Variable loop iterations leaked chain length | Fixed `w` iterations with conditional selection |
| XMSS Tree | Branch-based concatenation leaked tree path | Branchless `ct_concat_conditional()` |
| FORS Tree | Branch-based concatenation leaked indices | Branchless `ct_concat_conditional()` |
| Verification | Early-exit comparison enabled timing oracle | Constant-time `ct_equal()` comparison |

**Constant-Time Utilities** (`ct_utils.hpp`):
- `ct_select_bytes()` - Branchless byte array selection
- `ct_concat_conditional()` - Branchless concatenation ordering
- `ct_equal()` - Constant-time byte comparison
- `ct_barrier()` - Compiler memory barrier

See [Security Assessment](docs/SECURITY_ASSESSMENT.md) for detailed vulnerability analysis and mitigation documentation.

### Production Recommendations

For production use:

- Use NIST-certified cryptographic libraries with formal verification
- Consider [liboqs](https://github.com/open-quantum-safe/liboqs) or vendor implementations
- Verify constant-time properties with tools like [dudect](https://github.com/oreparaz/dudect) or ctgrind
- Store secret keys in Hardware Security Modules (HSMs)
- Follow your organization's key management policies

---

## Documentation

- **[User's Manual](docs/MANUAL.md)** - Complete guide for installation, usage, and integration:
  - Installation (Docker, C++, Python)
  - Key generation and management
  - Use cases: API auth, document signing, firmware signing
  - Web server integration (Nginx, Caddy) with Docker examples
  - Security considerations
- **[Security Assessment](docs/SECURITY_ASSESSMENT.md)** - Side-channel attack analysis and vulnerability assessment
- **[KAT Tests](docs/KAT_TESTS.md)** - NIST Known Answer Test documentation and compliance status
- **[Certificate Guide](docs/CERTIFICATE_GUIDE.md)** - Comprehensive guide on creating post-quantum certificates with ML-DSA and SLH-DSA, including:
  - Algorithm selection guidance
  - Certificate creation examples (Python & C++)
  - Use case examples (TLS, API auth, code signing, documents, IoT)
  - PKI hierarchy examples
  - Migration strategies from classical to post-quantum

---

## References

- [NIST FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- [NIST FIPS 205 - SLH-DSA Standard](https://csrc.nist.gov/publications/detail/fips/205/final)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

## License

MIT License
