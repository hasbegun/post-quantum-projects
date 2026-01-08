# Post-Quantum Cryptography User's Manual

This manual covers installation, key generation, certificate creation, and integration of post-quantum cryptographic algorithms:

- **ML-DSA (FIPS 204)** - Digital signatures based on lattice cryptography
- **SLH-DSA (FIPS 205)** - Digital signatures based on hash functions
- **ML-KEM (FIPS 203)** - Key encapsulation for secure key exchange

## Table of Contents

1. [Installation](#installation)
2. [Choosing an Algorithm](#choosing-an-algorithm)
3. [Key Generation](#key-generation)
4. [Password Protection](#password-protection)
5. [Signing Tool](#signing-tool)
6. [Signing and Verification](#signing-and-verification)
7. [Key Exchange with ML-KEM](#key-exchange-with-ml-kem)
8. [Use Cases](#use-cases)
   - [API Authentication](#api-authentication)
   - [Document Signing](#document-signing)
   - [Firmware Signing](#firmware-signing)
   - [Code Signing](#code-signing)
   - [Secure Key Exchange](#secure-key-exchange)
9. [Web Server Integration](#web-server-integration)
   - [Nginx Integration](#nginx-integration)
   - [Caddy Integration](#caddy-integration)
10. [Programming Examples](#programming-examples)
11. [Security Considerations](#security-considerations)

---

## Installation

### Prerequisites

**For C++ (recommended for production):**
- CMake 3.20+
- C++20 compatible compiler:
  - GCC 11+
  - Clang 14+
  - Apple Clang 14+ (Xcode 14+)
  - MSVC 19.29+ (Visual Studio 2019 16.10+)
- OpenSSL 3.0+ development libraries

**For Python:**
- Python 3.9+
- pip

### Option 1: Docker (Easiest)

```bash
# Clone the repository
git clone https://github.com/hasbegun/dsa.git
cd dsa

# Build Docker images
make build        # Build both Python and C++ images
make build-cpp    # Build C++ image only
make build-py     # Build Python image only

# Verify installation
make test
```

### Option 2: Local Build (C++)

Build C++ executables directly on your machine without Docker.

**Install Dependencies:**

```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake libssl-dev

# macOS (Homebrew)
brew install cmake openssl@3

# Fedora/RHEL
sudo dnf install cmake gcc-c++ openssl-devel

# Arch Linux
sudo pacman -S cmake openssl
```

**Build Using Make (Recommended):**

```bash
# Clone the repository
git clone https://github.com/hasbegun/dsa.git
cd dsa

# Build (Release mode, parallel compilation)
make build-local

# Run tests
make test-local

# Executables are in ./build/
./build/keygen --help
./build/mlkem_demo
```

**Build Options:**

```bash
# Debug build (with symbols, no optimization)
make build-local BUILD_TYPE=Debug

# Specify number of parallel jobs
make build-local CMAKE_JOBS=4

# Clean local build
make clean-local

# Clean everything (Docker + local)
make clean-all
```

**Manual CMake Build:**

```bash
# Clone and build manually
git clone https://github.com/hasbegun/dsa.git
cd dsa

mkdir build && cd build
cmake ../src/cpp -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install system-wide (optional)
sudo make install
```

**Output Executables (`./build/`):**

| Executable | Description |
|------------|-------------|
| `keygen` | Key generation with certificate metadata |
| `sign` | Message signing tool |
| `dsa_demo` | ML-DSA + SLH-DSA demonstration |
| `mlkem_demo` | ML-KEM key exchange demonstration |
| `test_mldsa` | ML-DSA test suite |
| `test_slhdsa` | SLH-DSA test suite |
| `test_mlkem` | ML-KEM test suite |
| `test_mldsa_kat` | ML-DSA NIST KAT tests |
| `test_slhdsa_kat` | SLH-DSA NIST KAT tests |
| `mldsa_cert_example` | ML-DSA certificate example |
| `slhdsa_cert_example` | SLH-DSA certificate example |
| `libmldsa.a` | ML-DSA static library |
| `libslhdsa.a` | SLH-DSA static library |
| `libmlkem.a` | ML-KEM static library |

### Option 3: Python Package

```bash
# Clone the repository
git clone https://github.com/hasbegun/dsa.git
cd dsa

# Install in development mode
pip install -e .

# Or install directly
pip install .
```

---

## Choosing an Algorithm

### ML-DSA (Recommended for most uses)

Based on lattice cryptography. Fast signing and verification, moderate key/signature sizes.

| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|---------------|------------|------------|-----------|
| ML-DSA-44 | 128-bit (Cat 1) | 1,312 bytes | 2,560 bytes | 2,420 bytes |
| ML-DSA-65 | 192-bit (Cat 3) | 1,952 bytes | 4,032 bytes | 3,309 bytes |
| ML-DSA-87 | 256-bit (Cat 5) | 2,592 bytes | 4,896 bytes | 4,627 bytes |

**Best for:** API authentication, real-time signing, high-volume operations

### SLH-DSA (Stateless Hash-Based)

Based on hash functions only. Larger signatures but relies on minimal cryptographic assumptions.

| Variant | Security Level | Public Key | Secret Key | Signature |
|---------|---------------|------------|------------|-----------|
| SLH-DSA-SHAKE-128f | 128-bit | 32 bytes | 64 bytes | 17,088 bytes |
| SLH-DSA-SHAKE-128s | 128-bit | 32 bytes | 64 bytes | 7,856 bytes |
| SLH-DSA-SHAKE-256f | 256-bit | 64 bytes | 128 bytes | 49,856 bytes |

**Best for:** Long-term document signing, firmware signing, high-security archives

### ML-KEM (Key Encapsulation)

Based on lattice cryptography (same as ML-DSA). Used for establishing shared secrets.

| Variant | Security Level | Encaps Key | Decaps Key | Ciphertext |
|---------|---------------|------------|------------|------------|
| ML-KEM-512 | 128-bit (Cat 1) | 800 bytes | 1,632 bytes | 768 bytes |
| ML-KEM-768 | 192-bit (Cat 3) | 1,184 bytes | 2,400 bytes | 1,088 bytes |
| ML-KEM-1024 | 256-bit (Cat 5) | 1,568 bytes | 3,168 bytes | 1,568 bytes |

**Best for:** TLS key exchange, hybrid encryption, VPN tunnels, secure messaging

### Decision Guide

**For Signatures:**
```
Need fast signing? ────────────────────────────► ML-DSA
Need smallest keys? ───────────────────────────► SLH-DSA
Need smallest signatures? ─────────────────────► ML-DSA
Maximum security assumptions? ─────────────────► SLH-DSA
Real-time API authentication? ─────────────────► ML-DSA-44
Long-term document archival? ──────────────────► SLH-DSA-256s
Firmware updates (size matters)? ──────────────► ML-DSA-44 or ML-DSA-65
```

**For Key Exchange:**
```
General purpose TLS? ─────────────────────────► ML-KEM-768
IoT/embedded devices? ────────────────────────► ML-KEM-512
High-security communications? ────────────────► ML-KEM-1024
```

**Using Together:**
- Use **ML-KEM** to establish a shared secret for symmetric encryption
- Use **ML-DSA** to sign the ciphertext for authentication
- This provides both confidentiality and authentication (like TLS)

---

## Key Generation

Key generation now supports X.509-like certificate parameters, similar to OpenSSL RSA key generation.

### Using Docker (Recommended)

```bash
# Build the image first
make build-cpp

# Basic key generation
make keygen-cpp ALG=mldsa65 OUT=./keys

# Key generation with certificate parameters
make keygen-cpp ALG=mldsa65 OUT=./keys \
    CN=api.example.com \
    ORG="Example Corp" \
    COUNTRY=US \
    STATE=California \
    DAYS=730

# All certificate options:
#   CN=<name>        Common Name (e.g., CN=api.example.com)
#   ORG=<name>       Organization (e.g., ORG="My Company")
#   OU=<name>        Organizational Unit
#   COUNTRY=<code>   2-letter country code (e.g., COUNTRY=US)
#   STATE=<name>     State or Province
#   LOCALITY=<name>  City
#   EMAIL=<email>    Email address
#   DAYS=<n>         Validity period in days (default: 365)
#   SERIAL=<hex>     Serial number in hex (optional)
#   PASSWORD=<pass>  Encrypt secret key with password

# Keys are saved to:
# ./keys/<algorithm>_public.key
# ./keys/<algorithm>_secret.key
# ./keys/<algorithm>_certificate.json
```

**Direct Docker commands:**

```bash
# Generate keys with Docker directly
docker run --rm -v $(pwd)/keys:/keys dsa-cpp \
    ./build/keygen mldsa65 /keys \
    --cn "api.example.com" \
    --org "Example Corp" \
    --country "US" \
    --days 730

# List generated keys
ls -la keys/
# mldsa65_public.key       (1952 bytes)
# mldsa65_secret.key       (4032 bytes)
# mldsa65_certificate.json
```

### Certificate JSON Format

The generated certificate JSON includes all metadata:

```json
{
  "version": 1,
  "algorithm": "MLDSA65",
  "type": "ML-DSA",
  "standard": "FIPS 204",
  "subject": {
    "commonName": "api.example.com",
    "organization": "Example Corp",
    "organizationalUnit": "",
    "country": "US",
    "state": "California",
    "locality": "",
    "email": "",
    "dn": "C=US, ST=California, O=Example Corp, CN=api.example.com"
  },
  "validity": {
    "notBefore": "2025-12-20T06:41:05Z",
    "notAfter": "2027-12-20T06:41:05Z",
    "days": 730
  },
  "serialNumber": "1d92ece3bdc774e3",
  "keyInfo": {
    "publicKeySize": 1952,
    "secretKeySize": 4032,
    "signatureSize": 3309,
    "publicKeyFile": "mldsa65_public.key",
    "secretKeyFile": "mldsa65_secret.key"
  },
  "created": "2025-12-20T06:41:05Z"
}
```

### Using C++ API

```cpp
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"
#include <fstream>

// ML-DSA key generation
void generate_mldsa_keys() {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    // Save keys
    std::ofstream pk_file("mldsa_public.key", std::ios::binary);
    pk_file.write(reinterpret_cast<char*>(pk.data()), pk.size());

    std::ofstream sk_file("mldsa_secret.key", std::ios::binary);
    sk_file.write(reinterpret_cast<char*>(sk.data()), sk.size());
}

// SLH-DSA key generation
void generate_slhdsa_keys() {
    slhdsa::SLHDSA_SHAKE_128f dsa;
    auto [sk, pk] = dsa.keygen();  // Note: returns (sk, pk)

    // Save keys
    std::ofstream pk_file("slhdsa_public.key", std::ios::binary);
    pk_file.write(reinterpret_cast<char*>(pk.data()), pk.size());

    std::ofstream sk_file("slhdsa_secret.key", std::ios::binary);
    sk_file.write(reinterpret_cast<char*>(sk.data()), sk.size());
}

// ML-KEM key generation
void generate_mlkem_keys() {
    mlkem::MLKEM768 kem;
    auto [ek, dk] = kem.keygen();  // ek = encapsulation key (public), dk = decapsulation key (secret)

    // Save keys
    std::ofstream ek_file("mlkem_encaps.key", std::ios::binary);
    ek_file.write(reinterpret_cast<char*>(ek.data()), ek.size());

    std::ofstream dk_file("mlkem_decaps.key", std::ios::binary);
    dk_file.write(reinterpret_cast<char*>(dk.data()), dk.size());
}
```

### Using Python API

```python
from dsa import MLDSA44, MLDSA65, MLDSA87
from dsa import slh_keygen, SLH_DSA_SHAKE_128f
from mlkem import MLKEM512, MLKEM768, MLKEM1024

# ML-DSA key generation
def generate_mldsa_keys():
    dsa = MLDSA65()
    pk, sk = dsa.keygen()

    with open("mldsa_public.key", "wb") as f:
        f.write(pk)
    with open("mldsa_secret.key", "wb") as f:
        f.write(sk)

    return pk, sk

# SLH-DSA key generation
def generate_slhdsa_keys():
    sk, pk = slh_keygen(SLH_DSA_SHAKE_128f)

    with open("slhdsa_public.key", "wb") as f:
        f.write(pk)
    with open("slhdsa_secret.key", "wb") as f:
        f.write(sk)

    return pk, sk

# ML-KEM key generation
def generate_mlkem_keys():
    kem = MLKEM768()
    ek, dk = kem.keygen()  # ek = encapsulation key (public), dk = decapsulation key (secret)

    with open("mlkem_encaps.key", "wb") as f:
        f.write(ek)
    with open("mlkem_decaps.key", "wb") as f:
        f.write(dk)

    return ek, dk
```

### Key Storage Best Practices

1. **Secret keys**: Store in HSM, secure enclave, or encrypted file system
2. **File permissions**: `chmod 600 secret.key` (owner read/write only)
3. **Backup**: Keep encrypted backups in separate physical locations
4. **Rotation**: Plan for key rotation (especially for long-lived services)
5. **Password protection**: Use `--password` option to encrypt secret keys at rest

---

## Password Protection

Secret keys can be encrypted with a password for secure storage. This provides an additional layer of protection beyond file system permissions.

### Encryption Details

- **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations (OWASP 2023 recommendation)
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Format**: Custom binary format with magic header `PQCRYPT1`

### Using Password Protection with Make

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

### Using Password Protection with keygen Binary

```bash
# Password on command line
./keygen mldsa65 mykey --password "mysecretpassword"

# Interactive password prompt (recommended for security)
./keygen mldsa65 mykey --password-prompt

# Password from stdin (for scripts)
echo "mysecretpassword" | ./keygen mldsa65 mykey --password-stdin
```

### Encrypted Key File Format

The encrypted secret key file has the following structure:

| Offset | Size | Description |
|--------|------|-------------|
| 0 | 8 | Magic header: `PQCRYPT1` |
| 8 | 4 | Format version (uint32 LE) |
| 12 | 4 | Algorithm ID (uint32 LE) |
| 16 | 32 | Random salt for PBKDF2 |
| 48 | 12 | IV/Nonce for AES-GCM |
| 60 | 16 | Authentication tag |
| 76 | 4 | Original key size (uint32 LE) |
| 80 | ... | Encrypted key data |

### Certificate Encryption Status

The certificate JSON indicates whether the secret key is encrypted:

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

For unencrypted keys:

```json
{
  "encryption": {
    "encrypted": false
  }
}
```

---

## Signing Tool

The `sign` tool allows you to sign messages using secret keys, with full support for password-protected (encrypted) keys.

### Basic Usage

```bash
# Sign a file
./sign <algorithm> <secret_key_file> <message_file> [options]

# Sign inline text
./sign <algorithm> <secret_key_file> --message <text> [options]
```

### Options

| Option | Description |
|--------|-------------|
| `--message <text>` | Sign inline text instead of reading from file |
| `--output <file>` | Write signature to file (default: stdout) |
| `--format <fmt>` | Output format: `hex` (default), `base64`, `binary` |
| `--password <pass>` | Password for encrypted secret key |
| `--password-stdin` | Read password from stdin (first line) |

### Using Sign Tool with Make

```bash
# Sign a file (prompts for password if key is encrypted)
make sign-cpp ALG=mldsa65 SK=./keys/mykey_secret.key MSG=document.txt

# Sign with password
make sign-cpp ALG=mldsa65 SK=./keys/mykey_secret.key MSG=document.txt PASSWORD=mysecret

# Sign inline text
make sign-cpp ALG=mldsa65 SK=./keys/mykey_secret.key TEXT="Hello World"

# Output to file in base64 format
make sign-cpp ALG=mldsa65 SK=./keys/mykey_secret.key MSG=doc.txt OUT=signature.b64 FORMAT=base64
```

### Using Sign Tool Directly

```bash
# Sign a file (auto-detects encrypted keys and prompts for password)
./sign mldsa65 mykey_secret.key document.txt

# With password on command line
./sign mldsa65 mykey_secret.key document.txt --password "mysecret"

# Sign inline text
./sign mldsa65 mykey_secret.key --message "Hello World"

# Output formats
./sign mldsa65 mykey_secret.key doc.txt --format hex      # Default
./sign mldsa65 mykey_secret.key doc.txt --format base64
./sign mldsa65 mykey_secret.key doc.txt --format binary --output sig.bin

# Password from stdin (for automation)
echo "password" | ./sign mldsa65 mykey_secret.key doc.txt --password-stdin
```

### Complete Workflow Example

```bash
# 1. Generate password-protected keys
make keygen-cpp ALG=mldsa65 OUT=mykey PASSWORD=mysecret123

# 2. Create a document to sign
echo "This is an important document" > document.txt

# 3. Sign the document (will use encrypted key)
make sign-cpp ALG=mldsa65 SK=./keys/mykey_secret.key MSG=document.txt PASSWORD=mysecret123

# Output: signature in hex format to stdout
```

### Supported Algorithms

**ML-DSA (FIPS 204):**
- `mldsa44` - Security Level 1 (128-bit)
- `mldsa65` - Security Level 3 (192-bit)
- `mldsa87` - Security Level 5 (256-bit)

**SLH-DSA (FIPS 205):**
- `slh-shake-128f`, `slh-shake-128s` - SHAKE, Level 1
- `slh-shake-192f`, `slh-shake-192s` - SHAKE, Level 3
- `slh-shake-256f`, `slh-shake-256s` - SHAKE, Level 5
- `slh-sha2-128f`, `slh-sha2-128s` - SHA2, Level 1
- `slh-sha2-192f`, `slh-sha2-192s` - SHA2, Level 3
- `slh-sha2-256f`, `slh-sha2-256s` - SHA2, Level 5

### Error Handling

The sign tool provides clear error messages:

```bash
# Wrong password
$ ./sign mldsa65 encrypted_key.key doc.txt --password wrongpass
Error: Decryption failed: wrong password or corrupted data

# Missing message
$ ./sign mldsa65 key.key
Error: No message provided. Use <message_file> or --message <text>

# Unknown algorithm
$ ./sign unknown key.key doc.txt
Error: Unknown algorithm 'unknown'
```

---

## Signing and Verification

### C++ Example

```cpp
#include "mldsa/mldsa.hpp"
#include <vector>
#include <string>

// Sign a message
std::vector<uint8_t> sign_message(
    const std::vector<uint8_t>& secret_key,
    const std::string& message
) {
    mldsa::MLDSA65 dsa;
    std::vector<uint8_t> msg(message.begin(), message.end());
    return dsa.sign(secret_key, msg);
}

// Verify a signature
bool verify_signature(
    const std::vector<uint8_t>& public_key,
    const std::string& message,
    const std::vector<uint8_t>& signature
) {
    mldsa::MLDSA65 dsa;
    std::vector<uint8_t> msg(message.begin(), message.end());
    return dsa.verify(public_key, msg, signature);
}
```

### Python Example

```python
from dsa import MLDSA65

def sign_message(secret_key: bytes, message: bytes) -> bytes:
    dsa = MLDSA65()
    return dsa.sign(secret_key, message)

def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    dsa = MLDSA65()
    return dsa.verify(public_key, message, signature)
```

---

## Key Exchange with ML-KEM

ML-KEM (Module-Lattice-Based Key Encapsulation Mechanism) provides quantum-resistant key exchange.

### Basic Key Exchange (Python)

```python
from mlkem import MLKEM768

# Create KEM instance
kem = MLKEM768()

# ALICE: Generate key pair and publish encapsulation key
encapsulation_key, decapsulation_key = kem.keygen()
# Send encapsulation_key to Bob (public)
# Keep decapsulation_key secret

# BOB: Encapsulate using Alice's public key
shared_secret_bob, ciphertext = kem.encaps(encapsulation_key)
# Send ciphertext to Alice
# Use shared_secret_bob for symmetric encryption (AES-GCM)

# ALICE: Decapsulate to get the same shared secret
shared_secret_alice = kem.decaps(decapsulation_key, ciphertext)

# Both parties now have the same 32-byte shared secret
assert shared_secret_bob == shared_secret_alice
```

### Basic Key Exchange (C++)

```cpp
#include "mlkem/mlkem.hpp"

void key_exchange_demo() {
    mlkem::MLKEM768 kem;

    // Alice generates key pair
    auto [ek, dk] = kem.keygen();

    // Bob encapsulates using Alice's public key
    auto [shared_secret_bob, ciphertext] = kem.encaps(ek);

    // Alice decapsulates
    auto shared_secret_alice = kem.decaps(dk, ciphertext);

    // Both have the same shared secret
    assert(shared_secret_bob == shared_secret_alice);
}
```

### Implicit Rejection

ML-KEM implements **implicit rejection**: if the ciphertext is tampered with, `decaps` returns a pseudorandom value instead of failing. This prevents timing-based attacks.

```python
# Tampered ciphertext
tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

# Decapsulation returns pseudorandom value, not an error
fake_secret = kem.decaps(decapsulation_key, tampered)

# The fake secret is different from the real one
assert fake_secret != shared_secret_alice
```

### Authenticated Key Exchange

For authenticated key exchange (like TLS), combine ML-KEM with ML-DSA:

```python
from mlkem import MLKEM768
from dsa import MLDSA65

# SETUP: Alice generates both signing and KEM keys
dsa = MLDSA65()
sign_pk, sign_sk = dsa.keygen()

kem = MLKEM768()
ek, dk = kem.keygen()

# Alice publishes: sign_pk (signing public key), ek (encapsulation key)

# BOB: Encapsulate and sign the ciphertext for authentication
shared_secret_bob, ciphertext = kem.encaps(ek)
signature = dsa.sign(sign_sk, ciphertext)  # Sign with Alice's private signing key
# Wait - Bob doesn't have Alice's private signing key!
# In practice, Bob would sign with HIS private signing key:
# signature = dsa.sign(bob_sign_sk, ciphertext)

# Correct authenticated key exchange:
# 1. Both parties have their own signing key pairs
# 2. Bob encapsulates with Alice's KEM public key
# 3. Bob signs the ciphertext with his own signing private key
# 4. Alice verifies Bob's signature, then decapsulates
```

**Correct Authenticated Key Exchange:**

```python
from mlkem import MLKEM768
from dsa import MLDSA65

# SETUP
dsa = MLDSA65()

# Alice's keys
alice_sign_pk, alice_sign_sk = dsa.keygen()
kem = MLKEM768()
alice_ek, alice_dk = kem.keygen()

# Bob's keys
bob_sign_pk, bob_sign_sk = dsa.keygen()

# KEY EXCHANGE
# Bob encapsulates using Alice's KEM public key
shared_secret_bob, ciphertext = kem.encaps(alice_ek)

# Bob signs the ciphertext with his signing key
bob_signature = dsa.sign(bob_sign_sk, ciphertext)

# Alice verifies Bob's signature, then decapsulates
if dsa.verify(bob_sign_pk, ciphertext, bob_signature):
    shared_secret_alice = kem.decaps(alice_dk, ciphertext)
    print("Authenticated key exchange successful!")
    # Use shared_secret for AES-256-GCM encryption
```

### ML-KEM Parameter Comparison

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|------------|-------------|
| Security Level | Cat 1 (128-bit) | Cat 3 (192-bit) | Cat 5 (256-bit) |
| Encapsulation Key | 800 bytes | 1,184 bytes | 1,568 bytes |
| Decapsulation Key | 1,632 bytes | 2,400 bytes | 3,168 bytes |
| Ciphertext | 768 bytes | 1,088 bytes | 1,568 bytes |
| Shared Secret | 32 bytes | 32 bytes | 32 bytes |

### Running ML-KEM Demo

```bash
# Python demo
make demo-mlkem

# C++ demo
make mlkem-demo

# Run ML-KEM tests
make test-mlkem      # Python tests
make test-mlkem-cpp  # C++ tests
```

---

## Use Cases

### Quick Start with Docker

Before diving into specific use cases, here's how to quickly get started:

```bash
# 1. Clone and build
git clone https://github.com/hasbegun/dsa.git
cd dsa
make build

# 2. Generate keys
make keygen-cpp ALG=mldsa65 OUT=./keys

# 3. Run the demo to see it in action
make demo-app

# 4. Run with SLH-DSA
make demo-app ALG=slh-shake-128f
```

### API Authentication

Sign API requests to prove authenticity and integrity.

#### Docker-Based API Server

First, let's create a complete Docker-based example.

**Project Structure:**
```
my-api/
├── docker-compose.yml
├── Dockerfile
├── server.py
├── client.py
└── keys/
    ├── mldsa65_public.key
    └── mldsa65_secret.key
```

**docker-compose.yml:**
```yaml
services:
  api-server:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./keys:/keys:ro
    environment:
      - PUBLIC_KEY_PATH=/keys/mldsa65_public.key

  api-client:
    build: .
    command: python client.py
    volumes:
      - ./keys:/keys:ro
    environment:
      - SECRET_KEY_PATH=/keys/mldsa65_secret.key
      - PUBLIC_KEY_PATH=/keys/mldsa65_public.key
      - API_URL=http://api-server:8080
    depends_on:
      - api-server
```

**Dockerfile:**
```dockerfile
FROM python:3.11-slim
WORKDIR /app

# Install DSA library
RUN pip install dsa

COPY *.py ./
CMD ["python", "server.py"]
```

#### Server Setup (Python/Flask)

```python
# server.py
from flask import Flask, request, jsonify
from dsa import MLDSA44
import json

app = Flask(__name__)
dsa = MLDSA44()

# Load registered public keys (in production, use a database)
registered_keys = {}

@app.route('/register', methods=['POST'])
def register():
    """Register a client's public key."""
    data = request.json
    client_id = data['client_id']
    public_key = bytes.fromhex(data['public_key'])
    registered_keys[client_id] = public_key
    return jsonify({'status': 'registered'})

@app.route('/api/secure', methods=['POST'])
def secure_endpoint():
    """Verify signed request."""
    client_id = request.headers.get('X-Client-ID')
    signature = bytes.fromhex(request.headers.get('X-Signature'))
    timestamp = request.headers.get('X-Timestamp')

    if client_id not in registered_keys:
        return jsonify({'error': 'Unknown client'}), 401

    # Reconstruct signed message
    body = request.get_data()
    message = f"{timestamp}:{body.decode()}".encode()

    # Verify signature
    public_key = registered_keys[client_id]
    if dsa.verify(public_key, message, signature):
        return jsonify({'status': 'authenticated', 'data': 'secret response'})
    else:
        return jsonify({'error': 'Invalid signature'}), 401

if __name__ == '__main__':
    app.run(port=8080)
```

#### Client Implementation (Python)

```python
# client.py
import requests
import time
from dsa import MLDSA44

class SecureAPIClient:
    def __init__(self, base_url: str, client_id: str, secret_key: bytes):
        self.base_url = base_url
        self.client_id = client_id
        self.secret_key = secret_key
        self.dsa = MLDSA44()

    def sign_request(self, body: str) -> tuple[str, str]:
        """Sign request body with timestamp."""
        timestamp = str(int(time.time()))
        message = f"{timestamp}:{body}".encode()
        signature = self.dsa.sign(self.secret_key, message)
        return timestamp, signature.hex()

    def post(self, endpoint: str, data: dict) -> dict:
        """Make signed POST request."""
        import json
        body = json.dumps(data)
        timestamp, signature = self.sign_request(body)

        headers = {
            'Content-Type': 'application/json',
            'X-Client-ID': self.client_id,
            'X-Timestamp': timestamp,
            'X-Signature': signature,
        }

        response = requests.post(
            f"{self.base_url}{endpoint}",
            data=body,
            headers=headers
        )
        return response.json()

# Usage
if __name__ == '__main__':
    # Generate keys (do this once)
    dsa = MLDSA44()
    pk, sk = dsa.keygen()

    # Register with server
    requests.post('http://localhost:8080/register', json={
        'client_id': 'my-client',
        'public_key': pk.hex()
    })

    # Make authenticated requests
    client = SecureAPIClient('http://localhost:8080', 'my-client', sk)
    response = client.post('/api/secure', {'action': 'get_data'})
    print(response)
```

### Document Signing

Sign documents with long-term verifiable signatures using SLH-DSA.

#### Docker-Based Document Signing

```bash
# 1. Generate long-term signing keys (using SLH-DSA for maximum security)
make keygen-cpp ALG=slh-shake-256f OUT=./doc-keys

# 2. Sign a document
docker run --rm \
    -v $(pwd)/doc-keys:/keys:ro \
    -v $(pwd)/documents:/docs \
    dsa-py python -c "
from dsa import slh_sign, slh_keygen, SLH_DSA_SHAKE_256f
import json, hashlib
from pathlib import Path

# Load secret key
sk = Path('/keys/slh-shake-256f_secret.key').read_bytes()
pk = Path('/keys/slh-shake-256f_public.key').read_bytes()

# Read document
doc = Path('/docs/contract.pdf').read_bytes()

# Create signature
params = SLH_DSA_SHAKE_256f
sig = slh_sign(params, doc, sk)

# Save signature bundle
bundle = {
    'filename': 'contract.pdf',
    'sha256': hashlib.sha256(doc).hexdigest(),
    'signature': sig.hex(),
    'public_key': pk.hex(),
    'algorithm': 'SLH-DSA-SHAKE-256f'
}
Path('/docs/contract.pdf.sig').write_text(json.dumps(bundle, indent=2))
print('Document signed successfully')
"

# 3. Verify document signature
docker run --rm \
    -v $(pwd)/documents:/docs:ro \
    dsa-py python -c "
from dsa import slh_verify, SLH_DSA_SHAKE_256f
import json, hashlib
from pathlib import Path

# Load signature bundle
bundle = json.loads(Path('/docs/contract.pdf.sig').read_text())

# Load document and verify hash
doc = Path('/docs/contract.pdf').read_bytes()
if hashlib.sha256(doc).hexdigest() != bundle['sha256']:
    print('Document hash mismatch!')
    exit(1)

# Verify signature
params = SLH_DSA_SHAKE_256f
sig = bytes.fromhex(bundle['signature'])
pk = bytes.fromhex(bundle['public_key'])

if slh_verify(params, doc, sig, pk):
    print('Signature VALID')
else:
    print('Signature INVALID')
    exit(1)
"
```

#### Python Document Signer

```python
# document_signer.py
import hashlib
import json
import time
from pathlib import Path
from dsa import slh_sign, slh_verify, slh_keygen, SLH_DSA_SHAKE_256f

class DocumentSigner:
    """Sign and verify documents with post-quantum signatures."""

    def __init__(self, secret_key: bytes = None, public_key: bytes = None):
        self.secret_key = secret_key
        self.public_key = public_key
        self.params = SLH_DSA_SHAKE_256f

    @classmethod
    def generate_keys(cls):
        """Generate new signing keys."""
        sk, pk = slh_keygen(SLH_DSA_SHAKE_256f)
        return cls(secret_key=sk, public_key=pk)

    def sign_document(self, file_path: str) -> dict:
        """Sign a document file."""
        path = Path(file_path)
        content = path.read_bytes()

        # Create signature metadata
        metadata = {
            'filename': path.name,
            'size': len(content),
            'sha256': hashlib.sha256(content).hexdigest(),
            'timestamp': time.time(),
            'algorithm': 'SLH-DSA-SHAKE-256f',
        }

        # Sign the content hash + metadata
        sign_data = json.dumps(metadata, sort_keys=True).encode() + content
        signature = slh_sign(self.params, sign_data, self.secret_key)

        return {
            'metadata': metadata,
            'signature': signature.hex(),
            'public_key': self.public_key.hex(),
        }

    def verify_document(self, file_path: str, signature_data: dict) -> bool:
        """Verify a signed document."""
        path = Path(file_path)
        content = path.read_bytes()

        # Reconstruct signed data
        metadata = signature_data['metadata']
        sign_data = json.dumps(metadata, sort_keys=True).encode() + content

        # Verify hash matches
        if hashlib.sha256(content).hexdigest() != metadata['sha256']:
            return False

        # Verify signature
        signature = bytes.fromhex(signature_data['signature'])
        public_key = bytes.fromhex(signature_data['public_key'])

        return slh_verify(self.params, sign_data, signature, public_key)

# Usage
if __name__ == '__main__':
    # Generate signing keys
    signer = DocumentSigner.generate_keys()

    # Save keys
    Path('signing_key.secret').write_bytes(signer.secret_key)
    Path('signing_key.public').write_bytes(signer.public_key)

    # Sign a document
    sig_data = signer.sign_document('contract.pdf')
    Path('contract.pdf.sig').write_text(json.dumps(sig_data, indent=2))

    # Verify later
    sig_data = json.loads(Path('contract.pdf.sig').read_text())
    is_valid = signer.verify_document('contract.pdf', sig_data)
    print(f"Signature valid: {is_valid}")
```

### Firmware Signing

Sign firmware images for secure boot and updates.

#### Docker-Based Firmware Signing Workflow

**Complete workflow using Docker:**

```bash
# 1. Generate signing keys
make keygen-cpp ALG=mldsa65 OUT=./firmware-keys

# 2. Create a firmware signing script
cat > sign_firmware.sh << 'EOF'
#!/bin/bash
FIRMWARE=$1
VERSION=$2

# Sign with Docker
docker run --rm \
    -v $(pwd)/firmware-keys:/keys:ro \
    -v $(pwd):/work \
    dsa-cpp \
    ./build/firmware_signer sign \
    /work/$FIRMWARE \
    /keys/mldsa65_secret.key \
    /work/${FIRMWARE}.signed \
    $VERSION
EOF
chmod +x sign_firmware.sh

# 3. Sign your firmware
./sign_firmware.sh my_firmware.bin 1.0.0

# 4. Verify the signature
docker run --rm \
    -v $(pwd)/firmware-keys:/keys:ro \
    -v $(pwd):/work \
    dsa-cpp \
    ./build/firmware_signer verify \
    /work/my_firmware.bin.signed \
    /keys/mldsa65_public.key
```

**Docker Compose for CI/CD Pipeline:**

```yaml
# firmware-signing/docker-compose.yml
services:
  firmware-signer:
    image: dsa-cpp
    volumes:
      - ./keys:/keys:ro
      - ./build:/firmware
    command: >
      ./build/firmware_signer sign
      /firmware/firmware.bin
      /keys/mldsa65_secret.key
      /firmware/firmware.signed
      ${VERSION:-1.0.0}

  firmware-verifier:
    image: dsa-cpp
    volumes:
      - ./keys:/keys:ro
      - ./build:/firmware
    command: >
      ./build/firmware_signer verify
      /firmware/firmware.signed
      /keys/mldsa65_public.key
```

#### Firmware Signing Tool (C++)

```cpp
// firmware_signer.cpp
#include "mldsa/mldsa.hpp"
#include <fstream>
#include <iostream>
#include <vector>
#include <cstring>

struct FirmwareHeader {
    char magic[4] = {'F', 'W', 'S', 'G'};  // Firmware Signed
    uint32_t version;
    uint32_t firmware_size;
    uint32_t signature_size;
    uint8_t public_key_hash[32];  // SHA-256 of public key
    // Signature follows header
    // Firmware follows signature
};

class FirmwareSigner {
public:
    FirmwareSigner() : dsa_() {}

    // Generate signing keys
    void generate_keys(const std::string& key_prefix) {
        auto [pk, sk] = dsa_.keygen();

        write_file(key_prefix + ".pub", pk);
        write_file(key_prefix + ".sec", sk);

        std::cout << "Keys generated:\n"
                  << "  Public key: " << key_prefix << ".pub (" << pk.size() << " bytes)\n"
                  << "  Secret key: " << key_prefix << ".sec (" << sk.size() << " bytes)\n";
    }

    // Sign firmware
    void sign_firmware(const std::string& firmware_path,
                       const std::string& secret_key_path,
                       const std::string& output_path,
                       uint32_t version) {
        auto firmware = read_file(firmware_path);
        auto secret_key = read_file(secret_key_path);

        // Generate public key for header
        auto [pk, _] = dsa_.keygen();  // We need the public key
        // In practice, load from corresponding .pub file

        // Sign the firmware
        auto signature = dsa_.sign(secret_key, firmware);

        // Create header
        FirmwareHeader header;
        header.version = version;
        header.firmware_size = firmware.size();
        header.signature_size = signature.size();
        // hash public key into header.public_key_hash

        // Write signed firmware
        std::ofstream out(output_path, std::ios::binary);
        out.write(reinterpret_cast<char*>(&header), sizeof(header));
        out.write(reinterpret_cast<char*>(signature.data()), signature.size());
        out.write(reinterpret_cast<char*>(firmware.data()), firmware.size());

        std::cout << "Signed firmware written to " << output_path << "\n"
                  << "  Version: " << version << "\n"
                  << "  Firmware size: " << firmware.size() << " bytes\n"
                  << "  Signature size: " << signature.size() << " bytes\n"
                  << "  Total size: " << sizeof(header) + signature.size() + firmware.size() << " bytes\n";
    }

    // Verify firmware
    bool verify_firmware(const std::string& signed_firmware_path,
                         const std::string& public_key_path) {
        auto public_key = read_file(public_key_path);

        std::ifstream in(signed_firmware_path, std::ios::binary);

        // Read header
        FirmwareHeader header;
        in.read(reinterpret_cast<char*>(&header), sizeof(header));

        if (std::memcmp(header.magic, "FWSG", 4) != 0) {
            std::cerr << "Invalid firmware format\n";
            return false;
        }

        // Read signature
        std::vector<uint8_t> signature(header.signature_size);
        in.read(reinterpret_cast<char*>(signature.data()), signature.size());

        // Read firmware
        std::vector<uint8_t> firmware(header.firmware_size);
        in.read(reinterpret_cast<char*>(firmware.data()), firmware.size());

        // Verify
        bool valid = dsa_.verify(public_key, firmware, signature);

        std::cout << "Firmware verification: " << (valid ? "PASSED" : "FAILED") << "\n"
                  << "  Version: " << header.version << "\n"
                  << "  Size: " << header.firmware_size << " bytes\n";

        return valid;
    }

private:
    mldsa::MLDSA65 dsa_;

    std::vector<uint8_t> read_file(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        auto size = f.tellg();
        f.seekg(0);
        std::vector<uint8_t> data(size);
        f.read(reinterpret_cast<char*>(data.data()), size);
        return data;
    }

    void write_file(const std::string& path, const std::vector<uint8_t>& data) {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(data.data()), data.size());
    }
};

int main(int argc, char* argv[]) {
    FirmwareSigner signer;

    if (argc < 2) {
        std::cout << "Usage:\n"
                  << "  " << argv[0] << " keygen <key_prefix>\n"
                  << "  " << argv[0] << " sign <firmware> <secret_key> <output> <version>\n"
                  << "  " << argv[0] << " verify <signed_firmware> <public_key>\n";
        return 1;
    }

    std::string cmd = argv[1];

    if (cmd == "keygen" && argc >= 3) {
        signer.generate_keys(argv[2]);
    } else if (cmd == "sign" && argc >= 6) {
        signer.sign_firmware(argv[2], argv[3], argv[4], std::stoul(argv[5]));
    } else if (cmd == "verify" && argc >= 4) {
        return signer.verify_firmware(argv[2], argv[3]) ? 0 : 1;
    }

    return 0;
}
```

#### Firmware Verification on Embedded Device (C++)

```cpp
// embedded_verifier.cpp - Minimal verification for embedded systems
#include "mldsa/mldsa.hpp"

// Embedded public key (baked into firmware)
extern const uint8_t VENDOR_PUBLIC_KEY[];
extern const size_t VENDOR_PUBLIC_KEY_SIZE;

bool verify_firmware_update(const uint8_t* data, size_t size) {
    // Parse header
    if (size < sizeof(FirmwareHeader)) return false;

    const auto* header = reinterpret_cast<const FirmwareHeader*>(data);
    if (memcmp(header->magic, "FWSG", 4) != 0) return false;

    // Extract components
    const uint8_t* signature = data + sizeof(FirmwareHeader);
    const uint8_t* firmware = signature + header->signature_size;

    // Verify signature
    mldsa::MLDSA65 dsa;
    std::span<const uint8_t> pk(VENDOR_PUBLIC_KEY, VENDOR_PUBLIC_KEY_SIZE);
    std::span<const uint8_t> msg(firmware, header->firmware_size);
    std::span<const uint8_t> sig(signature, header->signature_size);

    return dsa.verify(pk, msg, sig);
}
```

### Code Signing

Sign software releases and packages.

```python
# code_signer.py
import hashlib
import json
import os
from pathlib import Path
from dsa import MLDSA87  # Use highest security for code signing

class CodeSigner:
    """Sign software releases with manifest."""

    def __init__(self, secret_key: bytes, public_key: bytes):
        self.secret_key = secret_key
        self.public_key = public_key
        self.dsa = MLDSA87()

    def create_manifest(self, directory: str) -> dict:
        """Create manifest of all files in directory."""
        manifest = {
            'files': {},
            'algorithm': 'ML-DSA-87',
        }

        for path in Path(directory).rglob('*'):
            if path.is_file():
                rel_path = str(path.relative_to(directory))
                content = path.read_bytes()
                manifest['files'][rel_path] = {
                    'sha256': hashlib.sha256(content).hexdigest(),
                    'size': len(content),
                }

        return manifest

    def sign_release(self, directory: str, version: str) -> dict:
        """Sign a software release."""
        manifest = self.create_manifest(directory)
        manifest['version'] = version

        # Sign manifest
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        signature = self.dsa.sign(self.secret_key, manifest_bytes)

        return {
            'manifest': manifest,
            'signature': signature.hex(),
            'public_key': self.public_key.hex(),
        }

    def verify_release(self, directory: str, release_data: dict) -> bool:
        """Verify a signed release."""
        # Verify signature
        manifest = release_data['manifest']
        manifest_bytes = json.dumps(manifest, sort_keys=True).encode()
        signature = bytes.fromhex(release_data['signature'])
        public_key = bytes.fromhex(release_data['public_key'])

        if not self.dsa.verify(public_key, manifest_bytes, signature):
            print("Signature verification failed!")
            return False

        # Verify file hashes
        for rel_path, info in manifest['files'].items():
            path = Path(directory) / rel_path
            if not path.exists():
                print(f"Missing file: {rel_path}")
                return False

            content = path.read_bytes()
            if hashlib.sha256(content).hexdigest() != info['sha256']:
                print(f"Hash mismatch: {rel_path}")
                return False

        return True
```

### Secure Key Exchange

Establish shared secrets for encrypted communication.

```python
# secure_channel.py
from mlkem import MLKEM768
from dsa import MLDSA65
import os

class SecureChannel:
    """Authenticated key exchange using ML-KEM + ML-DSA."""

    def __init__(self):
        self.kem = MLKEM768()
        self.dsa = MLDSA65()

    def generate_identity(self) -> tuple:
        """Generate identity (signing keys) and KEM keys."""
        sign_pk, sign_sk = self.dsa.keygen()
        kem_ek, kem_dk = self.kem.keygen()
        return {
            'sign_pk': sign_pk,
            'sign_sk': sign_sk,
            'kem_ek': kem_ek,
            'kem_dk': kem_dk,
        }

    def initiate_exchange(self, peer_kem_ek: bytes, my_sign_sk: bytes) -> tuple:
        """Initiate key exchange (client side)."""
        # Encapsulate shared secret
        shared_secret, ciphertext = self.kem.encaps(peer_kem_ek)

        # Sign the ciphertext for authentication
        signature = self.dsa.sign(my_sign_sk, ciphertext)

        return shared_secret, ciphertext, signature

    def complete_exchange(self, ciphertext: bytes, signature: bytes,
                          peer_sign_pk: bytes, my_kem_dk: bytes) -> bytes:
        """Complete key exchange (server side)."""
        # Verify signature first
        if not self.dsa.verify(peer_sign_pk, ciphertext, signature):
            raise ValueError("Signature verification failed!")

        # Decapsulate to get shared secret
        shared_secret = self.kem.decaps(my_kem_dk, ciphertext)
        return shared_secret


# Usage example
if __name__ == "__main__":
    channel = SecureChannel()

    # Alice and Bob generate their identities
    alice = channel.generate_identity()
    bob = channel.generate_identity()

    # Exchange public keys (sign_pk, kem_ek) out of band
    # Alice initiates key exchange to Bob
    shared_alice, ciphertext, signature = channel.initiate_exchange(
        bob['kem_ek'], alice['sign_sk']
    )

    # Bob completes the exchange
    shared_bob = channel.complete_exchange(
        ciphertext, signature, alice['sign_pk'], bob['kem_dk']
    )

    assert shared_alice == shared_bob
    print(f"Shared secret established: {shared_alice.hex()[:32]}...")
    # Use shared_secret with AES-256-GCM for symmetric encryption
```

**C++ Version:**

```cpp
#include "mlkem/mlkem.hpp"
#include "mldsa/mldsa.hpp"
#include <iostream>

class SecureChannel {
    mlkem::MLKEM768 kem;
    mldsa::MLDSA65 dsa;

public:
    struct Identity {
        std::vector<uint8_t> sign_pk, sign_sk;
        std::vector<uint8_t> kem_ek, kem_dk;
    };

    Identity generate_identity() {
        Identity id;
        std::tie(id.sign_pk, id.sign_sk) = dsa.keygen();
        std::tie(id.kem_ek, id.kem_dk) = kem.keygen();
        return id;
    }

    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>
    initiate_exchange(const std::vector<uint8_t>& peer_kem_ek,
                      const std::vector<uint8_t>& my_sign_sk) {
        auto [shared_secret, ciphertext] = kem.encaps(peer_kem_ek);
        auto signature = dsa.sign(my_sign_sk, ciphertext);
        return {shared_secret, ciphertext, signature};
    }

    std::vector<uint8_t>
    complete_exchange(const std::vector<uint8_t>& ciphertext,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& peer_sign_pk,
                      const std::vector<uint8_t>& my_kem_dk) {
        if (!dsa.verify(peer_sign_pk, ciphertext, signature)) {
            throw std::runtime_error("Signature verification failed!");
        }
        return kem.decaps(my_kem_dk, ciphertext);
    }
};
```

---

## Web Server Integration

> **Note:** As of 2025, mainstream web servers don't have native support for ML-DSA/SLH-DSA certificates in TLS. The following shows how to prepare for future support and implement application-level signature verification.

### Current State of Post-Quantum TLS

- **OpenSSL 3.2+**: Experimental support via OQS provider
- **BoringSSL**: Limited experimental support
- **Nginx/Caddy**: No native support yet; requires patched OpenSSL

### Nginx Integration

#### Complete Docker + Nginx Example

Here's a complete, working example with Docker Compose:

**Project Structure:**
```
pq-nginx-demo/
├── docker-compose.yml
├── nginx/
│   └── nginx.conf
├── backend/
│   ├── Dockerfile
│   └── app.py
├── client/
│   ├── Dockerfile
│   └── client.py
└── keys/
    ├── mldsa65_public.key
    └── mldsa65_secret.key
```

**docker-compose.yml:**
```yaml
services:
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - backend

  backend:
    build: ./backend
    volumes:
      - ./keys:/keys:ro
    environment:
      - PUBLIC_KEY_PATH=/keys/mldsa65_public.key

  client:
    build: ./client
    volumes:
      - ./keys:/keys:ro
    environment:
      - SECRET_KEY_PATH=/keys/mldsa65_secret.key
      - API_URL=http://nginx:443
    depends_on:
      - nginx
```

**nginx/nginx.conf:**
```nginx
events {
    worker_connections 1024;
}

http {
    upstream backend {
        server backend:8080;
    }

    server {
        listen 443 ssl;
        server_name localhost;

        ssl_certificate /etc/nginx/ssl/server.crt;
        ssl_certificate_key /etc/nginx/ssl/server.key;

        location /api/ {
            # Pass PQ signature headers to backend
            proxy_pass http://backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-PQ-Signature $http_x_pq_signature;
            proxy_set_header X-PQ-Timestamp $http_x_pq_timestamp;
            proxy_set_header X-PQ-PublicKey $http_x_pq_publickey;
            proxy_set_header X-PQ-Algorithm $http_x_pq_algorithm;
        }

        # Health check endpoint (no auth required)
        location /health {
            proxy_pass http://backend;
        }
    }
}
```

**backend/Dockerfile:**
```dockerfile
FROM python:3.11-slim
WORKDIR /app

RUN pip install flask dsa

COPY app.py .
CMD ["python", "app.py"]
```

**backend/app.py:**
```python
#!/usr/bin/env python3
from flask import Flask, request, jsonify
from pathlib import Path
import os
import time

# Import DSA
from dsa import MLDSA65

app = Flask(__name__)
dsa = MLDSA65()

# Load public key
PUBLIC_KEY = None
pk_path = os.environ.get('PUBLIC_KEY_PATH')
if pk_path and Path(pk_path).exists():
    PUBLIC_KEY = Path(pk_path).read_bytes()
    print(f"Loaded public key: {len(PUBLIC_KEY)} bytes")

@app.before_request
def verify_signature():
    """Verify PQ signature on API requests."""
    if not request.path.startswith('/api/'):
        return None

    if PUBLIC_KEY is None:
        return jsonify({'error': 'Server not configured'}), 500

    # Get signature headers
    signature = request.headers.get('X-PQ-Signature')
    timestamp = request.headers.get('X-PQ-Timestamp')

    if not signature or not timestamp:
        return jsonify({'error': 'Missing signature headers'}), 401

    # Check timestamp (5 minute window)
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:
            return jsonify({'error': 'Request expired'}), 401
    except ValueError:
        return jsonify({'error': 'Invalid timestamp'}), 401

    # Verify signature
    try:
        sig = bytes.fromhex(signature)
        body = request.get_data().decode() or ''
        message = f"{timestamp}:{request.method}:{request.path}:{body}".encode()

        if not dsa.verify(PUBLIC_KEY, message, sig):
            return jsonify({'error': 'Invalid signature'}), 401

    except Exception as e:
        return jsonify({'error': f'Verification failed: {e}'}), 401

    return None

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

@app.route('/api/data', methods=['GET'])
def get_data():
    return jsonify({
        'status': 'authenticated',
        'message': 'This is protected data',
        'quantum_safe': True
    })

@app.route('/api/action', methods=['POST'])
def do_action():
    data = request.json or {}
    return jsonify({
        'status': 'success',
        'action': data.get('action', 'unknown'),
        'result': 'Action completed'
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
```

**client/Dockerfile:**
```dockerfile
FROM python:3.11-slim
WORKDIR /app

RUN pip install requests dsa

COPY client.py .
CMD ["python", "client.py"]
```

**client/client.py:**
```python
#!/usr/bin/env python3
import requests
import time
import os
from pathlib import Path

from dsa import MLDSA65

class PQClient:
    def __init__(self, base_url: str, secret_key: bytes):
        self.base_url = base_url
        self.secret_key = secret_key
        self.dsa = MLDSA65()
        # Disable SSL verification for demo (use proper certs in production)
        self.verify_ssl = False

    def sign_request(self, method: str, path: str, body: str = '') -> dict:
        timestamp = str(int(time.time()))
        message = f"{timestamp}:{method}:{path}:{body}".encode()
        signature = self.dsa.sign(self.secret_key, message)
        return {
            'X-PQ-Signature': signature.hex(),
            'X-PQ-Timestamp': timestamp,
            'X-PQ-Algorithm': 'ML-DSA-65',
        }

    def get(self, path: str) -> dict:
        headers = self.sign_request('GET', path)
        resp = requests.get(f"{self.base_url}{path}", headers=headers, verify=self.verify_ssl)
        return resp.json()

    def post(self, path: str, data: dict) -> dict:
        import json
        body = json.dumps(data)
        headers = self.sign_request('POST', path, body)
        headers['Content-Type'] = 'application/json'
        resp = requests.post(f"{self.base_url}{path}", data=body, headers=headers, verify=self.verify_ssl)
        return resp.json()

if __name__ == '__main__':
    # Load secret key
    sk_path = os.environ.get('SECRET_KEY_PATH', '/keys/mldsa65_secret.key')
    secret_key = Path(sk_path).read_bytes()

    api_url = os.environ.get('API_URL', 'https://localhost:443')

    print("=== Post-Quantum Authenticated Client ===")
    print(f"API URL: {api_url}")
    print(f"Secret key: {len(secret_key)} bytes")

    client = PQClient(api_url, secret_key)

    # Make authenticated requests
    print("\n--- GET /api/data ---")
    result = client.get('/api/data')
    print(f"Response: {result}")

    print("\n--- POST /api/action ---")
    result = client.post('/api/action', {'action': 'process', 'item_id': 123})
    print(f"Response: {result}")

    print("\n=== Client Demo Complete ===")
```

**Running the Example:**
```bash
# 1. Generate keys
cd pq-nginx-demo
docker run --rm -v $(pwd)/keys:/keys dsa-cpp ./build/keygen mldsa65 /keys

# 2. Generate self-signed SSL certificate (for demo)
mkdir -p nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout nginx/ssl/server.key \
    -out nginx/ssl/server.crt \
    -subj "/CN=localhost"

# 3. Run the stack
docker-compose up --build

# Expected output:
# backend   | Loaded public key: 1952 bytes
# client    | === Post-Quantum Authenticated Client ===
# client    | --- GET /api/data ---
# client    | Response: {'status': 'authenticated', 'message': 'This is protected data', 'quantum_safe': True}
```

#### Option 1: Application-Level Signature Verification

Use Nginx as reverse proxy with signature verification in your application.

```nginx
# /etc/nginx/nginx.conf

upstream backend {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl;
    server_name api.example.com;

    # Traditional TLS (still needed for transport)
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    location /api/ {
        # Pass signature headers to backend
        proxy_pass http://backend;
        proxy_set_header X-PQ-Signature $http_x_pq_signature;
        proxy_set_header X-PQ-Timestamp $http_x_pq_timestamp;
        proxy_set_header X-PQ-PublicKey $http_x_pq_publickey;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

#### Backend Verification (Python)

```python
# nginx_backend.py
from flask import Flask, request, jsonify
from dsa import MLDSA65
import time

app = Flask(__name__)
dsa = MLDSA65()

# Registered client public keys
TRUSTED_KEYS = {
    # client_id: public_key_bytes
}

@app.before_request
def verify_pq_signature():
    """Verify post-quantum signature on all API requests."""
    if not request.path.startswith('/api/'):
        return

    signature = request.headers.get('X-PQ-Signature')
    timestamp = request.headers.get('X-PQ-Timestamp')
    public_key_hex = request.headers.get('X-PQ-PublicKey')

    if not all([signature, timestamp, public_key_hex]):
        return jsonify({'error': 'Missing signature headers'}), 401

    # Check timestamp freshness (prevent replay attacks)
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > 300:  # 5 minute window
            return jsonify({'error': 'Request expired'}), 401
    except ValueError:
        return jsonify({'error': 'Invalid timestamp'}), 401

    # Verify signature
    try:
        public_key = bytes.fromhex(public_key_hex)
        sig = bytes.fromhex(signature)

        # Message = timestamp + method + path + body
        message = f"{timestamp}:{request.method}:{request.path}:{request.get_data().decode()}".encode()

        if not dsa.verify(public_key, message, sig):
            return jsonify({'error': 'Invalid signature'}), 401

    except Exception as e:
        return jsonify({'error': f'Verification failed: {e}'}), 401

@app.route('/api/data', methods=['GET', 'POST'])
def api_data():
    return jsonify({'status': 'authenticated', 'data': 'sensitive information'})

if __name__ == '__main__':
    app.run(port=8080)
```

#### Option 2: Hybrid Certificates (Future)

When support becomes available, use hybrid certificates combining traditional and post-quantum algorithms.

```nginx
# Future configuration (not yet supported)
server {
    listen 443 ssl;

    # Hybrid certificate chain
    ssl_certificate /etc/nginx/ssl/hybrid-cert.pem;
    ssl_certificate_key /etc/nginx/ssl/hybrid-key.pem;

    # Prefer post-quantum key exchange
    ssl_ecdh_curve X25519MLKEM768:X25519:P-256;

    # Post-quantum signature algorithms
    ssl_conf_command SignatureAlgorithms mldsa65:ecdsa_secp384r1_sha384;
}
```

### Caddy Integration

#### Complete Docker + Caddy Example

**docker-compose.yml:**
```yaml
services:
  caddy:
    image: caddy:alpine
    ports:
      - "8443:443"
      - "8080:80"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - caddy_data:/data
      - caddy_config:/config
    depends_on:
      - backend

  backend:
    build: ./backend
    volumes:
      - ./keys:/keys:ro
    environment:
      - PUBLIC_KEY_PATH=/keys/mldsa65_public.key

volumes:
  caddy_data:
  caddy_config:
```

**Caddyfile:**
```
{
    # Local development - self-signed certs
    local_certs
}

localhost {
    # Forward all API requests to backend
    reverse_proxy /api/* backend:8080 {
        header_up X-PQ-Signature {header.X-PQ-Signature}
        header_up X-PQ-Timestamp {header.X-PQ-Timestamp}
        header_up X-PQ-Algorithm {header.X-PQ-Algorithm}
    }

    # Health check
    reverse_proxy /health backend:8080

    # Default response
    respond "Post-Quantum API Gateway" 200
}
```

**Running:**
```bash
# Generate keys
docker run --rm -v $(pwd)/keys:/keys dsa-cpp ./build/keygen mldsa65 /keys

# Start services
docker-compose up --build
```

#### Caddyfile with Signature Verification Middleware

```
# Caddyfile

api.example.com {
    tls /etc/caddy/ssl/server.crt /etc/caddy/ssl/server.key

    @api path /api/*

    route @api {
        # Forward to backend with signature headers
        reverse_proxy localhost:8080 {
            header_up X-PQ-Signature {header.X-PQ-Signature}
            header_up X-PQ-Timestamp {header.X-PQ-Timestamp}
            header_up X-PQ-PublicKey {header.X-PQ-PublicKey}
        }
    }
}
```

#### Caddy Plugin for PQ Verification (Go)

```go
// caddy_pq_verify.go - Custom Caddy middleware
package pqverify

import (
    "encoding/hex"
    "fmt"
    "net/http"
    "time"

    "github.com/caddyserver/caddy/v2"
    "github.com/caddyserver/caddy/v2/caddyhttp"
)

func init() {
    caddy.RegisterModule(PQVerify{})
}

type PQVerify struct {
    MaxAge int `json:"max_age,omitempty"`
}

func (PQVerify) CaddyModule() caddy.ModuleInfo {
    return caddy.ModuleInfo{
        ID:  "http.handlers.pq_verify",
        New: func() caddy.Module { return new(PQVerify) },
    }
}

func (p PQVerify) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
    sig := r.Header.Get("X-PQ-Signature")
    ts := r.Header.Get("X-PQ-Timestamp")
    pk := r.Header.Get("X-PQ-PublicKey")

    if sig == "" || ts == "" || pk == "" {
        http.Error(w, "Missing PQ signature", http.StatusUnauthorized)
        return nil
    }

    // Verify timestamp
    // Verify signature using ML-DSA library
    // ...

    return next.ServeHTTP(w, r)
}
```

### Client Library for Web Requests

```python
# pq_http_client.py
import requests
import time
from dsa import MLDSA65

class PQHTTPClient:
    """HTTP client with post-quantum request signing."""

    def __init__(self, secret_key: bytes, public_key: bytes):
        self.secret_key = secret_key
        self.public_key = public_key
        self.dsa = MLDSA65()

    def _sign_request(self, method: str, url: str, body: str = '') -> dict:
        timestamp = str(int(time.time()))

        # Parse URL for path
        from urllib.parse import urlparse
        path = urlparse(url).path

        # Create message to sign
        message = f"{timestamp}:{method}:{path}:{body}".encode()
        signature = self.dsa.sign(self.secret_key, message)

        return {
            'X-PQ-Signature': signature.hex(),
            'X-PQ-Timestamp': timestamp,
            'X-PQ-PublicKey': self.public_key.hex(),
        }

    def get(self, url: str, **kwargs) -> requests.Response:
        headers = kwargs.pop('headers', {})
        headers.update(self._sign_request('GET', url))
        return requests.get(url, headers=headers, **kwargs)

    def post(self, url: str, json=None, data=None, **kwargs) -> requests.Response:
        import json as jsonlib
        body = jsonlib.dumps(json) if json else (data or '')

        headers = kwargs.pop('headers', {})
        headers.update(self._sign_request('POST', url, body))

        return requests.post(url, json=json, data=data, headers=headers, **kwargs)

# Usage
if __name__ == '__main__':
    # Load keys
    with open('client.sec', 'rb') as f:
        secret_key = f.read()
    with open('client.pub', 'rb') as f:
        public_key = f.read()

    client = PQHTTPClient(secret_key, public_key)

    # Make signed requests
    response = client.get('https://api.example.com/api/data')
    print(response.json())

    response = client.post('https://api.example.com/api/action', json={'command': 'do_something'})
    print(response.json())
```

---

## Programming Examples

### Complete C++ Example

```cpp
// complete_example.cpp
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>

// Utility functions
std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) throw std::runtime_error("Cannot open file: " + path);
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(size);
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    if (!f) throw std::runtime_error("Cannot create file: " + path);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

std::string to_hex(const std::vector<uint8_t>& data) {
    std::string hex;
    hex.reserve(data.size() * 2);
    for (uint8_t b : data) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

int main() {
    std::cout << "=== Post-Quantum DSA Complete Example ===\n\n";

    // 1. ML-DSA Example
    std::cout << "--- ML-DSA-65 ---\n";
    {
        mldsa::MLDSA65 dsa;

        // Generate keys
        auto [pk, sk] = dsa.keygen();
        std::cout << "Public key:  " << pk.size() << " bytes\n";
        std::cout << "Secret key:  " << sk.size() << " bytes\n";

        // Sign a message
        std::string msg_str = "Hello, Post-Quantum World!";
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        auto signature = dsa.sign(sk, message);
        std::cout << "Signature:   " << signature.size() << " bytes\n";

        // Verify
        bool valid = dsa.verify(pk, message, signature);
        std::cout << "Verification: " << (valid ? "PASSED" : "FAILED") << "\n";

        // Tamper detection
        message[0] ^= 0xFF;  // Flip bits
        bool tampered = dsa.verify(pk, message, signature);
        std::cout << "Tampered:    " << (tampered ? "FAILED (bad)" : "REJECTED (good)") << "\n";
    }

    std::cout << "\n--- SLH-DSA-SHAKE-128f ---\n";
    {
        slhdsa::SLHDSA_SHAKE_128f dsa;

        // Generate keys (note: returns sk, pk)
        auto [sk, pk] = dsa.keygen();
        std::cout << "Public key:  " << pk.size() << " bytes\n";
        std::cout << "Secret key:  " << sk.size() << " bytes\n";

        // Sign a message
        std::string msg_str = "Important document content";
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        auto signature = dsa.sign(sk, message);
        std::cout << "Signature:   " << signature.size() << " bytes\n";

        // Verify
        bool valid = dsa.verify(pk, message, signature);
        std::cout << "Verification: " << (valid ? "PASSED" : "FAILED") << "\n";
    }

    std::cout << "\n=== Example Complete ===\n";
    return 0;
}
```

### Complete Python Example

```python
#!/usr/bin/env python3
"""Complete Post-Quantum DSA Example"""

from dsa import MLDSA44, MLDSA65, MLDSA87
from dsa import slh_keygen, slh_sign, slh_verify, SLH_DSA_SHAKE_128f

def mldsa_example():
    """ML-DSA signing and verification."""
    print("--- ML-DSA-65 ---")

    dsa = MLDSA65()

    # Generate keys
    pk, sk = dsa.keygen()
    print(f"Public key:  {len(pk)} bytes")
    print(f"Secret key:  {len(sk)} bytes")

    # Sign a message
    message = b"Hello, Post-Quantum World!"
    signature = dsa.sign(sk, message)
    print(f"Signature:   {len(signature)} bytes")

    # Verify
    valid = dsa.verify(pk, message, signature)
    print(f"Verification: {'PASSED' if valid else 'FAILED'}")

    # Tamper detection
    tampered_msg = b"Hello, Post-Quantum World?"  # Changed ! to ?
    tampered = dsa.verify(pk, tampered_msg, signature)
    print(f"Tampered:    {'FAILED (bad)' if tampered else 'REJECTED (good)'}")

    return pk, sk

def slhdsa_example():
    """SLH-DSA signing and verification."""
    print("\n--- SLH-DSA-SHAKE-128f ---")

    params = SLH_DSA_SHAKE_128f

    # Generate keys (note: returns sk, pk)
    sk, pk = slh_keygen(params)
    print(f"Public key:  {len(pk)} bytes")
    print(f"Secret key:  {len(sk)} bytes")

    # Sign a message
    message = b"Important document content"
    signature = slh_sign(params, message, sk)
    print(f"Signature:   {len(signature)} bytes")

    # Verify
    valid = slh_verify(params, message, signature, pk)
    print(f"Verification: {'PASSED' if valid else 'FAILED'}")

    return pk, sk

def file_signing_example():
    """Sign and verify a file."""
    print("\n--- File Signing Example ---")

    import hashlib
    from pathlib import Path

    dsa = MLDSA87()
    pk, sk = dsa.keygen()

    # Create a test file
    test_content = b"This is the content of an important file."
    Path("test_file.txt").write_bytes(test_content)

    # Sign the file
    file_hash = hashlib.sha256(test_content).digest()
    signature = dsa.sign(sk, file_hash)

    # Save signature
    Path("test_file.txt.sig").write_bytes(signature)
    Path("test_file.txt.pub").write_bytes(pk)

    print(f"File signed: test_file.txt")
    print(f"Signature:   test_file.txt.sig ({len(signature)} bytes)")

    # Verify
    loaded_content = Path("test_file.txt").read_bytes()
    loaded_sig = Path("test_file.txt.sig").read_bytes()
    loaded_pk = Path("test_file.txt.pub").read_bytes()

    content_hash = hashlib.sha256(loaded_content).digest()
    valid = dsa.verify(loaded_pk, content_hash, loaded_sig)
    print(f"Verification: {'PASSED' if valid else 'FAILED'}")

    # Cleanup
    Path("test_file.txt").unlink()
    Path("test_file.txt.sig").unlink()
    Path("test_file.txt.pub").unlink()

if __name__ == '__main__':
    print("=== Post-Quantum DSA Complete Example ===\n")

    mldsa_example()
    slhdsa_example()
    file_signing_example()

    print("\n=== Example Complete ===")
```

---

## Security Considerations

### Key Management

1. **Generate keys securely**: Use cryptographically secure random number generators
2. **Protect secret keys**:
   - Store in HSM when possible
   - Use password protection (`--password-prompt`) for encrypted storage
   - Use encrypted storage (LUKS, encrypted keychain)
   - Set restrictive file permissions (`chmod 600`)
   - Never log or transmit secret keys
3. **Password-protected keys**:
   - Use strong passwords (12+ characters, mixed case, numbers, symbols)
   - The implementation uses PBKDF2 with 600,000 iterations (OWASP 2023)
   - AES-256-GCM provides authenticated encryption
   - Password prompts disable terminal echo for security
4. **Key rotation**: Plan for regular key rotation
5. **Key revocation**: Implement certificate revocation lists or OCSP

### Implementation Security

1. **Constant-time operations**: This library implements constant-time algorithms to prevent timing attacks
2. **Memory protection**:
   - Clear secret key memory after use
   - Use `mlock()` to prevent swapping
3. **Input validation**: Always validate key and signature sizes

### Protocol Security

1. **Replay attacks**: Include timestamps or nonces in signed messages
2. **Man-in-the-middle**: Verify public key authenticity through trusted channels
3. **Version binding**: Include protocol version in signed data

### Algorithm Selection

1. **ML-DSA**:
   - Based on lattice assumptions (MLWE problem)
   - Well-studied, part of NIST standard
   - Good balance of security and performance

2. **SLH-DSA**:
   - Based only on hash function security
   - More conservative security assumptions
   - Larger signatures but smaller keys

### Quantum Threat Timeline

- **Current**: Classical computers cannot break these algorithms
- **2030s**: Large-scale quantum computers may threaten RSA/ECC
- **Recommendation**: Begin migration to post-quantum algorithms now

---

## Troubleshooting

### Common Issues

**"Verification failed" for valid signatures**
- Ensure you're using the correct key pair
- For SLH-DSA, remember `keygen()` returns `(sk, pk)` not `(pk, sk)`
- Check that the message hasn't been modified (encoding, whitespace)

**"Key size mismatch"**
- Ensure you're using matching algorithm variants
- ML-DSA-44 keys don't work with ML-DSA-65, etc.

**Performance issues**
- Use C++ implementation for production
- SLH-DSA is slower than ML-DSA by design
- Consider ML-DSA for high-frequency operations

### Getting Help

- GitHub Issues: [repository-url]/issues
- Documentation: [repository-url]/docs
- Security Issues: security@example.com (PGP key available)

---

## References

- [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- [FIPS 205: Stateless Hash-Based Digital Signature Standard](https://csrc.nist.gov/publications/detail/fips/205/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
