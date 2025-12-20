# Post-Quantum DSA Demo Application (C++)

This demo application shows how post-quantum digital signatures work in a distributed system using the high-performance C++ implementation.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLIENT                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  SECRET KEY (private)                                │   │
│  │  - Signs messages                                    │   │
│  │  - Generates key pair                                │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────┬───────────────────┬───────────────────┘
                      │                   │
          Sign & Send │                   │ Sign & Send
                      ▼                   ▼
┌─────────────────────────────┐ ┌─────────────────────────────┐
│        SERVER 1             │ │        SERVER 2             │
│  ┌───────────────────────┐  │ │  ┌───────────────────────┐  │
│  │  PUBLIC KEY           │  │ │  │  PUBLIC KEY           │  │
│  │  - Verifies signatures│  │ │  │  - Verifies signatures│  │
│  └───────────────────────┘  │ │  └───────────────────────┘  │
└─────────────────────────────┘ └─────────────────────────────┘
```

## How It Works

1. **Key Generation**: Client generates a post-quantum key pair
2. **Key Distribution**: Client sends PUBLIC key to both servers
3. **Signing**: Client signs messages with SECRET key
4. **Verification**: Servers verify signatures using PUBLIC key
5. **Tamper Detection**: Demonstrates that altered messages are rejected

## Quick Start

```bash
# From the project root directory
make demo-app

# Or with a specific algorithm
make demo-app ALG=mldsa65
make demo-app ALG=slh-shake-128f
```

## Manual Docker Compose

```bash
cd examples/app

# Run with ML-DSA-44 (default)
docker-compose up --build

# Run with ML-DSA-65
ALGORITHM=mldsa65 docker-compose up --build

# Run with SLH-DSA
ALGORITHM=slh-shake-128f docker-compose up --build

# Clean up
docker-compose down
```

## Expected Output

```
============================================================
  Post-Quantum Digital Signature Demo (C++)
============================================================

Algorithm: mldsa44
Servers: server1:5001,server2:5002

[Client] Generating mldsa44 key pair...
[Client] Key generation completed in 1 ms
[Client] Public key:  1312 bytes
[Client] Secret key:  2560 bytes

------------------------------------------------------------
Step 1: Registering public key with servers
------------------------------------------------------------
  -> server1:5001: OK
  -> server2:5002: OK

------------------------------------------------------------
Step 2: Signing and verifying messages
------------------------------------------------------------

[Message 1]
  Content: Hello, Post-Quantum World!
  Signature: 2420 bytes (signed in 0.3 ms)
  -> Server-1: VALID (1.2 ms)
  -> Server-2: VALID (1.2 ms)

[Message 2]
  Content: Transaction: Transfer $1000 to Alice at 2025-12-20...
  Signature: 2420 bytes (signed in 0.5 ms)
  -> Server-1: VALID (0.5 ms)
  -> Server-2: VALID (0.5 ms)

------------------------------------------------------------
Step 3: Testing tamper detection
------------------------------------------------------------

  Original: Send $100 to Bob
  Tampered: Send $999 to Eve
  Signature of original: 2420 bytes
  -> Server-1: Tampered message REJECTED (Correct!)
  -> Server-2: Tampered message REJECTED (Correct!)

============================================================
  Demo completed successfully!
============================================================

Key takeaways:
  - Client holds the SECRET key (for signing)
  - Servers hold the PUBLIC key (for verification)
  - Signatures are quantum-resistant
  - Tampered messages are detected
```

## Performance

The C++ implementation is significantly faster than Python:

| Operation | Python | C++ |
|-----------|--------|-----|
| Key Generation | ~5 ms | ~1 ms |
| Signing (ML-DSA) | ~15-80 ms | ~0.3-0.8 ms |
| Verification | ~5 ms | ~0.4-1.2 ms |

## Available Algorithms

| Algorithm | Type | Security Level | Speed |
|-----------|------|----------------|-------|
| `mldsa44` | ML-DSA | Category 1 (128-bit) | Fast |
| `mldsa65` | ML-DSA | Category 3 (192-bit) | Fast |
| `mldsa87` | ML-DSA | Category 5 (256-bit) | Fast |
| `slh-shake-128f` | SLH-DSA | Category 1 (128-bit) | Slower |

## Files

| File | Description |
|------|-------------|
| `server.cpp` | C++ verification server (holds public key) |
| `client.cpp` | C++ signing client (holds secret key) |
| `docker-compose.yml` | Multi-container orchestration |
| `Dockerfile.cpp` | C++ container image definition |
| `server.py` | Python verification server (legacy) |
| `client.py` | Python signing client (legacy) |
| `Dockerfile` | Python container image definition (legacy) |
