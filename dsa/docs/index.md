# Post-Quantum Cryptography Library

High-performance Python and C++ implementations of NIST post-quantum cryptographic algorithms.

## Features

**Digital Signatures:**
- **ML-DSA (FIPS 204)**: Lattice-based signatures with excellent performance
- **SLH-DSA (FIPS 205)**: Hash-based signatures with conservative security

**Key Encapsulation:**
- **ML-KEM (FIPS 203)**: Lattice-based key encapsulation for secure key exchange

**Token Standards:**
- **JOSE Support**: JWT/JWS tokens with post-quantum signatures
- **COSE Support**: CBOR-based tokens for IoT applications

**Implementation:**
- **Native C++ Performance**: pybind11 bindings for optimal speed
- **Type Hints**: Full IDE support with `.pyi` stubs
- **Cross-Platform**: Linux, macOS, Windows support

## Quick Examples

### Digital Signatures (ML-DSA)
```python
from dsa import MLDSA65

# Generate keys
dsa = MLDSA65()
pk, sk = dsa.keygen()

# Sign a message
sig = dsa.sign(sk, b"Hello, post-quantum world!")

# Verify
assert dsa.verify(pk, b"Hello, post-quantum world!", sig)
```

### Key Exchange (ML-KEM)
```python
from mlkem import MLKEM768

# Alice generates key pair
kem = MLKEM768()
ek, dk = kem.keygen()

# Bob encapsulates a shared secret
shared_secret_bob, ciphertext = kem.encaps(ek)

# Alice decapsulates
shared_secret_alice = kem.decaps(dk, ciphertext)

# Both now share the same secret for symmetric encryption
assert shared_secret_bob == shared_secret_alice
```

### JWT with Post-Quantum Signatures (C++)
```cpp
#include "common/jose.hpp"
#include "mldsa/mldsa.hpp"

// Generate keys
mldsa::MLDSA65 dsa;
auto [pk, sk] = dsa.keygen();

// Create and verify JWT
std::string payload = R"({"sub":"user123"})";
std::string token = jose::create_jwt("ML-DSA-65", payload, sk);
auto result = jose::verify_jwt(token, pk);  // Returns payload if valid
```

## Installation

```bash
pip install pqc-dsa
```

Or use Docker:
```bash
make build
make test
```

## Choosing an Algorithm

### For Signatures

| Feature | ML-DSA | SLH-DSA |
|---------|--------|---------|
| Performance | Fast | Slow |
| Key Size | ~2KB | 32-64 bytes |
| Signature Size | 2-5KB | 8-50KB |
| Security Basis | Lattice | Hash |

**Recommendation**: Use **ML-DSA-65** for most applications. Use **SLH-DSA** for long-term security (root CAs, legal documents).

### For Key Exchange

| Parameter Set | Security | EK Size | CT Size |
|--------------|----------|---------|---------|
| ML-KEM-512 | Category 1 | 800 B | 768 B |
| ML-KEM-768 | Category 3 | 1,184 B | 1,088 B |
| ML-KEM-1024 | Category 5 | 1,568 B | 1,568 B |

**Recommendation**: Use **ML-KEM-768** for most applications (balance of security and performance).

## Links

- [Quick Start Guide](guide/quickstart.md)
- [ML-DSA API](api/mldsa.md)
- [SLH-DSA API](api/slhdsa.md)
- [ML-KEM API](api/mlkem.md)
- [JOSE/COSE API](api/jose_cose.md)
- [Building from Source](dev/building.md)
