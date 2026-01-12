# Post-Quantum Cryptography Library {#mainpage}

A C++20 implementation of NIST post-quantum cryptographic standards.

## Algorithms

This library provides implementations of three NIST-standardized post-quantum algorithms:

| Algorithm | Standard | Type | Security Levels |
|-----------|----------|------|-----------------|
| **ML-KEM** | FIPS 203 | Key Encapsulation | 512, 768, 1024 |
| **ML-DSA** | FIPS 204 | Digital Signature | 44, 65, 87 |
| **SLH-DSA** | FIPS 205 | Digital Signature | Multiple parameter sets |

## Quick Start

### ML-KEM (Key Encapsulation)

```cpp
#include "mlkem/mlkem.hpp"

// Create ML-KEM-768 instance
mlkem::MLKEM768 kem;

// Generate key pair
auto [ek, dk] = kem.keygen();

// Encapsulate - produces shared secret and ciphertext
auto [K, c] = kem.encaps(ek);

// Decapsulate - recovers the same shared secret
auto K_recovered = kem.decaps(dk, c);
// K == K_recovered
```

### ML-DSA (Digital Signatures)

```cpp
#include "mldsa/mldsa.hpp"

// Create ML-DSA-65 instance
mldsa::MLDSA65 dsa;

// Generate key pair
auto [pk, sk] = dsa.keygen();

// Sign a message
std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
auto signature = dsa.sign(sk, message);

// Verify signature
bool valid = dsa.verify(pk, message, signature);
```

### SLH-DSA (Stateless Hash-Based Signatures)

```cpp
#include "slhdsa/slhdsa.hpp"

// Create SLH-DSA-SHAKE-128f instance
slhdsa::SLHDSA_SHAKE_128f dsa;

// Generate key pair
auto [pk, sk] = dsa.keygen();

// Sign and verify
auto signature = dsa.sign(sk, message);
bool valid = dsa.verify(pk, message, signature);
```

## Security Features

This implementation includes several security hardening measures:

- **Constant-time operations** - Resistant to timing side-channel attacks
- **Implicit rejection** - ML-KEM returns pseudorandom values for invalid ciphertexts
- **Secure memory handling** - Sensitive data is zeroed after use
- **Input validation** - All public API inputs are validated

See the @ref md_docs_2SECURITY_AUDIT "Security Audit" document for details on security fixes applied.

## Module Structure

- @ref mlkem - ML-KEM key encapsulation mechanism
- @ref mldsa - ML-DSA digital signature algorithm
- @ref slhdsa - SLH-DSA stateless hash-based signatures

## Python Bindings

Python bindings are available for all algorithms:

```python
from mlkem import MLKEM768
from mldsa import MLDSA65
from slhdsa import SLHDSA_SHAKE_128f

# ML-KEM
kem = MLKEM768()
ek, dk = kem.keygen()
shared_secret, ciphertext = kem.encaps(ek)
recovered = kem.decaps(dk, ciphertext)

# ML-DSA
dsa = MLDSA65()
pk, sk = dsa.keygen()
sig = dsa.sign(sk, b"Hello, World!")
assert dsa.verify(pk, b"Hello, World!", sig)
```

## Building

```bash
# Build the library
make build

# Run tests
make test

# Generate documentation
make docs
```

## Standards Compliance

- **FIPS 203** - Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- **FIPS 204** - Module-Lattice-Based Digital Signature Algorithm (ML-DSA)
- **FIPS 205** - Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)

## License

See the LICENSE file for details.
