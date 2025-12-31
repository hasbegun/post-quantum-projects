# PQC-DSA: Post-Quantum Digital Signatures

High-performance Python bindings for NIST post-quantum digital signature algorithms.

## Features

- **ML-DSA (FIPS 204)**: Lattice-based signatures with excellent performance
- **SLH-DSA (FIPS 205)**: Hash-based signatures with conservative security
- **Native C++ Performance**: pybind11 bindings for optimal speed
- **Type Hints**: Full IDE support with `.pyi` stubs
- **Cross-Platform**: Linux, macOS, Windows support

## Quick Example

```python
from mldsa import MLDSA65

# Generate keys
dsa = MLDSA65()
pk, sk = dsa.keygen()

# Sign a message
sig = dsa.sign(sk, b"Hello, post-quantum world!")

# Verify
assert dsa.verify(pk, b"Hello, post-quantum world!", sig)
```

## Installation

```bash
pip install pqc-dsa
```

## Choosing an Algorithm

| Feature | ML-DSA | SLH-DSA |
|---------|--------|---------|
| Performance | Fast | Slow |
| Key Size | ~2KB | 32-64 bytes |
| Signature Size | 2-5KB | 8-50KB |
| Security Basis | Lattice | Hash |

**Recommendation**: Use **ML-DSA-65** for most applications.

## Links

- [Quick Start Guide](guide/quickstart.md)
- [ML-DSA API](api/mldsa.md)
- [SLH-DSA API](api/slhdsa.md)
- [Building from Source](dev/building.md)
