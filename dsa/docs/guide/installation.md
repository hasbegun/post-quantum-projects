# Installation Guide

## Requirements

- Python 3.9 or later
- OpenSSL development libraries
- C++20 compatible compiler (for building from source)

## Quick Install

```bash
pip install pqc-dsa
```

## Install from Source

### Prerequisites

**macOS:**
```bash
brew install openssl@3 cmake
```

**Ubuntu/Debian:**
```bash
sudo apt-get install libssl-dev cmake build-essential
```

**Fedora/RHEL:**
```bash
sudo dnf install openssl-devel cmake gcc-c++
```

### Build and Install

```bash
git clone https://github.com/example/pqc-dsa.git
cd pqc-dsa/dsa
pip install .
```

### Development Install

For development with editable install:

```bash
pip install -e ".[dev]"
```

## Docker

### Using Pre-built Image

```bash
# Pull and run
docker run --rm -it dsa-py python

# Run tests
docker run --rm dsa-py python -m pytest tests/py/ -v
```

### Build Locally

```bash
cd dsa
make build-py
make test-py
```

## Verify Installation

```python
# Test ML-DSA
from mldsa import MLDSA65
dsa = MLDSA65()
pk, sk = dsa.keygen()
sig = dsa.sign(sk, b"test")
assert dsa.verify(pk, b"test", sig)
print("ML-DSA: OK")

# Test SLH-DSA
from slhdsa import SLHDSA_SHAKE_128f
dsa = SLHDSA_SHAKE_128f()
pk, sk = dsa.keygen()
sig = dsa.sign(sk, b"test")
assert dsa.verify(pk, b"test", sig)
print("SLH-DSA: OK")
```

## Troubleshooting

### OpenSSL Not Found

```bash
# macOS
export OPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3

# Linux
export OPENSSL_ROOT_DIR=/usr
```

### CMake Version Too Old

```bash
pip install cmake --upgrade
```

### Compiler Issues

Ensure you have a C++20 compatible compiler:
- GCC 10+
- Clang 10+
- MSVC 19.29+
