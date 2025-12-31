# Quick Start Guide

Get started with post-quantum digital signatures in 5 minutes.

## ML-DSA (Recommended)

ML-DSA is the recommended choice for most use cases. It offers good performance and reasonable signature sizes.

```python
from mldsa import MLDSA65

# Create a signer
dsa = MLDSA65()

# Generate a key pair
public_key, secret_key = dsa.keygen()

# Sign a message
message = b"Hello, quantum-safe world!"
signature = dsa.sign(secret_key, message)

# Verify the signature
is_valid = dsa.verify(public_key, message, signature)
print(f"Signature valid: {is_valid}")  # True
```

## SLH-DSA (Hash-Based)

SLH-DSA offers the smallest public keys and conservative hash-based security.

```python
from slhdsa import SLHDSA_SHAKE_128f

# Create a signer
dsa = SLHDSA_SHAKE_128f()

# Generate keys
public_key, secret_key = dsa.keygen()

# Sign and verify
message = b"Important document"
signature = dsa.sign(secret_key, message)
is_valid = dsa.verify(public_key, message, signature)
```

## Choosing a Variant

### ML-DSA Variants

| Variant | Security | Use Case |
|---------|----------|----------|
| `MLDSA44` | 128-bit | General purpose |
| `MLDSA65` | 192-bit | Recommended default |
| `MLDSA87` | 256-bit | High security |

### SLH-DSA Variants

| Variant | Trade-off |
|---------|-----------|
| `*_128f` | Fast signing, larger signatures |
| `*_128s` | Small signatures, slower signing |
| `*_192*` | Higher security level |
| `*_256*` | Highest security level |

## Context Strings

Use context strings to domain-separate signatures:

```python
# Different contexts for different purposes
sig_auth = dsa.sign(sk, b"login request", ctx=b"authentication")
sig_doc = dsa.sign(sk, b"contract.pdf", ctx=b"document-signing")

# Verification requires matching context
dsa.verify(pk, b"login request", sig_auth, ctx=b"authentication")  # True
dsa.verify(pk, b"login request", sig_auth, ctx=b"document-signing")  # False
```

## Deterministic vs Randomized

```python
# Randomized (default) - different signature each time
sig1 = dsa.sign(sk, b"message")
sig2 = dsa.sign(sk, b"message")
assert sig1 != sig2  # Different!

# Deterministic - same signature for same input
sig1 = dsa.sign(sk, b"message", deterministic=True)
sig2 = dsa.sign(sk, b"message", deterministic=True)
assert sig1 == sig2  # Same!
```

## Key Sizes

```python
from mldsa import MLDSA65, MLDSA65_PARAMS

print(f"Public key: {MLDSA65_PARAMS.pk_size} bytes")   # 1952
print(f"Secret key: {MLDSA65_PARAMS.sk_size} bytes")   # 4032
print(f"Signature: {MLDSA65_PARAMS.sig_size} bytes")   # 3309
```

## Next Steps

- [ML-DSA API Reference](../api/mldsa.md)
- [SLH-DSA API Reference](../api/slhdsa.md)
- [Security Considerations](security.md)
