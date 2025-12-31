# SLH-DSA API Reference

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) is a post-quantum digital signature scheme standardized in NIST FIPS 205. It's based on SPHINCS+.

## Classes

SLH-DSA provides 12 parameter sets with different trade-offs:

### SHA2 Variants

Best performance on systems with SHA2 hardware acceleration.

```python
from slhdsa import (
    SLHDSA_SHA2_128s, SLHDSA_SHA2_128f,  # 128-bit security
    SLHDSA_SHA2_192s, SLHDSA_SHA2_192f,  # 192-bit security
    SLHDSA_SHA2_256s, SLHDSA_SHA2_256f,  # 256-bit security
)
```

### SHAKE Variants

Consistent performance across platforms.

```python
from slhdsa import (
    SLHDSA_SHAKE_128s, SLHDSA_SHAKE_128f,  # 128-bit security
    SLHDSA_SHAKE_192s, SLHDSA_SHAKE_192f,  # 192-bit security
    SLHDSA_SHAKE_256s, SLHDSA_SHAKE_256f,  # 256-bit security
)
```

### Suffix Meanings

- `s` (small): Smaller signatures, slower signing
- `f` (fast): Faster signing, larger signatures

## Methods

### keygen()

Generate a key pair.

**Returns:**
- `tuple[bytes, bytes]`: (public_key, secret_key)

**Example:**
```python
from slhdsa import SLHDSA_SHAKE_128f

dsa = SLHDSA_SHAKE_128f()
pk, sk = dsa.keygen()
```

### keygen_from_seeds(sk_seed, sk_prf, pk_seed)

Generate a key pair from seeds (for testing/KAT).

**Parameters:**
- `sk_seed` (bytes): Secret seed (n bytes)
- `sk_prf` (bytes): PRF key (n bytes)
- `pk_seed` (bytes): Public seed (n bytes)

**Returns:**
- `tuple[bytes, bytes]`: (public_key, secret_key)

**Example:**
```python
dsa = SLHDSA_SHAKE_128f()
n = dsa.params.n  # 16 for 128-bit security

pk, sk = dsa.keygen_from_seeds(
    sk_seed=b"\x01" * n,
    sk_prf=b"\x02" * n,
    pk_seed=b"\x03" * n
)
```

### sign(sk, message, ctx=None, randomize=True)

Sign a message.

**Parameters:**
- `sk` (bytes): Secret key
- `message` (bytes): Message to sign
- `ctx` (bytes, optional): Context string (max 255 bytes)
- `randomize` (bool): If True (default), use randomized signing

**Returns:**
- `bytes`: Signature

**Raises:**
- `ValueError`: If context string exceeds 255 bytes.

**Example:**
```python
sig = dsa.sign(sk, b"Hello, World!")

# Deterministic signing
sig = dsa.sign(sk, b"Hello", randomize=False)

# With context
sig = dsa.sign(sk, b"Hello", ctx=b"greeting")
```

### verify(pk, message, signature, ctx=None)

Verify a signature.

**Parameters:**
- `pk` (bytes): Public key
- `message` (bytes): Message
- `signature` (bytes): Signature to verify
- `ctx` (bytes, optional): Context string (must match signing context)

**Returns:**
- `bool`: True if valid, False otherwise

**Example:**
```python
is_valid = dsa.verify(pk, b"Hello, World!", sig)
```

### params (property)

Get the parameter set for this instance.

**Returns:**
- `SLHDSAParams`: Parameter set object

## Parameter Sets

### SLHDSAParams

| Property | Description |
|----------|-------------|
| `name` | Parameter set name |
| `n` | Security parameter (hash output bytes) |
| `h` | Total tree height |
| `d` | Number of hypertree layers |
| `hp` | Height per layer (h/d) |
| `a` | FORS tree height |
| `k` | Number of FORS trees |
| `lg_w` | Log2 of Winternitz parameter |
| `m` | Message digest length |
| `w` | Winternitz parameter (computed) |
| `pk_size` | Public key size in bytes |
| `sk_size` | Secret key size in bytes |
| `sig_size` | Signature size in bytes |

### Size Comparison

| Parameter Set | pk_size | sk_size | sig_size |
|--------------|---------|---------|----------|
| SLH-DSA-SHAKE-128s | 32 | 64 | 7,856 |
| SLH-DSA-SHAKE-128f | 32 | 64 | 17,088 |
| SLH-DSA-SHAKE-192s | 48 | 96 | 16,224 |
| SLH-DSA-SHAKE-192f | 48 | 96 | 35,664 |
| SLH-DSA-SHAKE-256s | 64 | 128 | 29,792 |
| SLH-DSA-SHAKE-256f | 64 | 128 | 49,856 |

SHA2 variants have the same sizes as their SHAKE counterparts.

## Performance Characteristics

- **Key Generation**: Slower than ML-DSA
- **Signing**: Much slower than ML-DSA (especially `s` variants)
- **Verification**: Moderate speed
- **Key Sizes**: Very small (32-64 bytes for public key)
- **Signature Sizes**: Large (7KB-50KB)

## When to Use SLH-DSA

Choose SLH-DSA when:
- You need the smallest possible public keys
- Conservative security assumptions are important (hash-based security)
- Signature size is not a concern
- Signing performance is not critical

Choose ML-DSA when:
- Performance is important
- Smaller signatures are needed
- Frequent signing operations are required
