# ML-DSA API Reference

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a post-quantum digital signature scheme standardized in NIST FIPS 204.

## Classes

### MLDSA44

ML-DSA with security category 2 (128-bit classical security).

```python
from mldsa import MLDSA44

dsa = MLDSA44()
```

### MLDSA65

ML-DSA with security category 3 (192-bit classical security).

```python
from mldsa import MLDSA65

dsa = MLDSA65()
```

### MLDSA87

ML-DSA with security category 5 (256-bit classical security).

```python
from mldsa import MLDSA87

dsa = MLDSA87()
```

## Methods

### keygen(seed=None)

Generate a key pair.

**Parameters:**
- `seed` (bytes, optional): 32-byte seed for deterministic key generation. If None, random keys are generated.

**Returns:**
- `tuple[bytes, bytes]`: (public_key, secret_key)

**Raises:**
- `ValueError`: If seed is provided but not 32 bytes.

**Example:**
```python
from mldsa import MLDSA65

dsa = MLDSA65()

# Random key generation
pk, sk = dsa.keygen()

# Deterministic key generation
seed = bytes(32)  # 32 zero bytes
pk, sk = dsa.keygen(seed)
```

### sign(sk, message, ctx=None, deterministic=False)

Sign a message.

**Parameters:**
- `sk` (bytes): Secret key
- `message` (bytes): Message to sign
- `ctx` (bytes, optional): Context string (max 255 bytes)
- `deterministic` (bool): If True, use deterministic signing (default: False)

**Returns:**
- `bytes`: Signature

**Raises:**
- `ValueError`: If context string exceeds 255 bytes.

**Example:**
```python
sig = dsa.sign(sk, b"Hello, World!")

# With context
sig = dsa.sign(sk, b"Hello", ctx=b"greeting")

# Deterministic signing (same inputs = same signature)
sig = dsa.sign(sk, b"Hello", deterministic=True)
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
if is_valid:
    print("Signature is valid")
```

### params (property)

Get the parameter set for this instance.

**Returns:**
- `MLDSAParams`: Parameter set object

**Example:**
```python
dsa = MLDSA65()
print(f"Public key size: {dsa.params.pk_size} bytes")
print(f"Signature size: {dsa.params.sig_size} bytes")
```

## Parameter Sets

### MLDSAParams

Parameter set class with the following read-only properties:

| Property | Description |
|----------|-------------|
| `name` | Parameter set name |
| `k` | Matrix rows |
| `l` | Matrix columns |
| `eta` | Secret key coefficient range |
| `tau` | Challenge weight |
| `beta` | Signature bound |
| `gamma1` | Mask range |
| `gamma2` | Decomposition parameter |
| `omega` | Maximum hint weight |
| `lambda_` | Security parameter (bits) |
| `pk_size` | Public key size in bytes |
| `sk_size` | Secret key size in bytes |
| `sig_size` | Signature size in bytes |

### Constants

```python
from mldsa import MLDSA44_PARAMS, MLDSA65_PARAMS, MLDSA87_PARAMS
```

| Parameter Set | pk_size | sk_size | sig_size | Security |
|--------------|---------|---------|----------|----------|
| MLDSA44_PARAMS | 1312 | 2560 | 2420 | Level 2 |
| MLDSA65_PARAMS | 1952 | 4032 | 3309 | Level 3 |
| MLDSA87_PARAMS | 2592 | 4896 | 4627 | Level 5 |
