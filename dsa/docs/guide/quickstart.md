# Quick Start Guide

Get started with post-quantum cryptography in 5 minutes.

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

## ML-KEM (Key Exchange)

ML-KEM provides quantum-resistant key encapsulation for establishing shared secrets.

```python
from mlkem import MLKEM768

# Create a KEM instance
kem = MLKEM768()

# Alice generates key pair
encapsulation_key, decapsulation_key = kem.keygen()

# Bob encapsulates a shared secret using Alice's public key
shared_secret_bob, ciphertext = kem.encaps(encapsulation_key)

# Alice decapsulates to get the same shared secret
shared_secret_alice = kem.decaps(decapsulation_key, ciphertext)

# Both now share a 32-byte secret for symmetric encryption (AES-GCM, etc.)
print(f"Secrets match: {shared_secret_bob == shared_secret_alice}")  # True
print(f"Shared secret: {shared_secret_alice.hex()}")
```

### Implicit Rejection

If the ciphertext is tampered with, `decaps` returns a pseudorandom value instead of failing. This prevents timing attacks:

```python
# Tampered ciphertext
tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
fake_secret = kem.decaps(decapsulation_key, tampered)

# fake_secret is pseudorandom, not an error
assert fake_secret != shared_secret_alice
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

### ML-KEM Variants

| Variant | Security | Use Case |
|---------|----------|----------|
| `MLKEM512` | 128-bit | IoT, embedded systems |
| `MLKEM768` | 192-bit | Recommended default |
| `MLKEM1024` | 256-bit | High security |

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

### ML-DSA
```python
from dsa import MLDSA65

dsa = MLDSA65()
print(f"Public key: {dsa.params.pk_size} bytes")   # 1952
print(f"Secret key: {dsa.params.sk_size} bytes")   # 4032
print(f"Signature: {dsa.params.sig_size} bytes")   # 3309
```

### ML-KEM
```python
from mlkem import MLKEM768

kem = MLKEM768()
print(f"Encapsulation key: {kem.params.ek_size} bytes")  # 1184
print(f"Decapsulation key: {kem.params.dk_size} bytes")  # 2400
print(f"Ciphertext: {kem.params.ct_size} bytes")         # 1088
print(f"Shared secret: 32 bytes")                         # Always 32
```

## Using ML-KEM with ML-DSA Together

For authenticated key exchange (like TLS), combine ML-KEM for confidentiality with ML-DSA for authentication:

```python
from mlkem import MLKEM768
from dsa import MLDSA65

# Alice: Generate both signing and KEM keys
dsa = MLDSA65()
sign_pk, sign_sk = dsa.keygen()

kem = MLKEM768()
ek, dk = kem.keygen()

# Bob: Encapsulate and sign the ciphertext
shared_secret_bob, ciphertext = kem.encaps(ek)
signature = dsa.sign(sign_sk, ciphertext)

# Alice: Verify signature first, then decapsulate
if dsa.verify(sign_pk, ciphertext, signature):
    shared_secret_alice = kem.decaps(dk, ciphertext)
    # Use shared_secret for AES-GCM encryption
    print("Authenticated key exchange successful!")
```

## JWT Tokens with Post-Quantum Signatures (C++)

Create standards-compliant JWT tokens with post-quantum signatures:

```cpp
#include "common/jose.hpp"
#include "mldsa/mldsa.hpp"

// Generate keys
mldsa::MLDSA65 dsa;
auto [pk, sk] = dsa.keygen();

// Create JWT
std::string payload = R"({"sub":"user123","iss":"myapp","exp":1735689600})";
std::string token = jose::create_jwt("ML-DSA-65", payload, sk);

// Verify JWT
auto result = jose::verify_jwt(token, pk);
if (result) {
    std::cout << "Valid! Payload: " << *result << "\n";
}
```

## COSE Messages for IoT (C++)

For constrained devices, use COSE (compact binary format):

```cpp
#include "common/cose.hpp"
#include "mldsa/mldsa.hpp"

// Generate keys
mldsa::MLDSA65 dsa;
auto [pk, sk] = dsa.keygen();

// Create COSE_Sign1 message
std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
auto cose_msg = cose::sign1("ML-DSA-65", payload, sk);

// Verify
auto result = cose::verify1(cose_msg, pk);
if (result) {
    std::cout << "Valid COSE message\n";
}
```

## Next Steps

- [ML-DSA API Reference](../api/mldsa.md)
- [SLH-DSA API Reference](../api/slhdsa.md)
- [ML-KEM API Reference](../api/mlkem.md)
- [Security Considerations](security.md)
