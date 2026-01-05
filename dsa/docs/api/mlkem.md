# ML-KEM API Reference

ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) is a post-quantum key encapsulation mechanism standardized in NIST FIPS 203.

## Overview

ML-KEM provides quantum-resistant key exchange based on the Module Learning With Errors (MLWE) problem. It enables two parties to establish a shared secret key over an insecure channel.

## Classes

### MLKEM512

ML-KEM with security category 1 (128-bit classical security).

```python
from mlkem import MLKEM512

kem = MLKEM512()
```

### MLKEM768

ML-KEM with security category 3 (192-bit classical security).

```python
from mlkem import MLKEM768

kem = MLKEM768()
```

### MLKEM1024

ML-KEM with security category 5 (256-bit classical security).

```python
from mlkem import MLKEM1024

kem = MLKEM1024()
```

## Methods

### keygen(seed=None)

Generate an encapsulation/decapsulation key pair.

**Parameters:**
- `seed` (bytes, optional): 64-byte seed for deterministic key generation. If None, random keys are generated.

**Returns:**
- `tuple[bytes, bytes]`: (encapsulation_key, decapsulation_key)

**Raises:**
- `ValueError`: If seed is provided but not 64 bytes.

**Example:**
```python
from mlkem import MLKEM768

kem = MLKEM768()

# Random key generation
ek, dk = kem.keygen()

# Deterministic key generation
seed = bytes(64)  # 64 zero bytes
ek, dk = kem.keygen(seed)
```

### encaps(ek, rand=None)

Encapsulate to produce a shared secret and ciphertext.

**Parameters:**
- `ek` (bytes): Encapsulation key (public key)
- `rand` (bytes, optional): 32-byte randomness for deterministic encapsulation

**Returns:**
- `tuple[bytes, bytes]`: (shared_secret, ciphertext)

**Raises:**
- `ValueError`: If encapsulation key size is invalid.

**Example:**
```python
# Alice generates key pair and sends ek to Bob
ek, dk = kem.keygen()

# Bob encapsulates using Alice's public key
shared_secret, ciphertext = kem.encaps(ek)

# Bob sends ciphertext to Alice
```

### decaps(dk, ciphertext)

Decapsulate to recover the shared secret.

**Parameters:**
- `dk` (bytes): Decapsulation key (private key)
- `ciphertext` (bytes): Ciphertext received from encapsulator

**Returns:**
- `bytes`: Shared secret (32 bytes)

**Note:**
If the ciphertext is invalid, a pseudorandom value is returned (implicit rejection) rather than raising an error. This provides protection against chosen-ciphertext attacks.

**Example:**
```python
# Alice decapsulates using her private key
shared_secret = kem.decaps(dk, ciphertext)

# Now both Alice and Bob have the same shared_secret
```

### params (property)

Get the parameter set for this instance.

**Returns:**
- `MLKEMParams`: Parameter set object

**Example:**
```python
kem = MLKEM768()
print(f"Encapsulation key size: {kem.params.ek_size} bytes")
print(f"Ciphertext size: {kem.params.ct_size} bytes")
```

## Parameter Sets

### MLKEMParams

Parameter set class with the following read-only properties:

| Property | Description |
|----------|-------------|
| `name` | Parameter set name |
| `k` | Module rank |
| `eta1` | CBD parameter for secret |
| `eta2` | CBD parameter for error |
| `du` | Compression bits for u |
| `dv` | Compression bits for v |
| `ek_size` | Encapsulation key size in bytes |
| `dk_size` | Decapsulation key size in bytes |
| `ct_size` | Ciphertext size in bytes |
| `ss_size` | Shared secret size in bytes |

### Constants

```python
from mlkem import MLKEM512_PARAMS, MLKEM768_PARAMS, MLKEM1024_PARAMS
```

| Parameter Set | ek_size | dk_size | ct_size | ss_size | Security |
|--------------|---------|---------|---------|---------|----------|
| MLKEM512_PARAMS | 800 | 1632 | 768 | 32 | Level 1 |
| MLKEM768_PARAMS | 1184 | 2400 | 1088 | 32 | Level 3 |
| MLKEM1024_PARAMS | 1568 | 3168 | 1568 | 32 | Level 5 |

## Complete Example

```python
from mlkem import MLKEM768

# Create KEM instance
kem = MLKEM768()

# === Alice's side ===
# Generate key pair
ek, dk = kem.keygen()
# Send ek (public key) to Bob

# === Bob's side ===
# Receive ek from Alice
# Encapsulate to create shared secret and ciphertext
shared_secret_bob, ciphertext = kem.encaps(ek)
# Send ciphertext to Alice

# === Alice's side ===
# Receive ciphertext from Bob
# Decapsulate to recover shared secret
shared_secret_alice = kem.decaps(dk, ciphertext)

# Both parties now have the same 32-byte shared secret
assert shared_secret_alice == shared_secret_bob

# Use shared_secret for symmetric encryption (e.g., AES-256-GCM)
```

## C++ API

### Header

```cpp
#include "mlkem/mlkem.hpp"
```

### Classes

```cpp
namespace mlkem {
    class MLKEM512;   // Security Category 1
    class MLKEM768;   // Security Category 3
    class MLKEM1024;  // Security Category 5
}
```

### Methods

```cpp
// Key generation
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> keygen();

// Encapsulation
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encaps(
    const std::vector<uint8_t>& ek);

// Decapsulation
std::vector<uint8_t> decaps(
    const std::vector<uint8_t>& dk,
    const std::vector<uint8_t>& ciphertext);
```

### C++ Example

```cpp
#include "mlkem/mlkem.hpp"
#include <iostream>
#include <cassert>

int main() {
    mlkem::MLKEM768 kem;

    // Alice generates key pair
    auto [ek, dk] = kem.keygen();
    std::cout << "Encapsulation key: " << ek.size() << " bytes\n";
    std::cout << "Decapsulation key: " << dk.size() << " bytes\n";

    // Bob encapsulates
    auto [shared_secret_bob, ciphertext] = kem.encaps(ek);
    std::cout << "Ciphertext: " << ciphertext.size() << " bytes\n";
    std::cout << "Shared secret: " << shared_secret_bob.size() << " bytes\n";

    // Alice decapsulates
    auto shared_secret_alice = kem.decaps(dk, ciphertext);

    // Verify
    assert(shared_secret_bob == shared_secret_alice);
    std::cout << "Key exchange successful!\n";

    return 0;
}
```

### Free Functions

Alternatively, use the free functions with explicit parameters:

```cpp
#include "mlkem/mlkem.hpp"

// Using free functions
auto [ek, dk] = mlkem::mlkem_keygen(mlkem::MLKEM768_PARAMS);
auto [ss, ct] = mlkem::mlkem_encaps(mlkem::MLKEM768_PARAMS, ek);
auto ss2 = mlkem::mlkem_decaps(mlkem::MLKEM768_PARAMS, dk, ct);
```

## Security Considerations

1. **Key Management**: The decapsulation key (dk) must be kept secret. Only share the encapsulation key (ek).

2. **Implicit Rejection**: ML-KEM uses implicit rejection - invalid ciphertexts return a pseudorandom value instead of an error. This prevents chosen-ciphertext attacks.

3. **Key Reuse**: Each key pair should ideally be used for a single key exchange session for forward secrecy.

4. **Hybrid Usage**: Consider combining ML-KEM with classical key exchange (e.g., X25519) for defense in depth during the transition period.

5. **Authentication**: ML-KEM provides confidentiality but not authentication. For authenticated key exchange, combine with ML-DSA signatures.

## Related Documentation

- [Quick Start Guide](../guide/quickstart.md)
- [User Manual - Key Exchange Section](../MANUAL.md#key-exchange-with-ml-kem)
- [ML-DSA API](mldsa.md) - For authenticated key exchange
- [SLH-DSA API](slhdsa.md) - Alternative hash-based signatures
