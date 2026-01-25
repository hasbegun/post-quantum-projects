# Developer Guide

This guide provides detailed information for developers who want to understand, integrate, or extend the post-quantum DSA library implementation.

## Table of Contents

1. [Project Architecture](#project-architecture)
2. [ML-DSA Implementation](#ml-dsa-implementation)
3. [SLH-DSA Implementation](#slh-dsa-implementation)
4. [Key Encryption](#key-encryption)
5. [JOSE/COSE Support](#josecose-support)
6. [C++ API Reference](#c-api-reference)
7. [Python API Reference](#python-api-reference)
8. [Integration Examples](#integration-examples)
9. [Building and Testing](#building-and-testing)
10. [Extending the Library](#extending-the-library)

---

## Project Architecture

### Directory Structure

```
dsa/
├── src/
│   ├── cpp/                    # C++ implementation
│   │   ├── mldsa/              # ML-DSA (FIPS 204)
│   │   │   ├── mldsa.hpp       # Core ML-DSA class
│   │   │   ├── params.hpp      # Parameter sets
│   │   │   ├── ntt.hpp         # Number Theoretic Transform
│   │   │   ├── encoding.hpp    # Key/signature encoding
│   │   │   ├── sampling.hpp    # Polynomial sampling
│   │   │   └── utils.hpp       # Utility functions
│   │   ├── slhdsa/             # SLH-DSA (FIPS 205)
│   │   │   ├── slh_dsa.hpp     # Core SLH-DSA functions
│   │   │   ├── params.hpp      # Parameter sets
│   │   │   ├── hash_functions.hpp  # Hash function abstraction
│   │   │   ├── wots.hpp        # WOTS+ one-time signatures
│   │   │   ├── xmss.hpp        # XMSS tree operations
│   │   │   ├── fors.hpp        # FORS few-time signatures
│   │   │   ├── hypertree.hpp   # Hypertree operations
│   │   │   └── address.hpp     # Address structure
│   │   ├── key_encryption.hpp  # Password-based encryption
│   │   ├── main.cpp            # keygen CLI tool
│   │   ├── sign.cpp            # sign CLI tool
│   │   └── CMakeLists.txt      # Build configuration
│   └── py/                     # Python implementation
│       ├── __init__.py         # Package exports
│       ├── mldsa/              # ML-DSA (FIPS 204)
│       │   ├── __init__.py
│       │   ├── mldsa.py        # Core ML-DSA class
│       │   ├── params.py       # Parameter sets
│       │   ├── ntt.py          # NTT operations
│       │   ├── encoding.py     # Key/signature encoding
│       │   ├── sampling.py     # Polynomial sampling
│       │   └── utils.py        # Utility functions
│       └── slhdsa/             # SLH-DSA (FIPS 205)
│           ├── __init__.py
│           ├── slh_dsa.py      # Core SLH-DSA functions
│           ├── parameters.py   # Parameter sets
│           ├── hash_functions.py
│           ├── wots.py         # WOTS+ one-time signatures
│           ├── xmss.py         # XMSS tree operations
│           ├── fors.py         # FORS few-time signatures
│           ├── hypertree.py    # Hypertree operations
│           ├── address.py      # Address structure
│           └── utils.py
├── tests/
│   ├── cpp/                    # C++ tests
│   └── py/                     # Python tests
├── examples/                   # Example applications
├── docs/                       # Documentation
└── Makefile                    # Build automation
```

### Design Principles

1. **Standards Compliance**: Direct implementation of FIPS 204 and FIPS 205 algorithms
2. **Type Safety**: Heavy use of C++20 features (`std::span`, `std::array`, concepts)
3. **Const Correctness**: All non-modifying operations are `const` and `[[nodiscard]]`
4. **Zero-Copy Where Possible**: Use of `std::span` to avoid unnecessary copies
5. **Compile-Time Computation**: NTT tables and parameters computed at compile time

---

## ML-DSA Implementation

ML-DSA (Module-Lattice Digital Signature Algorithm) is based on the hardness of the Module Learning With Errors (MLWE) problem.

### Core Constants

```cpp
// From params.hpp
namespace mldsa {
    inline constexpr int32_t Q = 8380417;      // Modulus q = 2^23 - 2^13 + 1
    inline constexpr size_t N = 256;            // Polynomial degree
    inline constexpr int D = 13;                // Dropped bits from t
    inline constexpr int32_t ZETA = 1753;       // Primitive 512th root of unity
}
```

### Parameter Sets

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| Security Level | 128-bit | 192-bit | 256-bit |
| k (rows) | 4 | 6 | 8 |
| l (cols) | 4 | 5 | 7 |
| eta | 2 | 4 | 2 |
| tau | 39 | 49 | 60 |
| gamma1 | 2^17 | 2^19 | 2^19 |
| gamma2 | (q-1)/88 | (q-1)/32 | (q-1)/32 |
| Public Key | 1,312 B | 1,952 B | 2,592 B |
| Secret Key | 2,560 B | 4,032 B | 4,896 B |
| Signature | 2,420 B | 3,309 B | 4,627 B |

### Algorithm Flow

#### Key Generation (Algorithm 1, 6)

```
1. Generate 32-byte random seed ξ
2. Expand seed with domain separation: H(ξ || k || l) → (ρ, ρ', K)
3. Expand A matrix from ρ in NTT domain
4. Sample secret vectors s1, s2 from ρ' with coefficients in [-η, η]
5. Compute t = NTT^(-1)(A * NTT(s1)) + s2
6. Split t into (t1, t0) using Power2Round
7. Encode pk = (ρ, t1)
8. Compute tr = H(pk) for binding
9. Encode sk = (ρ, K, tr, s1, s2, t0)
```

#### Signing (Algorithm 2, 7)

```
1. Decode secret key
2. Compute message representative μ = H(tr || M')
3. Generate mask seed ρ' = H(K || rnd || μ)
4. Rejection sampling loop:
   a. Generate mask y from ρ'
   b. Compute w = A*y
   c. Extract high bits w1
   d. Compute challenge c = H(μ || w1)
   e. Compute z = y + c*s1
   f. Check bounds on z and w - c*s2
   g. Compute hints h
   h. If all checks pass, return (c̃, z, h)
```

#### Verification (Algorithm 3, 8)

```
1. Decode public key (ρ, t1)
2. Decode signature (c̃, z, h)
3. Check z norm < γ1 - β
4. Check hint count ≤ ω
5. Expand A from ρ
6. Compute c from c̃
7. Compute w' = A*z - c*t1*2^d
8. Recover w1' using hints
9. Recompute c̃' = H(μ || w1')
10. Return c̃ == c̃'
```

### NTT Implementation

The Number Theoretic Transform enables efficient polynomial multiplication:

```cpp
// From ntt.hpp
namespace mldsa {

// Forward NTT: O(n log n) polynomial multiplication
Poly ntt(Poly a);

// Inverse NTT
Poly ntt_inv(Poly a);

// Pointwise multiplication in NTT domain
Poly ntt_multiply(const Poly& a, const Poly& b);

// Vector operations
PolyVec vec_ntt(const PolyVec& v);
PolyVec vec_ntt_inv(const PolyVec& v);
PolyVec mat_vec_mul_ntt(const PolyMatrix& A, const PolyVec& v);

}
```

The NTT uses precomputed powers of the primitive root:

```cpp
// Zeta values computed at compile time
inline constexpr auto NTT_ZETAS = compute_ntt_zetas();

// NTT_ZETAS[k] = ζ^(BitRev8(k)) mod Q
```

---

## SLH-DSA Implementation

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm) is based purely on hash function security.

### Architecture

```
SLH-DSA Signature
├── FORS (Forest of Random Subsets)
│   └── Few-time signature for message
└── Hypertree
    ├── XMSS Tree (Layer d-1) ← signs FORS public key
    ├── XMSS Tree (Layer d-2) ← signs layer d-1 root
    │   ...
    └── XMSS Tree (Layer 0) ← root is in public key
        └── WOTS+ (One-Time Signature)
```

### Parameter Sets

| Parameter | 128f | 128s | 192f | 192s | 256f | 256s |
|-----------|------|------|------|------|------|------|
| n | 16 | 16 | 24 | 24 | 32 | 32 |
| h | 66 | 63 | 66 | 63 | 68 | 64 |
| d | 22 | 7 | 22 | 7 | 17 | 8 |
| k | 33 | 14 | 33 | 14 | 35 | 14 |
| a | 6 | 12 | 6 | 12 | 9 | 14 |
| Signature | 17KB | 8KB | 35KB | 16KB | 50KB | 29KB |

### Component Functions

#### WOTS+ (Winternitz OTS)

```cpp
// From wots.hpp
namespace slhdsa {

// Generate WOTS+ public key
std::vector<uint8_t> wots_PKgen(
    const HashFunctions& H,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs);

// Sign with WOTS+
std::vector<uint8_t> wots_sign(
    const HashFunctions& H,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs);

// Compute public key from signature
std::vector<uint8_t> wots_PKFromSig(
    const HashFunctions& H,
    std::span<const uint8_t> sig,
    std::span<const uint8_t> M,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs);

}
```

#### FORS (Forest of Random Subsets)

```cpp
// From fors.hpp
namespace slhdsa {

// Sign message digest with FORS
std::vector<uint8_t> fors_sign(
    const HashFunctions& H,
    std::span<const uint8_t> md,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs);

// Recover FORS public key from signature
std::vector<uint8_t> fors_pkFromSig(
    const HashFunctions& H,
    std::span<const uint8_t> sig_fors,
    std::span<const uint8_t> md,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs);

}
```

#### XMSS Tree

```cpp
// From xmss.hpp
namespace slhdsa {

// Compute XMSS tree node
std::vector<uint8_t> xmss_node(
    const HashFunctions& H,
    std::span<const uint8_t> sk_seed,
    uint32_t i,          // Start index
    uint32_t z,          // Target height
    std::span<const uint8_t> pk_seed,
    ADRS& adrs);

// Sign with XMSS
std::vector<uint8_t> xmss_sign(
    const HashFunctions& H,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk_seed,
    uint32_t idx,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs);

}
```

#### Hypertree

```cpp
// From hypertree.hpp
namespace slhdsa {

// Sign message with hypertree
std::vector<uint8_t> ht_sign(
    const HashFunctions& H,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    uint64_t idx_tree,
    uint32_t idx_leaf);

// Verify hypertree signature
bool ht_verify(
    const HashFunctions& H,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sig_ht,
    std::span<const uint8_t> pk_seed,
    uint64_t idx_tree,
    uint32_t idx_leaf,
    std::span<const uint8_t> pk_root);

}
```

### Hash Function Abstraction

```cpp
// From hash_functions.hpp
namespace slhdsa {

struct HashFunctions {
    // Tweakable hash functions
    virtual std::vector<uint8_t> F(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M1) const = 0;

    virtual std::vector<uint8_t> H(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M1,
        std::span<const uint8_t> M2) const = 0;

    virtual std::vector<uint8_t> T(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M) const = 0;

    // Message processing
    virtual std::vector<uint8_t> PRF_msg(...) const = 0;
    virtual std::vector<uint8_t> H_msg(...) const = 0;
};

// Get appropriate hash functions for parameter set
std::unique_ptr<HashFunctions> get_hash_functions(const Params& params);

}
```

---

## Key Encryption

The library provides password-based encryption for secret keys using industry-standard algorithms.

### Encryption Scheme

```cpp
// From key_encryption.hpp
namespace pqc {

// Encryption parameters
constexpr int PBKDF2_ITERATIONS = 600000;  // OWASP 2023 recommendation
constexpr size_t SALT_SIZE = 32;
constexpr size_t IV_SIZE = 12;              // GCM nonce
constexpr size_t TAG_SIZE = 16;             // GCM auth tag
constexpr size_t KEY_SIZE = 32;             // AES-256

// Encrypt secret key
std::vector<uint8_t> encrypt_secret_key(
    const std::vector<uint8_t>& plaintext,
    const std::string& password,
    uint32_t alg_id = 0);

// Decrypt secret key
std::vector<uint8_t> decrypt_secret_key(
    const std::vector<uint8_t>& encrypted,
    const std::string& password);

// Check if data is encrypted
bool is_encrypted_key(const std::vector<uint8_t>& data);

}
```

### File Format

```
Offset  Size  Field
------  ----  -----
0       8     Magic: "PQCRYPT1"
8       4     Version (uint32 LE)
12      4     Algorithm ID (uint32 LE)
16      32    Salt (random)
48      12    IV/Nonce
60      16    Authentication Tag
76      4     Original Size (uint32 LE)
80      ...   Encrypted Data
```

### Usage Example

```cpp
#include "key_encryption.hpp"

// Encrypt a secret key
std::vector<uint8_t> sk = /* ... */;
std::string password = "my-secure-password";
auto encrypted = pqc::encrypt_secret_key(sk, password, pqc::ALG_MLDSA65);

// Later, decrypt it
if (pqc::is_encrypted_key(encrypted)) {
    auto decrypted = pqc::decrypt_secret_key(encrypted, password);
    // Use decrypted key...
}
```

---

## JOSE/COSE Support

The library provides JWT (JSON Web Token) and COSE (CBOR Object Signing) support for PQC algorithms, enabling integration with web applications and IoT systems.

### JWS (JSON Web Signature) API

```cpp
#include "common/jose.hpp"

// Create a JWT with post-quantum signature
auto dsa = pqc::create_dsa("ML-DSA-65");
auto [pk, sk] = dsa->keygen();

// Using the builder pattern
jose::JWSBuilder builder;
std::string jwt = builder
    .set_algorithm("ML-DSA-65")
    .set_type("JWT")
    .set_key_id("key-123")
    .set_payload(R"({"sub":"user@example.com","exp":1700000000})")
    .sign(sk);

// Using convenience function
std::string jwt = jose::create_jwt(
    "ML-DSA-65",
    R"({"sub":"user","role":"admin"})",
    sk
);

// Verify and extract payload
auto payload = jose::verify_jwt(jwt, pk);
if (payload) {
    std::cout << "Payload: " << *payload << std::endl;
}

// Using verifier class for more control
jose::JWSVerifier verifier(jwt);
std::cout << "Algorithm: " << verifier.algorithm() << std::endl;
std::cout << "Key ID: " << verifier.key_id() << std::endl;

if (verifier.verify(pk)) {
    auto sub = verifier.claim("sub");  // Extract claims
}
```

### Supported JOSE Algorithms

| Algorithm | Security Level | Standard |
|-----------|----------------|----------|
| ML-DSA-44 | Level 2 | FIPS 204 |
| ML-DSA-65 | Level 3 | FIPS 204 |
| ML-DSA-87 | Level 5 | FIPS 204 |
| SLH-DSA-SHA2-128f | Level 1 | FIPS 205 |
| SLH-DSA-SHA2-128s | Level 1 | FIPS 205 |
| SLH-DSA-SHAKE-128f | Level 1 | FIPS 205 |
| ... | ... | ... |

### COSE_Sign1 API

COSE provides a compact binary format ideal for IoT and constrained environments.

```cpp
#include "common/cose.hpp"

// Create a COSE_Sign1 message
auto dsa = pqc::create_dsa("ML-DSA-65");
auto [pk, sk] = dsa->keygen();

std::vector<uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};

// Sign
auto signed_msg = cose::sign1("ML-DSA-65", payload, sk);

// Verify
auto verified_payload = cose::verify1(signed_msg, pk);
if (verified_payload) {
    // Use payload
}

// With External AAD (Additional Authenticated Data)
std::vector<uint8_t> aad = {'c', 'o', 'n', 't', 'e', 'x', 't'};
auto signed_with_aad = cose::sign1("ML-DSA-65", payload, sk, aad);
auto verified = cose::verify1(signed_with_aad, pk, aad);

// Detached payload (payload not included in message)
auto detached_sig = cose::sign1_detached("ML-DSA-65", payload, sk);
bool valid = cose::verify1_detached(detached_sig, payload, pk);
```

### COSE Algorithm IDs (Proposed)

| Algorithm | COSE ID | Internal Name |
|-----------|---------|---------------|
| ML-DSA-44 | -48 | ML-DSA-44 |
| ML-DSA-65 | -49 | ML-DSA-65 |
| ML-DSA-87 | -50 | ML-DSA-87 |
| SLH-DSA-SHA2-128s | -51 | SLH-DSA-SHA2-128s |
| SLH-DSA-SHA2-128f | -52 | SLH-DSA-SHA2-128f |
| ... | ... | ... |

### CBOR Utilities

Low-level CBOR encoding/decoding functions are available:

```cpp
#include "common/cose.hpp"

std::vector<uint8_t> out;

// Encode various CBOR types
cose::cbor::encode_uint(out, 42);           // Unsigned integer
cose::cbor::encode_int(out, -10);           // Negative integer
cose::cbor::encode_bytes(out, data);        // Byte string
cose::cbor::encode_text(out, "hello");      // Text string
cose::cbor::encode_array_header(out, 3);    // Array of 3 items
cose::cbor::encode_map_header(out, 2);      // Map with 2 pairs

// Decode
auto result = cose::cbor::decode_int(data);
if (result) {
    auto [value, bytes_consumed] = *result;
}
```

### Base64url Utilities

```cpp
#include "common/jose.hpp"

// Base64url encoding (URL-safe, no padding)
std::vector<uint8_t> data = {0x01, 0x02, 0x03};
std::string encoded = jose::detail::base64url_encode(data);

// Decoding
auto decoded = jose::detail::base64url_decode(encoded);
```

### Testing JOSE/COSE

```bash
# Run JOSE/COSE tests
make test-jose

# Tests include:
# - Base64url encoding/decoding
# - JWS creation and verification
# - JWT claims extraction
# - COSE_Sign1 with all algorithms
# - External AAD
# - Detached payloads
```

---

## C++ API Reference

### ML-DSA API

```cpp
#include "mldsa/mldsa.hpp"

namespace mldsa {

class MLDSA {
public:
    explicit MLDSA(const Params& params);

    // Key generation
    // Returns (public_key, secret_key)
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen(std::span<const uint8_t> seed = {}) const;

    // Sign message
    std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {},
        bool deterministic = false) const;

    // Verify signature
    bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const;

    // Get parameters
    const Params& params() const noexcept;
};

// Convenience classes
class MLDSA44 : public MLDSA { /* k=4, l=4 */ };
class MLDSA65 : public MLDSA { /* k=6, l=5 */ };
class MLDSA87 : public MLDSA { /* k=8, l=7 */ };

}
```

### SLH-DSA API

```cpp
#include "slhdsa/slh_dsa.hpp"

namespace slhdsa {

// Template class for any parameter set
template<const Params& P>
class SLHDSA {
public:
    // Key generation - returns (secret_key, public_key)
    // Note: Order is different from ML-DSA!
    std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> keygen() const;

    // Sign message
    std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {},
        bool randomize = true) const;

    // Verify signature
    bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const;

    const Params& params() const noexcept;
};

// Pre-defined types
using SLHDSA_SHA2_128f = SLHDSA<SLH_DSA_SHA2_128f>;
using SLHDSA_SHA2_128s = SLHDSA<SLH_DSA_SHA2_128s>;
// ... etc for all parameter sets

using SLHDSA_SHAKE_128f = SLHDSA<SLH_DSA_SHAKE_128f>;
using SLHDSA_SHAKE_128s = SLHDSA<SLH_DSA_SHAKE_128s>;
// ... etc

}
```

### Complete C++ Example

```cpp
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "key_encryption.hpp"
#include <fstream>
#include <iostream>

// Utility to read/write files
std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    auto size = f.tellg();
    f.seekg(0);
    std::vector<uint8_t> data(size);
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream f(path, std::ios::binary);
    f.write(reinterpret_cast<const char*>(data.data()), data.size());
}

int main() {
    // ===== ML-DSA Example =====
    std::cout << "=== ML-DSA-65 ===\n";

    mldsa::MLDSA65 mldsa;

    // Generate keys
    auto [pk, sk] = mldsa.keygen();
    std::cout << "Public key: " << pk.size() << " bytes\n";
    std::cout << "Secret key: " << sk.size() << " bytes\n";

    // Sign a message
    std::string msg_str = "Hello, Post-Quantum World!";
    std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

    auto signature = mldsa.sign(sk, message);
    std::cout << "Signature: " << signature.size() << " bytes\n";

    // Verify
    bool valid = mldsa.verify(pk, message, signature);
    std::cout << "Valid: " << (valid ? "YES" : "NO") << "\n";

    // Sign with context
    std::string ctx_str = "my-app-v1";
    std::vector<uint8_t> ctx(ctx_str.begin(), ctx_str.end());
    auto sig_ctx = mldsa.sign(sk, message, ctx);

    // Must verify with same context
    bool valid_ctx = mldsa.verify(pk, message, sig_ctx, ctx);

    // ===== SLH-DSA Example =====
    std::cout << "\n=== SLH-DSA-SHAKE-128f ===\n";

    slhdsa::SLHDSA_SHAKE_128f slhdsa;

    // Generate keys (note: returns sk, pk - different order!)
    auto [slh_sk, slh_pk] = slhdsa.keygen();
    std::cout << "Public key: " << slh_pk.size() << " bytes\n";
    std::cout << "Secret key: " << slh_sk.size() << " bytes\n";

    // Sign
    auto slh_sig = slhdsa.sign(slh_sk, message);
    std::cout << "Signature: " << slh_sig.size() << " bytes\n";

    // Verify
    bool slh_valid = slhdsa.verify(slh_pk, message, slh_sig);
    std::cout << "Valid: " << (slh_valid ? "YES" : "NO") << "\n";

    // ===== Password Protection =====
    std::cout << "\n=== Password Protection ===\n";

    std::string password = "my-secure-password";

    // Encrypt secret key
    auto encrypted_sk = pqc::encrypt_secret_key(sk, password, pqc::ALG_MLDSA65);
    std::cout << "Encrypted key: " << encrypted_sk.size() << " bytes\n";

    // Save to file
    write_file("secret.key.enc", encrypted_sk);

    // Load and decrypt
    auto loaded = read_file("secret.key.enc");
    if (pqc::is_encrypted_key(loaded)) {
        auto decrypted_sk = pqc::decrypt_secret_key(loaded, password);
        std::cout << "Decrypted key: " << decrypted_sk.size() << " bytes\n";

        // Use decrypted key to sign
        auto new_sig = mldsa.sign(decrypted_sk, message);
        bool new_valid = mldsa.verify(pk, message, new_sig);
        std::cout << "Signature with decrypted key valid: "
                  << (new_valid ? "YES" : "NO") << "\n";
    }

    return 0;
}
```

---

## Python API Reference

### ML-DSA API

```python
from dsa import MLDSA44, MLDSA65, MLDSA87

class MLDSA:
    def keygen(self) -> tuple[bytes, bytes]:
        """Generate (public_key, secret_key) pair."""
        pass

    def sign(self, sk: bytes, message: bytes,
             ctx: bytes = b'', deterministic: bool = False) -> bytes:
        """Sign message with secret key."""
        pass

    def verify(self, pk: bytes, message: bytes,
               signature: bytes, ctx: bytes = b'') -> bool:
        """Verify signature with public key."""
        pass
```

### SLH-DSA API

```python
from dsa import (
    slh_keygen, slh_sign, slh_verify,
    SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_256f, SLH_DSA_SHAKE_256s,
    SLH_DSA_SHA2_128f, SLH_DSA_SHA2_128s,
    # ... etc
)

def slh_keygen(params) -> tuple[bytes, bytes]:
    """Generate (secret_key, public_key) pair.
    Note: Order is different from ML-DSA!
    """
    pass

def slh_sign(params, message: bytes, sk: bytes,
             ctx: bytes = b'', randomize: bool = True) -> bytes:
    """Sign message with secret key."""
    pass

def slh_verify(params, message: bytes, signature: bytes,
               pk: bytes, ctx: bytes = b'') -> bool:
    """Verify signature with public key."""
    pass
```

### Complete Python Example

```python
#!/usr/bin/env python3
"""Complete Python DSA Example"""

from pathlib import Path
import hashlib
import json

# ML-DSA
from dsa import MLDSA44, MLDSA65, MLDSA87

# SLH-DSA
from dsa import (
    slh_keygen, slh_sign, slh_verify,
    SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_256f
)


def mldsa_example():
    """ML-DSA signing and verification."""
    print("=== ML-DSA-65 ===")

    dsa = MLDSA65()

    # Generate keys
    pk, sk = dsa.keygen()
    print(f"Public key: {len(pk)} bytes")
    print(f"Secret key: {len(sk)} bytes")

    # Sign a message
    message = b"Hello, Post-Quantum World!"
    signature = dsa.sign(sk, message)
    print(f"Signature: {len(signature)} bytes")

    # Verify
    valid = dsa.verify(pk, message, signature)
    print(f"Valid: {valid}")

    # Sign with context
    ctx = b"my-app-v1"
    sig_ctx = dsa.sign(sk, message, ctx=ctx)

    # Must verify with same context
    valid_ctx = dsa.verify(pk, message, sig_ctx, ctx=ctx)
    print(f"Valid with context: {valid_ctx}")

    # Deterministic signing (same signature for same message)
    sig1 = dsa.sign(sk, message, deterministic=True)
    sig2 = dsa.sign(sk, message, deterministic=True)
    print(f"Deterministic signatures match: {sig1 == sig2}")

    return pk, sk


def slhdsa_example():
    """SLH-DSA signing and verification."""
    print("\n=== SLH-DSA-SHAKE-128f ===")

    params = SLH_DSA_SHAKE_128f

    # Generate keys (note: sk, pk order!)
    sk, pk = slh_keygen(params)
    print(f"Public key: {len(pk)} bytes")
    print(f"Secret key: {len(sk)} bytes")

    # Sign a message
    message = b"Important document content"
    signature = slh_sign(params, message, sk)
    print(f"Signature: {len(signature)} bytes")

    # Verify
    valid = slh_verify(params, message, signature, pk)
    print(f"Valid: {valid}")

    return pk, sk


def file_signing_example():
    """Sign and verify files."""
    print("\n=== File Signing ===")

    dsa = MLDSA87()  # Use highest security for documents
    pk, sk = dsa.keygen()

    # Create test file
    test_content = b"This is the content of an important file."
    Path("test_file.txt").write_bytes(test_content)

    # Sign the file hash
    file_content = Path("test_file.txt").read_bytes()
    file_hash = hashlib.sha256(file_content).digest()
    signature = dsa.sign(sk, file_hash)

    # Create signature bundle
    bundle = {
        "filename": "test_file.txt",
        "sha256": hashlib.sha256(file_content).hexdigest(),
        "signature": signature.hex(),
        "public_key": pk.hex(),
        "algorithm": "ML-DSA-87"
    }
    Path("test_file.txt.sig").write_text(json.dumps(bundle, indent=2))
    print("File signed: test_file.txt.sig")

    # Verify
    loaded = json.loads(Path("test_file.txt.sig").read_text())
    content = Path("test_file.txt").read_bytes()

    # Check hash
    if hashlib.sha256(content).hexdigest() != loaded["sha256"]:
        print("Hash mismatch!")
        return

    # Verify signature
    content_hash = hashlib.sha256(content).digest()
    sig = bytes.fromhex(loaded["signature"])
    pub_key = bytes.fromhex(loaded["public_key"])
    valid = dsa.verify(pub_key, content_hash, sig)
    print(f"Signature valid: {valid}")

    # Cleanup
    Path("test_file.txt").unlink()
    Path("test_file.txt.sig").unlink()


def api_authentication_example():
    """Demonstrate API request signing."""
    print("\n=== API Authentication ===")

    import time

    dsa = MLDSA44()  # Fast signing for API use
    pk, sk = dsa.keygen()

    # Simulate API request
    method = "POST"
    path = "/api/v1/transactions"
    body = '{"amount": 100, "to": "user123"}'
    timestamp = str(int(time.time()))

    # Create message to sign
    message = f"{timestamp}:{method}:{path}:{body}".encode()

    # Sign
    signature = dsa.sign(sk, message)

    # Simulate headers
    headers = {
        "X-Timestamp": timestamp,
        "X-Signature": signature.hex(),
        "X-Algorithm": "ML-DSA-44",
    }

    print(f"Request signed with {len(signature)} byte signature")
    print(f"Headers: X-Timestamp={timestamp}")
    print(f"         X-Signature={signature.hex()[:64]}...")

    # Server-side verification
    received_ts = headers["X-Timestamp"]
    received_sig = bytes.fromhex(headers["X-Signature"])
    received_msg = f"{received_ts}:{method}:{path}:{body}".encode()

    valid = dsa.verify(pk, received_msg, received_sig)
    print(f"Server verification: {valid}")


if __name__ == "__main__":
    mldsa_example()
    slhdsa_example()
    file_signing_example()
    api_authentication_example()
```

---

## Integration Examples

### Integrating with Flask

```python
from flask import Flask, request, jsonify, g
from functools import wraps
from dsa import MLDSA65
import time

app = Flask(__name__)
dsa = MLDSA65()

# Load server's verification key
with open("server_public.key", "rb") as f:
    SERVER_PUBLIC_KEY = f.read()


def require_pq_signature(f):
    """Decorator to verify post-quantum signatures on requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        signature = request.headers.get("X-PQ-Signature")
        timestamp = request.headers.get("X-PQ-Timestamp")
        client_pk = request.headers.get("X-PQ-PublicKey")

        if not all([signature, timestamp, client_pk]):
            return jsonify({"error": "Missing signature headers"}), 401

        # Check timestamp freshness
        try:
            ts = int(timestamp)
            if abs(time.time() - ts) > 300:  # 5 min window
                return jsonify({"error": "Request expired"}), 401
        except ValueError:
            return jsonify({"error": "Invalid timestamp"}), 401

        # Verify signature
        try:
            body = request.get_data().decode()
            message = f"{timestamp}:{request.method}:{request.path}:{body}"
            sig = bytes.fromhex(signature)
            pk = bytes.fromhex(client_pk)

            if not dsa.verify(pk, message.encode(), sig):
                return jsonify({"error": "Invalid signature"}), 401

            g.client_public_key = pk

        except Exception as e:
            return jsonify({"error": str(e)}), 401

        return f(*args, **kwargs)
    return decorated


@app.route("/api/secure", methods=["POST"])
@require_pq_signature
def secure_endpoint():
    return jsonify({
        "status": "authenticated",
        "client_pk_hash": hashlib.sha256(g.client_public_key).hexdigest()[:16]
    })
```

### Integrating with CMake

```cmake
# CMakeLists.txt for your project

cmake_minimum_required(VERSION 3.20)
project(MyPQApp)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL (required for SLH-DSA hash functions)
find_package(OpenSSL REQUIRED)

# Add DSA library
add_subdirectory(path/to/dsa/src/cpp dsa_lib)

# Your application
add_executable(myapp main.cpp)

target_link_libraries(myapp PRIVATE
    mldsa
    slhdsa
    OpenSSL::Crypto
)

target_include_directories(myapp PRIVATE
    path/to/dsa/src/cpp
)
```

### Integrating with Docker

```dockerfile
# Dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy DSA library
COPY dsa/ /app/dsa/

# Build DSA library
WORKDIR /app/dsa
RUN mkdir build && cd build && \
    cmake ../src/cpp -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

# Copy and build your application
COPY myapp/ /app/myapp/
WORKDIR /app/myapp
RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

CMD ["./build/myapp"]
```

---

## Building and Testing

### Build Requirements

- C++20 compiler (GCC 11+, Clang 14+, MSVC 2022+)
- CMake 3.20+
- OpenSSL 3.0+

### Build Commands

```bash
# Build with CMake
mkdir build && cd build
cmake ../src/cpp -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Build with Docker
make build-cpp

# Run tests
make test-cpp

# Run specific tests
./build/test_mldsa      # ML-DSA unit tests
./build/test_slhdsa     # SLH-DSA unit tests
./build/test_keygen     # Key generation tests
./build/test_mldsa_kat  # Known Answer Tests
./build/test_slhdsa_kat # Known Answer Tests
```

### Test Structure

```cpp
// Example test structure (test_mldsa.cpp)

void test_keygen() {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    assert(pk.size() == dsa.params().pk_size());
    assert(sk.size() == dsa.params().sk_size());
}

void test_sign_verify() {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
    auto sig = dsa.sign(sk, msg);

    assert(dsa.verify(pk, msg, sig) == true);

    // Tamper with message
    msg[0] ^= 0xFF;
    assert(dsa.verify(pk, msg, sig) == false);
}

void test_deterministic_signing() {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> msg = {1, 2, 3};
    auto sig1 = dsa.sign(sk, msg, {}, true);  // deterministic
    auto sig2 = dsa.sign(sk, msg, {}, true);

    assert(sig1 == sig2);
}
```

---

## Extending the Library

### Adding a New Parameter Set

To add a custom ML-DSA parameter set:

```cpp
// In params.hpp

inline constexpr Params MY_CUSTOM_PARAMS = {
    .name = "ML-DSA-CUSTOM",
    .k = 5,
    .l = 4,
    .eta = 3,
    .tau = 45,
    .beta = 135,
    .gamma1 = 1 << 18,
    .gamma2 = (Q - 1) / 64,
    .omega = 70,
    .lambda = 160,
};

// Create convenience class
class MLDSACustom : public MLDSA {
public:
    MLDSACustom() : MLDSA(MY_CUSTOM_PARAMS) {}
};
```

### Implementing Custom Hash Functions for SLH-DSA

```cpp
// Custom hash function implementation
class MyHashFunctions : public slhdsa::HashFunctions {
public:
    explicit MyHashFunctions(size_t n) : n_(n) {}

    std::vector<uint8_t> F(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M1) const override {

        // Your custom implementation
        // Must return n_ bytes
    }

    // Implement other required methods...

private:
    size_t n_;
};

// Register custom hash functions
std::unique_ptr<HashFunctions> get_custom_hash_functions(const Params& params) {
    return std::make_unique<MyHashFunctions>(params.n);
}
```

### Adding New CLI Tools

```cpp
// my_tool.cpp
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "key_encryption.hpp"

int main(int argc, char* argv[]) {
    // Parse arguments
    // Load keys
    // Perform operations
    return 0;
}
```

Add to CMakeLists.txt:

```cmake
add_executable(my_tool my_tool.cpp)
target_link_libraries(my_tool PRIVATE mldsa slhdsa)
```

---

## Performance Considerations

### ML-DSA Performance

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|-----------|
| KeyGen | ~0.1 ms | ~0.2 ms | ~0.3 ms |
| Sign | ~0.3 ms | ~0.5 ms | ~0.7 ms |
| Verify | ~0.1 ms | ~0.2 ms | ~0.3 ms |

### SLH-DSA Performance

| Operation | 128f | 128s | 256f | 256s |
|-----------|------|------|------|------|
| KeyGen | ~5 ms | ~50 ms | ~15 ms | ~200 ms |
| Sign | ~10 ms | ~200 ms | ~30 ms | ~800 ms |
| Verify | ~1 ms | ~5 ms | ~3 ms | ~15 ms |

### Optimization Tips

1. **Use ML-DSA for high-frequency signing**: ML-DSA is ~100x faster than SLH-DSA
2. **Use "f" variants for faster SLH-DSA**: Fast variants trade signature size for speed
3. **Enable compiler optimizations**: Use `-O3 -march=native`
4. **Precompute NTT tables**: Already done at compile-time in this implementation
5. **Batch verification**: For multiple signatures, parallelize verification

---

## Security Notes

1. **Constant-Time Implementation**: Core operations are implemented in constant time to prevent timing side-channels
2. **Secure Memory Handling**: Secret keys should be cleared after use
3. **Random Number Generation**: Uses system CSPRNG (`/dev/urandom` or `CryptGenRandom`)
4. **Password Protection**: PBKDF2 with 600,000 iterations (OWASP 2023 recommendation)

---

## References

- [FIPS 204: ML-DSA Standard](https://csrc.nist.gov/publications/detail/fips/204/final)
- [FIPS 205: SLH-DSA Standard](https://csrc.nist.gov/publications/detail/fips/205/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
