# Post-Quantum Cryptography Roadmap

A tracking document for library features and NIST standards.

---

## Progress Summary

| Category | Completed | In Progress | Total |
|----------|-----------|-------------|-------|
| **Phase 1: Quick Wins** | 5/5 | 0 | 5 |
| **Phase 2: Medium Effort** | 5/5 | 0 | 5 |
| **Phase 3: Standards Integration** | 2/2 | 0 | 2 |
| **Phase 4: Larger Efforts** | 0/3 | 0 | 3 |
| **Core Algorithms** | 3/3 | 0 | 3 |

**Test Suites:** 19 passing (mldsa, slhdsa, mlkem, kat, keygen, constant-time, simd, pkcs8, x509, algorithm-factory, batch-verify, hybrid, fips-selftest, streaming, hsm, ossl-provider, jose-cose, composite)

---

## Next Features

### Upcoming NIST Standards

| Feature | Priority | Timeline | Description |
|---------|----------|----------|-------------|
| **FN-DSA (FALCON)** | 1 | After FIPS 206 (2025) | Smallest PQC signatures (~666 bytes) |
| **HQC** | 2 | After draft (2026) | Backup KEM based on error-correcting codes |

### Research Phase

| Feature | Priority | Effort | Description |
|---------|----------|--------|-------------|
| **Power Analysis Resistance** | Low | 4+ weeks | Masking, threshold implementation |
| **Formal Verification** | Low | External | Coq/SMT proofs |
| **Algorithm Agility (HQC)** | Low | 4+ weeks | NIST backup KEM (~2027) |

---

## Library Implementation Roadmap

### Completed Features

#### Security Hardening
- [x] Constant-time verification (ML-DSA, SLH-DSA)
- [x] Constant-time utility functions (`ct::equal`, `ct::select_u32`, `ct::ge_u32`)
- [x] Fixed variable-iteration rejection sampling (`sample_in_ball`)
- [x] Automatic key zeroization (`SecureBytes` RAII)
- [x] Input validation for key/signature decoding
- [x] Timing leak detection tests (dudect methodology)

#### Testing Infrastructure
- [x] Fuzz testing with libFuzzer + ASan/UBSan (`make fuzz`)
- [x] NIST Known Answer Tests (KAT)
- [x] Constant-time verification tests (`make test-constant-time`)
- [x] Cross-validation tests (C++ <-> Python)
- [x] Performance benchmarks
- [x] SIMD correctness tests (`make test-simd`)

#### Performance Infrastructure
- [x] SIMD CPU detection (AVX2/AVX-512/NEON) via `simd::cpu_features()`
- [x] AVX2 NTT and polynomial operations for ML-KEM (x86-64)
- [x] AVX2 NTT and polynomial operations for ML-DSA (x86-64)
- [x] NEON NTT and polynomial operations for ML-KEM (ARM64)
- [x] NEON NTT and polynomial operations for ML-DSA (ARM64)
- [x] Montgomery multiplication for modular arithmetic
- [x] Barrett reduction for efficient modular reduction

#### Key Serialization
- [x] PKCS#8 private key format (DER/PEM) via `pkcs8::encode_private_key_*`
- [x] SubjectPublicKeyInfo format (DER/PEM) via `pkcs8::encode_public_key_*`
- [x] NIST OIDs for ML-DSA, SLH-DSA, ML-KEM (all parameter sets)
- [x] ASN.1 DER encoding/decoding utilities (`common/asn1.hpp`)
- [x] PEM Base64 encoding/decoding (`common/pem.hpp`)
- [x] PKCS#8 key format tests (`make test-pkcs8`)

#### X.509 Certificates
- [x] X.509 v3 certificate generation (`common/x509.hpp`)
- [x] Self-signed certificate creation (ML-DSA, SLH-DSA)
- [x] Distinguished Name (DN) encoding (CN, O, OU, C, ST, L, email)
- [x] Validity period encoding (UTCTime/GeneralizedTime)
- [x] BasicConstraints and KeyUsage extensions
- [x] Certificate parsing from DER and PEM
- [x] Certificate signature verification
- [x] Tampered certificate detection
- [x] X.509 certificate tests (`make test-x509`)

#### Runtime Algorithm Selection
- [x] Abstract `DigitalSignature` and `KeyEncapsulation` interfaces (`common/algorithm_factory.hpp`)
- [x] Factory functions: `pqc::create_dsa()`, `pqc::create_kem()` for runtime selection by name
- [x] ML-DSA adapter (all 3 parameter sets) with normalized keygen order
- [x] SLH-DSA adapter (all 12 parameter sets) with normalized keygen order
- [x] ML-KEM adapter (all 3 parameter sets)
- [x] Algorithm listing: `available_dsa_algorithms()`, `available_kem_algorithms()`
- [x] Algorithm validation: `is_dsa_algorithm()`, `is_kem_algorithm()`
- [x] Runtime algorithm selection tests (`make test-factory`)

#### Batch Verification
- [x] Parallel batch verification using `std::async` (`common/batch_verify.hpp`)
- [x] Sequential batch verification for embedded/constrained environments
- [x] Homogeneous batches (same algorithm, most efficient)
- [x] Heterogeneous batches (mixed algorithms, algorithm caching)
- [x] Configurable thread count and chunk size
- [x] Fail-fast mode for early termination on first failure
- [x] Detailed `BatchResult` with individual verification results and statistics
- [x] Batch verification tests (`make test-batch`)

#### Hybrid Cryptography
- [x] Hybrid signature schemes: ML-DSA + ECDSA/Ed25519 (`common/hybrid.hpp`)
- [x] Hybrid KEM schemes: ML-KEM + X25519/ECDH-P256
- [x] Classical algorithms: ECDSA-P256, ECDSA-P384, Ed25519, X25519, ECDH-P256
- [x] Combined key generation (concatenated PQC + classical keys)
- [x] Combined signatures with length-prefixed classical component
- [x] Combined KEM using HKDF-SHA256 for shared secret derivation
- [x] Factory functions: `pqc::create_hybrid_dsa()`, `pqc::create_hybrid_kem()`
- [x] Hybrid cryptography tests (`make test-hybrid`)

#### FIPS 140-3 Self-Tests
- [x] Conditional Algorithm Self-Tests (CAST) on first use (`common/fips_selftest.hpp`)
- [x] ML-DSA Known Answer Test (KAT) with pre-computed test vectors
- [x] Pairwise Consistency Tests (PCT) for ML-DSA, SLH-DSA, ML-KEM
- [x] Thread-safe state tracking using `std::atomic` and `std::mutex`
- [x] Individual self-tests: `run_mldsa_self_test()`, `run_slhdsa_self_test()`, `run_mlkem_self_test()`
- [x] Combined self-test: `run_all_self_tests()`
- [x] Guard functions: `ensure_mldsa_tested()`, `ensure_slhdsa_tested()`, `ensure_mlkem_tested()`
- [x] Status query: `get_self_test_status()`, `SelfTestStatus` struct
- [x] `SelfTestFailure` exception for failure propagation
- [x] FIPS self-test tests (`make test-fips`)

#### Streaming API
- [x] Pre-hash mode (HashML-DSA, HashSLH-DSA) for large message signing (`common/streaming.hpp`)
- [x] Streaming signer and verifier interfaces with incremental `update()` calls
- [x] Hash algorithm support: SHA-256/384/512, SHA3-256/384/512, SHAKE128/256
- [x] OID-prefixed pre-hash messages per FIPS 204/205 specifications
- [x] OpenSSL-based hash context with RAII resource management
- [x] Factory functions: `pqc::streaming::create_signer()`, `pqc::streaming::create_verifier()`
- [x] Convenience functions: `sign_streaming()`, `verify_streaming()` for chunked messages
- [x] Context string support (0-255 bytes)
- [x] All ML-DSA (44/65/87) and SLH-DSA (12 parameter sets) supported
- [x] Streaming API tests (`make test-streaming`)

#### HSM Integration
- [x] PKCS#11-inspired interface for Hardware Security Module integration (`common/hsm.hpp`)
- [x] Provider interface: slot management, token initialization, session handling
- [x] Session interface: login/logout, key generation, import/export, sign/verify, encaps/decaps
- [x] Software token implementation for testing without hardware HSM
- [x] Key management: generate, import, export, delete, find by label
- [x] Key attributes: extractable, sensitive, sign, verify, encrypt, decrypt
- [x] Support for all ML-DSA, SLH-DSA, and ML-KEM algorithms (18 total)
- [x] RAII session guard for automatic logout on scope exit
- [x] Thread-safe key storage with mutex protection
- [x] Secure key zeroization on deletion
- [x] HSM integration tests (`make test-hsm`)

#### OpenSSL Provider
- [x] OpenSSL 3.x-style provider interface for PQC algorithms (`common/ossl_provider.hpp`)
- [x] `PQCProvider` class with algorithm registration and lifecycle management
- [x] `KeyContext` class mimicking EVP_PKEY for key storage and operations
- [x] `SignContext` class mimicking EVP_MD_CTX for incremental sign/verify
- [x] `KemContext` class for encapsulation/decapsulation operations
- [x] Algorithm metadata with OIDs, security levels, and size information
- [x] Support for all 18 PQC algorithms (3 ML-DSA + 12 SLH-DSA + 3 ML-KEM)
- [x] Convenience functions: `keygen()`, `sign()`, `verify()`, `encapsulate()`, `decapsulate()`
- [x] Algorithm name mapping between internal and provider naming conventions
- [x] Key import/export for public keys and key pairs
- [x] Context string support for domain separation
- [x] Default provider singleton with automatic initialization
- [x] OpenSSL provider tests (`make test-ossl`)

#### JOSE/COSE Support
- [x] JWS (JSON Web Signature) implementation (`common/jose.hpp`)
- [x] JWT (JSON Web Token) creation and verification
- [x] COSE_Sign1 (CBOR Object Signing) implementation (`common/cose.hpp`)
- [x] Base64url encoding/decoding (RFC 4648)
- [x] CBOR encoding/decoding for COSE messages
- [x] All ML-DSA algorithms supported (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- [x] All SLH-DSA algorithms supported (12 parameter sets)
- [x] Proposed COSE algorithm IDs (-48 to -62 for PQC)
- [x] JWS builder with fluent API for token creation
- [x] JWS verifier with claims extraction
- [x] COSE_Sign1 with external AAD support
- [x] COSE_Sign1 detached payload mode
- [x] Context string support for ML-DSA signatures
- [x] JWT claims extraction utilities
- [x] JOSE/COSE tests (`make test-jose`)

#### X.509 Composite Certificates
- [x] Composite signature implementation (`common/composite.hpp`)
- [x] ML-DSA + ECDSA P-256/P-384 combinations
- [x] ML-DSA + Ed25519/Ed448 combinations
- [x] IETF draft OIDs (draft-ietf-lamps-pq-composite-sigs-13)
- [x] Factory function `pqc::create_composite_dsa()`
- [x] Both signatures required for verification (defense in depth)
- [x] Key splitting utilities for composite keys
- [x] Signature splitting utilities for composite signatures
- [x] Context string support
- [x] X.509 certificate generation with composite signatures
- [x] Composite certificate tests (`make test-composite`)

---

### API Header Files

| Header | Purpose |
|--------|---------|
| `mldsa/mldsa.hpp` | ML-DSA (FIPS 204) implementation |
| `slhdsa/slh_dsa.hpp` | SLH-DSA (FIPS 205) implementation |
| `mlkem/mlkem.hpp` | ML-KEM (FIPS 203) implementation |
| `common/algorithm_factory.hpp` | Runtime algorithm selection |
| `common/batch_verify.hpp` | Parallel batch verification |
| `common/hybrid.hpp` | Hybrid PQC + classical schemes |
| `common/streaming.hpp` | Pre-hash streaming API |
| `common/hsm.hpp` | HSM/PKCS#11 integration |
| `common/ossl_provider.hpp` | OpenSSL 3.x provider interface |
| `common/jose.hpp` | JWS/JWT support for PQC |
| `common/cose.hpp` | COSE_Sign1 support for PQC |
| `common/composite.hpp` | Composite ML-DSA + ECDSA/Ed25519 signatures |
| `common/fips_selftest.hpp` | FIPS 140-3 self-tests |
| `common/pkcs8.hpp` | PKCS#8 key serialization |
| `common/x509.hpp` | X.509 certificate generation |
| `common/asn1.hpp` | ASN.1 DER encoding utilities |
| `common/pem.hpp` | PEM Base64 encoding |
| `common/simd_detect.hpp` | SIMD CPU feature detection |
| `mldsa/ntt_avx2.hpp` | ML-DSA AVX2 NTT implementation |
| `mldsa/ntt_neon.hpp` | ML-DSA NEON NTT implementation |
| `mlkem/ntt_avx2.hpp` | ML-KEM AVX2 NTT implementation |
| `mlkem/ntt_neon.hpp` | ML-KEM NEON NTT implementation |

---

### Phase 1: Quick Wins

| Feature | Status | Priority | Effort | Description |
|---------|--------|----------|--------|-------------|
| **SIMD Optimization** | Done | High | 1 week | AVX2/NEON NTT for ML-DSA & ML-KEM |
| **PKCS#8 Key Format** | Done | High | 3-5 days | Standard DER/PEM serialization |
| **X.509 Certificates** | Done | High | 1 week | v3 certs with PQC OIDs |
| **Runtime Algorithm Selection** | Done | Medium | 2-3 days | Factory pattern for param sets |
| **Batch Verification** | Done | Medium | 3-5 days | Multiple signatures efficiently |

### Phase 2: Medium Effort

| Feature | Status | Priority | Effort | Description |
|---------|--------|----------|--------|-------------|
| **Hybrid Cryptography** | Done | High | 2 weeks | ML-DSA+ECDSA, ML-KEM+X25519 |
| **FIPS 140-3 Self-Tests** | Done | High | 1 week | CAST on first use |
| **Streaming API** | Done | Medium | 1 week | Pre-hash mode for large messages |
| **HSM Integration** | Done | Medium | 2 weeks | PKCS#11 provider wrapper |
| **OpenSSL Provider** | Done | Medium | 2 weeks | OpenSSL 3.x integration |

### Phase 3: Larger Efforts

| Feature | Status | Priority | Effort | Description |
|---------|--------|----------|--------|-------------|
| **Power Analysis Resistance** | Research | Low | 4+ weeks | Masking, threshold implementation |
| **Formal Verification** | Research | Low | External | Coq/SMT proofs |
| **Algorithm Agility (HQC)** | Research | Low | 4+ weeks | NIST backup KEM (~2027) |

---

## NIST Standards Status

### Current Implementation Status

This project currently implements:

| Standard | Algorithm | Type | Status |
|----------|-----------|------|--------|
| FIPS 203 | ML-KEM | Key Encapsulation | Implemented |
| FIPS 204 | ML-DSA | Digital Signature | Implemented |
| FIPS 205 | SLH-DSA | Digital Signature | Implemented |

---

## Upcoming NIST Standards

### Priority 1: High Benefit, Moderate Effort

#### 1. FN-DSA (FALCON) - FIPS 206

| Attribute | Details |
|-----------|---------|
| **Type** | Digital Signature |
| **Status** | Draft submitted August 2025, expected final 2026-2027 |
| **Benefit** | Smallest PQC signatures (~666 bytes vs ML-DSA's ~2,420 bytes) |
| **Use Cases** | Certificate chains, DNSSEC, bandwidth-constrained environments |
| **Difficulty** | Moderate - requires floating-point arithmetic |

**Why Add:**
- FN-DSA-512 signature: ~666 bytes, public key: ~897 bytes
- Much closer to ECC signature sizes than ML-DSA
- Ideal for root/intermediate certificates where signing is controlled
- Complements ML-DSA for size-sensitive applications

**Implementation Notes:**
- Uses NTRU lattices with FFT
- Floating-point arithmetic adds complexity
- Less suitable for constrained devices due to signing complexity

**References:**
- [NIST FIPS 206 Presentation](https://csrc.nist.gov/presentations/2025/fips-206-fn-dsa-falcon)
- [DigiCert: FN-DSA Nears Draft Approval](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist)

---

#### 2. HQC - Key Encapsulation (Backup for ML-KEM)

| Attribute | Details |
|-----------|---------|
| **Type** | Key Encapsulation Mechanism |
| **Status** | Selected March 2025, draft expected 2026, final 2027 |
| **Benefit** | Algorithmic diversity - different math than ML-KEM |
| **Use Cases** | Backup KEM if lattice vulnerabilities discovered |
| **Difficulty** | Moderate |

**Why Add:**
- Based on error-correcting codes (not lattices like ML-KEM)
- Provides cryptographic diversity in case lattice attacks improve
- NIST's official backup for ML-KEM
- Stronger security proofs than alternatives (BIKE)

**References:**
- [NIST Selects HQC](https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption)
- [NIST IR 8545 - Fourth Round Status Report](https://csrc.nist.gov/pubs/ir/8545/final)

---

### Priority 2: High Benefit, Higher Effort

#### 3. JOSE/COSE Support for PQC

| Attribute | Details |
|-----------|---------|
| **Type** | Serialization Format |
| **Status** | IETF drafts in progress |
| **Benefit** | Web/API interoperability (JWT, CWT, WebAuthn) |
| **Use Cases** | PQC tokens, API authentication, WebAuthn |
| **Difficulty** | Moderate |

**Components:**
- **ML-DSA for JOSE/COSE** ([draft-ietf-cose-dilithium](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/))
- **SLH-DSA for JOSE/COSE** ([draft-ietf-cose-sphincs-plus](https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/))
- **Hybrid Composite Signatures** ([draft-prabel-jose-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-prabel-jose-pq-composite-sigs/))

**Why Add:**
- Enables standard JWT/CWT tokens with PQC signatures
- Required for WebAuthn/FIDO2 PQC support
- Industry standard for web authentication

**Algorithm IDs (Proposed):**
| Algorithm | COSE ID | JOSE ID |
|-----------|---------|---------|
| ML-DSA-44 | -48 | ML-DSA-44 |
| ML-DSA-65 | -49 | ML-DSA-65 |
| ML-DSA-87 | -50 | ML-DSA-87 |

---

#### 4. X.509 PQC Certificates

| Attribute | Details |
|-----------|---------|
| **Type** | Certificate Format |
| **Status** | IETF drafts, implementations emerging |
| **Benefit** | PKI compatibility, TLS certificates |
| **Use Cases** | HTTPS, code signing, S/MIME |
| **Difficulty** | Moderate-High |

**Components:**
- Pure PQC certificates (ML-DSA, SLH-DSA, FN-DSA)
- Composite certificates (PQC + traditional in one cert)
- Dual certificate chains (separate PQC and traditional chains)

**References:**
- [IETF PQC Certificates Hackathon](https://github.com/IETF-Hackathon/pqc-certificates)
- [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/)

**Why Add:**
- Required for TLS/HTTPS with PQC
- Enables code signing with standard PKI
- Industry moving to hybrid certificates 2025-2030

---

### Priority 3: Medium Benefit, Variable Effort

#### 5. Hybrid TLS Support

| Attribute | Details |
|-----------|---------|
| **Type** | Protocol Integration |
| **Status** | Chrome/CloudFlare deployed X25519MLKEM768 |
| **Benefit** | Secure key exchange during transition |
| **Use Cases** | Web servers, API gateways |
| **Difficulty** | High (protocol integration) |

**Current State:**
- X25519MLKEM768 already in Chrome, CloudFlare
- Dual certificate authentication in draft

**References:**
- [RFC 9794: PQ/T Hybrid Terminology](https://www.rfc-editor.org/rfc/rfc9794.html)
- [draft-ietf-uta-pqc-app](https://datatracker.ietf.org/doc/draft-ietf-uta-pqc-app/)

---

#### 6. OpenSSL Provider ✅ COMPLETED

| Attribute | Details |
|-----------|---------|
| **Type** | Integration |
| **Status** | ✅ Implemented in `common/ossl_provider.hpp` |
| **Benefit** | Drop-in OpenSSL compatibility |
| **Use Cases** | Existing applications using OpenSSL |

**Implementation:**
- `PQCProvider` class with algorithm registration
- `KeyContext`, `SignContext`, `KemContext` classes
- Support for all 18 PQC algorithms
- Tests: `make test-ossl`

---

## NIST Migration Timeline

From [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd):

| Year | Action |
|------|--------|
| **2024** | FIPS 203, 204, 205 published - begin migration |
| **2025-2030** | Transition period - hybrid deployments recommended |
| **2030** | Classical algorithms deprecated (112-bit security) |
| **2035** | Classical algorithms disallowed |

**Algorithms to be deprecated by 2030:**
- RSA (all key sizes for signatures)
- ECDSA, EdDSA (112-bit security)
- Elliptic Curve DH, Finite Field DH

---

## Implementation Priority Matrix

### Awaiting Standards
| Project | Benefit | Effort | Timeline |
|---------|---------|--------|----------|
| FN-DSA (FALCON) | High | Medium | After FIPS 206 draft (2025-2026) |
| HQC | High | Medium | After draft (2026-2027) |
| Hybrid TLS | Medium | High | After X.509 composite |

### Completed
| Project | Status |
|---------|--------|
| X.509 Composite Certs | ✅ Done |
| JOSE/COSE Support | ✅ Done |
| OpenSSL Provider | ✅ Done |
| SIMD Optimization | ✅ Done |
| All Phase 1 & 2 | ✅ Done |

---

## Quick Reference: Algorithm Comparison

### Digital Signatures

| Algorithm | Standard | PK Size | Sig Size | Security | Speed |
|-----------|----------|---------|----------|----------|-------|
| ML-DSA-44 | FIPS 204 | 1,312 B | 2,420 B | Level 2 | Fast |
| ML-DSA-65 | FIPS 204 | 1,952 B | 3,309 B | Level 3 | Fast |
| ML-DSA-87 | FIPS 204 | 2,592 B | 4,627 B | Level 5 | Fast |
| SLH-DSA-128f | FIPS 205 | 32 B | 17,088 B | Level 1 | Slow |
| FN-DSA-512 | FIPS 206* | 897 B | 666 B | Level 1 | Medium |
| FN-DSA-1024 | FIPS 206* | 1,793 B | 1,280 B | Level 5 | Medium |

*Draft standard

### Key Encapsulation

| Algorithm | Standard | PK Size | CT Size | SS Size | Security |
|-----------|----------|---------|---------|---------|----------|
| ML-KEM-512 | FIPS 203 | 800 B | 768 B | 32 B | Level 1 |
| ML-KEM-768 | FIPS 203 | 1,184 B | 1,088 B | 32 B | Level 3 |
| ML-KEM-1024 | FIPS 203 | 1,568 B | 1,568 B | 32 B | Level 5 |
| HQC-128 | TBD* | 2,249 B | 4,481 B | 64 B | Level 1 |
| HQC-192 | TBD* | 4,522 B | 9,026 B | 64 B | Level 3 |
| HQC-256 | TBD* | 7,245 B | 14,469 B | 64 B | Level 5 |

*Expected 2027

---

## Resources

### NIST Official
- [NIST PQC Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST IR 8547 - Transition Guidelines](https://csrc.nist.gov/pubs/ir/8547/ipd)

### IETF Drafts
- [ML-DSA for JOSE/COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/)
- [SLH-DSA for JOSE/COSE](https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/)
- [PQC for TLS Applications](https://datatracker.ietf.org/doc/draft-ietf-uta-pqc-app/)
- [IETF Protocol PQC Status](https://github.com/ietf-wg-pquip/state-of-protocols-and-pqc)

### Industry
- [PQShield Whitepaper 2025](https://pqshield.com/updated-whitepaper-for-2025-the-new-nist-standards-are-here-what-does-it-mean-for-pqc-in-2025/)
- [IBM PQC Standards](https://research.ibm.com/blog/nist-pqc-standards)

---

## Quick Test Commands

```bash
# Build and run all tests
make build-local && make test-local

# Individual test suites
make test-mldsa-cpp      # ML-DSA core tests
make test-slhdsa-cpp     # SLH-DSA core tests
make test-mlkem-cpp      # ML-KEM core tests
make test-kat            # NIST Known Answer Tests
make test-constant-time  # Timing leak detection (dudect)
make test-simd           # SIMD correctness tests
make test-pkcs8          # PKCS#8 key format tests
make test-x509           # X.509 certificate tests
make test-factory        # Runtime algorithm selection tests
make test-batch          # Batch verification tests
make test-hybrid         # Hybrid cryptography tests
make test-fips           # FIPS 140-3 self-tests
make test-streaming      # Streaming API tests
make test-hsm            # HSM integration tests
make test-ossl           # OpenSSL provider tests
make test-jose           # JOSE/COSE support tests
make test-composite      # X.509 composite certificate tests

# Fuzz testing
make fuzz-local          # Run all fuzzers locally
make fuzz                # Run fuzzers in Docker
```

---

*Last updated: January 2026*
