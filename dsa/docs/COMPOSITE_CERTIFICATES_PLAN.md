# X.509 Composite Certificates - Feature Plan

## Executive Summary

X.509 Composite Certificates combine post-quantum and classical cryptographic algorithms into a single certificate, providing dual-algorithm security during the PQC transition period (2025-2035). This document outlines what composite certificates are, why they matter, and how to implement them in this library.

---

## Table of Contents

1. [What Are Composite Certificates?](#what-are-composite-certificates)
2. [Why Are They Important?](#why-are-they-important)
3. [Benefits for This Project](#benefits-for-this-project)
4. [Technical Specification](#technical-specification)
5. [Implementation Plan](#implementation-plan)
6. [Testing Strategy](#testing-strategy)
7. [References](#references)

---

## What Are Composite Certificates?

### The Problem

The advent of quantum computing poses an existential threat to current cryptographic systems:

- **RSA, DSA, ECDSA** - Will be broken by Shor's algorithm on a cryptographically relevant quantum computer (CRQC)
- **Timeline** - NIST mandates deprecation of classical-only algorithms by 2030, full ban by 2035
- **Harvest Now, Decrypt Later** - Adversaries may collect encrypted data today to decrypt when quantum computers arrive

However, we face a dilemma:

1. **PQC algorithms are new** - Less cryptanalysis than 40+ years of RSA/ECC research
2. **Implementation bugs** - New code may have undiscovered vulnerabilities
3. **Regulatory requirements** - Many standards still require classical algorithms

### The Solution: Composite Certificates

A **composite certificate** combines two signature algorithms into one:

```
Composite Signature = ML-DSA Signature || Classical Signature
```

Both signatures are computed over the same message. For verification to succeed, **both signatures must verify**. This provides:

- **Defense in depth** - Security if either algorithm survives
- **Protocol compatibility** - Appears as a single signature algorithm
- **Regulatory compliance** - Satisfies both PQC and classical requirements

### Certificate Structure

```
Certificate ::= SEQUENCE {
    tbsCertificate       TBSCertificate,
    signatureAlgorithm   id-MLDSA65-ECDSA-P256-SHA512,  -- Composite OID
    signatureValue       BIT STRING {                   -- Concatenated
        mldsaSignature   OCTET STRING (3309 bytes),
        ecdsaSignature   OCTET STRING (variable)
    }
}

SubjectPublicKeyInfo ::= SEQUENCE {
    algorithm   id-MLDSA65-ECDSA-P256-SHA512,           -- Same composite OID
    publicKey   BIT STRING {                            -- Concatenated
        mldsaPublicKey   OCTET STRING (1952 bytes),
        ecdsaPublicKey   OCTET STRING (65 bytes)        -- Uncompressed point
    }
}
```

---

## Why Are They Important?

### 1. NIST Migration Timeline

| Year | Requirement |
|------|-------------|
| 2024 | FIPS 203/204/205 published - begin migration |
| 2025-2030 | Transition period - **hybrid deployments recommended** |
| 2030 | RSA/ECDSA deprecated for signatures |
| 2035 | RSA/ECDSA disallowed |

Source: [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd)

### 2. Regulatory Requirements

Many industries require specific algorithms:

| Sector | Requirement | Solution |
|--------|-------------|----------|
| Financial (PCI-DSS) | Approved algorithms only | Composite satisfies both PQC and classical requirements |
| Government (FIPS) | FIPS-validated algorithms | ML-DSA is FIPS 204; ECDSA is FIPS 186 |
| Healthcare (HIPAA) | Strong encryption | Dual-algorithm provides defense in depth |

### 3. Risk Mitigation

| Risk | Mitigation via Composite |
|------|-------------------------|
| Quantum computer breaks ML-DSA | Classical ECDSA still protects |
| Bug discovered in ML-DSA implementation | Classical ECDSA still protects |
| Bug discovered in ECDSA implementation | ML-DSA still protects |
| Cryptanalytic breakthrough against lattices | Classical algorithms still secure |

### 4. Industry Adoption

- **Chrome/Cloudflare**: Already deployed X25519MLKEM768 hybrid key exchange
- **DigiCert, Entrust, Sectigo**: Offering hybrid certificate trials
- **AWS, Google, Microsoft**: PQC migration underway

---

## Benefits for This Project

### 1. Complete PQC Solution

With composite certificates, this library provides a **full PKI stack**:

```
Application Layer     →  JOSE/COSE tokens (JWT with ML-DSA)
Certificate Layer     →  X.509 Composite Certificates  ← NEW
Key Serialization     →  PKCS#8, SubjectPublicKeyInfo
Algorithm Layer       →  ML-DSA, SLH-DSA, ML-KEM
```

### 2. Leverages Existing Components

| Existing Component | Used For |
|-------------------|----------|
| `common/x509.hpp` | Certificate structure, DN encoding, validity |
| `common/hybrid.hpp` | Classical ECDSA/Ed25519 via OpenSSL |
| `common/pkcs8.hpp` | OID encoding, key serialization |
| `common/asn1.hpp` | DER encoding/decoding |
| `common/algorithm_factory.hpp` | Runtime algorithm selection |

### 3. Market Differentiation

Few open-source libraries offer composite certificates:

| Library | PQC Signatures | Composite Certs |
|---------|---------------|-----------------|
| liboqs | Yes | No |
| BouncyCastle | Yes | Partial |
| OpenSSL | Experimental | No |
| **This library** | Yes | **Yes (proposed)** |

### 4. Interoperability Testing

IETF Hackathon provides [test artifacts](https://github.com/IETF-Hackathon/pqc-certificates) for interoperability testing, enabling validation against other implementations.

---

## Technical Specification

### Composite Algorithm Identifiers (OIDs)

Based on [draft-ietf-lamps-pq-composite-sigs-13](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/):

| Algorithm | OID | PQC Component | Classical Component |
|-----------|-----|---------------|---------------------|
| `id-MLDSA44-ECDSA-P256-SHA256` | 1.3.6.1.5.5.7.6.41 | ML-DSA-44 | ECDSA P-256 |
| `id-MLDSA44-Ed25519-SHA512` | 1.3.6.1.5.5.7.6.43 | ML-DSA-44 | Ed25519 |
| `id-MLDSA65-ECDSA-P256-SHA512` | 1.3.6.1.5.5.7.6.45 | ML-DSA-65 | ECDSA P-256 |
| `id-MLDSA65-ECDSA-P384-SHA512` | 1.3.6.1.5.5.7.6.46 | ML-DSA-65 | ECDSA P-384 |
| `id-MLDSA65-Ed25519-SHA512` | 1.3.6.1.5.5.7.6.48 | ML-DSA-65 | Ed25519 |
| `id-MLDSA87-ECDSA-P384-SHA512` | 1.3.6.1.5.5.7.6.49 | ML-DSA-87 | ECDSA P-384 |
| `id-MLDSA87-Ed448-SHA512` | 1.3.6.1.5.5.7.6.51 | ML-DSA-87 | Ed448 |

Note: OIDs are from the current draft and may change before final standardization.

### Key Sizes

| Composite Algorithm | Public Key Size | Signature Size |
|--------------------|-----------------|----------------|
| MLDSA44-ECDSA-P256 | 1,312 + 65 = **1,377 bytes** | 2,420 + ~72 = **~2,492 bytes** |
| MLDSA65-ECDSA-P256 | 1,952 + 65 = **2,017 bytes** | 3,309 + ~72 = **~3,381 bytes** |
| MLDSA65-Ed25519 | 1,952 + 32 = **1,984 bytes** | 3,309 + 64 = **3,373 bytes** |
| MLDSA87-ECDSA-P384 | 2,592 + 97 = **2,689 bytes** | 4,627 + ~104 = **~4,731 bytes** |
| MLDSA87-Ed448 | 2,592 + 57 = **2,649 bytes** | 4,627 + 114 = **4,741 bytes** |

### ASN.1 Structure (No Wrapping)

Per the specification, composite keys and signatures use **raw concatenation** with no additional ASN.1 wrapping:

```
CompositePublicKey ::= mldsaPublicKey || classicalPublicKey

CompositeSignature ::= mldsaSignature || classicalSignature
```

- **ML-DSA public keys**: Raw bytes (1312/1952/2592 bytes)
- **ECDSA public keys**: Uncompressed X9.62 format (0x04 || X || Y)
- **Ed25519 public keys**: Raw 32 bytes
- **Ed448 public keys**: Raw 57 bytes

### Signature Generation Algorithm

```
Input: message M, composite secret key (sk_pq, sk_classical), context ctx

1. Construct message representative:
   M' = Domain || len(ctx) || ctx || M
   where Domain is algorithm-specific

2. Generate ML-DSA signature:
   sig_pq = ML-DSA.Sign(sk_pq, M', ctx)

3. Generate classical signature:
   sig_classical = Classical.Sign(sk_classical, M')

4. Return: sig_pq || sig_classical
```

### Signature Verification Algorithm

```
Input: message M, signature sig, composite public key (pk_pq, pk_classical), context ctx

1. Parse signature:
   sig_pq = sig[0:pq_sig_len]
   sig_classical = sig[pq_sig_len:]

2. Reconstruct message representative:
   M' = Domain || len(ctx) || ctx || M

3. Verify ML-DSA signature:
   valid_pq = ML-DSA.Verify(pk_pq, M', sig_pq, ctx)

4. Verify classical signature:
   valid_classical = Classical.Verify(pk_classical, M', sig_classical)

5. Return: valid_pq AND valid_classical
```

---

## Implementation Plan

### Phase 1: Core Composite Signature Support

**File:** `src/cpp/common/composite.hpp`

#### 1.1 OID Definitions

```cpp
namespace composite::oid {
    // ML-DSA-44 combinations
    inline const std::string MLDSA44_ECDSA_P256_SHA256 = "1.3.6.1.5.5.7.6.41";
    inline const std::string MLDSA44_Ed25519_SHA512    = "1.3.6.1.5.5.7.6.43";

    // ML-DSA-65 combinations
    inline const std::string MLDSA65_ECDSA_P256_SHA512 = "1.3.6.1.5.5.7.6.45";
    inline const std::string MLDSA65_ECDSA_P384_SHA512 = "1.3.6.1.5.5.7.6.46";
    inline const std::string MLDSA65_Ed25519_SHA512    = "1.3.6.1.5.5.7.6.48";

    // ML-DSA-87 combinations
    inline const std::string MLDSA87_ECDSA_P384_SHA512 = "1.3.6.1.5.5.7.6.49";
    inline const std::string MLDSA87_Ed448_SHA512      = "1.3.6.1.5.5.7.6.51";
}
```

#### 1.2 Composite Algorithm Interface

```cpp
class CompositeSignature : public DigitalSignature {
public:
    // Algorithm metadata
    virtual std::string pqc_algorithm() const = 0;
    virtual std::string classical_algorithm() const = 0;
    virtual std::string oid() const = 0;

    // Key sizes
    virtual size_t pqc_public_key_size() const = 0;
    virtual size_t classical_public_key_size() const = 0;
    virtual size_t pqc_signature_size() const = 0;
    virtual size_t classical_signature_size() const = 0;

    // Key parsing utilities
    virtual std::pair<std::span<const uint8_t>, std::span<const uint8_t>>
        split_public_key(std::span<const uint8_t> composite_pk) const = 0;

    virtual std::pair<std::span<const uint8_t>, std::span<const uint8_t>>
        split_signature(std::span<const uint8_t> composite_sig) const = 0;
};
```

#### 1.3 Factory Function

```cpp
std::unique_ptr<CompositeSignature> create_composite_dsa(const std::string& name);

// Usage:
auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
auto [pk, sk] = composite->keygen();
auto sig = composite->sign(sk, message);
bool valid = composite->verify(pk, message, sig);
```

### Phase 2: X.509 Composite Certificate Support

**File:** `src/cpp/common/x509_composite.hpp`

#### 2.1 Composite Certificate Builder

```cpp
class CompositeCertificateBuilder {
public:
    CompositeCertificateBuilder& algorithm(const std::string& composite_alg);
    CompositeCertificateBuilder& subject(const DistinguishedName& dn);
    CompositeCertificateBuilder& issuer(const DistinguishedName& dn);
    CompositeCertificateBuilder& validity(int days);
    CompositeCertificateBuilder& serial(const std::vector<uint8_t>& serial);

    // Build self-signed certificate
    std::vector<uint8_t> build_self_signed(
        std::span<const uint8_t> composite_sk) const;

    // Build CA-signed certificate
    std::vector<uint8_t> build(
        std::span<const uint8_t> subject_pk,
        std::span<const uint8_t> issuer_sk,
        const std::vector<uint8_t>& issuer_cert) const;
};
```

#### 2.2 Certificate Verification

```cpp
struct CompositeCertificateInfo {
    std::string algorithm;
    DistinguishedName subject;
    DistinguishedName issuer;
    std::vector<uint8_t> pqc_public_key;
    std::vector<uint8_t> classical_public_key;
    // ... validity, extensions, etc.
};

// Parse and verify
std::optional<CompositeCertificateInfo> parse_composite_certificate(
    std::span<const uint8_t> cert_der);

bool verify_composite_certificate(
    std::span<const uint8_t> cert_der,
    std::span<const uint8_t> issuer_pk);
```

### Phase 3: Integration and Tools

#### 3.1 Update keygen Tool

```bash
# Generate composite keys and certificate
./keygen composite-mldsa65-p256 output/ \
    --cn "example.com" \
    --org "Example Corp" \
    --days 365
```

#### 3.2 Certificate Chain Support

```cpp
// Verify a certificate chain
bool verify_certificate_chain(
    const std::vector<std::vector<uint8_t>>& chain,  // leaf to root
    std::span<const uint8_t> trust_anchor);
```

### Implementation Checklist

#### Phase 1: Core (Est. 3-4 days)
- [ ] Define composite algorithm OIDs in `composite.hpp`
- [ ] Implement `CompositeSignature` base class
- [ ] Implement MLDSA44-ECDSA-P256-SHA256
- [ ] Implement MLDSA65-ECDSA-P256-SHA512
- [ ] Implement MLDSA65-Ed25519-SHA512
- [ ] Implement MLDSA87-ECDSA-P384-SHA512
- [ ] Implement MLDSA87-Ed448-SHA512
- [ ] Add factory function `create_composite_dsa()`
- [ ] Write unit tests for all combinations

#### Phase 2: X.509 Integration (Est. 3-4 days)
- [ ] Update `x509.hpp` to support composite OIDs
- [ ] Implement `CompositeCertificateBuilder`
- [ ] Implement composite certificate parsing
- [ ] Implement composite certificate verification
- [ ] Add PEM encoding/decoding support
- [ ] Write certificate generation tests
- [ ] Write certificate verification tests

#### Phase 3: Tools and Integration (Est. 2-3 days)
- [ ] Update `keygen` tool for composite algorithms
- [ ] Add certificate chain verification
- [ ] Update documentation (MANUAL.md, DEVELOPER.md)
- [ ] Add interoperability tests with IETF test vectors
- [ ] Update Makefile with `make test-composite`

---

## Testing Strategy

### Unit Tests

```cpp
// Test composite key generation
TEST(CompositeSignature, KeygenMLDSA65_ECDSA_P256) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    EXPECT_EQ(pk.size(), 1952 + 65);  // ML-DSA-65 + P-256
    EXPECT_EQ(sk.size(), 4032 + 32);  // ML-DSA-65 + P-256
}

// Test sign/verify
TEST(CompositeSignature, SignVerifyMLDSA65_ECDSA_P256) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> msg = {'H', 'e', 'l', 'l', 'o'};
    auto sig = composite->sign(sk, msg);

    EXPECT_TRUE(composite->verify(pk, msg, sig));
}

// Test both signatures required
TEST(CompositeSignature, BothSignaturesRequired) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> msg = {'H', 'e', 'l', 'l', 'o'};
    auto sig = composite->sign(sk, msg);

    // Corrupt PQC signature
    sig[0] ^= 0xFF;
    EXPECT_FALSE(composite->verify(pk, msg, sig));

    // Restore PQC, corrupt classical
    sig[0] ^= 0xFF;
    sig[3309] ^= 0xFF;  // After ML-DSA signature
    EXPECT_FALSE(composite->verify(pk, msg, sig));
}
```

### Certificate Tests

```cpp
// Test composite certificate generation
TEST(CompositeCertificate, SelfSigned) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    x509::DistinguishedName dn;
    dn.common_name = "test.example.com";
    dn.organization = "Test Org";

    auto cert = x509::CompositeCertificateBuilder()
        .algorithm("MLDSA65-ECDSA-P256")
        .subject(dn)
        .issuer(dn)
        .validity(365)
        .build_self_signed(sk);

    // Verify certificate
    EXPECT_TRUE(x509::verify_composite_certificate(cert, pk));
}
```

### Interoperability Tests

Use [IETF PQC Certificates](https://github.com/IETF-Hackathon/pqc-certificates) test vectors:

```cpp
TEST(CompositeCertificate, IETFInteroperability) {
    // Load IETF test certificate
    auto cert = load_test_cert("ietf_mldsa65_p256_cert.der");
    auto issuer_pk = load_test_pk("ietf_mldsa65_p256_issuer.pub");

    // Verify using our implementation
    EXPECT_TRUE(x509::verify_composite_certificate(cert, issuer_pk));
}
```

---

## API Summary

### New Files

| File | Purpose |
|------|---------|
| `common/composite.hpp` | Composite signature implementation |
| `common/x509_composite.hpp` | Composite certificate support |
| `tests/cpp/test_composite.cpp` | Unit tests |

### New Functions

```cpp
// Composite signatures
std::unique_ptr<CompositeSignature> pqc::create_composite_dsa(const std::string& name);
std::vector<std::string> pqc::available_composite_algorithms();
bool pqc::is_composite_algorithm(const std::string& name);

// Composite certificates
x509::CompositeCertificateBuilder  // Builder class
x509::parse_composite_certificate(cert_der)
x509::verify_composite_certificate(cert_der, issuer_pk)
```

### Supported Composite Algorithms

| Name | Components | Use Case |
|------|------------|----------|
| `MLDSA44-ECDSA-P256` | ML-DSA-44 + ECDSA P-256 | General purpose, Cat 1 |
| `MLDSA44-Ed25519` | ML-DSA-44 + Ed25519 | Fast verification, Cat 1 |
| `MLDSA65-ECDSA-P256` | ML-DSA-65 + ECDSA P-256 | **Recommended default** |
| `MLDSA65-ECDSA-P384` | ML-DSA-65 + ECDSA P-384 | Higher classical security |
| `MLDSA65-Ed25519` | ML-DSA-65 + Ed25519 | Fast verification, Cat 3 |
| `MLDSA87-ECDSA-P384` | ML-DSA-87 + ECDSA P-384 | High security, Cat 5 |
| `MLDSA87-Ed448` | ML-DSA-87 + Ed448 | Maximum security |

---

## References

### Standards
- [draft-ietf-lamps-pq-composite-sigs-13](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) - Composite ML-DSA for X.509
- [draft-ietf-lamps-pq-composite-kem-12](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-kem/) - Composite ML-KEM for X.509
- [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/ipd) - PQC Transition Guidelines
- [RFC 9794](https://www.rfc-editor.org/rfc/rfc9794.html) - PQ/T Hybrid Terminology

### Research
- [Comparative Study of Hybrid PQC X.509 Certificates](https://arxiv.org/abs/2511.00111) - Analysis of composite vs catalyst vs chameleon approaches
- [The Viability of Post-Quantum X.509 Certificates](https://eprint.iacr.org/2018/063.pdf) - Early analysis of PQC certificate sizes

### Implementations
- [IETF PQC Certificates Hackathon](https://github.com/IETF-Hackathon/pqc-certificates) - Interoperability test vectors
- [lamps-wg/draft-composite-sigs](https://github.com/lamps-wg/draft-composite-sigs) - Reference implementation notes

### Industry
- [Keyfactor: Quantum-Safe Certificates](https://www.keyfactor.com/blog/quantum-safe-certificates-what-are-they-and-what-do-they-want-from-us/)
- [Sectigo: Hybrid Certificates](https://www.sectigo.com/blog/what-are-quantum-safe-and-hybrid-certificates)

---

*Document created: January 2026*
*Based on draft-ietf-lamps-pq-composite-sigs-13 (October 2025)*
