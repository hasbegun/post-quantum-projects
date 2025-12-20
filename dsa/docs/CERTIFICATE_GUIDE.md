# Post-Quantum Certificate Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Algorithm Selection](#algorithm-selection)
3. [ML-DSA Certificates (FIPS 204)](#ml-dsa-certificates-fips-204)
4. [SLH-DSA Certificates (FIPS 205)](#slh-dsa-certificates-fips-205)
5. [Use Case Examples](#use-case-examples)
6. [Certificate Chain Examples](#certificate-chain-examples)
7. [Migration Strategies](#migration-strategies)

---

## Introduction

### What is a Post-Quantum Certificate?

A digital certificate binds a public key to an identity (person, organization, or device). Post-quantum certificates use quantum-resistant signature algorithms instead of traditional RSA or ECDSA.

```
Traditional Certificate:
┌─────────────────────────────────────┐
│ Subject: example.com                │
│ Public Key: RSA-2048 or ECDSA-P256  │  ← Broken by quantum computers
│ Signature: RSA/ECDSA                │
└─────────────────────────────────────┘

Post-Quantum Certificate:
┌─────────────────────────────────────┐
│ Subject: example.com                │
│ Public Key: ML-DSA-65 or SLH-DSA    │  ← Quantum-resistant
│ Signature: ML-DSA/SLH-DSA           │
└─────────────────────────────────────┘
```

### Certificate Lifecycle

```
1. Key Generation    → Create public/private key pair
2. CSR Creation      → Create Certificate Signing Request
3. Certificate Issue → CA signs the certificate
4. Certificate Use   → Sign documents, authenticate, etc.
5. Verification      → Others verify signatures with public key
```

---

## Algorithm Selection

### Quick Decision Guide

| Use Case | Recommended Algorithm | Reason |
|----------|----------------------|--------|
| TLS/HTTPS servers | ML-DSA-65 | Fast handshakes, reasonable sizes |
| API authentication | ML-DSA-44 | Speed critical, high volume |
| Root CA certificates | SLH-DSA-256s | Maximum long-term security |
| Intermediate CA | ML-DSA-87 or SLH-DSA-192f | Balance of security and performance |
| Code signing | SLH-DSA-128f | Long validity, hash-only security |
| Document signing | SLH-DSA-128s | Smaller signatures for archival |
| IoT devices | ML-DSA-44 | Constrained resources |
| Firmware updates | SLH-DSA-128f | Decades of validity needed |

### Algorithm Comparison

#### ML-DSA (FIPS 204) - Lattice-Based

| Parameter Set | Security Level | Public Key | Secret Key | Signature |
|--------------|----------------|------------|------------|-----------|
| ML-DSA-44 | 128-bit (Cat 2) | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | 192-bit (Cat 3) | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | 256-bit (Cat 5) | 2,592 B | 4,896 B | 4,627 B |

**Pros:**
- Fast signing (~0.5 ms)
- Fast verification (~0.3 ms)
- Smaller signatures

**Cons:**
- Larger public keys
- Security based on lattice assumptions (newer)

#### SLH-DSA (FIPS 205) - Hash-Based

| Parameter Set | Security Level | Public Key | Secret Key | Signature |
|--------------|----------------|------------|------------|-----------|
| SLH-DSA-SHAKE-128f | 128-bit | 32 B | 64 B | 17,088 B |
| SLH-DSA-SHAKE-128s | 128-bit | 32 B | 64 B | 7,856 B |
| SLH-DSA-SHAKE-192f | 192-bit | 48 B | 96 B | 35,664 B |
| SLH-DSA-SHAKE-256f | 256-bit | 64 B | 128 B | 49,856 B |

**Pros:**
- Tiny public keys (32-64 bytes)
- Security based only on hash functions (well-understood)
- Conservative, minimal assumptions

**Cons:**
- Larger signatures (7-50 KB)
- Slower signing (40-500 ms depending on variant)

---

## ML-DSA Certificates (FIPS 204)

### Creating an ML-DSA Certificate

#### Python Example

```python
from dsa import MLDSA44, MLDSA65, MLDSA87
import hashlib
import json
import base64
from datetime import datetime, timedelta

class MLDSACertificate:
    """Simple X.509-like certificate using ML-DSA."""

    def __init__(self, dsa_class=MLDSA65):
        self.dsa = dsa_class()

    def generate_keypair(self, seed=None):
        """Generate a new key pair."""
        if seed:
            return self.dsa.keygen(seed=seed)
        return self.dsa.keygen()

    def create_certificate(self, subject: dict, public_key: bytes,
                          issuer_sk: bytes, issuer_name: str,
                          validity_days: int = 365) -> dict:
        """
        Create a signed certificate.

        Args:
            subject: Dictionary with subject info (CN, O, etc.)
            public_key: Subject's public key
            issuer_sk: Issuer's secret key for signing
            issuer_name: Issuer's distinguished name
            validity_days: Certificate validity period

        Returns:
            Signed certificate as dictionary
        """
        now = datetime.utcnow()

        # Certificate structure (simplified X.509)
        cert_data = {
            "version": 3,
            "serial_number": hashlib.sha256(
                public_key + str(now.timestamp()).encode()
            ).hexdigest()[:32],
            "signature_algorithm": f"ML-DSA-{self.dsa.params().name}",
            "issuer": issuer_name,
            "validity": {
                "not_before": now.isoformat(),
                "not_after": (now + timedelta(days=validity_days)).isoformat()
            },
            "subject": subject,
            "public_key": {
                "algorithm": f"ML-DSA-{self.dsa.params().name}",
                "key": base64.b64encode(public_key).decode()
            }
        }

        # Sign the certificate data
        tbs_bytes = json.dumps(cert_data, sort_keys=True).encode()
        signature = self.dsa.sign(issuer_sk, tbs_bytes)

        return {
            "certificate": cert_data,
            "signature": base64.b64encode(signature).decode()
        }

    def verify_certificate(self, cert: dict, issuer_pk: bytes) -> bool:
        """Verify a certificate's signature."""
        tbs_bytes = json.dumps(cert["certificate"], sort_keys=True).encode()
        signature = base64.b64decode(cert["signature"])
        return self.dsa.verify(issuer_pk, tbs_bytes, signature)

    def create_self_signed_ca(self, ca_name: str) -> tuple:
        """
        Create a self-signed CA certificate.

        Returns:
            Tuple of (certificate, public_key, secret_key)
        """
        pk, sk = self.generate_keypair()

        subject = {
            "CN": ca_name,
            "O": "Certificate Authority",
            "CA": True
        }

        cert = self.create_certificate(
            subject=subject,
            public_key=pk,
            issuer_sk=sk,
            issuer_name=ca_name,
            validity_days=3650  # 10 years for CA
        )

        return cert, pk, sk


# Usage Example
def demo_mldsa_certificate():
    print("=== ML-DSA Certificate Demo ===\n")

    # Create CA with ML-DSA-65 (recommended for CAs)
    ca = MLDSACertificate(MLDSA65)
    ca_cert, ca_pk, ca_sk = ca.create_self_signed_ca("My Root CA")

    print(f"CA Certificate created:")
    print(f"  Algorithm: {ca_cert['certificate']['signature_algorithm']}")
    print(f"  Subject: {ca_cert['certificate']['subject']['CN']}")
    print(f"  Valid until: {ca_cert['certificate']['validity']['not_after']}")

    # Verify CA certificate (self-signed)
    valid = ca.verify_certificate(ca_cert, ca_pk)
    print(f"  Self-signature valid: {valid}\n")

    # Create end-entity certificate
    entity = MLDSACertificate(MLDSA44)  # ML-DSA-44 for end entities
    entity_pk, entity_sk = entity.generate_keypair()

    # CA signs the entity certificate
    entity_cert = ca.create_certificate(
        subject={
            "CN": "api.example.com",
            "O": "Example Corp",
            "CA": False
        },
        public_key=entity_pk,
        issuer_sk=ca_sk,
        issuer_name="My Root CA",
        validity_days=365
    )

    print(f"Entity Certificate created:")
    print(f"  Subject: {entity_cert['certificate']['subject']['CN']}")
    print(f"  Issuer: {entity_cert['certificate']['issuer']}")

    # Verify entity certificate with CA public key
    valid = ca.verify_certificate(entity_cert, ca_pk)
    print(f"  Signature valid: {valid}\n")

    # Use entity certificate to sign a message
    message = b"API request: GET /users/123"
    signature = entity.dsa.sign(entity_sk, message)

    # Verify using public key from certificate
    extracted_pk = base64.b64decode(
        entity_cert['certificate']['public_key']['key']
    )
    valid = entity.dsa.verify(extracted_pk, message, signature)
    print(f"Message signature valid: {valid}")


if __name__ == "__main__":
    demo_mldsa_certificate()
```

#### C++ Example

```cpp
#include "mldsa/mldsa.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>

using namespace mldsa;

/**
 * Simple certificate structure for ML-DSA
 */
struct MLDSACertificate {
    std::string subject_cn;
    std::string issuer_cn;
    std::string algorithm;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> signature;
    time_t not_before;
    time_t not_after;
    bool is_ca;

    // Serialize certificate data for signing
    std::vector<uint8_t> to_bytes() const {
        std::ostringstream oss;
        oss << subject_cn << "|" << issuer_cn << "|" << algorithm << "|";
        oss << not_before << "|" << not_after << "|" << is_ca << "|";
        for (auto b : public_key) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        std::string s = oss.str();
        return std::vector<uint8_t>(s.begin(), s.end());
    }
};

template<typename DSA>
class CertificateAuthority {
public:
    CertificateAuthority(const std::string& name) : name_(name) {
        // Generate CA key pair
        auto [pk, sk] = dsa_.keygen();
        ca_pk_ = pk;
        ca_sk_ = sk;

        // Create self-signed CA certificate
        ca_cert_.subject_cn = name;
        ca_cert_.issuer_cn = name;
        ca_cert_.algorithm = dsa_.params().name;
        ca_cert_.public_key = pk;
        ca_cert_.is_ca = true;
        ca_cert_.not_before = time(nullptr);
        ca_cert_.not_after = ca_cert_.not_before + (10 * 365 * 24 * 3600); // 10 years

        // Self-sign
        auto tbs = ca_cert_.to_bytes();
        ca_cert_.signature = dsa_.sign(sk, tbs);
    }

    // Issue a certificate for an entity
    MLDSACertificate issue_certificate(
        const std::string& subject_cn,
        const std::vector<uint8_t>& subject_pk,
        int validity_days = 365,
        bool is_ca = false
    ) {
        MLDSACertificate cert;
        cert.subject_cn = subject_cn;
        cert.issuer_cn = name_;
        cert.algorithm = dsa_.params().name;
        cert.public_key = subject_pk;
        cert.is_ca = is_ca;
        cert.not_before = time(nullptr);
        cert.not_after = cert.not_before + (validity_days * 24 * 3600);

        // Sign with CA key
        auto tbs = cert.to_bytes();
        cert.signature = dsa_.sign(ca_sk_, tbs);

        return cert;
    }

    // Verify a certificate issued by this CA
    bool verify_certificate(const MLDSACertificate& cert) const {
        auto tbs = cert.to_bytes();
        return dsa_.verify(ca_pk_, tbs, cert.signature);
    }

    const MLDSACertificate& ca_certificate() const { return ca_cert_; }
    const std::vector<uint8_t>& public_key() const { return ca_pk_; }

private:
    DSA dsa_;
    std::string name_;
    std::vector<uint8_t> ca_pk_;
    std::vector<uint8_t> ca_sk_;
    MLDSACertificate ca_cert_;
};

int main() {
    std::cout << "=== ML-DSA Certificate Demo (C++) ===" << std::endl;

    // Create CA with ML-DSA-65
    CertificateAuthority<MLDSA65> ca("My Root CA");
    std::cout << "\nCA created: " << ca.ca_certificate().subject_cn << std::endl;
    std::cout << "Algorithm: ML-DSA-65" << std::endl;

    // Generate entity key pair
    MLDSA44 entity_dsa;
    auto [entity_pk, entity_sk] = entity_dsa.keygen();

    // CA issues certificate for entity
    auto entity_cert = ca.issue_certificate("api.example.com", entity_pk);
    std::cout << "\nEntity certificate issued for: " << entity_cert.subject_cn << std::endl;

    // Verify certificate
    bool valid = ca.verify_certificate(entity_cert);
    std::cout << "Certificate valid: " << (valid ? "YES" : "NO") << std::endl;

    // Use entity certificate to sign a message
    std::string message = "API request: GET /users/123";
    std::vector<uint8_t> msg(message.begin(), message.end());
    auto signature = entity_dsa.sign(entity_sk, msg);

    // Verify message signature using certificate's public key
    valid = entity_dsa.verify(entity_cert.public_key, msg, signature);
    std::cout << "Message signature valid: " << (valid ? "YES" : "NO") << std::endl;

    return 0;
}
```

---

## SLH-DSA Certificates (FIPS 205)

### Creating an SLH-DSA Certificate

#### Python Example

```python
from dsa import (
    slh_keygen, slh_sign, slh_verify,
    SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_256s
)
import hashlib
import json
import base64
from datetime import datetime, timedelta

class SLHDSACertificate:
    """Certificate using SLH-DSA (hash-based signatures)."""

    def __init__(self, params=SLH_DSA_SHAKE_128f):
        self.params = params

    def generate_keypair(self):
        """Generate a new key pair."""
        return slh_keygen(self.params)

    def create_certificate(self, subject: dict, public_key: bytes,
                          issuer_sk: bytes, issuer_name: str,
                          issuer_params=None,
                          validity_years: int = 10) -> dict:
        """
        Create a signed certificate.

        Note: SLH-DSA certificates typically have longer validity
        due to their conservative security assumptions.
        """
        if issuer_params is None:
            issuer_params = self.params

        now = datetime.utcnow()

        cert_data = {
            "version": 3,
            "serial_number": hashlib.sha256(
                public_key + str(now.timestamp()).encode()
            ).hexdigest()[:32],
            "signature_algorithm": f"SLH-DSA-{issuer_params.name}",
            "issuer": issuer_name,
            "validity": {
                "not_before": now.isoformat(),
                "not_after": (now + timedelta(days=validity_years * 365)).isoformat()
            },
            "subject": subject,
            "public_key": {
                "algorithm": f"SLH-DSA-{self.params.name}",
                "key": base64.b64encode(public_key).decode()
            }
        }

        tbs_bytes = json.dumps(cert_data, sort_keys=True).encode()
        signature = slh_sign(issuer_params, tbs_bytes, issuer_sk)

        return {
            "certificate": cert_data,
            "signature": base64.b64encode(signature).decode()
        }

    def verify_certificate(self, cert: dict, issuer_pk: bytes,
                          issuer_params=None) -> bool:
        """Verify a certificate's signature."""
        if issuer_params is None:
            # Extract from certificate
            algo = cert["certificate"]["signature_algorithm"]
            issuer_params = self._get_params_from_name(algo)

        tbs_bytes = json.dumps(cert["certificate"], sort_keys=True).encode()
        signature = base64.b64decode(cert["signature"])
        return slh_verify(issuer_params, tbs_bytes, signature, issuer_pk)

    def _get_params_from_name(self, name):
        params_map = {
            "SLH-DSA-SHAKE-128f": SLH_DSA_SHAKE_128f,
            "SLH-DSA-SHAKE-128s": SLH_DSA_SHAKE_128s,
            "SLH-DSA-SHAKE-192f": SLH_DSA_SHAKE_192f,
            "SLH-DSA-SHAKE-256s": SLH_DSA_SHAKE_256s,
        }
        return params_map.get(name, SLH_DSA_SHAKE_128f)

    def create_root_ca(self, ca_name: str, params=None) -> tuple:
        """
        Create a self-signed root CA certificate.

        For root CAs, use SLH-DSA-256s for maximum security.

        Returns:
            Tuple of (certificate, public_key, secret_key)
        """
        if params is None:
            params = SLH_DSA_SHAKE_256s  # Maximum security for root CA

        sk, pk = slh_keygen(params)

        subject = {
            "CN": ca_name,
            "O": "Root Certificate Authority",
            "CA": True,
            "pathLen": 2  # Can sign intermediate CAs
        }

        now = datetime.utcnow()
        cert_data = {
            "version": 3,
            "serial_number": "00000001",
            "signature_algorithm": f"SLH-DSA-{params.name}",
            "issuer": ca_name,
            "validity": {
                "not_before": now.isoformat(),
                "not_after": (now + timedelta(days=30 * 365)).isoformat()  # 30 years
            },
            "subject": subject,
            "public_key": {
                "algorithm": f"SLH-DSA-{params.name}",
                "key": base64.b64encode(pk).decode()
            }
        }

        tbs_bytes = json.dumps(cert_data, sort_keys=True).encode()
        signature = slh_sign(params, tbs_bytes, sk)

        cert = {
            "certificate": cert_data,
            "signature": base64.b64encode(signature).decode()
        }

        return cert, pk, sk, params


# Usage Example
def demo_slhdsa_certificate():
    print("=== SLH-DSA Certificate Demo ===\n")

    # Create Root CA with SLH-DSA-256s (maximum security)
    print("Creating Root CA with SLH-DSA-SHAKE-256s...")
    print("(This may take a few seconds due to hash-based signing)\n")

    ca = SLHDSACertificate()
    ca_cert, ca_pk, ca_sk, ca_params = ca.create_root_ca("Global Root CA")

    print(f"Root CA Certificate created:")
    print(f"  Algorithm: {ca_cert['certificate']['signature_algorithm']}")
    print(f"  Subject: {ca_cert['certificate']['subject']['CN']}")
    print(f"  Valid until: {ca_cert['certificate']['validity']['not_after']}")
    print(f"  Public key size: {len(ca_pk)} bytes")
    print(f"  Signature size: {len(base64.b64decode(ca_cert['signature']))} bytes")

    # Create intermediate CA with SLH-DSA-192f
    print("\nCreating Intermediate CA with SLH-DSA-SHAKE-192f...")
    intermediate = SLHDSACertificate(SLH_DSA_SHAKE_192f)
    int_sk, int_pk = intermediate.generate_keypair()

    int_cert = SLHDSACertificate(SLH_DSA_SHAKE_192f).create_certificate(
        subject={
            "CN": "Intermediate CA",
            "O": "Certificate Authority",
            "CA": True,
            "pathLen": 1
        },
        public_key=int_pk,
        issuer_sk=ca_sk,
        issuer_name="Global Root CA",
        issuer_params=ca_params,
        validity_years=15
    )

    print(f"Intermediate CA Certificate created:")
    print(f"  Subject: {int_cert['certificate']['subject']['CN']}")
    print(f"  Issuer: {int_cert['certificate']['issuer']}")

    # Create end-entity certificate for code signing
    print("\nCreating Code Signing Certificate with SLH-DSA-SHAKE-128f...")
    code_signer = SLHDSACertificate(SLH_DSA_SHAKE_128f)
    cs_sk, cs_pk = code_signer.generate_keypair()

    cs_cert = code_signer.create_certificate(
        subject={
            "CN": "Code Signing Certificate",
            "O": "Software Vendor Inc",
            "CA": False,
            "keyUsage": ["digitalSignature", "codeSigning"]
        },
        public_key=cs_pk,
        issuer_sk=int_sk,
        issuer_name="Intermediate CA",
        issuer_params=SLH_DSA_SHAKE_192f,
        validity_years=3
    )

    print(f"Code Signing Certificate created:")
    print(f"  Subject: {cs_cert['certificate']['subject']['CN']}")

    # Sign some code/firmware
    firmware = b"FIRMWARE_v1.2.3: " + bytes(1000)  # Simulated firmware
    print(f"\nSigning firmware ({len(firmware)} bytes)...")

    firmware_sig = slh_sign(SLH_DSA_SHAKE_128f, firmware, cs_sk)
    print(f"  Signature size: {len(firmware_sig)} bytes")

    # Verify the signature
    valid = slh_verify(SLH_DSA_SHAKE_128f, firmware, firmware_sig, cs_pk)
    print(f"  Firmware signature valid: {valid}")


if __name__ == "__main__":
    demo_slhdsa_certificate()
```

#### C++ Example

```cpp
#include "slhdsa/slh_dsa.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <chrono>

using namespace slhdsa;

/**
 * Certificate structure for SLH-DSA
 */
struct SLHDSACertificate {
    std::string subject_cn;
    std::string issuer_cn;
    std::string algorithm;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> signature;
    time_t not_before;
    time_t not_after;
    bool is_ca;

    std::vector<uint8_t> to_bytes() const {
        std::ostringstream oss;
        oss << subject_cn << "|" << issuer_cn << "|" << algorithm << "|";
        oss << not_before << "|" << not_after << "|" << is_ca << "|";
        for (auto b : public_key) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        std::string s = oss.str();
        return std::vector<uint8_t>(s.begin(), s.end());
    }
};

template<typename DSA>
class SLHDSACertificateAuthority {
public:
    SLHDSACertificateAuthority(const std::string& name) : name_(name) {
        std::cout << "Generating CA key pair (this may take a moment)..." << std::endl;

        auto start = std::chrono::high_resolution_clock::now();
        auto [sk, pk] = dsa_.keygen();
        auto end = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "KeyGen completed in " << ms << " ms" << std::endl;

        ca_pk_ = pk;
        ca_sk_ = sk;

        // Create self-signed CA certificate
        ca_cert_.subject_cn = name;
        ca_cert_.issuer_cn = name;
        ca_cert_.algorithm = dsa_.params().name;
        ca_cert_.public_key = pk;
        ca_cert_.is_ca = true;
        ca_cert_.not_before = time(nullptr);
        ca_cert_.not_after = ca_cert_.not_before + (30L * 365 * 24 * 3600); // 30 years

        // Self-sign
        auto tbs = ca_cert_.to_bytes();
        ca_cert_.signature = dsa_.sign(sk, tbs);
    }

    template<typename EntityDSA>
    SLHDSACertificate issue_certificate(
        const std::string& subject_cn,
        const std::vector<uint8_t>& subject_pk,
        const std::string& subject_algo,
        int validity_years = 10,
        bool is_ca = false
    ) {
        SLHDSACertificate cert;
        cert.subject_cn = subject_cn;
        cert.issuer_cn = name_;
        cert.algorithm = subject_algo;
        cert.public_key = subject_pk;
        cert.is_ca = is_ca;
        cert.not_before = time(nullptr);
        cert.not_after = cert.not_before + (validity_years * 365L * 24 * 3600);

        auto tbs = cert.to_bytes();
        cert.signature = dsa_.sign(ca_sk_, tbs);

        return cert;
    }

    bool verify_certificate(const SLHDSACertificate& cert) const {
        auto tbs = cert.to_bytes();
        return dsa_.verify(ca_pk_, tbs, cert.signature);
    }

    const SLHDSACertificate& ca_certificate() const { return ca_cert_; }
    const std::vector<uint8_t>& public_key() const { return ca_pk_; }
    const std::vector<uint8_t>& secret_key() const { return ca_sk_; }

private:
    DSA dsa_;
    std::string name_;
    std::vector<uint8_t> ca_pk_;
    std::vector<uint8_t> ca_sk_;
    SLHDSACertificate ca_cert_;
};

int main() {
    std::cout << "=== SLH-DSA Certificate Demo (C++) ===" << std::endl;
    std::cout << "\nNote: SLH-DSA operations are slower but provide" << std::endl;
    std::cout << "security based only on hash functions.\n" << std::endl;

    // Create Root CA with SLH-DSA-SHAKE-128f (faster variant for demo)
    std::cout << "Creating Root CA with SLH-DSA-SHAKE-128f..." << std::endl;
    SLHDSACertificateAuthority<SLHDSA_SHAKE_128f> ca("Root CA");

    std::cout << "\nCA Certificate:" << std::endl;
    std::cout << "  Subject: " << ca.ca_certificate().subject_cn << std::endl;
    std::cout << "  PK size: " << ca.ca_certificate().public_key.size() << " bytes" << std::endl;
    std::cout << "  Signature size: " << ca.ca_certificate().signature.size() << " bytes" << std::endl;

    // Generate entity key pair
    std::cout << "\nGenerating code signing key pair..." << std::endl;
    SLHDSA_SHAKE_128f entity_dsa;
    auto [entity_sk, entity_pk] = entity_dsa.keygen();

    // Issue certificate
    auto entity_cert = ca.issue_certificate<SLHDSA_SHAKE_128f>(
        "Code Signing Cert",
        entity_pk,
        "SLH-DSA-SHAKE-128f",
        5,    // 5 years
        false // not a CA
    );

    std::cout << "\nEntity Certificate issued:" << std::endl;
    std::cout << "  Subject: " << entity_cert.subject_cn << std::endl;
    std::cout << "  Issuer: " << entity_cert.issuer_cn << std::endl;

    // Verify certificate
    bool valid = ca.verify_certificate(entity_cert);
    std::cout << "  Certificate valid: " << (valid ? "YES" : "NO") << std::endl;

    // Sign firmware
    std::cout << "\nSigning firmware..." << std::endl;
    std::vector<uint8_t> firmware(10000, 0x42); // Simulated firmware

    auto start = std::chrono::high_resolution_clock::now();
    auto fw_sig = entity_dsa.sign(entity_sk, firmware);
    auto end = std::chrono::high_resolution_clock::now();
    auto sign_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "  Firmware size: " << firmware.size() << " bytes" << std::endl;
    std::cout << "  Signature size: " << fw_sig.size() << " bytes" << std::endl;
    std::cout << "  Sign time: " << sign_ms << " ms" << std::endl;

    // Verify firmware signature
    start = std::chrono::high_resolution_clock::now();
    valid = entity_dsa.verify(entity_pk, firmware, fw_sig);
    end = std::chrono::high_resolution_clock::now();
    auto verify_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "  Signature valid: " << (valid ? "YES" : "NO") << std::endl;
    std::cout << "  Verify time: " << verify_ms << " ms" << std::endl;

    return 0;
}
```

---

## Use Case Examples

### Use Case 1: TLS Server Certificate (ML-DSA)

**Scenario:** HTTPS web server authentication

**Why ML-DSA:** Fast handshakes, reasonable certificate sizes

```python
from dsa import MLDSA65
import json
import base64

class TLSCertificateManager:
    """Manage TLS certificates with ML-DSA."""

    def __init__(self):
        self.dsa = MLDSA65()

    def create_server_certificate(self, domain: str, ca_sk: bytes, ca_name: str) -> dict:
        """Create a TLS server certificate."""
        pk, sk = self.dsa.keygen()

        cert_data = {
            "subject": {
                "CN": domain,
                "SAN": [domain, f"www.{domain}"]  # Subject Alternative Names
            },
            "key_usage": ["digitalSignature", "keyEncipherment"],
            "extended_key_usage": ["serverAuth"],
            "public_key": base64.b64encode(pk).decode()
        }

        tbs = json.dumps(cert_data, sort_keys=True).encode()
        signature = self.dsa.sign(ca_sk, tbs)

        return {
            "certificate": cert_data,
            "signature": base64.b64encode(signature).decode(),
            "private_key": sk  # Store securely!
        }

    def tls_handshake_sign(self, handshake_data: bytes, server_sk: bytes) -> bytes:
        """Sign TLS handshake messages."""
        return self.dsa.sign(server_sk, handshake_data)

    def tls_handshake_verify(self, handshake_data: bytes,
                             signature: bytes, server_pk: bytes) -> bool:
        """Verify TLS handshake signature."""
        return self.dsa.verify(server_pk, handshake_data, signature)


# Usage
def demo_tls():
    print("=== TLS Certificate with ML-DSA ===\n")

    # CA setup
    mgr = TLSCertificateManager()
    ca_pk, ca_sk = mgr.dsa.keygen()

    # Create server certificate
    server_cert = mgr.create_server_certificate(
        domain="api.example.com",
        ca_sk=ca_sk,
        ca_name="Example CA"
    )

    print(f"Server certificate created for: {server_cert['certificate']['subject']['CN']}")
    print(f"Public key size: {len(base64.b64decode(server_cert['certificate']['public_key']))} bytes")

    # Simulate TLS handshake
    handshake_data = b"ClientHello|ServerHello|Certificate|..."
    server_sk = server_cert['private_key']
    server_pk = base64.b64decode(server_cert['certificate']['public_key'])

    # Server signs handshake
    sig = mgr.tls_handshake_sign(handshake_data, server_sk)
    print(f"\nHandshake signature size: {len(sig)} bytes")

    # Client verifies
    valid = mgr.tls_handshake_verify(handshake_data, sig, server_pk)
    print(f"Handshake verified: {valid}")
```

### Use Case 2: Code Signing (SLH-DSA)

**Scenario:** Sign software releases and firmware updates

**Why SLH-DSA:** Long-term validity (decades), conservative security

```python
from dsa import slh_keygen, slh_sign, slh_verify, SLH_DSA_SHAKE_128f
import hashlib
import json
import time

class CodeSigningService:
    """Sign and verify software with SLH-DSA."""

    def __init__(self, params=SLH_DSA_SHAKE_128f):
        self.params = params

    def create_signing_key(self) -> tuple:
        """Generate code signing key pair."""
        return slh_keygen(self.params)

    def sign_software(self, binary_data: bytes, sk: bytes,
                      metadata: dict = None) -> dict:
        """
        Sign a software binary.

        Returns a detached signature package.
        """
        # Compute hash of binary (for efficiency)
        binary_hash = hashlib.sha3_256(binary_data).digest()

        # Create signature payload
        payload = {
            "hash_algorithm": "SHA3-256",
            "binary_hash": binary_hash.hex(),
            "binary_size": len(binary_data),
            "timestamp": int(time.time()),
            "metadata": metadata or {}
        }

        payload_bytes = json.dumps(payload, sort_keys=True).encode()
        signature = slh_sign(self.params, payload_bytes, sk)

        return {
            "payload": payload,
            "signature": signature.hex(),
            "algorithm": f"SLH-DSA-{self.params.name}"
        }

    def verify_software(self, binary_data: bytes,
                        sig_package: dict, pk: bytes) -> tuple:
        """
        Verify a signed software binary.

        Returns (is_valid, error_message).
        """
        # Verify hash matches
        computed_hash = hashlib.sha3_256(binary_data).hexdigest()
        if computed_hash != sig_package["payload"]["binary_hash"]:
            return False, "Binary hash mismatch"

        # Verify signature
        payload_bytes = json.dumps(sig_package["payload"], sort_keys=True).encode()
        signature = bytes.fromhex(sig_package["signature"])

        if slh_verify(self.params, payload_bytes, signature, pk):
            return True, "Signature valid"
        else:
            return False, "Signature verification failed"


# Usage
def demo_code_signing():
    print("=== Code Signing with SLH-DSA ===\n")

    signer = CodeSigningService()

    # Generate signing keys (do this once, store securely)
    print("Generating signing key pair...")
    sk, pk = signer.create_signing_key()
    print(f"Public key size: {len(pk)} bytes (distribute this)")
    print(f"Secret key size: {len(sk)} bytes (keep secure!)\n")

    # Sign a software release
    software_binary = b"#!/bin/bash\necho 'Hello, World!'\n" * 1000
    print(f"Signing software ({len(software_binary)} bytes)...")

    start = time.time()
    sig_package = signer.sign_software(
        software_binary,
        sk,
        metadata={
            "version": "1.0.0",
            "product": "MyApp",
            "author": "Developer"
        }
    )
    sign_time = time.time() - start

    print(f"Signing completed in {sign_time*1000:.0f} ms")
    print(f"Signature size: {len(bytes.fromhex(sig_package['signature']))} bytes\n")

    # Verify the software
    print("Verifying software...")
    start = time.time()
    valid, message = signer.verify_software(software_binary, sig_package, pk)
    verify_time = time.time() - start

    print(f"Result: {message}")
    print(f"Verification time: {verify_time*1000:.0f} ms\n")

    # Test with tampered binary
    print("Testing with tampered binary...")
    tampered = software_binary + b"MALWARE"
    valid, message = signer.verify_software(tampered, sig_package, pk)
    print(f"Result: {message}")


if __name__ == "__main__":
    demo_code_signing()
```

### Use Case 3: Document Signing (SLH-DSA)

**Scenario:** Sign legal documents, contracts, certificates

**Why SLH-DSA:** Documents may need to be verified decades later

```python
from dsa import slh_keygen, slh_sign, slh_verify
from dsa import SLH_DSA_SHAKE_128s  # 's' variant for smaller signatures
import hashlib
import json
from datetime import datetime
import base64

class DocumentSigningService:
    """Sign and verify documents with SLH-DSA."""

    def __init__(self):
        # Use 128s for smaller signatures (important for document storage)
        self.params = SLH_DSA_SHAKE_128s

    def sign_document(self, document: bytes, signer_sk: bytes,
                      signer_info: dict) -> dict:
        """
        Create a signed document package.

        Similar to PDF digital signatures or CAdES.
        """
        doc_hash = hashlib.sha3_256(document).digest()

        signed_attrs = {
            "content_type": "application/octet-stream",
            "message_digest": base64.b64encode(doc_hash).decode(),
            "signing_time": datetime.utcnow().isoformat(),
            "signer": signer_info,
        }

        # Sign the signed attributes
        attrs_bytes = json.dumps(signed_attrs, sort_keys=True).encode()
        signature = slh_sign(self.params, attrs_bytes, signer_sk)

        return {
            "signed_attributes": signed_attrs,
            "signature_algorithm": f"SLH-DSA-{self.params.name}",
            "signature": base64.b64encode(signature).decode()
        }

    def verify_document(self, document: bytes, sig_info: dict,
                        signer_pk: bytes) -> dict:
        """
        Verify a signed document.

        Returns verification result with details.
        """
        result = {
            "valid": False,
            "signer": sig_info["signed_attributes"].get("signer", {}),
            "signing_time": sig_info["signed_attributes"].get("signing_time"),
            "errors": []
        }

        # Verify document hash
        doc_hash = hashlib.sha3_256(document).digest()
        stored_hash = base64.b64decode(
            sig_info["signed_attributes"]["message_digest"]
        )

        if doc_hash != stored_hash:
            result["errors"].append("Document has been modified")
            return result

        # Verify signature
        attrs_bytes = json.dumps(
            sig_info["signed_attributes"],
            sort_keys=True
        ).encode()
        signature = base64.b64decode(sig_info["signature"])

        if slh_verify(self.params, attrs_bytes, signature, signer_pk):
            result["valid"] = True
        else:
            result["errors"].append("Signature verification failed")

        return result


# Usage
def demo_document_signing():
    print("=== Document Signing with SLH-DSA ===\n")

    service = DocumentSigningService()

    # Generate signer's key pair
    sk, pk = slh_keygen(service.params)
    print(f"Using SLH-DSA-SHAKE-128s (smaller signatures)")
    print(f"Public key: {len(pk)} bytes")

    # Create a document
    contract = """
    AGREEMENT

    This agreement is made between Party A and Party B...

    Terms and conditions apply.

    Signed electronically.
    """.encode()

    print(f"\nDocument size: {len(contract)} bytes")

    # Sign the document
    print("\nSigning document...")
    sig_info = service.sign_document(
        contract,
        sk,
        signer_info={
            "name": "John Doe",
            "email": "john@example.com",
            "organization": "Example Corp"
        }
    )

    sig_size = len(base64.b64decode(sig_info["signature"]))
    print(f"Signature size: {sig_size} bytes")
    print(f"Signing time: {sig_info['signed_attributes']['signing_time']}")

    # Verify the document
    print("\nVerifying document...")
    result = service.verify_document(contract, sig_info, pk)

    print(f"Valid: {result['valid']}")
    print(f"Signer: {result['signer']['name']}")
    print(f"Signed at: {result['signing_time']}")

    # Test with modified document
    print("\n--- Testing with modified document ---")
    modified = contract + b"\nUNAUTHORIZED ADDITION"
    result = service.verify_document(modified, sig_info, pk)
    print(f"Valid: {result['valid']}")
    print(f"Errors: {result['errors']}")


if __name__ == "__main__":
    demo_document_signing()
```

### Use Case 4: API Authentication (ML-DSA)

**Scenario:** Authenticate API requests between services

**Why ML-DSA:** High-frequency requests need fast signing/verification

```python
from dsa import MLDSA44
import hashlib
import hmac
import time
import json
import base64

class APIAuthenticator:
    """API request authentication using ML-DSA signatures."""

    def __init__(self):
        self.dsa = MLDSA44()  # Fastest variant

    def generate_api_keys(self) -> dict:
        """Generate API key pair for a service."""
        pk, sk = self.dsa.keygen()

        # Create API key ID from public key hash
        key_id = hashlib.sha256(pk).hexdigest()[:16]

        return {
            "key_id": key_id,
            "public_key": base64.b64encode(pk).decode(),
            "secret_key": base64.b64encode(sk).decode()
        }

    def sign_request(self, method: str, path: str, body: bytes,
                     secret_key: str, key_id: str) -> dict:
        """
        Sign an API request.

        Returns headers to include in the request.
        """
        timestamp = str(int(time.time()))

        # Canonical request string
        body_hash = hashlib.sha256(body).hexdigest() if body else ""
        canonical = f"{method}\n{path}\n{timestamp}\n{body_hash}"

        # Sign
        sk = base64.b64decode(secret_key)
        signature = self.dsa.sign(sk, canonical.encode())

        return {
            "X-API-Key": key_id,
            "X-API-Timestamp": timestamp,
            "X-API-Signature": base64.b64encode(signature).decode()
        }

    def verify_request(self, method: str, path: str, body: bytes,
                       headers: dict, public_key: str,
                       max_age_seconds: int = 300) -> tuple:
        """
        Verify an API request signature.

        Returns (is_valid, error_message).
        """
        try:
            timestamp = int(headers.get("X-API-Timestamp", "0"))
            signature = base64.b64decode(headers.get("X-API-Signature", ""))

            # Check timestamp
            now = int(time.time())
            if abs(now - timestamp) > max_age_seconds:
                return False, "Request expired"

            # Rebuild canonical request
            body_hash = hashlib.sha256(body).hexdigest() if body else ""
            canonical = f"{method}\n{path}\n{timestamp}\n{body_hash}"

            # Verify signature
            pk = base64.b64decode(public_key)
            if self.dsa.verify(pk, canonical.encode(), signature):
                return True, "Valid"
            else:
                return False, "Invalid signature"

        except Exception as e:
            return False, f"Verification error: {str(e)}"


# Usage
def demo_api_auth():
    print("=== API Authentication with ML-DSA ===\n")

    auth = APIAuthenticator()

    # Service A generates API keys
    service_a_keys = auth.generate_api_keys()
    print(f"Service A API Key ID: {service_a_keys['key_id']}")
    print(f"Public key size: {len(base64.b64decode(service_a_keys['public_key']))} bytes")

    # Service B stores Service A's public key (key registry)
    key_registry = {
        service_a_keys['key_id']: service_a_keys['public_key']
    }

    # Service A makes an API request
    print("\n--- Service A sends request ---")
    request_body = json.dumps({"action": "create_user", "name": "Alice"}).encode()

    start = time.time()
    headers = auth.sign_request(
        method="POST",
        path="/api/users",
        body=request_body,
        secret_key=service_a_keys['secret_key'],
        key_id=service_a_keys['key_id']
    )
    sign_time = (time.time() - start) * 1000

    print(f"Request signed in {sign_time:.2f} ms")
    print(f"Signature size: {len(base64.b64decode(headers['X-API-Signature']))} bytes")

    # Service B verifies the request
    print("\n--- Service B verifies request ---")
    key_id = headers['X-API-Key']
    public_key = key_registry.get(key_id)

    if not public_key:
        print("Unknown API key!")
    else:
        start = time.time()
        valid, message = auth.verify_request(
            method="POST",
            path="/api/users",
            body=request_body,
            headers=headers,
            public_key=public_key
        )
        verify_time = (time.time() - start) * 1000

        print(f"Verification result: {message}")
        print(f"Verified in {verify_time:.2f} ms")

    # Test replay attack
    print("\n--- Testing replay attack (wait 6 minutes) ---")
    # Simulate old request
    old_headers = headers.copy()
    old_headers['X-API-Timestamp'] = str(int(time.time()) - 400)  # 6+ minutes ago

    valid, message = auth.verify_request(
        method="POST",
        path="/api/users",
        body=request_body,
        headers=old_headers,
        public_key=public_key
    )
    print(f"Result: {message}")


if __name__ == "__main__":
    demo_api_auth()
```

### Use Case 5: IoT Device Authentication (ML-DSA)

**Scenario:** Authenticate IoT devices and their messages

**Why ML-DSA:** Constrained devices, frequent communication

```python
from dsa import MLDSA44
import hashlib
import json
import base64
import time

class IoTDeviceManager:
    """Manage IoT device certificates and message authentication."""

    def __init__(self):
        self.dsa = MLDSA44()  # Smallest, fastest variant
        self.device_registry = {}  # device_id -> public_key

    def provision_device(self, device_id: str) -> dict:
        """
        Provision a new IoT device.

        Returns credentials to be stored on the device.
        """
        pk, sk = self.dsa.keygen()

        # Store public key in registry
        self.device_registry[device_id] = pk

        # Return credentials for device
        return {
            "device_id": device_id,
            "secret_key": base64.b64encode(sk).decode(),
            "public_key_fingerprint": hashlib.sha256(pk).hexdigest()[:16]
        }

    def create_device_message(self, device_id: str, secret_key: str,
                              sensor_data: dict) -> dict:
        """Create a signed message from an IoT device."""
        message = {
            "device_id": device_id,
            "timestamp": int(time.time()),
            "data": sensor_data
        }

        message_bytes = json.dumps(message, sort_keys=True).encode()
        sk = base64.b64decode(secret_key)
        signature = self.dsa.sign(sk, message_bytes)

        return {
            "message": message,
            "signature": base64.b64encode(signature).decode()
        }

    def verify_device_message(self, signed_message: dict) -> tuple:
        """
        Verify a message from an IoT device.

        Returns (is_valid, device_id, data).
        """
        device_id = signed_message["message"]["device_id"]

        # Look up device public key
        pk = self.device_registry.get(device_id)
        if not pk:
            return False, device_id, None

        # Verify signature
        message_bytes = json.dumps(
            signed_message["message"],
            sort_keys=True
        ).encode()
        signature = base64.b64decode(signed_message["signature"])

        if self.dsa.verify(pk, message_bytes, signature):
            return True, device_id, signed_message["message"]["data"]
        else:
            return False, device_id, None


# Usage
def demo_iot():
    print("=== IoT Device Authentication with ML-DSA ===\n")

    manager = IoTDeviceManager()

    # Provision devices
    print("Provisioning devices...")
    device1 = manager.provision_device("sensor-001")
    device2 = manager.provision_device("sensor-002")

    print(f"Device 1 ID: {device1['device_id']}")
    print(f"Device 2 ID: {device2['device_id']}")
    print(f"Secret key size: {len(base64.b64decode(device1['secret_key']))} bytes")

    # Device 1 sends temperature reading
    print("\n--- Device 1 sends data ---")
    start = time.time()
    msg1 = manager.create_device_message(
        device_id=device1['device_id'],
        secret_key=device1['secret_key'],
        sensor_data={
            "temperature": 23.5,
            "humidity": 45.2,
            "battery": 87
        }
    )
    sign_time = (time.time() - start) * 1000

    print(f"Message signed in {sign_time:.2f} ms")
    print(f"Signature size: {len(base64.b64decode(msg1['signature']))} bytes")

    # Server verifies message
    print("\n--- Server verifies message ---")
    start = time.time()
    valid, device_id, data = manager.verify_device_message(msg1)
    verify_time = (time.time() - start) * 1000

    print(f"Valid: {valid}")
    print(f"Device: {device_id}")
    print(f"Data: {data}")
    print(f"Verified in {verify_time:.2f} ms")

    # Test spoofed message (wrong signature)
    print("\n--- Testing spoofed message ---")
    spoofed = msg1.copy()
    spoofed["message"] = msg1["message"].copy()
    spoofed["message"]["data"]["temperature"] = 100.0  # Tampered!

    valid, device_id, data = manager.verify_device_message(spoofed)
    print(f"Valid: {valid} (tampering detected)")


if __name__ == "__main__":
    demo_iot()
```

---

## Certificate Chain Examples

### Example: Complete PKI Hierarchy

```
Root CA (SLH-DSA-256s)           ← Maximum security, 30-year validity
    │
    ├── Intermediate CA (SLH-DSA-192f)  ← Balance of security/performance
    │       │
    │       ├── TLS Server Cert (ML-DSA-65)   ← Fast TLS handshakes
    │       ├── Code Signing Cert (SLH-DSA-128f) ← Long-term code validity
    │       └── Client Auth Cert (ML-DSA-44)  ← Fast client auth
    │
    └── Policy CA (ML-DSA-87)    ← High security, operational CA
            │
            ├── Employee Certs (ML-DSA-44)  ← Fast, high volume
            └── Device Certs (ML-DSA-44)    ← IoT devices
```

### Python Implementation

```python
from dsa import MLDSA44, MLDSA65, MLDSA87
from dsa import slh_keygen, slh_sign, slh_verify
from dsa import SLH_DSA_SHAKE_128f, SLH_DSA_SHAKE_192f, SLH_DSA_SHAKE_256s
import json
import base64
from datetime import datetime, timedelta

class PKIHierarchy:
    """Complete PKI with post-quantum algorithms."""

    def __init__(self):
        self.certificates = {}
        self.keys = {}

    def create_root_ca(self, name: str) -> str:
        """Create root CA with SLH-DSA-256s."""
        params = SLH_DSA_SHAKE_256s
        sk, pk = slh_keygen(params)

        cert_id = f"root-{name}"
        self.keys[cert_id] = {"sk": sk, "pk": pk, "params": params, "type": "slh"}

        cert = {
            "id": cert_id,
            "subject": {"CN": name, "CA": True},
            "issuer": name,
            "algorithm": "SLH-DSA-SHAKE-256s",
            "public_key": base64.b64encode(pk).decode(),
            "validity": {
                "years": 30
            }
        }

        # Self-sign
        tbs = json.dumps(cert, sort_keys=True).encode()
        sig = slh_sign(params, tbs, sk)

        self.certificates[cert_id] = {
            "certificate": cert,
            "signature": base64.b64encode(sig).decode()
        }

        return cert_id

    def create_intermediate_ca(self, name: str, issuer_id: str) -> str:
        """Create intermediate CA with SLH-DSA-192f."""
        params = SLH_DSA_SHAKE_192f
        sk, pk = slh_keygen(params)

        cert_id = f"int-{name}"
        self.keys[cert_id] = {"sk": sk, "pk": pk, "params": params, "type": "slh"}

        cert = {
            "id": cert_id,
            "subject": {"CN": name, "CA": True},
            "issuer": issuer_id,
            "algorithm": "SLH-DSA-SHAKE-192f",
            "public_key": base64.b64encode(pk).decode(),
            "validity": {"years": 15}
        }

        # Sign with issuer's key
        tbs = json.dumps(cert, sort_keys=True).encode()
        issuer_key = self.keys[issuer_id]
        sig = slh_sign(issuer_key["params"], tbs, issuer_key["sk"])

        self.certificates[cert_id] = {
            "certificate": cert,
            "signature": base64.b64encode(sig).decode()
        }

        return cert_id

    def create_tls_cert(self, domain: str, issuer_id: str) -> str:
        """Create TLS certificate with ML-DSA-65."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        cert_id = f"tls-{domain}"
        self.keys[cert_id] = {"sk": sk, "pk": pk, "dsa": dsa, "type": "ml"}

        cert = {
            "id": cert_id,
            "subject": {"CN": domain, "CA": False},
            "issuer": issuer_id,
            "algorithm": "ML-DSA-65",
            "public_key": base64.b64encode(pk).decode(),
            "key_usage": ["digitalSignature", "keyEncipherment"],
            "extended_key_usage": ["serverAuth"],
            "validity": {"years": 1}
        }

        # Sign with issuer's key
        tbs = json.dumps(cert, sort_keys=True).encode()
        issuer_key = self.keys[issuer_id]
        sig = slh_sign(issuer_key["params"], tbs, issuer_key["sk"])

        self.certificates[cert_id] = {
            "certificate": cert,
            "signature": base64.b64encode(sig).decode()
        }

        return cert_id

    def create_code_signing_cert(self, name: str, issuer_id: str) -> str:
        """Create code signing certificate with SLH-DSA-128f."""
        params = SLH_DSA_SHAKE_128f
        sk, pk = slh_keygen(params)

        cert_id = f"code-{name}"
        self.keys[cert_id] = {"sk": sk, "pk": pk, "params": params, "type": "slh"}

        cert = {
            "id": cert_id,
            "subject": {"CN": name, "CA": False},
            "issuer": issuer_id,
            "algorithm": "SLH-DSA-SHAKE-128f",
            "public_key": base64.b64encode(pk).decode(),
            "key_usage": ["digitalSignature"],
            "extended_key_usage": ["codeSigning"],
            "validity": {"years": 5}
        }

        tbs = json.dumps(cert, sort_keys=True).encode()
        issuer_key = self.keys[issuer_id]
        sig = slh_sign(issuer_key["params"], tbs, issuer_key["sk"])

        self.certificates[cert_id] = {
            "certificate": cert,
            "signature": base64.b64encode(sig).decode()
        }

        return cert_id

    def verify_chain(self, cert_id: str) -> list:
        """Verify certificate chain back to root."""
        chain = []
        current_id = cert_id

        while current_id:
            cert_data = self.certificates.get(current_id)
            if not cert_data:
                return [(current_id, False, "Certificate not found")]

            cert = cert_data["certificate"]
            issuer_id = cert["issuer"]

            # Self-signed (root)?
            if issuer_id == cert["subject"]["CN"]:
                # Verify self-signature
                issuer_key = self.keys[current_id]
                tbs = json.dumps(cert, sort_keys=True).encode()
                sig = base64.b64decode(cert_data["signature"])

                if issuer_key["type"] == "slh":
                    valid = slh_verify(issuer_key["params"], tbs, sig, issuer_key["pk"])
                else:
                    valid = issuer_key["dsa"].verify(issuer_key["pk"], tbs, sig)

                chain.append((current_id, valid, "Root CA"))
                break
            else:
                # Verify with issuer's key
                issuer_key = self.keys.get(issuer_id)
                if not issuer_key:
                    chain.append((current_id, False, "Issuer not found"))
                    break

                tbs = json.dumps(cert, sort_keys=True).encode()
                sig = base64.b64decode(cert_data["signature"])

                if issuer_key["type"] == "slh":
                    valid = slh_verify(issuer_key["params"], tbs, sig, issuer_key["pk"])
                else:
                    valid = issuer_key["dsa"].verify(issuer_key["pk"], tbs, sig)

                chain.append((current_id, valid, f"Signed by {issuer_id}"))
                current_id = issuer_id

        return chain

    def print_hierarchy(self):
        """Print the certificate hierarchy."""
        print("\n=== PKI Hierarchy ===\n")
        for cert_id, cert_data in self.certificates.items():
            cert = cert_data["certificate"]
            indent = "  " if "root" in cert_id else "    " if "int" in cert_id else "      "
            ca = " (CA)" if cert["subject"].get("CA") else ""
            print(f"{indent}{cert['subject']['CN']}{ca}")
            print(f"{indent}  Algorithm: {cert['algorithm']}")
            print(f"{indent}  Validity: {cert['validity']['years']} years")


# Usage
def demo_pki():
    print("=== Post-Quantum PKI Hierarchy Demo ===\n")

    pki = PKIHierarchy()

    # Build hierarchy
    print("Building PKI hierarchy...")
    print("(This may take a moment due to SLH-DSA key generation)\n")

    root_id = pki.create_root_ca("Global Root CA")
    print(f"Created: {root_id}")

    int_id = pki.create_intermediate_ca("Intermediate CA", root_id)
    print(f"Created: {int_id}")

    tls_id = pki.create_tls_cert("api.example.com", int_id)
    print(f"Created: {tls_id}")

    code_id = pki.create_code_signing_cert("Code Signer", int_id)
    print(f"Created: {code_id}")

    pki.print_hierarchy()

    # Verify chains
    print("\n=== Verifying Certificate Chains ===\n")

    for cert_id in [tls_id, code_id]:
        print(f"Chain for {cert_id}:")
        chain = pki.verify_chain(cert_id)
        for cert, valid, info in chain:
            status = "OK" if valid else "FAILED"
            print(f"  [{status}] {cert} - {info}")
        print()


if __name__ == "__main__":
    demo_pki()
```

---

## Migration Strategies

### Hybrid Certificates (Transition Period)

During the transition to post-quantum cryptography, use hybrid certificates that contain both traditional and post-quantum signatures:

```python
from dsa import MLDSA65
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import json
import base64

class HybridCertificate:
    """
    Hybrid certificate with both ECDSA and ML-DSA signatures.

    Provides security even if one algorithm is broken.
    """

    def __init__(self):
        self.mldsa = MLDSA65()

    def create_hybrid_certificate(self, subject: dict) -> dict:
        """
        Create a certificate with both ECDSA and ML-DSA keys/signatures.
        """
        # Generate ECDSA key pair
        ecdsa_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ecdsa_public = ecdsa_private.public_key()
        ecdsa_public_bytes = ecdsa_public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Generate ML-DSA key pair
        mldsa_public, mldsa_private = self.mldsa.keygen()

        # Certificate data with both public keys
        cert_data = {
            "subject": subject,
            "public_keys": {
                "ecdsa_p256": base64.b64encode(ecdsa_public_bytes).decode(),
                "mldsa_65": base64.b64encode(mldsa_public).decode()
            }
        }

        tbs = json.dumps(cert_data, sort_keys=True).encode()

        # Sign with both algorithms
        ecdsa_sig = ecdsa_private.sign(tbs, ec.ECDSA(hashes.SHA256()))
        mldsa_sig = self.mldsa.sign(mldsa_private, tbs)

        return {
            "certificate": cert_data,
            "signatures": {
                "ecdsa_p256_sha256": base64.b64encode(ecdsa_sig).decode(),
                "mldsa_65": base64.b64encode(mldsa_sig).decode()
            },
            "private_keys": {
                "ecdsa": ecdsa_private,
                "mldsa": mldsa_private
            }
        }

    def verify_hybrid(self, cert: dict, require_both: bool = True) -> dict:
        """
        Verify hybrid certificate.

        Args:
            cert: The hybrid certificate
            require_both: If True, both signatures must be valid
        """
        tbs = json.dumps(cert["certificate"], sort_keys=True).encode()

        results = {
            "ecdsa_valid": False,
            "mldsa_valid": False,
            "overall_valid": False
        }

        # Verify ECDSA (would need the public key extracted)
        # Simplified for demo - in practice, extract from cert

        # Verify ML-DSA
        mldsa_pk = base64.b64decode(cert["certificate"]["public_keys"]["mldsa_65"])
        mldsa_sig = base64.b64decode(cert["signatures"]["mldsa_65"])
        results["mldsa_valid"] = self.mldsa.verify(mldsa_pk, tbs, mldsa_sig)

        # Overall result
        if require_both:
            results["overall_valid"] = results["ecdsa_valid"] and results["mldsa_valid"]
        else:
            results["overall_valid"] = results["ecdsa_valid"] or results["mldsa_valid"]

        return results
```

### Migration Timeline Recommendation

```
Phase 1 (Now - 2025): Preparation
├── Inventory existing certificates
├── Test post-quantum algorithms
├── Update cryptographic libraries
└── Plan hybrid deployment

Phase 2 (2025 - 2027): Hybrid Deployment
├── Deploy hybrid Root CAs
├── Issue hybrid intermediate certificates
├── Begin hybrid end-entity certificates
└── Monitor performance impact

Phase 3 (2027 - 2030): Transition
├── New certificates: post-quantum only
├── Existing certificates: hybrid until expiry
├── Phase out classical-only certificates
└── Update all verification systems

Phase 4 (2030+): Post-Quantum Native
├── All certificates use post-quantum algorithms
├── Remove classical algorithm support
├── Archive migration documentation
└── Continuous security monitoring
```

---

## Summary

### Quick Reference

| Use Case | Algorithm | Key Sizes | Signature Size |
|----------|-----------|-----------|----------------|
| TLS Server | ML-DSA-65 | PK: 1.9KB, SK: 4KB | 3.3KB |
| API Auth | ML-DSA-44 | PK: 1.3KB, SK: 2.5KB | 2.4KB |
| IoT Device | ML-DSA-44 | PK: 1.3KB, SK: 2.5KB | 2.4KB |
| Root CA | SLH-DSA-256s | PK: 64B, SK: 128B | 29KB |
| Code Signing | SLH-DSA-128f | PK: 32B, SK: 64B | 17KB |
| Documents | SLH-DSA-128s | PK: 32B, SK: 64B | 7.8KB |

### Key Takeaways

1. **Use ML-DSA when speed matters** - APIs, TLS, IoT, real-time systems
2. **Use SLH-DSA for long-term security** - Root CAs, code signing, legal documents
3. **Start with hybrid certificates** during the transition period
4. **Plan for larger key/signature sizes** in storage and bandwidth
5. **Test thoroughly** before production deployment

---

## References

- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/publications/detail/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/publications/detail/fips/205/final)
- [NIST Post-Quantum Cryptography](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [X.509 Certificate Standard](https://datatracker.ietf.org/doc/html/rfc5280)
